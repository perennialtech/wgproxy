package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type healthRoundTripper func(*http.Request) (*http.Response, error)

func (f healthRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRequestHealthCheck(t *testing.T) {
	failure := errors.New("destination failed")

	tests := []struct {
		name     string
		err      error
		canceled bool
		healthy  bool
		want     int
	}{
		{"failure", failure, false, true, 1},
		{"dial timeout", context.DeadlineExceeded, false, true, 1},
		{"no error", nil, false, true, 0},
		{"cancellation error", context.Canceled, false, true, 0},
		{"canceled request", failure, true, true, 0},
		{"already unhealthy", failure, false, false, 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if test.canceled {
				cancel()
			}

			p := &profile{
				healthy:        test.healthy,
				healthRequests: make(chan struct{}, 1),
			}

			for range 4 {
				p.requestHealthCheck(ctx, test.err)
			}

			if got := len(p.healthRequests); got != test.want {
				t.Fatalf("pending checks = %d, want %d", got, test.want)
			}

			if p.isHealthy() != test.healthy {
				t.Fatal("a destination failure changed profile health directly")
			}
		})
	}
}

func TestHealthLogsEveryFailure(t *testing.T) {
	var output bytes.Buffer

	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))

	defer slog.SetDefault(previous)

	p := &profile{config: profileConfig{id: "test"}}
	p.setHealth(errors.New("first failure"))
	p.setHealth(errors.New("second failure"))
	p.setHealth(nil)
	p.setHealth(nil)

	logs := output.String()

	if got := strings.Count(logs, `"msg":"profile unhealthy"`); got != 2 {
		t.Fatalf("failure log count = %d, want 2: %s", got, logs)
	}

	if got := strings.Count(logs, `"msg":"profile healthy"`); got != 1 {
		t.Fatalf("recovery log count = %d, want 1: %s", got, logs)
	}

	if !strings.Contains(logs, "first failure") || !strings.Contains(logs, "second failure") {
		t.Fatalf("failure details were lost: %s", logs)
	}
}

func TestRunHealthExpeditedChecks(t *testing.T) {
	for _, interval := range []time.Duration{30 * time.Second, 2 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var checks, status atomic.Int32

				status.Store(http.StatusNoContent)

				p := &profile{
					endpointSet:    true,
					healthRequests: make(chan struct{}, 1),
					healthClient: &http.Client{
						Transport: healthRoundTripper(func(*http.Request) (*http.Response, error) {
							checks.Add(1)

							return &http.Response{
								StatusCode: int(status.Load()),
								Body:       http.NoBody,
							}, nil
						}),
					},
				}

				o := defaultOptions()
				o.healthInterval = interval

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				go runHealth(ctx, p, o, 0)

				assertChecks := func(want int32) {
					t.Helper()
					synctest.Wait()

					if got := checks.Load(); got != want {
						t.Fatalf("checks = %d, want %d", got, want)
					}
				}

				assertChecks(1)

				if !p.isHealthy() {
					t.Fatal("initial successful check did not enable the profile")
				}

				failure := errors.New("destination failed")
				gap := min(5*time.Second, interval)

				for range 20 {
					p.requestHealthCheck(ctx, failure)
				}

				assertChecks(1)

				time.Sleep(gap / 2)
				p.requestHealthCheck(ctx, failure)
				assertChecks(1)

				// Another failure must not postpone the already pending check.
				time.Sleep(gap / 2)
				assertChecks(2)

				status.Store(http.StatusServiceUnavailable)
				p.requestHealthCheck(ctx, failure)
				assertChecks(2)

				time.Sleep(gap)
				assertChecks(3)

				if p.isHealthy() {
					t.Fatal("failed expedited check did not disable the profile")
				}

				// Late failures from already assigned operations must not
				// accelerate recovery checks for an unhealthy profile.
				p.requestHealthCheck(ctx, failure)
				time.Sleep(interval / 2)
				assertChecks(3)

				status.Store(http.StatusNoContent)
				time.Sleep(interval / 2)
				assertChecks(4)

				if !p.isHealthy() {
					t.Fatal("periodic successful check did not restore the profile")
				}

				cancel()
				synctest.Wait()
				time.Sleep(interval)
				assertChecks(4)
			})
		})
	}
}

func TestRunHealthCoalescesRequestsDuringCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var checks atomic.Int32

		release := make(chan struct{})

		p := &profile{
			endpointSet:    true,
			healthy:        true,
			healthRequests: make(chan struct{}, 1),
			healthClient: &http.Client{
				Transport: healthRoundTripper(func(r *http.Request) (*http.Response, error) {
					if checks.Add(1) == 1 {
						select {
						case <-release:
						case <-r.Context().Done():
							return nil, r.Context().Err()
						}
					}

					return &http.Response{
						StatusCode: http.StatusNoContent,
						Body:       http.NoBody,
					}, nil
				}),
			},
		}

		o := defaultOptions()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go runHealth(ctx, p, o, 0)

		synctest.Wait()

		if got := checks.Load(); got != 1 {
			t.Fatalf("initial checks = %d, want 1", got)
		}

		for range 20 {
			p.requestHealthCheck(ctx, errors.New("destination failed"))
		}

		// Let the early-check cooldown expire while the first check is
		// still running. No second check may overlap it.
		time.Sleep(6 * time.Second)
		synctest.Wait()

		if got := checks.Load(); got != 1 {
			t.Fatalf("overlapping checks: got %d, want 1", got)
		}

		close(release)
		synctest.Wait()

		if got := checks.Load(); got != 1 {
			t.Fatalf("queued failures caused a redundant check: got %d, want 1", got)
		}

		time.Sleep(o.healthInterval)
		synctest.Wait()

		if got := checks.Load(); got != 2 {
			t.Fatalf("periodic checks = %d, want 2", got)
		}

		cancel()
		synctest.Wait()
	})
}
