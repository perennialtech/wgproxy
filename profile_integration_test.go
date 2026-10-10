package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startTestDNS serves only inside the peer's userspace stack. Returning nil
// deliberately drops a query without sending a response or an ICMP rejection.
func startTestDNS(
	t *testing.T,
	stack *netstack.Net,
	address netip.Addr,
	respond func(dnsmessage.Message) *dnsmessage.Message,
) {
	t.Helper()

	dns, err := stack.DialUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, 53)), nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	t.Cleanup(func() {
		_ = dns.Close()

		<-done
	})

	go func() {
		defer close(done)

		buffer := make([]byte, 4096)

		for {
			n, source, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}

			var query dnsmessage.Message
			if err := query.Unpack(buffer[:n]); err != nil {
				continue
			}

			response := respond(query)
			if response == nil {
				continue
			}

			packet, err := response.Pack()
			if err != nil {
				return
			}

			if _, err := dns.WriteTo(packet, source); err != nil {
				return
			}
		}
	}()
}

func testDNSResponse(query dnsmessage.Message) *dnsmessage.Message {
	response := &dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: true,
		},
		Questions: query.Questions,
	}

	for _, question := range query.Questions {
		name := question.Name.String()
		header := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  question.Type,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}

		switch {
		case question.Type == dnsmessage.TypeA &&
			(name == "only-in-tunnel.invalid." || name == "only-v4-in-tunnel.invalid."):
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: header,
				Body:   &dnsmessage.AResource{A: [4]byte{10, 2, 0, 1}},
			})
		case question.Type == dnsmessage.TypeAAAA &&
			(name == "only-in-tunnel.invalid." || name == "only-v6-in-tunnel.invalid."):
			response.Answers = append(response.Answers, dnsmessage.Resource{
				Header: header,
				Body: &dnsmessage.AAAAResource{
					AAAA: netip.MustParseAddr("fd00::1").As16(),
				},
			})
		}
	}

	return response
}

func dualStackTestConfig(config profileConfig) profileConfig {
	config.addresses = append(config.addresses, netip.MustParseAddr("fd00::2"))
	config.allowedIPs = append(config.allowedIPs, netip.MustParsePrefix("::/0"))
	config.ipv6 = true

	return config
}

func TestProfileDualStackDNS(t *testing.T) {
	tests := []struct {
		name string
		dns  string
		ipv6 bool
	}{
		{"IPv4 only", "10.2.0.1", false},
		{"dual stack with IPv4 DNS", "10.2.0.1", true},
		{"dual stack with IPv6 DNS", "fd00::1", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit := newTestExitPeer(t, "dns")
			config := exit.config

			if test.ipv6 {
				config = dualStackTestConfig(config)
			}

			config.dns = []netip.Addr{netip.MustParseAddr(test.dns)}

			var aQueries, aaaaQueries atomic.Int64

			startTestDNS(t, exit.stack, config.dns[0],
				func(query dnsmessage.Message) *dnsmessage.Message {
					for _, question := range query.Questions {
						switch question.Type {
						case dnsmessage.TypeA:
							aQueries.Add(1)
						case dnsmessage.TypeAAAA:
							aaaaQueries.Add(1)
						}
					}

					return testDNSResponse(query)
				})

			p := newTestProfile(t, config, defaultOptions())
			targets := []struct {
				host string
				ip   netip.Addr
			}{
				{"only-v4-in-tunnel.invalid", netip.MustParseAddr("10.2.0.1")},
				{"only-v6-in-tunnel.invalid", netip.MustParseAddr("fd00::1")},
			}

			if !test.ipv6 {
				targets = targets[:1]
			}

			for _, target := range targets {
				beforeA := aQueries.Load()
				beforeAAAA := aaaaQueries.Load()

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				connection, err := p.dial(ctx, "tcp", net.JoinHostPort(target.host, "8081"))

				cancel()

				if err != nil {
					t.Fatalf("dial %s: %v", target.host, err)
				}

				remote, parseErr := netip.ParseAddrPort(connection.RemoteAddr().String())
				_ = connection.Close()

				if parseErr != nil || remote.Addr().Unmap() != target.ip {
					t.Fatalf("dial %s reached %v, want %v: %v",
						target.host, remote, target.ip, parseErr)
				}

				if aQueries.Load() == beforeA {
					t.Fatalf("%s did not issue an A query", target.host)
				}

				if test.ipv6 {
					if aaaaQueries.Load() == beforeAAAA {
						t.Fatalf("%s did not issue an AAAA query", target.host)
					}
				} else if aaaaQueries.Load() != 0 {
					t.Fatal("an IPv4-only profile issued an AAAA query")
				}
			}
		})
	}
}

func TestProfileDNSFallsBackAfterSilentResolver(t *testing.T) {
	exit := newTestExitPeer(t, "dns-fallback")
	config := dualStackTestConfig(exit.config)
	config.dns = []netip.Addr{
		netip.MustParseAddr("fd00::1"),
		netip.MustParseAddr("10.2.0.1"),
	}

	var silentQueries, responsiveQueries atomic.Int64

	startTestDNS(t, exit.stack, config.dns[0],
		func(dnsmessage.Message) *dnsmessage.Message {
			silentQueries.Add(1)

			return nil
		})
	startTestDNS(t, exit.stack, config.dns[1],
		func(query dnsmessage.Message) *dnsmessage.Message {
			responsiveQueries.Add(1)

			return testDNSResponse(query)
		})

	p := newTestProfile(t, config, defaultOptions())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	connection, err := p.dial(ctx, "tcp", "only-v4-in-tunnel.invalid:8081")
	if err != nil {
		t.Fatalf("dial through the second resolver: %v", err)
	}
	defer connection.Close()

	if silentQueries.Load() == 0 {
		t.Fatal("the first resolver never received a query")
	}

	if responsiveQueries.Load() == 0 {
		t.Fatal("the responsive resolver never received a query")
	}
}

func TestProfileDNSRetriesShareDeadline(t *testing.T) {
	// Allow the first five-second resolver attempt to expire, leaving only
	// part of an attempt for the second server. A fresh timeout per retry
	// would exceed the total budget.
	const budget = 7 * time.Second

	tests := []struct {
		name          string
		callerTimeout time.Duration
		dialTimeout   time.Duration
	}{
		{"caller deadline", budget, 20 * time.Second},
		{"dial timeout", 20 * time.Second, budget},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit := newTestExitPeer(t, "dns-deadline")
			config := dualStackTestConfig(exit.config)
			config.dns = []netip.Addr{
				netip.MustParseAddr("10.2.0.1"),
				netip.MustParseAddr("fd00::1"),
			}

			var queries [2]atomic.Int64

			for index, address := range config.dns {
				startTestDNS(t, exit.stack, address,
					func(dnsmessage.Message) *dnsmessage.Message {
						queries[index].Add(1)

						return nil
					})
			}

			o := defaultOptions()
			o.dialTimeout = test.dialTimeout
			p := newTestProfile(t, config, o)

			ctx, cancel := context.WithTimeout(context.Background(), test.callerTimeout)
			defer cancel()

			start := time.Now()
			connection, err := p.dial(ctx, "tcp", "only-in-tunnel.invalid:8081")
			elapsed := time.Since(start)

			if connection != nil {
				_ = connection.Close()

				t.Fatal("silent resolvers unexpectedly produced a connection")
			}

			var networkError net.Error
			if !errors.As(err, &networkError) || !networkError.Timeout() {
				t.Fatalf("dial error = %v, want a timeout", err)
			}

			if elapsed < budget-time.Second || elapsed > budget+2*time.Second {
				t.Fatalf("dial took %v, want exhaustion of the shared %v budget", elapsed, budget)
			}

			for index := range queries {
				if queries[index].Load() == 0 {
					t.Fatalf("resolver %d was not attempted before the deadline", index+1)
				}
			}

			if test.callerTimeout == budget {
				if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatalf("caller context error = %v, want deadline exceeded", ctx.Err())
				}
			} else if ctx.Err() != nil {
				t.Fatalf("dial timeout should leave the caller context live: %v", ctx.Err())
			}
		})
	}
}

func TestProfileStartupWithKeepalive(t *testing.T) {
	const keepalive = 25

	tests := []struct {
		name        string
		endpoint    string
		endpointSet bool
	}{
		{"numeric endpoint", "127.0.0.1", true},
		{"hostname endpoint", "localhost", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit := newTestExitPeer(t, "keepalive")
			config := exit.config
			config.endpointHost = test.endpoint
			config.keepalive = keepalive

			// Unlike newTestExit, this does not perform a health check:
			// inspect startup state before endpoint discovery can change it.
			p := newTestProfile(t, config, defaultOptions())

			if p.endpointSet != test.endpointSet {
				t.Fatalf("startup endpointSet = %v, want %v", p.endpointSet, test.endpointSet)
			}

			initialKeepalive := uint16(0)
			if test.endpointSet {
				initialKeepalive = keepalive
			}

			assertTestKeepalive(t, p, initialKeepalive)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// A numeric health destination keeps endpoint bootstrap DNS
			// separate from destination DNS in this startup test.
			if err := p.check(ctx, "http://10.2.0.1:8081/health"); err != nil {
				t.Fatalf("health check after keepalive-enabled startup: %v", err)
			}

			if !p.endpointSet {
				t.Fatal("successful health check did not install the endpoint")
			}

			assertTestKeepalive(t, p, keepalive)
		})
	}
}

func assertTestKeepalive(t *testing.T, p *profile, want uint16) {
	t.Helper()

	state, err := p.device.IpcGet()
	if err != nil {
		t.Fatal(err)
	}

	expected := fmt.Sprintf("persistent_keepalive_interval=%d", want)

	for _, line := range strings.Split(state, "\n") {
		if line == expected {
			return
		}
	}

	// Do not print the IPC state: it contains private key material.
	t.Fatalf("WireGuard did not report the expected keepalive interval %d", want)
}
