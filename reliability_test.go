package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapacityReadinessAndStatus(t *testing.T) {
	p := &profile{healthy: true}

	g := newGateway([]*profile{p}, 1)
	defer g.forceClose()

	if !g.begin() {
		t.Fatal("failed to occupy slot")
	}
	defer g.end()

	if g.fullSince.IsZero() {
		t.Fatal("capacity admission did not set fullSince")
	}

	readiness := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if readiness.Code != http.StatusServiceUnavailable || !strings.Contains(readiness.Body.String(), "capacity exhausted") {
		t.Fatalf("full proxy must not claim to be ready: %d %q", readiness.Code, readiness.Body.String())
	}

	rejected := httptest.NewRecorder()
	g.ServeHTTP(rejected, httptest.NewRequest(http.MethodGet, "http://example.invalid/", nil))

	if rejected.Code != http.StatusServiceUnavailable {
		t.Fatalf("rejection: %d", rejected.Code)
	}

	status := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/status", nil))

	var payload struct{ Gateway gatewayStatus }
	if err := json.Unmarshal(status.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	if payload.Gateway.Active != 1 || payload.Gateway.MaxActive != 1 || payload.Gateway.RejectedCapacity != 1 {
		t.Fatalf("unexpected counters: %+v", payload.Gateway)
	}

	// Capacity is not evidence that existing sessions have failed.
	state := []profileStatus{{Checked: true, Healthy: false, ConsecutiveFailures: 3}}
	if eligibleForRestart(state, 1) {
		t.Fatal("cannot restart with accepted active operations")
	}
}

func tcpPair(t *testing.T) (net.Conn, *net.TCPConn) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })

	return conn, peer.(*net.TCPConn)
}

func TestAbandonedHalfClosedRelayReleasesSlot(t *testing.T) {
	client, clientPeer := tcpPair(t)
	upstream, upstreamPeer := tcpPair(t)
	done := make(chan struct{})

	go func() {
		relayWithIdleTimeout(client, upstream, bufio.NewReader(client), 70*time.Millisecond, nil, nil)
		close(done)
	}()

	if err := clientPeer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := upstreamPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err := upstreamPeer.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("client FIN was not propagated: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("abandoned relay retained its slot")
	}
}

func TestHalfClosedRelayAllowsStreamingResponse(t *testing.T) {
	client, clientPeer := tcpPair(t)
	upstream, upstreamPeer := tcpPair(t)
	done := make(chan struct{})

	go func() {
		relayWithIdleTimeout(client, upstream, bufio.NewReader(client), 100*time.Millisecond, nil, nil)
		close(done)
	}()

	if err := clientPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := upstreamPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err := upstreamPeer.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("client FIN was not propagated: %v", err)
	}

	go func() {
		for range 5 {
			_, _ = upstreamPeer.Write([]byte("x"))

			time.Sleep(30 * time.Millisecond)
		}

		_ = upstreamPeer.CloseWrite()
	}()

	if err := clientPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(clientPeer)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "xxxxx" {
		t.Fatalf("streaming response truncated: %q", data)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not finish after both half-closes")
	}
}

func TestBlockedHalfClosedWriteReleasesSlot(t *testing.T) {
	client, clientPeer := tcpPair(t)

	upstream, upstreamPeer := tcpPair(t)
	if err := client.(*net.TCPConn).SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})

	go func() {
		relayWithIdleTimeout(client, upstream, bufio.NewReader(client), 80*time.Millisecond, nil, nil)
		close(done)
	}()

	if err := clientPeer.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := upstreamPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err := upstreamPeer.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("client FIN was not forwarded: %v", err)
	}

	// The client stops reading, so an upstream stream blocks while writing to
	// the client socket, not while reading upstream bytes.
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)

		_ = upstreamPeer.SetWriteDeadline(time.Now().Add(2 * time.Second))

		chunk := bytes.Repeat([]byte("x"), 64<<10)
		for range 256 {
			if _, err := upstreamPeer.Write(chunk); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked write retained relay after half-close idle timeout")
	}

	<-pumpDone
}

func TestHTTPProgressAndHealthRecovery(t *testing.T) {
	g := newGateway(nil, 1)
	defer g.forceClose()

	g.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano())

	if !g.begin() {
		t.Fatal("cannot occupy slot")
	}
	defer g.end()

	if g.fullSince.IsZero() {
		t.Fatal("newly saturated gateway did not record its start time")
	}

	if g.begin() {
		t.Fatal("should be full")
	}

	// Request acceptance, upload bytes, and response bytes are useful traffic.
	if time.Since(time.Unix(0, g.lastActivity.Load())) > time.Minute {
		t.Fatal("newly admitted work did not record progress")
	}

	g.lastActivity.Store(time.Now().Add(-4 * time.Minute).UnixNano())

	writer := &activityResponseWriter{ResponseWriter: httptest.NewRecorder(), activity: g.noteActivity}
	if _, err := writer.Write([]byte("streaming")); err != nil {
		t.Fatal(err)
	}

	if time.Since(time.Unix(0, g.lastActivity.Load())) > time.Minute {
		t.Fatal("HTTP streaming output did not record progress")
	}

	g.lastActivity.Store(time.Now().Add(-4 * time.Minute).UnixNano())

	reader := &activityReadCloser{ReadCloser: io.NopCloser(strings.NewReader("upload")), activity: g.noteActivity}
	if _, err := reader.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}

	if time.Since(time.Unix(0, g.lastActivity.Load())) > time.Minute {
		t.Fatal("HTTP request upload did not record progress")
	}

	// Restart is only permitted after every scheduled profile has
	// performed at least two failed probes, with no active operations.
	states := []profileStatus{
		{Checked: true, Healthy: false, ConsecutiveFailures: 2},
		{Checked: false, Healthy: false, ConsecutiveFailures: 0},
	}
	if eligibleForRestart(states, 0) {
		t.Fatal("restart must wait for staggered initial checks")
	}

	states[1] = profileStatus{Checked: true, Healthy: false, ConsecutiveFailures: 1}
	if eligibleForRestart(states, 0) {
		t.Fatal("restart must wait for another scheduled failed check")
	}

	states[1].ConsecutiveFailures = 2
	if !eligibleForRestart(states, 0) {
		t.Fatal("two failed cycles with no active sessions should allow recovery")
	}

	if eligibleForRestart(states, 1) {
		t.Fatal("existing CONNECT work must block process restart")
	}

	states[0].Healthy = true
	if eligibleForRestart(states, 0) {
		t.Fatal("working profile must prevent restart")
	}

	p := &profile{config: profileConfig{id: "probe"}}
	p.setHealth(errors.New("probe temporarily unavailable"))

	if ps := p.status(); !ps.Checked || ps.ConsecutiveFailures != 1 || ps.LastCheck == nil {
		t.Fatalf("first probe status: %+v", ps)
	}

	p.setHealth(errors.New("probe still unavailable"))

	if ps := p.status(); ps.ConsecutiveFailures != 2 || !eligibleForRestart([]profileStatus{ps}, 0) {
		t.Fatalf("second probe status: %+v", ps)
	}

	p.setHealth(nil)

	if ps := p.status(); ps.ConsecutiveFailures != 0 || !ps.Healthy || eligibleForRestart([]profileStatus{ps}, 0) {
		t.Fatalf("recovered probe status: %+v", ps)
	}
}

func TestSlowActiveWriteSurvivesHalfCloseDeadline(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	writer := &relayWriter{conn: left, idle: 160 * time.Millisecond}
	writer.arm()

	// The entire write takes much longer than the deadline, while every
	// chunk moves forward. Without chunking this write times out.
	payload := bytes.Repeat([]byte("x"), 16<<10)
	result := make(chan error, 1)

	go func() {
		n, err := writer.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}

		result <- err
	}()

	received := make([]byte, 256)
	for range len(payload) / len(received) {
		if _, err := io.ReadFull(right, received); err != nil {
			t.Fatal(err)
		}

		time.Sleep(8 * time.Millisecond)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("slow but active write ended early: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("paced stream remained blocked")
	}
}

type countingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func TestHealthLocksAcrossRecovery(t *testing.T) {
	first := &profile{config: profileConfig{id: "first"}}

	second := &profile{config: profileConfig{id: "second"}}
	for _, p := range []*profile{first, second} {
		p.setHealth(errors.New("initial failure"))
		p.setHealth(errors.New("consecutive failure"))
	}

	g := newGateway([]*profile{first, second}, 1)
	defer g.forceClose()

	// Hold the second profile's health lock so recovery must stop after
	// acquiring the first. A change in the first must not slip through
	// before the restart decision is finalized.
	second.mu.Lock()

	decision := make(chan bool, 1)
	go func() { decision <- g.beginRecovery() }()

	deadline := time.Now().Add(time.Second)

	for g.mu.TryLock() {
		g.mu.Unlock()

		if time.Now().After(deadline) {
			second.mu.Unlock()
			t.Fatal("recovery did not enter its critical section")
		}

		time.Sleep(time.Millisecond)
	}

	recovered := make(chan struct{})

	go func() { first.setHealth(nil); close(recovered) }()

	select {
	case <-recovered:
		second.mu.Unlock()
		t.Fatal("profile health changed while recovery was examining it")
	case <-time.After(20 * time.Millisecond):
	}
	second.mu.Unlock()

	select {
	case ok := <-decision:
		if !ok {
			t.Fatal("stable failed profiles did not authorize recovery")
		}
	case <-time.After(time.Second):
		t.Fatal("recovery did not finish")
	}

	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("health update remained blocked after decision")
	}
}

func TestHalfCloseDuringActiveSlowWrite(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	c := &countingConn{Conn: left}
	writer := &relayWriter{conn: c, idle: 180 * time.Millisecond}

	payload := bytes.Repeat([]byte("x"), 32<<10)
	result := make(chan error, 1)

	go func() {
		n, err := writer.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}

		result <- err
	}()

	firstChunk := make([]byte, 128)
	if _, err := io.ReadFull(right, firstChunk); err != nil {
		t.Fatal(err)
	}

	writer.arm()

	// Read continuously, but a 32 KiB unbounded write would take more
	// than the inactivity deadline. Short writes must survive arming.
	for n := len(firstChunk); n < len(payload); n += len(firstChunk) {
		if _, err := io.ReadFull(right, firstChunk); err != nil {
			t.Fatal(err)
		}

		time.Sleep(10 * time.Millisecond)
	}

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("stream transferring bytes continuously was truncated: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow active write did not finish")
	}

	if c.writes.Load() <= 1 {
		t.Fatal("mid-write half-close was not bounded into progress-sized writes")
	}
}
