package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

	// Exhausted slots may be occupied by valid idle sessions; readiness
	// reports overload without triggering an indiscriminate process restart.
	if since, restart := unhealthyLongEnough(time.Now().Add(-time.Hour), 1, time.Now()); restart || !since.IsZero() {
		t.Fatal("healthy profiles must prevent a whole-process restart")
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

	now := time.Now()

	since, restart := unhealthyLongEnough(time.Time{}, 0, now)
	if restart || !since.Equal(now) {
		t.Fatal("first all-unhealthy observation must not restart immediately")
	}

	if _, restart := unhealthyLongEnough(since, 0, now.Add(2*time.Minute)); restart {
		t.Fatal("transient VPN health failure must not restart")
	}

	if _, restart := unhealthyLongEnough(since, 0, now.Add(4*time.Minute)); !restart {
		t.Fatal("sustained complete VPN health failure must trigger recovery")
	}

	if reset, restart := unhealthyLongEnough(since, 1, now.Add(4*time.Minute)); restart || !reset.IsZero() {
		t.Fatal("a recovered profile must clear the restart timer")
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
