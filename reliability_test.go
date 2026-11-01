package main

import (
	"bufio"
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

	if g.stalled(time.Now()) {
		t.Fatal("fresh work should not force restart")
	}

	g.lastActivity.Store(time.Now().Add(-4 * time.Minute).UnixNano())

	if !g.stalled(time.Now()) {
		t.Fatal("stalled proxy must request recovery")
	}

	g.noteActivity()

	if g.stalled(time.Now()) {
		t.Fatal("traffic must prevent restart")
	}

	g.lastActivity.Store(time.Now().Add(-4 * time.Minute).UnixNano())
	g.lastCapacityReject.Store(time.Now().Add(-2 * time.Minute).UnixNano())

	if g.stalled(time.Now()) {
		t.Fatal("old rejection must not request restart")
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
		relayWithIdleTimeout(client, upstream, bufio.NewReader(client), 70*time.Millisecond, nil)
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
		relayWithIdleTimeout(client, upstream, bufio.NewReader(client), 100*time.Millisecond, nil)
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
