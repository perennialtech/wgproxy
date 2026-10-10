package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type testExit struct {
	profile    *profile
	dnsQueries atomic.Int64
	holdStart  chan struct{}
	holdEnd    chan struct{}
}

func testKey(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(key.Bytes()), hex.EncodeToString(key.PublicKey().Bytes())
}

func newTestExit(t *testing.T, id string) *testExit {
	t.Helper()

	serverPrivate, serverPublic := testKey(t)
	clientPrivate, clientPublic := testKey(t)

	tun, stack, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.2.0.1")},
		nil,
		1420,
	)
	if err != nil {
		t.Fatal(err)
	}

	wg := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(wg.Close)

	ipc := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\nreplace_peers=true\npublic_key=%s\nallowed_ip=10.2.0.2/32\n",
		serverPrivate, clientPublic,
	)
	if err := wg.IpcSet(ipc); err != nil {
		t.Fatal(err)
	}

	if err := wg.Up(); err != nil {
		t.Fatal(err)
	}

	state, err := wg.IpcGet()
	if err != nil {
		t.Fatal(err)
	}

	var port uint16

	for _, line := range strings.Split(state, "\n") {
		if value, found := strings.CutPrefix(line, "listen_port="); found {
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				t.Fatal(err)
			}

			port = uint16(n)
		}
	}

	if port == 0 {
		t.Fatal("WireGuard server did not allocate a UDP port")
	}

	exit := &testExit{
		holdStart: make(chan struct{}, 1),
		holdEnd:   make(chan struct{}),
	}

	// This DNS server is reachable only inside this exit's userspace stack.
	dns, err := stack.DialUDP(&net.UDPAddr{
		IP:   net.ParseIP("10.2.0.1"),
		Port: 53,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = dns.Close() })

	go func() {
		buffer := make([]byte, 4096)

		for {
			n, address, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}

			var query dnsmessage.Message
			if err := query.Unpack(buffer[:n]); err != nil {
				continue
			}

			exit.dnsQueries.Add(1)

			response := dnsmessage.Message{
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
				if question.Type == dnsmessage.TypeA &&
					question.Name.String() == "only-in-tunnel.invalid." {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{
							Name:  question.Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   60,
						},
						Body: &dnsmessage.AResource{A: [4]byte{10, 2, 0, 1}},
					})
				}
			}

			packet, err := response.Pack()
			if err != nil {
				return
			}

			if _, err := dns.WriteTo(packet, address); err != nil {
				return
			}
		}
	}()

	listener, err := stack.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("10.2.0.1"),
		Port: 8081,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
				http.Error(w, "hop-by-hop header leaked", http.StatusInternalServerError)
				return
			}

			if r.URL.Path == "/hold" {
				select {
				case exit.holdStart <- struct{}{}:
				default:
				}

				select {
				case <-exit.holdEnd:
				case <-r.Context().Done():
					return
				}
			}

			if r.URL.Path == "/stream" {
				w.Header().Set("Trailer", "X-Complete")
				w.WriteHeader(http.StatusOK)
				http.NewResponseController(w).Flush()
				_, _ = io.CopyN(w, zeroReader{}, 4<<20)
				w.Header().Set("X-Complete", "yes")

				return
			}

			_, _ = io.WriteString(w, id)
		}),
	}

	t.Cleanup(func() { _ = server.Close() })

	go func() { _ = server.Serve(listener) }()

	config := profileConfig{
		id:           id,
		privateKey:   clientPrivate,
		publicKey:    serverPublic,
		addresses:    []netip.Addr{netip.MustParseAddr("10.2.0.2")},
		dns:          []netip.Addr{netip.MustParseAddr("10.2.0.1")},
		allowedIPs:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		endpointHost: "127.0.0.1",
		endpointPort: port,
		mtu:          1420,
	}

	p, err := newProfile(config, defaultOptions())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(p.close)

	exit.profile = p

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := p.check(ctx, "http://only-in-tunnel.invalid:8081/health"); err != nil {
		t.Fatalf("initial tunneled health check: %v", err)
	}

	p.setHealth(nil)

	return exit
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func proxyClient(t *testing.T, g *gateway) (*http.Client, string) {
	t.Helper()

	server := httptest.NewServer(g)
	t.Cleanup(server.Close)
	t.Cleanup(g.forceClose)

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}, proxyURL.Host
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	return string(body)
}

func TestRealWireGuardRoundRobinDNSAndConnect(t *testing.T) {
	a := newTestExit(t, "a")
	b := newTestExit(t, "b")
	g := newGateway([]*profile{a.profile, b.profile}, 16)
	client, proxyAddress := proxyClient(t, g)

	for _, expected := range []string{"a", "b", "a", "b"} {
		request, err := http.NewRequest(http.MethodGet, "http://only-in-tunnel.invalid:8081/", nil)
		if err != nil {
			t.Fatal(err)
		}

		request.Header.Set("Connection", "X-Hop")
		request.Header.Set("X-Hop", "must-not-arrive")
		request.Header.Set("Proxy-Authorization", "Basic dGVzdDp0ZXN0")

		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}

		body := readBody(t, response)
		if response.StatusCode != http.StatusOK || body != expected {
			t.Fatalf("HTTP: status=%d body=%q, want %q", response.StatusCode, body, expected)
		}
	}

	for _, expected := range []string{"a", "b"} {
		testCONNECT(t, proxyAddress, expected)
	}

	if a.dnsQueries.Load() == 0 || b.dnsQueries.Load() == 0 {
		t.Fatal("each isolated DNS server must receive queries")
	}

	b.profile.setHealth(errors.New("test failure"))

	for range 2 {
		response, err := client.Get("http://only-in-tunnel.invalid:8081/")
		if err != nil {
			t.Fatal(err)
		}

		if body := readBody(t, response); body != "a" {
			t.Fatalf("unhealthy profile was selected: %q", body)
		}
	}

	a.profile.setHealth(errors.New("test failure"))

	response, err := client.Get("http://only-in-tunnel.invalid:8081/")
	if err != nil {
		t.Fatal(err)
	}

	_ = readBody(t, response)

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("empty healthy pool returned %d", response.StatusCode)
	}

	b.profile.setHealth(nil)

	response, err = client.Get("http://only-in-tunnel.invalid:8081/")
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, response); body != "b" {
		t.Fatalf("recovered profile was not selected: %q", body)
	}
}

func testCONNECT(t *testing.T, proxyAddress, expected string) {
	t.Helper()

	address, err := net.ResolveTCPAddr("tcp", proxyAddress)
	if err != nil {
		t.Fatal(err)
	}

	connection, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Send application data with CONNECT so it can be buffered by net/http.
	_, err = io.WriteString(connection,
		"CONNECT only-in-tunnel.invalid:8081 HTTP/1.1\r\n"+
			"Host: only-in-tunnel.invalid:8081\r\n\r\n"+
			"GET / HTTP/1.1\r\nHost: only-in-tunnel.invalid:8081\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(connection)

	connected, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}

	if connected.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT returned %d", connected.StatusCode)
	}

	// The successful CONNECT body is the tunnel itself. Continue with the
	// same buffered reader rather than reading or closing that body.
	first, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, first); body != expected {
		t.Fatalf("first tunneled response %q, want %q", body, expected)
	}

	_, err = io.WriteString(connection,
		"GET / HTTP/1.1\r\nHost: only-in-tunnel.invalid:8081\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	// A client write-half-close must not discard the server's response.
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	second, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}

	if body := readBody(t, second); body != expected {
		t.Fatalf("CONNECT changed profiles: %q, want %q", body, expected)
	}
}

func TestNoDirectDialAndNoIPv6Fallback(t *testing.T) {
	exit := newTestExit(t, "isolated")

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)

	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}

			_ = connection.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	connection, dialErr := exit.profile.dial(ctx, "tcp", listener.Addr().String())

	cancel()

	if connection != nil {
		_ = connection.Close()
	}

	if dialErr == nil {
		t.Fatal("a host-network-only TCP listener was reachable through the profile")
	}

	select {
	case <-accepted:
		t.Fatal("destination traffic used the host network")
	default:
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	connection, dialErr = exit.profile.dial(ctx, "tcp", "[::1]:8081")
	if connection != nil {
		_ = connection.Close()
	}

	if dialErr == nil {
		t.Fatal("an IPv4-only profile accepted an IPv6 destination")
	}
}

func TestLimitsStreamingTrailersAndDraining(t *testing.T) {
	exit := newTestExit(t, "a")
	g := newGateway([]*profile{exit.profile}, 1)
	client, _ := proxyClient(t, g)

	firstResult := make(chan error, 1)

	go func() {
		response, err := client.Get("http://only-in-tunnel.invalid:8081/hold")
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}

		firstResult <- err
	}()

	select {
	case <-exit.holdStart:
	case <-time.After(15 * time.Second):
		t.Fatal("first request did not reach the tunneled server")
	}

	response, err := client.Get("http://only-in-tunnel.invalid:8081/")
	if err != nil {
		t.Fatal(err)
	}

	_ = readBody(t, response)

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("active-operation limit returned %d", response.StatusCode)
	}

	close(exit.holdEnd)

	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}

	response, err = client.Get("http://only-in-tunnel.invalid:8081/stream")
	if err != nil {
		t.Fatal(err)
	}

	n, copyErr := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	if copyErr != nil || n != 4<<20 {
		t.Fatalf("stream: bytes=%d error=%v", n, copyErr)
	}

	if response.Trailer.Get("X-Complete") != "yes" {
		t.Fatal("response trailer was not forwarded")
	}

	g.beginDrain()

	response, err = client.Get("http://only-in-tunnel.invalid:8081/")
	if err != nil {
		t.Fatal(err)
	}

	_ = readBody(t, response)

	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("draining returned %d", response.StatusCode)
	}

	admin := httptest.NewRecorder()
	g.adminHandler().ServeHTTP(admin, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if admin.Code != http.StatusServiceUnavailable {
		t.Fatalf("draining readiness returned %d", admin.Code)
	}
}

func TestUpstreamFailuresRequestHealthChecks(t *testing.T) {
	exit := newTestExit(t, "a")
	g := newGateway([]*profile{exit.profile}, 1)

	defer g.forceClose()

	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		t.Run(method, func(t *testing.T) {
			// This address is inside the tunnel, but the port has no listener.
			request := httptest.NewRequest(method, "http://10.2.0.1:8082/", nil)
			if method == http.MethodConnect {
				request.RequestURI = "10.2.0.1:8082"
			}

			response := httptest.NewRecorder()
			g.ServeHTTP(response, request)

			if response.Code != http.StatusBadGateway {
				t.Fatalf("failed destination returned %d, want 502", response.Code)
			}

			select {
			case <-exit.profile.healthRequests:
			default:
				t.Fatal("upstream failure did not request a health check")
			}

			if !exit.profile.isHealthy() {
				t.Fatal("a destination failure directly disabled a healthy profile")
			}
		})
	}
}

func TestForceCloseTerminatesConnect(t *testing.T) {
	exit := newTestExit(t, "a")
	g := newGateway([]*profile{exit.profile}, 1)
	_, proxyAddress := proxyClient(t, g)

	connection, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}

	_, err = io.WriteString(connection,
		"CONNECT only-in-tunnel.invalid:8081 HTTP/1.1\r\n"+
			"Host: only-in-tunnel.invalid:8081\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(connection)

	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT returned %d", response.StatusCode)
	}

	g.beginDrain()
	g.forceClose()

	_, err = reader.ReadByte()
	if err == nil {
		t.Fatal("CONNECT remained open after forced shutdown")
	}

	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		t.Fatal("CONNECT was not closed; read timed out")
	}

	done := make(chan struct{})

	go func() {
		g.active.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not finish")
	}
}
