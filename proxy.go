package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tunnel struct {
	client   net.Conn
	upstream net.Conn
	started  time.Time
}

type gateway struct {
	profiles []*profile

	selectionMu sync.Mutex
	next        int

	mu                 sync.Mutex
	draining           bool
	closed             bool
	tunnels            map[*tunnel]struct{}
	active             sync.WaitGroup
	slots              chan struct{}
	rejectedCapacity   atomic.Uint64
	rejectedProfiles   atomic.Uint64
	completed          atomic.Uint64
	lastActivity       atomic.Int64
	lastCapacityReject atomic.Int64

	forceCtx    context.Context
	forceCancel context.CancelFunc
}

func newGateway(profiles []*profile, maxActive int) *gateway {
	ctx, cancel := context.WithCancel(context.Background())

	g := &gateway{
		profiles:    profiles,
		tunnels:     make(map[*tunnel]struct{}),
		slots:       make(chan struct{}, maxActive),
		forceCtx:    ctx,
		forceCancel: cancel,
	}
	g.lastActivity.Store(time.Now().UnixNano())

	return g
}

func (g *gateway) choose() *profile {
	g.selectionMu.Lock()
	defer g.selectionMu.Unlock()

	for range len(g.profiles) {
		p := g.profiles[g.next]
		g.next = (g.next + 1) % len(g.profiles)

		if p.isHealthy() {
			p.selected.Add(1)
			return p
		}
	}

	return nil
}

func (g *gateway) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.draining {
		return false
	}

	select {
	case g.slots <- struct{}{}:
		g.active.Add(1)
		return true
	default:
		total := g.rejectedCapacity.Add(1)
		g.lastCapacityReject.Store(time.Now().UnixNano())

		if total == 1 || total&(total-1) == 0 {
			slog.Warn("proxy admission rejected", "reason", "capacity",
				"active", len(g.slots), "max_active", cap(g.slots),
				"rejected_capacity_total", total)
		}

		return false
	}
}

func (g *gateway) end() {
	<-g.slots
	g.completed.Add(1)
	g.noteActivity()
	g.active.Done()
}

func (g *gateway) noteActivity() {
	g.lastActivity.Store(time.Now().UnixNano())
}

func (g *gateway) beginDrain() {
	g.mu.Lock()
	g.draining = true
	g.mu.Unlock()
}

func (g *gateway) addTunnel(t *tunnel) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return false
	}

	g.tunnels[t] = struct{}{}

	return true
}

func (g *gateway) removeTunnel(t *tunnel) {
	g.mu.Lock()
	delete(g.tunnels, t)
	g.mu.Unlock()
}

func (g *gateway) forceClose() {
	g.mu.Lock()
	g.draining = true
	g.closed = true

	tunnels := make([]*tunnel, 0, len(g.tunnels))
	for t := range g.tunnels {
		tunnels = append(tunnels, t)
	}
	g.mu.Unlock()

	g.forceCancel()

	for _, t := range tunnels {
		_ = t.client.Close()
		_ = t.upstream.Close()
	}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var destination string

	if r.Method == http.MethodConnect {
		if _, _, err := parseAuthority(r.RequestURI); err != nil {
			http.Error(w, "CONNECT requires a valid host:port", http.StatusBadRequest)
			return
		}

		destination = r.RequestURI
	} else {
		if r.URL.Scheme != "http" || r.URL.Host == "" ||
			r.URL.User != nil || r.URL.Fragment != "" {
			http.Error(w, "use an absolute http:// URL, or CONNECT for HTTPS", http.StatusBadRequest)
			return
		}

		if _, err := urlDestination(r.URL); err != nil {
			http.Error(w, "invalid destination authority", http.StatusBadRequest)
			return
		}

		if r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade") {
			http.Error(w, "HTTP Upgrade is not supported; use CONNECT", http.StatusNotImplemented)
			return
		}
	}

	if !g.begin() {
		http.Error(w, "proxy is draining or at its active-operation limit", http.StatusServiceUnavailable)
		return
	}
	defer g.end()

	p := g.choose()
	if p == nil {
		total := g.rejectedProfiles.Add(1)
		if total == 1 || total&(total-1) == 0 {
			slog.Warn("proxy admission rejected", "reason", "no_healthy_profiles",
				"rejected_profiles_total", total)
		}

		http.Error(w, "no healthy WireGuard profiles", http.StatusServiceUnavailable)

		return
	}

	p.active.Add(1)
	defer p.active.Add(-1)

	ctx, cancel := context.WithCancel(r.Context())

	stop := context.AfterFunc(g.forceCtx, cancel)
	defer cancel()
	defer stop()

	r = r.WithContext(ctx)

	if r.Method == http.MethodConnect {
		g.connect(w, r, p, destination)
		return
	}

	p.forward.ServeHTTP(w, r)
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}

	return false
}

func (g *gateway) connect(w http.ResponseWriter, r *http.Request, p *profile, destination string) {
	upstream, err := p.dial(r.Context(), "tcp", destination)
	if err != nil {
		p.requestHealthCheck(r.Context(), err)
		upstreamError(w, err)
		slog.Warn("CONNECT upstream failed",
			"profile", p.config.id,
			"destination", destination,
			"error", err)

		return
	}
	defer upstream.Close()

	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "cannot establish CONNECT tunnel", http.StatusInternalServerError)
		return
	}
	defer client.Close()

	t := &tunnel{client: client, upstream: upstream, started: time.Now()}
	if !g.addTunnel(t) {
		return
	}
	defer g.removeTunnel(t)

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	if err := buffered.Flush(); err != nil {
		return
	}

	// buffered.Reader may already contain application bytes sent immediately
	// after CONNECT headers. Reading directly from client would lose them.
	relayWithIdleTimeout(client, upstream, buffered.Reader, halfClosedIdleTimeout, g.noteActivity)
}

// Once either peer half-closes, idle reads on the opposite peer must end.
// Successful half-closes still permit an active streaming response to finish.
const halfClosedIdleTimeout = 90 * time.Second

type relayReader struct {
	source   io.Reader
	conn     net.Conn
	idle     time.Duration
	armed    atomic.Bool
	activity func()
}

func (r *relayReader) Read(p []byte) (int, error) {
	if r.armed.Load() {
		if err := r.conn.SetReadDeadline(time.Now().Add(r.idle)); err != nil {
			return 0, err
		}
	}

	n, err := r.source.Read(p)
	if n > 0 && r.activity != nil {
		r.activity()
	}

	return n, err
}

func (r *relayReader) arm() {
	r.armed.Store(true)
	_ = r.conn.SetReadDeadline(time.Now().Add(r.idle))
}

func relayWithIdleTimeout(client, upstream net.Conn, clientReader io.Reader, idle time.Duration, activity func()) {
	clientRead := &relayReader{source: clientReader, conn: client, idle: idle, activity: activity}
	upstreamRead := &relayReader{source: upstream, conn: upstream, idle: idle, activity: activity}
	done := make(chan struct{}, 2)

	copyDirection := func(direction string, destination net.Conn, source, opposite *relayReader) {
		defer func() { done <- struct{}{} }()

		_, err := io.Copy(destination, source)
		if err == nil {
			if halfCloser, ok := destination.(interface{ CloseWrite() error }); ok {
				err = halfCloser.CloseWrite()
			} else {
				err = destination.Close()
			}
		}

		if err != nil {
			var networkError net.Error
			if source.armed.Load() && errors.As(err, &networkError) && networkError.Timeout() {
				slog.Warn("CONNECT half-closed peer idle timeout", "direction", direction, "idle_timeout", idle)
			}

			_ = client.Close()
			_ = upstream.Close()

			return
		}

		opposite.arm()
	}
	go copyDirection("client_to_upstream", upstream, clientRead, upstreamRead)
	go copyDirection("upstream_to_client", client, upstreamRead, clientRead)

	<-done
	<-done
}

type gatewayStatus struct {
	Active              int    `json:"active"`
	MaxActive           int    `json:"max_active"`
	OpenTunnels         int    `json:"open_tunnels"`
	OldestTunnelSeconds int64  `json:"oldest_tunnel_seconds"`
	RejectedCapacity    uint64 `json:"rejected_capacity_total"`
	RejectedProfiles    uint64 `json:"rejected_profiles_total"`
	Completed           uint64 `json:"completed_total"`
}

func (g *gateway) status() gatewayStatus {
	g.mu.Lock()
	defer g.mu.Unlock()

	oldest := time.Time{}
	for t := range g.tunnels {
		if oldest.IsZero() || t.started.Before(oldest) {
			oldest = t.started
		}
	}

	result := gatewayStatus{
		Active: len(g.slots), MaxActive: cap(g.slots),
		OpenTunnels:      len(g.tunnels),
		RejectedCapacity: g.rejectedCapacity.Load(),
		RejectedProfiles: g.rejectedProfiles.Load(),
		Completed:        g.completed.Load(),
	}
	if !oldest.IsZero() {
		result.OldestTunnelSeconds = int64(time.Since(oldest).Seconds())
	}

	return result
}

// A persistently saturated proxy without useful work needs to exit so its
// container restart policy can recover it. Healthcheck failure alone does not
// restart a Docker container.
func (g *gateway) stalled(now time.Time) bool {
	const stallTimeout = 3 * time.Minute

	status := g.status()
	lastRejected := g.lastCapacityReject.Load()

	return status.Active == status.MaxActive &&
		lastRejected > 0 &&
		now.Sub(time.Unix(0, lastRejected)) < time.Minute &&
		now.Sub(time.Unix(0, g.lastActivity.Load())) >= stallTimeout
}

func (g *gateway) ready() (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.draining {
		return false, "draining"
	}

	if len(g.slots) == cap(g.slots) {
		return false, "capacity exhausted"
	}

	for _, p := range g.profiles {
		if p.isHealthy() {
			return true, ""
		}
	}

	return false, "no healthy WireGuard profiles"
}

func (g *gateway) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready, reason := g.ready(); !ready {
			http.Error(w, reason, http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		statuses := make([]profileStatus, 0, len(g.profiles))
		for _, p := range g.profiles {
			statuses = append(statuses, p.status())
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Gateway  gatewayStatus   `json:"gateway"`
			Profiles []profileStatus `json:"profiles"`
		}{Gateway: g.status(), Profiles: statuses})
	})

	return mux
}
