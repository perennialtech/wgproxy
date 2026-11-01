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
	fullSince          time.Time
	draining           bool
	closed             bool
	tunnels            map[*tunnel]struct{}
	active             sync.WaitGroup
	slots              chan struct{}
	rejectedCapacity   atomic.Uint64
	rejectedProfiles   atomic.Uint64
	halfCloseTimeouts  atomic.Uint64
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

	if g.draining {
		g.mu.Unlock()
		return false
	}

	select {
	case g.slots <- struct{}{}:
		g.active.Add(1)
		g.noteActivity()

		if len(g.slots) == cap(g.slots) {
			g.fullSince = time.Now()
		}
		g.mu.Unlock()

		return true
	default:
		total := g.rejectedCapacity.Add(1)
		g.lastCapacityReject.Store(time.Now().UnixNano())
		active, maximum := len(g.slots), cap(g.slots)
		g.mu.Unlock()

		if total == 1 || total&(total-1) == 0 {
			slog.Warn("proxy admission rejected", "reason", "capacity",
				"active", active, "max_active", maximum,
				"rejected_capacity_total", total)
		}

		return false
	}
}

func (g *gateway) end() {
	g.mu.Lock()
	<-g.slots
	g.fullSince = time.Time{}
	g.mu.Unlock()
	g.completed.Add(1)
	g.noteActivity()
	g.active.Done()
}

func (g *gateway) noteActivity() {
	g.lastActivity.Store(time.Now().UnixNano())
}

// Make recovery admission-safe: recheck current health while holding the
// admission lock, then stop new work in the same critical section. Monitor
// snapshots alone cannot safely authorize a restart.
func (g *gateway) beginRecovery() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.draining || g.closed || len(g.slots) != 0 {
		return false
	}

	// Lock every profile until the restart decision is committed. Reading
	// their statuses one at a time permits a previously examined profile
	// to recover before the final decision.
	for _, p := range g.profiles {
		p.mu.RLock()
	}
	defer func() {
		for i := len(g.profiles) - 1; i >= 0; i-- {
			g.profiles[i].mu.RUnlock()
		}
	}()

	if len(g.profiles) == 0 {
		return false
	}

	for _, p := range g.profiles {
		if !p.checked || p.healthy || p.failedChecks < 2 {
			return false
		}
	}

	g.draining = true

	return true
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

	if r.Body != nil {
		r.Body = &activityReadCloser{ReadCloser: r.Body, activity: g.noteActivity}
	}

	p.forward.ServeHTTP(&activityResponseWriter{ResponseWriter: w, activity: g.noteActivity}, r)
}

type activityReadCloser struct {
	io.ReadCloser
	activity func()
}

func (r *activityReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.activity()
	}

	return n, err
}

type activityResponseWriter struct {
	http.ResponseWriter
	activity func()
}

func (w *activityResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.activity()
	}

	return n, err
}

// Preserve optional response-controller capabilities such as streaming flush.
func (w *activityResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
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
	relayWithIdleTimeout(client, upstream, buffered.Reader, halfClosedIdleTimeout, g.noteActivity,
		func(direction string) {
			total := g.halfCloseTimeouts.Add(1)
			slog.Warn("CONNECT half-closed peer idle timeout",
				"profile", p.config.id, "destination", destination,
				"direction", direction, "idle_timeout", halfClosedIdleTimeout,
				"half_closed_timeouts_total", total)
		})
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

type relayWriter struct {
	conn     net.Conn
	idle     time.Duration
	armed    atomic.Bool
	activity func()
}

// Smaller writes let the deadline measure continuing progress when a peer is
// slow but still consuming bytes. net.Conn.Write may block until its entire
// input is accepted even while the peer keeps draining its socket.
const relayWriteChunk = 1024

func (w *relayWriter) Write(p []byte) (int, error) {
	// Use bounded writes from the start of a tunnel. Otherwise a large
	// Write already in progress could inherit a write deadline in arm()
	// after the opposite direction half-closes, and time out even though
	// the receiver continues making forward progress.
	written := 0
	for written < len(p) {
		if w.armed.Load() {
			if err := w.conn.SetWriteDeadline(time.Now().Add(w.idle)); err != nil {
				return written, err
			}
		}

		end := min(len(p), written+relayWriteChunk)
		n, err := w.conn.Write(p[written:end])
		written += n

		if n > 0 && w.activity != nil {
			w.activity()
		}

		if err != nil {
			return written, err
		}

		if n == 0 {
			return written, io.ErrShortWrite
		}
	}

	return written, nil
}

func (w *relayWriter) arm() {
	w.armed.Store(true)
	_ = w.conn.SetWriteDeadline(time.Now().Add(w.idle))
}

func relayWithIdleTimeout(client, upstream net.Conn, clientReader io.Reader, idle time.Duration, activity func(), onTimeout func(string)) {
	clientRead := &relayReader{source: clientReader, conn: client, idle: idle, activity: activity}
	upstreamRead := &relayReader{source: upstream, conn: upstream, idle: idle, activity: activity}
	clientWrite := &relayWriter{conn: client, idle: idle, activity: activity}
	upstreamWrite := &relayWriter{conn: upstream, idle: idle, activity: activity}
	done := make(chan struct{}, 2)

	copyDirection := func(direction string, destination *relayWriter, source, oppositeReader *relayReader, oppositeWriter *relayWriter) {
		defer func() { done <- struct{}{} }()

		_, err := io.Copy(destination, source)
		if err == nil {
			if halfCloser, ok := destination.conn.(interface{ CloseWrite() error }); ok {
				err = halfCloser.CloseWrite()
			} else {
				err = destination.conn.Close()
			}
		}

		if err != nil {
			var networkError net.Error
			if (source.armed.Load() || destination.armed.Load()) &&
				errors.As(err, &networkError) && networkError.Timeout() {
				if onTimeout != nil {
					onTimeout(direction)
				}
			}

			_ = client.Close()
			_ = upstream.Close()

			return
		}

		// A half-close permits remaining traffic, but not unbounded silence
		// while reading or writing to the other connection.
		oppositeReader.arm()
		oppositeWriter.arm()
	}

	go copyDirection("client_to_upstream", upstreamWrite, clientRead, upstreamRead, clientWrite)
	go copyDirection("upstream_to_client", clientWrite, upstreamRead, clientRead, upstreamWrite)

	<-done
	<-done
}

type gatewayStatus struct {
	Active               int    `json:"active"`
	MaxActive            int    `json:"max_active"`
	OpenTunnels          int    `json:"open_tunnels"`
	OldestTunnelSeconds  int64  `json:"oldest_tunnel_seconds"`
	FullForSeconds       int64  `json:"full_for_seconds"`
	RejectedCapacity     uint64 `json:"rejected_capacity_total"`
	RejectedProfiles     uint64 `json:"rejected_profiles_total"`
	HalfCloseTimeouts    uint64 `json:"half_closed_timeouts_total"`
	Completed            uint64 `json:"completed_total"`
	LastActivitySeconds  int64  `json:"last_activity_seconds"`
	LastRejectionSeconds int64  `json:"last_rejection_seconds"`
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
		OpenTunnels:       len(g.tunnels),
		RejectedCapacity:  g.rejectedCapacity.Load(),
		RejectedProfiles:  g.rejectedProfiles.Load(),
		HalfCloseTimeouts: g.halfCloseTimeouts.Load(),
		Completed:         g.completed.Load(),
	}
	if !oldest.IsZero() {
		result.OldestTunnelSeconds = int64(time.Since(oldest).Seconds())
	}

	if !g.fullSince.IsZero() {
		result.FullForSeconds = int64(time.Since(g.fullSince).Seconds())
	}

	if last := g.lastActivity.Load(); last > 0 {
		result.LastActivitySeconds = int64(time.Since(time.Unix(0, last)).Seconds())
	}

	if last := g.lastCapacityReject.Load(); last > 0 {
		result.LastRejectionSeconds = int64(time.Since(time.Unix(0, last)).Seconds())
	}

	return result
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
