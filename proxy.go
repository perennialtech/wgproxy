package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
)

type tunnel struct {
	client   net.Conn
	upstream net.Conn
}

type gateway struct {
	profiles []*profile

	selectionMu sync.Mutex
	next        int

	mu       sync.Mutex
	draining bool
	closed   bool
	tunnels  map[*tunnel]struct{}
	active   sync.WaitGroup
	slots    chan struct{}

	forceCtx    context.Context
	forceCancel context.CancelFunc
}

func newGateway(profiles []*profile, maxActive int) *gateway {
	ctx, cancel := context.WithCancel(context.Background())

	return &gateway{
		profiles:    profiles,
		tunnels:     make(map[*tunnel]struct{}),
		slots:       make(chan struct{}, maxActive),
		forceCtx:    ctx,
		forceCancel: cancel,
	}
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
		return false
	}
}

func (g *gateway) end() {
	<-g.slots
	g.active.Done()
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

	t := &tunnel{client: client, upstream: upstream}
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
	relay(client, upstream, buffered.Reader)
}

func relay(client, upstream net.Conn, clientReader io.Reader) {
	done := make(chan struct{}, 2)

	copyDirection := func(destination net.Conn, source io.Reader) {
		defer func() { done <- struct{}{} }()

		_, err := io.Copy(destination, source)
		if err == nil {
			if halfCloser, ok := destination.(interface{ CloseWrite() error }); ok {
				err = halfCloser.CloseWrite()
			} else {
				// A connection without half-close support must be closed to
				// propagate EOF. The production TCP connections support it.
				err = destination.Close()
			}
		}

		if err != nil {
			slog.Debug("CONNECT relay ended", "error", err)

			_ = client.Close()
			_ = upstream.Close()
		}
	}

	go copyDirection(upstream, clientReader)
	go copyDirection(client, upstream)

	<-done
	<-done
}

func (g *gateway) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		g.mu.Lock()
		draining := g.draining
		g.mu.Unlock()

		if !draining {
			for _, p := range g.profiles {
				if p.isHealthy() {
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}

		http.Error(w, "not ready", http.StatusServiceUnavailable)
	})

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		statuses := make([]profileStatus, 0, len(g.profiles))
		for _, p := range g.profiles {
			statuses = append(statuses, p.status())
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Profiles []profileStatus `json:"profiles"`
		}{Profiles: statuses})
	})

	return mux
}
