package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type profile struct {
	config          profileConfig
	stack           *netstack.Net
	device          *device.Device
	transport       *http.Transport
	healthTransport *http.Transport
	healthClient    *http.Client
	forward         *httputil.ReverseProxy
	dialTimeout     time.Duration

	// After construction, only the health worker mutates endpointSet.
	endpointSet bool

	mu          sync.RWMutex
	checked     bool
	healthy     bool
	lastSuccess time.Time
	lastError   string

	active   atomic.Int64
	selected atomic.Uint64
}

type profileStatus struct {
	ID             string     `json:"id"`
	Healthy        bool       `json:"healthy"`
	Active         int64      `json:"active"`
	Selections     uint64     `json:"selections"`
	LastSuccessful *time.Time `json:"last_successful_check,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

func newProfile(config profileConfig, o options) (*profile, error) {
	// A configured IPv6 address without ::/0 does not enable IPv6.
	addresses := make([]netip.Addr, 0, len(config.addresses))
	for _, address := range config.addresses {
		if address.Is4() || config.ipv6 {
			addresses = append(addresses, address)
		}
	}

	tun, stack, err := netstack.CreateNetTUN(addresses, config.dns, config.mtu)
	if err != nil {
		return nil, fmt.Errorf("create network stack: %w", err)
	}

	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf: func(format string, args ...any) {
			slog.Error("WireGuard error", "profile", config.id, "error", fmt.Sprintf(format, args...))
		},
	}

	wg := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", config.privateKey, config.publicKey)

	if config.presharedKey != "" {
		fmt.Fprintf(&ipc, "preshared_key=%s\n", config.presharedKey)
	}

	// Numeric endpoints need no bootstrap lookup. Install them before
	// enabling keepalive so the peer knows where to send its handshake.
	endpointSet := false
	keepalive := uint16(0)

	if ip, err := netip.ParseAddr(config.endpointHost); err == nil {
		endpoint := netip.AddrPortFrom(ip, config.endpointPort)
		fmt.Fprintf(&ipc, "endpoint=%s\n", endpoint)

		endpointSet = true
		keepalive = config.keepalive
	}

	// Hostname endpoints retain keepalive=0 until ensureEndpoint succeeds.
	fmt.Fprintf(&ipc, "replace_allowed_ips=true\npersistent_keepalive_interval=%d\n", keepalive)

	for _, prefix := range config.allowedIPs {
		fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix)
	}

	if err := wg.IpcSet(ipc.String()); err != nil {
		wg.Close()
		return nil, fmt.Errorf("configure WireGuard: %w", err)
	}

	if err := wg.Up(); err != nil {
		wg.Close()
		return nil, fmt.Errorf("start WireGuard: %w", err)
	}

	p := &profile{
		config:      config,
		stack:       stack,
		device:      wg,
		dialTimeout: o.dialTimeout,
		endpointSet: endpointSet,
	}

	p.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           p.dial,
		DisableCompression:    true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: o.responseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}

	p.healthTransport = p.transport.Clone()
	p.healthTransport.DisableKeepAlives = true

	p.healthClient = &http.Client{
		Transport: p.healthTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ReverseProxy supplies the HTTP forwarding machinery, including
	// hop-by-hop header removal, streaming, and response trailers.
	// Profile selection and forward-proxy target validation happen outside it.
	p.forward = &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			request.Out.Host = request.In.URL.Host

			// The proxy does not interpret application query parameters.
			// Preserve the original query instead of normalizing it.
			request.Out.URL.RawQuery = request.In.URL.RawQuery
		},
		Transport: p.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamError(w, err)
			slog.Warn("HTTP upstream failed",
				"profile", config.id,
				"destination", r.URL.Host,
				"error", err)
		},
	}

	return p, nil
}

func (p *profile) dial(ctx context.Context, _ string, address string) (net.Conn, error) {
	network := "tcp4"
	if p.config.ipv6 {
		network = "tcp"
	}

	ctx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	defer cancel()

	// This is the only destination dial path. The userspace stack performs
	// destination DNS using the DNS addresses passed to CreateNetTUN.
	return p.stack.DialContext(ctx, network, address)
}

func (p *profile) ensureEndpoint(ctx context.Context) error {
	if p.endpointSet {
		return nil
	}

	ip, err := netip.ParseAddr(p.config.endpointHost)
	if err != nil {
		// Endpoint discovery is bootstrap traffic, not destination DNS.
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", p.config.endpointHost)
		if err != nil {
			return fmt.Errorf("resolve WireGuard endpoint: %w", err)
		}

		if len(addresses) == 0 {
			return fmt.Errorf("WireGuard endpoint has no IP addresses")
		}

		ip = addresses[0].Unmap()
		for _, address := range addresses {
			if address.Is4() || address.Is4In6() {
				ip = address.Unmap()
				break
			}
		}
	}

	endpoint := netip.AddrPortFrom(ip, p.config.endpointPort)
	ipc := fmt.Sprintf(
		"public_key=%s\nupdate_only=true\nendpoint=%s\npersistent_keepalive_interval=%d\n",
		p.config.publicKey, endpoint, p.config.keepalive,
	)

	if err := p.device.IpcSet(ipc); err != nil {
		return fmt.Errorf("set WireGuard endpoint: %w", err)
	}

	p.endpointSet = true

	return nil
}

func (p *profile) check(ctx context.Context, healthURL string) error {
	if err := p.ensureEndpoint(ctx); err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}

	response, err := p.healthClient.Do(request)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("health endpoint returned status %d, expected 204", response.StatusCode)
	}

	return nil
}

func (p *profile) setHealth(err error) {
	healthy := err == nil

	p.mu.Lock()
	changed := !p.checked || p.healthy != healthy
	p.checked = true
	p.healthy = healthy
	p.lastError = ""

	if healthy {
		p.lastSuccess = time.Now().UTC()
	} else {
		p.lastError = err.Error()
	}
	p.mu.Unlock()

	if changed {
		if healthy {
			slog.Info("profile healthy", "profile", p.config.id)
		} else {
			slog.Warn("profile unhealthy", "profile", p.config.id, "error", err)
		}
	}
}

func (p *profile) isHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.healthy
}

func (p *profile) status() profileStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	result := profileStatus{
		ID:         p.config.id,
		Healthy:    p.healthy,
		Active:     p.active.Load(),
		Selections: p.selected.Load(),
		LastError:  p.lastError,
	}

	if !p.lastSuccess.IsZero() {
		lastSuccess := p.lastSuccess
		result.LastSuccessful = &lastSuccess
	}

	return result
}

func (p *profile) close() {
	p.transport.CloseIdleConnections()
	p.healthTransport.CloseIdleConnections()
	p.device.Close()
}

func runHealth(ctx context.Context, p *profile, o options, initialDelay time.Duration) {
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		checkCtx, cancel := context.WithTimeout(ctx, o.healthTimeout)
		err := p.check(checkCtx, o.healthURL)

		cancel()

		if ctx.Err() != nil {
			return
		}

		p.setHealth(err)
		timer.Reset(o.healthInterval)
	}
}

func upstreamError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway

	var networkError net.Error

	if errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkError) && networkError.Timeout()) {
		status = http.StatusGatewayTimeout
	}

	http.Error(w, http.StatusText(status), status)
}
