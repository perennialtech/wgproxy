package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	var err error

	switch {
	case len(os.Args) == 1:
		err = serve()
	case len(os.Args) == 2 && os.Args[1] == "healthcheck":
		err = healthcheckCommand()
	default:
		err = fmt.Errorf("usage: %s [healthcheck]", os.Args[0])
	}

	if err != nil {
		slog.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func serve() error {
	o, err := loadOptions()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return run(ctx, o)
}

func run(ctx context.Context, o options) error {
	configs, err := loadConfigs(o.configDir)
	if err != nil {
		return err
	}

	profiles := make([]*profile, 0, len(configs))
	for _, config := range configs {
		p, err := newProfile(config, o)
		if err != nil {
			return fmt.Errorf("profile %s: %w", config.id, err)
		}
		defer p.close()

		profiles = append(profiles, p)
	}

	proxyListener, err := net.Listen("tcp", o.proxyAddr)
	if err != nil {
		return fmt.Errorf("listen for proxy clients: %w", err)
	}
	defer proxyListener.Close()

	adminListener, err := net.Listen("tcp", o.adminAddr)
	if err != nil {
		return fmt.Errorf("listen for administration: %w", err)
	}
	defer adminListener.Close()

	g := newGateway(profiles, o.maxActive)
	defer g.forceClose()

	proxyServer := &http.Server{
		Handler:           g,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	adminServer := &http.Server{
		Handler:           g.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	serveErrors := make(chan error, 2)

	startServer := func(server *http.Server, listener net.Listener) {
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErrors <- err
			}
		}()
	}

	startServer(proxyServer, proxyListener)
	startServer(adminServer, adminListener)

	healthCtx, cancelHealth := context.WithCancel(ctx)
	defer cancelHealth()

	var healthWorkers sync.WaitGroup

	for index, p := range profiles {
		// Spread initial checks across one interval, then keep checking
		// independently. The first profile is checked immediately.
		delay := time.Duration(float64(o.healthInterval) * float64(index) / float64(len(profiles)))

		healthWorkers.Add(1)
		go func() {
			defer healthWorkers.Done()

			runHealth(healthCtx, p, o, delay)
		}()
	}

	slog.Info("started",
		"proxy", proxyListener.Addr().String(),
		"admin", adminListener.Addr().String(),
		"profiles", len(profiles),
		"max_active", o.maxActive)

	var serveErr error

	select {
	case <-ctx.Done():
	case serveErr = <-serveErrors:
	}

	slog.Info("draining")
	cancelHealth()
	g.beginDrain()

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), o.shutdownTimeout)
	defer cancelDrain()

	httpStopped := make(chan struct{})

	go func() {
		_ = proxyServer.Shutdown(drainCtx)

		close(httpStopped)
	}()

	operationsStopped := make(chan struct{})

	go func() {
		g.active.Wait()
		close(operationsStopped)
	}()

	select {
	case <-operationsStopped:
	case <-drainCtx.Done():
		slog.Info("drain deadline reached")
	}

	// Shutdown alone does not close hijacked CONNECT connections.
	g.forceClose()

	_ = proxyServer.Close()

	<-httpStopped

	_ = adminServer.Shutdown(drainCtx)
	_ = adminServer.Close()

	<-operationsStopped
	healthWorkers.Wait()

	return serveErr
}

func healthcheckCommand() error {
	address := defaultOptions().adminAddr
	if value, exists := os.LookupEnv("ADMIN_ADDR"); exists {
		address = value
	}

	if err := validateAdminAddress(address); err != nil {
		return err
	}

	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := client.Get("http://" + address + "/readyz")
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: status %d", response.StatusCode)
	}

	return nil
}
