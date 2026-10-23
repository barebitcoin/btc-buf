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
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"github.com/barebitcoin/btc-buf/cmd/btc-buf/internal/connectserver"
	"github.com/barebitcoin/btc-buf/server"
)

func realMain(cfg *config) error {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		signal := <-sig
		zerolog.Ctx(ctx).Info().
			Stringer("signal", signal).
			Msg("received signal, canceling context")
		cancel(fmt.Errorf("received %s signal", signal))
	}()

	opts := []server.Option{
		// connectserver.Handler gives each HTTP request an ID.
		server.WithRequestID(connectserver.RequestID),
		// The library logs through slog. Route it to our zerolog setup.
		server.WithLogging(func(ctx context.Context) *slog.Logger {
			return slog.New(zerolog.NewSlogHandler(*zerolog.Ctx(ctx)))
		}),
	}
	if cfg.SSH.Host != "" {
		opts = append(opts, server.WithSSHTunnel(server.SSHTunnel{
			Host:       cfg.SSH.Host,
			KeyFile:    cfg.SSH.KeyFile,
			KnownHosts: cfg.SSH.KnownHosts,
			LocalPort:  cfg.SSH.LocalPort,
			RemotePort: cfg.SSH.RemotePort,
		}))
	}

	// Bounds startup: the SSH tunnel, if any, and the connection check.
	clientCtx, clientCancel := context.WithTimeout(ctx, time.Second*30)
	defer clientCancel()

	if cfg.Bitcoind.CookiePath != "" {
		opts = append(opts, server.WithCookiePath(cfg.Bitcoind.CookiePath))
	}

	if cfg.AllowPrivateDescriptorsExport {
		zerolog.Ctx(ctx).Info().Msg("allowing private descriptors export")
		opts = append(opts, server.WithAllowPrivateDescriptorsExport())
	}

	bitcoind, err := server.NewBitcoind(
		clientCtx, cfg.Bitcoind.Host, cfg.Bitcoind.User, cfg.Bitcoind.Pass,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	// serve returns once ctx is cancelled and in-flight requests have
	// finished, so they can still reach Bitcoin Core until then.
	err = serve(ctx, cfg.Listen, connectserver.Handler(bitcoind.Server()))
	bitcoind.Shutdown(ctx)
	if err != nil {
		return err
	}

	return context.Cause(ctx)
}

// How long in-flight requests get to finish on shutdown, before we close
// their connections.
const shutdownTimeout = time.Second * 3

// serve serves handler on address, over both HTTP/1 and HTTP/2 without TLS
// (h2c). When ctx is cancelled it stops gracefully, forcing a stop if
// in-flight requests don't finish in time. It returns once the server has
// stopped.
func serve(ctx context.Context, address string, handler http.Handler) error {
	log := zerolog.Ctx(ctx)

	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("could not listen: %w", err)
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: time.Minute,
		Protocols:         protocols,
	}

	// Serve closes the listener when it returns.
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()

	log.Info().Str("address", address).Msg("serving")

	select {
	case err := <-served:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	log.Print("server: trying graceful stop")
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	err = server.Shutdown(shutdownCtx)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		log.Printf("server: forcing stop after %s", shutdownTimeout)
		if err := server.Close(); err != nil {
			return fmt.Errorf("force stop: %w", err)
		}

	case err != nil:
		return fmt.Errorf("graceful stop: %w", err)

	default:
		log.Print("server: successful graceful stop")
	}

	return nil
}

func main() {
	ctx := context.Background()

	cfg, err := readConfig(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to read config:", err)
		os.Exit(1)
	}

	// important: this is only usable AFTER readConfig has been called
	log := zerolog.Ctx(ctx)

	if info, ok := debug.ReadBuildInfo(); ok {
		log.Info().
			Str("go", info.GoVersion).
			Str("vcs.sha", findSetting("vcs.revision", info.Settings)).
			Str("vcs.modified", findSetting("vcs.modified", info.Settings)).
			Msgf("starting %s", os.Args[0])
	}

	if err := realMain(cfg); err != nil {
		log.Fatal().Err(err).Msg("main: received error")
	}
	log.Info().Msgf("main: exiting with 0 code")
}

func findSetting(key string, settings []debug.BuildSetting) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}

	return "unknown"
}
