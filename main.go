package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

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

	errs := make(chan error)
	var opts []server.Option
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

	go func() {
		if err := bitcoind.Listen(ctx, cfg.Listen); err != nil {
			errs <- err
		}
	}()
	go func() {
		<-ctx.Done()
		bitcoind.Shutdown(ctx)

		errs <- context.Cause(ctx)
	}()

	return <-errs
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
