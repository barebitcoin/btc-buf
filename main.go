package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"time"

	"github.com/barebitcoin/btc-buf/server"
	"github.com/rs/zerolog"
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

	clientCtx, clientCancel := context.WithTimeout(ctx, time.Second*10)
	defer clientCancel()

	bitcoind, err := server.NewBitcoind(
		clientCtx, cfg.Bitcoind.Host, cfg.Bitcoind.User, cfg.Bitcoind.Pass,
	)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	errs := make(chan error)

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
		panic(fmt.Sprintf("read config: %s", err))
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
