package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/barebitcoin/btc-buf/server"
	"github.com/rs/zerolog/log"
)

func realMain(cfg *config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		signal := <-sig
		log.Info().
			Stringer("signal", signal).
			Msg("received signal, canceling context")
		cancel()
	}()

	bitcoind, err := server.NewBitcoind(
		ctx, cfg.Bitcoind.Host, cfg.Bitcoind.User, cfg.Bitcoind.Pass,
	)
	if err != nil {
		return err
	}

	defer bitcoind.Stop()

	return bitcoind.Listen(ctx, "localhost:5080")
}

func main() {
	cfg, err := readConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("main: could not read config")
	}

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
}

func findSetting(key string, settings []debug.BuildSetting) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}

	return "unknown"
}
