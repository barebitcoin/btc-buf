package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/barebitcoin/btc-buf/server"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog/log"
)

func realMain(cfg config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt, os.Kill)

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
	var cfg config
	if _, err := flags.Parse(&cfg); err != nil {
		// help was requested, avoid print and non-zero exit code
		if flagErr := new(flags.Error); errors.As(
			err, &flagErr,
		) && flagErr.Type == flags.ErrHelp {
			return
		}

		log.Fatal().Err(err).Msg("could not parse config")
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		log.Info().
			Str("go", info.GoVersion).
			Str("vcs.sha", findSetting("vcs.revision", info.Settings)).
			Str("vcs.modified", findSetting("vcs.modified", info.Settings)).
			Msgf("starting %s", os.Args[0])
	}

	err := realMain(cfg)
	if err != nil {
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
