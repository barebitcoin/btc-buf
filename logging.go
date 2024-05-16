package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func configureLogging(cfg *config) error {
	parsed, err := zerolog.ParseLevel(strings.ToLower(cfg.LogLevel))
	if err != nil {
		return fmt.Errorf("invalid log level: %s", cfg.LogLevel)
	}
	zerolog.SetGlobalLevel(parsed)

	if !cfg.JsonLog {
		log.Logger = log.Output(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = os.Stderr
		}))
	}

	l := log.Logger.With().Caller().Logger()
	log.Logger = l

	// default is with whole second precision
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.DefaultContextLogger = &l
	return nil
}
