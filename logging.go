package main

import (
	"fmt"
	"os"
	"strings"

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

	zerolog.DefaultContextLogger = &log.Logger
	return nil
}
