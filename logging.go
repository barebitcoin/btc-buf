package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func configureLogging(cfg *config) {
	if !cfg.JsonLog {
		log.Logger = log.Output(zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
			w.Out = os.Stderr
		}))
	}

	zerolog.DefaultContextLogger = &log.Logger
}
