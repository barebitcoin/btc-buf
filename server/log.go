package server

import (
	"context"
	"log/slog"
)

// levelTrace is for logs too noisy for debug. It maps to zerolog's trace
// level through zerolog.NewSlogHandler.
const levelTrace = slog.LevelDebug - 4

type loggerKey struct{}

// withLogger returns a copy of ctx carrying l, for logFrom.
func withLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// logFrom returns the logger ctx carries: the request's logger while serving
// a request, and the WithLogging logger in background work. Falls back to
// slog.Default.
func logFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
