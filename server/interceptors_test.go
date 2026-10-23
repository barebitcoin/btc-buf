package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"connectrpc.com/connect/v2"
)

type recordingHandler struct {
	slog.Handler
	levels *[]slog.Level
}

func (h recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h recordingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.levels = append(*h.levels, r.Level)
	return nil
}

func (h recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

// A request the client gave up on isn't a server error.
func TestLoggingInterceptorLevels(t *testing.T) {
	tests := []struct {
		err  error
		want slog.Level
	}{
		{nil, slog.LevelDebug},
		{fmt.Errorf("post: %w", context.Canceled), slog.LevelInfo},
		{context.DeadlineExceeded, slog.LevelWarn},
		{connect.NewError(connect.CodeNotFound, "missing"), slog.LevelDebug},
		{errors.New("boom"), slog.LevelError},
	}
	for _, tt := range tests {
		var levels []slog.Level
		logger := slog.New(recordingHandler{levels: &levels})
		handler := loggingInterceptor(func(context.Context) *slog.Logger { return logger }, nil)(
			func(context.Context, connect.Spec, connect.ServerStream) error { return tt.err },
		)

		_ = handler(t.Context(), connect.Spec{Procedure: "/test"}, nil)
		if len(levels) != 1 || levels[0] != tt.want {
			t.Errorf("%v: logged at %v, want %v", tt.err, levels, tt.want)
		}
	}
}
