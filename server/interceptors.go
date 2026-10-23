package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
)

// panicInterceptor ensures we never crash with a panic when serving
// Cribbed from https://github.com/grpc-ecosystem/go-grpc-middleware
func panicInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) (err error) {
			panicked := true
			defer func() {
				if r := recover(); r != nil || panicked {
					err = recoverFrom(ctx, r)
				}
			}()
			err = next(ctx, spec, stream)
			panicked = false
			return err
		}
	}
}

func recoverFrom(ctx context.Context, panic any) error {
	err := fmt.Errorf("panic: %v", panic)

	logFrom(ctx).WarnContext(ctx, "recovered while serving Connect",
		"error", err, "stack", string(debug.Stack()))

	return err
}

// loggingInterceptor gives each request its own logger, available through
// logFrom and tagged with the endpoint and the request ID if there is one, and
// logs the request's outcome. requestID may be nil.
func loggingInterceptor(
	logging func(ctx context.Context) *slog.Logger, requestID func(ctx context.Context) string,
) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			start := time.Now()
			log := logging(ctx).With("endpoint", spec.Procedure)
			if requestID != nil {
				if id := requestID(ctx); id != "" {
					log = log.With("requestId", id)
				}
			}
			ctx = withLogger(ctx, log)

			handlerErr := next(ctx, spec, stream)
			var code connect.Code
			if handlerErr != nil {
				code = connect.CodeOf(handlerErr)
			}
			// Connect sends context errors with their own codes, but CodeOf
			// only knows those of a *connect.Error.
			if code == connect.CodeUnknown {
				switch {
				case errors.Is(handlerErr, context.Canceled):
					code = connect.CodeCanceled
				case errors.Is(handlerErr, context.DeadlineExceeded):
					code = connect.CodeDeadlineExceeded
				}
			}
			level := slog.LevelDebug
			switch code {
			case connect.CodeInternal, connect.CodeUnknown:
				level = slog.LevelError
			case connect.CodeCanceled:
				level = slog.LevelInfo
			case connect.CodeDeadlineExceeded:
				level = slog.LevelWarn
			}
			attrs := []any{"duration", time.Since(start), "status", describeCode(code)}
			if handlerErr != nil {
				attrs = append(attrs, "error", handlerErr)
			}
			message := fmt.Sprintf("%s: %s", spec.Procedure, describeCode(code))
			if handlerErr != nil {
				handlerErrMessage := handlerErr.Error()
				cutset := fmt.Sprintf("%s: ", describeCode(code))
				if _, trimmed, ok := strings.Cut(handlerErrMessage, cutset); ok {
					handlerErrMessage = trimmed
				}
				message = fmt.Sprintf("%s: %s", message, handlerErrMessage)
			}
			log.Log(ctx, level, message, attrs...)
			return handlerErr
		}
	}
}

func describeCode(code connect.Code) string {
	if code == 0 {
		return "ok"
	}

	return code.String()
}
