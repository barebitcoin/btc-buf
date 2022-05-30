package server

import (
	context "context"
	"path"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Based on grpc-ecosystem/go-grpc-middleware
// Copyright to original authors.
// https://github.com/grpc-ecosystem/go-grpc-middleware/blob/master/logging/logrus/server_interceptors.go
func serverLogger() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		startTime := time.Now()

		resp, err := handler(ctx, req)

		service := path.Dir(info.FullMethod)[1:]
		method := path.Base(info.FullMethod)

		code := status.Code(err)

		event := log.WithLevel(codeToLevel(code)).
			Fields(map[string]interface{}{
				"grpc.service":    service,
				"grpc.method":     method,
				"grpc.start_time": startTime,
				"grpc.code":       code.String(),
				"grpc.duration":   time.Since(startTime).String(),
			})

		// Add the deadline (if we got one)
		if d, ok := ctx.Deadline(); ok {
			event = event.Time("grpc.request.deadline", d)
		}

		// Add the error (if we got one)
		event = event.Err(err)

		// finish of the log, and execute
		event.Msgf("%s: %s", info.FullMethod, code)

		return resp, err
	}
}

func codeToLevel(code codes.Code) zerolog.Level {
	switch code {
	case codes.OK:
		return zerolog.InfoLevel
	case codes.Canceled:
		return zerolog.InfoLevel
	case codes.Unknown:
		return zerolog.ErrorLevel
	case codes.InvalidArgument:
		return zerolog.InfoLevel
	case codes.DeadlineExceeded:
		return zerolog.WarnLevel
	case codes.NotFound:
		return zerolog.InfoLevel
	case codes.AlreadyExists:
		return zerolog.InfoLevel
	case codes.PermissionDenied:
		return zerolog.WarnLevel
	case codes.Unauthenticated:
		return zerolog.InfoLevel // unauthenticated requests can happen
	case codes.ResourceExhausted:
		return zerolog.WarnLevel
	case codes.FailedPrecondition:
		return zerolog.WarnLevel
	case codes.Aborted:
		return zerolog.WarnLevel
	case codes.OutOfRange:
		return zerolog.WarnLevel
	case codes.Unimplemented:
		return zerolog.ErrorLevel
	case codes.Internal:
		return zerolog.ErrorLevel
	case codes.Unavailable:
		return zerolog.WarnLevel
	case codes.DataLoss:
		return zerolog.ErrorLevel
	default:
		return zerolog.ErrorLevel
	}
}
