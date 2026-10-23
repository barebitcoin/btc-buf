package connectserver

import (
	"context"
	"net/http"

	"github.com/oklog/ulid/v2"
)

// RequestIDHeader is the header requests can pass their ID in, and that the
// ID is sent back in.
const RequestIDHeader = "x-trace-id"

type requestIDKey struct{}

// RequestID returns the ID of the request ctx belongs to, or the empty string
// if it doesn't belong to one.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestID gives each request an ID, available through RequestID. The
// ID is taken from the request's RequestIDHeader if present, and generated
// otherwise. It's sent back in the response's RequestIDHeader.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if id == "" {
			id = "req_" + ulid.Make().String()
		}
		w.Header().Set(RequestIDHeader, id)

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}
