package rpcclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startIDEchoServer spins up a stub JSON-RPC server that records the "id" of
// every request it receives and always replies with an empty result.
func startIDEchoServer(t *testing.T) (*httptest.Server, *[]json.RawMessage) {
	t.Helper()

	var ids []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		ids = append(ids, req.ID)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{},"error":null,"id":1}`))
	}))
	t.Cleanup(srv.Close)

	return srv, &ids
}

func newTestClient(t *testing.T, srv *httptest.Server, requestID func(context.Context) string) *Client {
	t.Helper()

	client, err := New(context.Background(), &ConnConfig{
		Host:       strings.TrimPrefix(srv.URL, "http://"),
		User:       "user",
		Pass:       "pass",
		DisableTLS: true,
		RequestID:  requestID,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { client.Shutdown(context.Background()) })

	return client
}

func TestRequestIDHookOverridesWireID(t *testing.T) {
	srv, ids := startIDEchoServer(t)

	const custom = "req_01CUSTOM"
	client := newTestClient(t, srv, func(context.Context) string { return custom })

	if _, err := client.RawRequest(context.Background(), "getblockchaininfo", nil); err != nil {
		t.Fatalf("raw request: %v", err)
	}

	if len(*ids) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*ids))
	}
	if got := string((*ids)[0]); got != `"`+custom+`"` {
		t.Fatalf("wire id = %s, want %q", got, custom)
	}
}

func TestRequestIDHookEmptyFallsBackToNumeric(t *testing.T) {
	srv, ids := startIDEchoServer(t)

	// Hook present but returns empty: should fall back to the numeric id.
	client := newTestClient(t, srv, func(context.Context) string { return "" })

	if _, err := client.RawRequest(context.Background(), "getblockchaininfo", nil); err != nil {
		t.Fatalf("raw request: %v", err)
	}

	if len(*ids) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*ids))
	}
	// Numeric ids are unquoted JSON numbers.
	if got := string((*ids)[0]); strings.Contains(got, `"`) {
		t.Fatalf("wire id = %s, want a numeric id", got)
	}
}

func TestRequestIDNoHookIsNumeric(t *testing.T) {
	srv, ids := startIDEchoServer(t)

	client := newTestClient(t, srv, nil)

	if _, err := client.RawRequest(context.Background(), "getblockchaininfo", nil); err != nil {
		t.Fatalf("raw request: %v", err)
	}

	if got := string((*ids)[0]); strings.Contains(got, `"`) {
		t.Fatalf("wire id = %s, want a numeric id", got)
	}
}
