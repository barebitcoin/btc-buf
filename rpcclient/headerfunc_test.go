package rpcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeaderFunc(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{},"error":null,"id":1}`))
	}))
	t.Cleanup(srv.Close)

	calls := 0
	client, err := New(&ConnConfig{
		Host:       strings.TrimPrefix(srv.URL, "http://"),
		User:       "user",
		Pass:       "pass",
		DisableTLS: true,
		HeaderFunc: func(_ context.Context, h http.Header) error {
			calls++
			h.Set("X-Token", fmt.Sprintf("token-%d", calls))
			return nil
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	for range 2 {
		if _, err := client.RawRequest(context.Background(), "getblockchaininfo", nil); err != nil {
			t.Fatalf("raw request: %v", err)
		}
	}

	if calls != 2 {
		t.Fatalf("HeaderFunc called %d times, want once per request (2)", calls)
	}
	if v := got.Get("X-Token"); v != "token-2" {
		t.Fatalf("X-Token = %q, want the second request's token-2", v)
	}
	// Basic auth is still Core's.
	if user, pass, ok := (&http.Request{Header: got}).BasicAuth(); !ok || user != "user" || pass != "pass" {
		t.Fatalf("basic auth = %q/%q (ok=%v), want user/pass", user, pass, ok)
	}
}

func TestHeaderFuncErrorFailsRequest(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	t.Cleanup(srv.Close)

	boom := errors.New("no token")
	client, err := New(&ConnConfig{
		Host:       strings.TrimPrefix(srv.URL, "http://"),
		User:       "user",
		Pass:       "pass",
		DisableTLS: true,
		HeaderFunc: func(context.Context, http.Header) error { return boom },
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.RawRequest(context.Background(), "getblockchaininfo", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap %v", err, boom)
	}
	if hit {
		t.Fatal("request reached the server despite HeaderFunc failing")
	}
}
