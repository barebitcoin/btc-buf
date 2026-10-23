package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
)

// The request ID in the context reaches Core as the JSON-RPC id.
func TestWithRequestID(t *testing.T) {
	type key struct{}
	newCore := func() *fakeCore {
		return &fakeCore{responses: map[string]fakeResponse{
			"listwallets": {result: []string{}},
		}}
	}
	ctx := context.WithValue(context.Background(), key{}, "mine")

	t.Run("with option", func(t *testing.T) {
		core := newCore()
		b, err := newTestBitcoind(t, core, WithRequestID(func(ctx context.Context) string {
			id, _ := ctx.Value(key{}).(string)
			return id
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inProcessClient(b).ListWallets(ctx, &emptypb.Empty{}); err != nil {
			t.Fatal(err)
		}
		if got := core.lastID(); got != `"mine"` {
			t.Errorf("JSON-RPC id: got %s, want %q", got, "mine")
		}
	})

	t.Run("without option", func(t *testing.T) {
		core := newCore()
		b, err := newTestBitcoind(t, core)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inProcessClient(b).ListWallets(ctx, &emptypb.Empty{}); err != nil {
			t.Fatal(err)
		}
		if got := core.lastID(); strings.HasPrefix(got, `"`) {
			t.Errorf("JSON-RPC id: got %s, want a numeric one", got)
		}
	})
}

func TestRpcForWallet_ReusesClients(t *testing.T) {
	ctx := context.Background()

	// Nothing listens on this port; the HTTP client connects lazily.
	b, err := NewBitcoind(ctx, "localhost:1", "user", "pass", WithoutInitialConnectionCheck())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Shutdown(ctx) })

	get := func(wallet string) interface{} {
		t.Helper()
		rpc, err := b.rpcForWallet(ctx, wallet)
		if err != nil {
			t.Fatal(err)
		}
		return rpc
	}

	if get("") != b.rpc {
		t.Error("no wallet: expected the base client")
	}
	if get("hot") != get("hot") {
		t.Error("same wallet: expected the same client")
	}
	if get("hot") == b.rpc || get("hot") == get("cold") {
		t.Error("wallet clients must be distinct from the base client and each other")
	}
	if n := len(b.walletClients); n != 2 {
		t.Errorf("expected 2 cached wallet clients, got %d", n)
	}
}

// A fetch failing because the request was cancelled reports the cancellation,
// not the fetch's own error.
func TestCallRPC_ReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	fetch := func(ctx context.Context) (int, error) {
		<-ctx.Done()
		return 0, fmt.Errorf("post: %w", ctx.Err())
	}
	_, err := callRPC(ctx, fetch, func(r int) *int { return &r })
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}
