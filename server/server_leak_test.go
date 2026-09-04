package server

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
)

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
		rpc, err := b.rpcForWallet(ctx, &pb.GetWalletInfoRequest{Wallet: wallet})
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

// The fetch goroutine must exit even when the caller stopped waiting.
func TestWithCancel_NoGoroutineLeakOnCancel(t *testing.T) {
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetch := func(context.Context) (int, error) {
		time.Sleep(20 * time.Millisecond)
		return 42, nil
	}
	_, err := withCancel(ctx, newConfig(nil), fetch, func(r int) *int { return &r })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("fetch goroutine still parked after the caller gave up: %d goroutines, was %d",
				runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
