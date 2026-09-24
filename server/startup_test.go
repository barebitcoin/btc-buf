package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeCore answers Bitcoin Core JSON-RPC calls from canned responses, keyed
// by method, or by method and wallet as "method@wallet".
type fakeCore struct {
	responses map[string]fakeResponse
	// gate, if set, holds every call until it is closed.
	gate chan struct{}
}

type fakeResponse struct {
	result any
	// code, if set, makes the call fail with this RPC error code.
	code int
}

var errMethodNotFound = fakeResponse{code: -32601}

func (f *fakeCore) start(t *testing.T) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.gate != nil {
			<-f.gate
		}

		var req struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}

		key := req.Method
		if _, wallet, ok := strings.Cut(r.URL.Path, "/wallet/"); ok {
			key += "@" + wallet
		}
		res, ok := f.responses[key]
		if !ok {
			res = errMethodNotFound
		}

		body := map[string]any{"id": req.ID, "result": res.result, "error": nil}
		if res.code != 0 {
			body["result"] = nil
			body["error"] = map[string]any{"code": res.code, "message": "fake error"}
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	return strings.TrimPrefix(srv.URL, "http://")
}

func newTestBitcoind(t *testing.T, core *fakeCore, opts ...Option) (*Bitcoind, error) {
	t.Helper()
	ctx := context.Background()

	opts = append([]Option{WithoutInitialConnectionCheck()}, opts...)
	b, err := NewBitcoind(ctx, core.start(t), "user", "pass", opts...)
	if err == nil {
		t.Cleanup(func() { b.Shutdown(ctx) })
	}
	return b, err
}

func walletInfo(name string, privateKeys bool) fakeResponse {
	return fakeResponse{result: map[string]any{
		"walletname":           name,
		"private_keys_enabled": privateKeys,
		"scanning":             false,
	}}
}

func TestWithoutPrivateKeys(t *testing.T) {
	t.Run("accepts watch-only wallets", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets":         {result: []string{"watch", "other"}},
			"getwalletinfo@watch": walletInfo("watch", false),
			"getwalletinfo@other": walletInfo("other", false),
		}}

		if _, err := newTestBitcoind(t, core, WithoutPrivateKeys()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("accepts Core without wallet functionality", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets": errMethodNotFound,
		}}

		if _, err := newTestBitcoind(t, core, WithoutPrivateKeys()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("refuses a wallet with private keys", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets":         {result: []string{"watch", "hot"}},
			"getwalletinfo@watch": walletInfo("watch", false),
			"getwalletinfo@hot":   walletInfo("hot", true),
		}}

		_, err := newTestBitcoind(t, core, WithoutPrivateKeys())
		if err == nil || !strings.Contains(err.Error(), "private keys enabled: hot") {
			t.Fatalf("expected a private keys error naming the wallet, got %v", err)
		}
	})

	t.Run("fails when the check can't run", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets": {code: -1},
		}}

		if _, err := newTestBitcoind(t, core, WithoutPrivateKeys()); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestBackgroundStartup(t *testing.T) {
	t.Run("holds requests until startup succeeds", func(t *testing.T) {
		core := &fakeCore{
			gate: make(chan struct{}),
			responses: map[string]fakeResponse{
				"listwallets": {result: []string{}},
			},
		}

		b, err := newTestBitcoind(t, core, WithoutPrivateKeys(), WithBackgroundStartup())
		if err != nil {
			t.Fatal(err)
		}
		client := b.InProcessClient()

		done := make(chan error, 1)
		go func() {
			_, err := client.ListWallets(context.Background(), connect.NewRequest(&emptypb.Empty{}))
			done <- err
		}()

		select {
		case err := <-done:
			t.Fatalf("request completed during startup: %v", err)
		case <-time.After(50 * time.Millisecond):
		}

		close(core.gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := b.Ready(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fails requests when startup fails", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets":       {result: []string{"hot"}},
			"getwalletinfo@hot": walletInfo("hot", true),
		}}

		b, err := newTestBitcoind(t, core, WithoutPrivateKeys(), WithBackgroundStartup())
		if err != nil {
			t.Fatal(err)
		}

		if err := b.Ready(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "private keys enabled") {
			t.Fatalf("expected a private keys error, got %v", err)
		}

		_, err = b.InProcessClient().ListWallets(context.Background(), connect.NewRequest(&emptypb.Empty{}))
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("expected unavailable, got %v", err)
		}
	})

	t.Run("a held request gives up with its context", func(t *testing.T) {
		core := &fakeCore{
			gate: make(chan struct{}),
			responses: map[string]fakeResponse{
				"listwallets": {result: []string{}},
			},
		}
		b, err := newTestBitcoind(t, core, WithoutPrivateKeys(), WithBackgroundStartup())
		if err != nil {
			t.Fatal(err)
		}
		// Registered after the fake Core, so it runs first: closing the
		// server waits for the held call.
		t.Cleanup(func() { close(core.gate) })

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err = b.InProcessClient().ListWallets(ctx, connect.NewRequest(&emptypb.Empty{}))
		if connect.CodeOf(err) != connect.CodeDeadlineExceeded {
			t.Fatalf("expected deadline exceeded, got %v", err)
		}
		if err := b.Ready(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected Ready to give up with ctx, got %v", err)
		}
	})

	t.Run("shutdown ends a pending startup", func(t *testing.T) {
		core := &fakeCore{
			gate: make(chan struct{}),
			responses: map[string]fakeResponse{
				"listwallets": {result: []string{}},
			},
		}

		b, err := newTestBitcoind(t, core, WithoutPrivateKeys(), WithBackgroundStartup())
		if err != nil {
			t.Fatal(err)
		}
		// Registered after the fake Core, so it runs first: closing the
		// server waits for the held call.
		t.Cleanup(func() { close(core.gate) })

		b.Shutdown(context.Background())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.Ready(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected startup to end canceled, got %v", err)
		}
	})

	t.Run("synchronous startup is ready on return", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"listwallets": {result: []string{}},
		}}

		b, err := newTestBitcoind(t, core, WithoutPrivateKeys())
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		for range 100 {
			if err := b.Ready(ctx); err != nil {
				t.Fatalf("a finished startup must win over a done ctx: %v", err)
			}
		}
	})
}

func TestSSHArgs(t *testing.T) {
	t.Run("validates", func(t *testing.T) {
		for name, conf := range map[string]SSHTunnel{
			"no host":  {KeyFile: "key", LocalPort: 1, RemotePort: 2},
			"no key":   {Host: "h", LocalPort: 1, RemotePort: 2},
			"no ports": {Host: "h", KeyFile: "key"},
		} {
			if _, _, err := sshArgs(conf); err == nil {
				t.Errorf("%s: expected an error", name)
			}
		}
	})

	t.Run("builds the forward", func(t *testing.T) {
		args, cleanup, err := sshArgs(SSHTunnel{
			Host: "root@example.com", KeyFile: "key",
			KnownHosts: []string{"example.com ssh-ed25519 AAAA"},
			LocalPort:  9332, RemotePort: 8332, RemoteHost: "bitcoind",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cleanup)

		joined := strings.Join(args, " ")
		for _, want := range []string{
			"-L 9332:bitcoind:8332",
			"StrictHostKeyChecking=yes",
			"BatchMode=yes",
			"UserKnownHostsFile=",
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("expected %q in %q", want, joined)
			}
		}
		if args[len(args)-1] != "root@example.com" {
			t.Errorf("expected the destination last, got %q", args[len(args)-1])
		}
	})
}
