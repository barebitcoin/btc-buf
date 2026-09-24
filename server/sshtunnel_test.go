package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
)

type fakeNext struct {
	mu    sync.Mutex
	calls int
	fn    func(call int) error
}

func (f *fakeNext) unary(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()

	if err := f.fn(call); err != nil {
		return nil, err
	}
	return connect.NewResponse(&struct{}{}), nil
}

func (f *fakeNext) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func callThroughGate(ctx context.Context, gate *tunnelGate, wait time.Duration, next *fakeNext) error {
	handler := gate.interceptor(wait).WrapUnary(next.unary)
	_, err := handler(ctx, connect.NewRequest(&struct{}{}))
	return err
}

func refused() error {
	return connect.NewError(connect.CodeUnavailable, ErrUnreachable)
}

func isUp(gate *tunnelGate) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err := gate.waitUp(ctx, 0)
	return err == nil
}

func TestTunnelGate_PassesThroughWhenUp(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	next := &fakeNext{fn: func(int) error { return nil }}
	if err := callThroughGate(context.Background(), gate, time.Second, next); err != nil {
		t.Fatal(err)
	}
	if next.count() != 1 {
		t.Fatalf("expected 1 call, got %d", next.count())
	}
}

func TestTunnelGate_HoldsRequestUntilUp(t *testing.T) {
	gate := newTunnelGate()
	next := &fakeNext{fn: func(int) error { return nil }}

	done := make(chan error, 1)
	go func() { done <- callThroughGate(context.Background(), gate, 5*time.Second, next) }()

	select {
	case err := <-done:
		t.Fatalf("request completed while tunnel was down: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	gate.set(true)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if next.count() != 1 {
		t.Fatalf("expected 1 call, got %d", next.count())
	}
}

func TestTunnelGate_ReleasesAllWaiters(t *testing.T) {
	gate := newTunnelGate()
	next := &fakeNext{fn: func(int) error { return nil }}

	const waiters = 20
	errs := make(chan error, waiters)
	for range waiters {
		go func() { errs <- callThroughGate(context.Background(), gate, 5*time.Second, next) }()
	}

	time.Sleep(30 * time.Millisecond)
	gate.set(true)

	for range waiters {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if next.count() != waiters {
		t.Fatalf("expected %d calls, got %d", waiters, next.count())
	}
}

func TestTunnelGate_FailsWhenTunnelStaysDown(t *testing.T) {
	gate := newTunnelGate()
	next := &fakeNext{fn: func(int) error { return nil }}

	err := callThroughGate(context.Background(), gate, 50*time.Millisecond, next)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("expected unavailable, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause, got %v", err)
	}
	if next.count() != 0 {
		t.Fatalf("expected no calls, got %d", next.count())
	}
}

func TestTunnelGate_CallerCancelWhileHeld(t *testing.T) {
	gate := newTunnelGate()
	next := &fakeNext{fn: func(int) error { return nil }}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := callThroughGate(ctx, gate, 5*time.Second, next)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	// Left uncoded on purpose: connect maps it to CodeCanceled.
	if connect.CodeOf(err) == connect.CodeUnavailable {
		t.Fatalf("caller cancellation must not be reported as unavailable: %v", err)
	}
	if next.count() != 0 {
		t.Fatalf("expected no calls, got %d", next.count())
	}
}

func TestTunnelGate_SlowRPCNotBoundedByWait(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	next := &fakeNext{fn: func(int) error {
		time.Sleep(60 * time.Millisecond)
		return nil
	}}
	if err := callThroughGate(context.Background(), gate, 20*time.Millisecond, next); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelGate_RetriesRefusedAfterRepair(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	next := &fakeNext{}
	next.fn = func(call int) error {
		if call > 1 {
			return nil
		}
		return refused()
	}

	// The supervisor notices the dead ssh a bit later and brings up a new one.
	go func() {
		time.Sleep(30 * time.Millisecond)
		gate.set(false)
		time.Sleep(30 * time.Millisecond)
		gate.set(true)
	}()

	if err := callThroughGate(context.Background(), gate, time.Second, next); err != nil {
		t.Fatal(err)
	}
	if next.count() != 2 {
		t.Fatalf("expected 2 calls, got %d", next.count())
	}
}

func TestTunnelGate_RetriesRefusedOnlyOnce(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	next := &fakeNext{fn: func(int) error {
		gate.set(false)
		gate.set(true)
		return refused()
	}}

	err := callThroughGate(context.Background(), gate, time.Second, next)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("expected refused error, got %v", err)
	}
	if next.count() != 2 {
		t.Fatalf("expected 2 calls, got %d", next.count())
	}
}

func TestTunnelGate_RefusedWithoutRepairFails(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	next := &fakeNext{fn: func(int) error { return refused() }}

	err := callThroughGate(context.Background(), gate, 50*time.Millisecond, next)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("expected unavailable, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded cause, got %v", err)
	}
	if next.count() != 1 {
		t.Fatalf("expected 1 call, got %d", next.count())
	}
}

func TestTunnelGate_OtherErrorsPassThrough(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)

	boom := errors.New("boom")
	next := &fakeNext{fn: func(int) error { return boom }}

	if err := callThroughGate(context.Background(), gate, time.Second, next); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
	if next.count() != 1 {
		t.Fatalf("expected 1 call, got %d", next.count())
	}
}

func TestTunnelGate_SetIsIdempotent(t *testing.T) {
	gate := newTunnelGate()
	gate.set(true)
	gate.set(true)

	gen, err := gate.waitUp(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 {
		t.Fatalf("expected generation 1, got %d", gen)
	}

	gate.set(false)
	gate.set(false)
	gate.set(true)

	gen, err = gate.waitUp(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 2 {
		t.Fatalf("expected generation 2, got %d", gen)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func spawnCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "spawn")
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	start := time.Now()
	for !cond() {
		if time.Since(start) > timeout {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("%s after %s", what, time.Since(start).Round(time.Millisecond))
}

// Drives superviseSSHTunnel with a shell script standing in for ssh: the
// script records each spawn and then sleeps, and the test binds the local
// port itself to make a spawn "ready".
func TestSuperviseSSHTunnel(t *testing.T) {
	sshBinary = "sh"
	t.Cleanup(func() { sshBinary = "ssh" })

	counter := filepath.Join(t.TempDir(), "spawns")
	args := []string{"-c", `echo spawn >> "$0"; exec sleep 30`, counter}
	port := freePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Logger()
	ctx = log.WithContext(ctx)

	gate := newTunnelGate()
	gate.set(true)

	first, err := startSSHTunnel(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "first spawn", func() bool { return spawnCount(t, counter) >= 1 })

	const readyTimeout = 300 * time.Millisecond
	supervisorDone := make(chan struct{})
	go func() {
		defer close(supervisorDone)
		superviseSSHTunnel(ctx, port, args, first, gate, readyTimeout)
	}()

	// ssh dies: the gate goes down and a replacement is spawned after the
	// 1s minimum backoff.
	if err := first.kill(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "gate down", func() bool { return !isUp(gate) })
	waitFor(t, 10*time.Second, "second spawn", func() bool { return spawnCount(t, counter) >= 2 })

	// Nothing binds the port, so the replacement is killed after readyTimeout
	// and a third one is spawned after the 2s backoff. Bind only once that
	// kill is certain, or the replacement would find the port and count as
	// ready.
	time.Sleep(2 * readyTimeout)
	if isUp(gate) {
		t.Fatal("gate came up without anything listening on the port")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	waitFor(t, 10*time.Second, "third spawn", func() bool { return spawnCount(t, counter) >= 3 })

	// The port now accepts, so the third spawn is ready and the gate comes up
	// with a new generation.
	upCtx, upCancel := context.WithTimeout(ctx, 10*time.Second)
	defer upCancel()
	gen, err := gate.waitUp(upCtx, 1)
	if err != nil {
		t.Fatalf("gate never came up: %v", err)
	}
	if gen != 2 {
		t.Fatalf("expected generation 2, got %d", gen)
	}

	cancel()
	select {
	case <-supervisorDone:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisor did not stop after ctx cancel")
	}
}

func TestStartTunnel_RefusesBusyPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Anything that starts would do; the port check comes first.
	sshBinary = "false"
	t.Cleanup(func() { sshBinary = "ssh" })

	err = startTunnel(context.Background(), context.Background(), SSHTunnel{
		Host: "example.com", KeyFile: "key",
		LocalPort: listener.Addr().(*net.TCPAddr).Port, RemotePort: 8332,
	}, newTunnelGate())
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected a port in use error, got %v", err)
	}
}

func TestStartSSHTunnel_KeepsStderrTail(t *testing.T) {
	sshBinary = "sh"
	t.Cleanup(func() { sshBinary = "ssh" })

	// More lines than are kept, ending in the reason, as ssh -v would.
	script := `for i in $(seq 1 30); do echo "debug1: line $i" >&2; done
echo "root@example.com: Permission denied (publickey)." >&2
exit 255`
	tunnel, err := startSSHTunnel(context.Background(), []string{"-c", script})
	if err != nil {
		t.Fatal(err)
	}

	err = waitForSSHTunnel(context.Background(), freePort(t), tunnel)
	if err == nil || !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expected the reason in the error, got %v", err)
	}

	lines := strings.Split(tunnel.stderr, "\n")
	if len(lines) != stderrTailLines {
		t.Fatalf("expected %d lines kept, got %d: %q", stderrTailLines, len(lines), tunnel.stderr)
	}
	if strings.Contains(tunnel.stderr, "line 1\n") {
		t.Fatalf("expected only the last lines, got %q", tunnel.stderr)
	}
}
