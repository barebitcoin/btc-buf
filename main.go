package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"

	"github.com/barebitcoin/btc-buf/server"
)

func realMain(cfg *config) error {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		signal := <-sig
		zerolog.Ctx(ctx).Info().
			Stringer("signal", signal).
			Msg("received signal, canceling context")
		cancel(fmt.Errorf("received %s signal", signal))
	}()

	errs := make(chan error)
	var opts []server.Option
	if cfg.SSH.Host != "" {
		zerolog.Ctx(ctx).Info().
			Msgf("setting up SSH tunnel: %d:localhost:%d -> %s",
				cfg.SSH.LocalPort, cfg.SSH.RemotePort, cfg.SSH.Host,
			)
		gate := newTunnelGate()
		if err := setupSSHTunnel(ctx, cfg.SSH, gate); err != nil {
			return fmt.Errorf("setup SSH tunnel: %w", err)
		}
		opts = append(opts, server.WithInterceptors(gate.interceptor(tunnelRepairWait)))
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, time.Second*10)
	defer clientCancel()

	if cfg.AllowPrivateDescriptorsExport {
		zerolog.Ctx(ctx).Info().Msg("allowing private descriptors export")
		opts = append(opts, server.WithAllowPrivateDescriptorsExport())
	}

	bitcoind, err := server.NewBitcoind(
		clientCtx, cfg.Bitcoind.Host, cfg.Bitcoind.User, cfg.Bitcoind.Pass,
		opts...,
	)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	go func() {
		if err := bitcoind.Listen(ctx, cfg.Listen); err != nil {
			errs <- err
		}
	}()
	go func() {
		<-ctx.Done()
		bitcoind.Shutdown(ctx)

		errs <- context.Cause(ctx)
	}()

	return <-errs
}

func main() {
	ctx := context.Background()

	cfg, err := readConfig(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to read config:", err)
		os.Exit(1)
	}

	// important: this is only usable AFTER readConfig has been called
	log := zerolog.Ctx(ctx)

	if info, ok := debug.ReadBuildInfo(); ok {
		log.Info().
			Str("go", info.GoVersion).
			Str("vcs.sha", findSetting("vcs.revision", info.Settings)).
			Str("vcs.modified", findSetting("vcs.modified", info.Settings)).
			Msgf("starting %s", os.Args[0])
	}

	if err := realMain(cfg); err != nil {
		log.Fatal().Err(err).Msg("main: received error")
	}
	log.Info().Msgf("main: exiting with 0 code")
}

func findSetting(key string, settings []debug.BuildSetting) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}

	return "unknown"
}

// setupSSHTunnel starts an ssh port forward and keeps it running until ctx is
// done. Only the initial connection can fail the call. Later exits are
// handled by superviseSSHTunnel.
func setupSSHTunnel(ctx context.Context, conf sshConfig, gate *tunnelGate) error {
	if conf.KeyFile == "" {
		return fmt.Errorf("ssh: key file is required")
	}

	args := []string{
		"-v", "-N",
		"-F", "none", // don't read the default config file
		"-o", "PasswordAuthentication=no", // disable password authentication
		"-o", "PreferredAuthentications=publickey", // only use public key authentication
		"-o", "IdentitiesOnly=yes", // only use explicitly provided keys
		"-o", "ServerAliveInterval=60", // send keep-alive every 60 seconds
		"-o", "ServerAliveCountMax=3", // allow 3 missed keep-alive responses before disconnecting
		"-o", "TCPKeepAlive=yes", // enable TCP keep-alive
		"-o", "ConnectTimeout=10", // never hang in connect, so the supervisor can retry
		"-o", "ExitOnForwardFailure=yes", // a tunnel that can't bind the local port is useless, exit and retry
		"-i", conf.KeyFile, // specify the key file to use
		"-L", fmt.Sprintf("%d:localhost:%d", conf.LocalPort, conf.RemotePort),
		conf.Host,
	}
	if conf.KnownHosts != nil {
		tempFile, err := os.CreateTemp("", "")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}

		for _, host := range conf.KnownHosts {
			_, err := fmt.Fprintln(tempFile, host)
			if err != nil {
				return fmt.Errorf("write temp file: %w", err)
			}
		}
		if err := tempFile.Close(); err != nil {
			return fmt.Errorf("close temp file: %w", err)
		}

		args = append(args, "-o", "UserKnownHostsFile="+tempFile.Name())
	}
	tunnel, err := startSSHTunnel(ctx, args)
	if err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := waitForSSHTunnel(waitCtx, conf.LocalPort, tunnel); err != nil {
		return err
	}
	gate.set(true)

	go superviseSSHTunnel(ctx, conf.LocalPort, args, tunnel, gate, tunnelReadyTimeout)

	return nil
}

// sshBinary is a variable so tests can substitute a script.
var sshBinary = "ssh"

type sshTunnel struct {
	done chan struct{} // closed once ssh has exited
	err  error         // exit error, set before done is closed
	kill func() error
}

const (
	// tunnelRepairWait bounds how long a request waits for the supervisor to
	// bring the tunnel back before failing with Unavailable.
	tunnelRepairWait = 15 * time.Second

	// tunnelReadyTimeout bounds how long the supervisor lets a restarted ssh
	// take to bind the local port before killing it. ConnectTimeout only
	// covers the TCP connect and key exchange, not authentication.
	tunnelReadyTimeout = 30 * time.Second
)

// tunnelGate tracks whether the local ssh port forward accepts connections.
// It says nothing about the remote end of the forward. The tunnel code flips
// it; requests only wait on it.
type tunnelGate struct {
	mu      sync.Mutex
	up      bool
	gen     uint64        // incremented each time the tunnel comes up
	changed chan struct{} // closed and replaced on every transition
}

func newTunnelGate() *tunnelGate {
	return &tunnelGate{changed: make(chan struct{})}
}

func (g *tunnelGate) set(up bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.up == up {
		return
	}
	g.up = up
	if up {
		g.gen++
	}
	close(g.changed)
	g.changed = make(chan struct{})
}

// waitUp blocks until the tunnel is up with a generation newer than after,
// and returns that generation.
func (g *tunnelGate) waitUp(ctx context.Context, after uint64) (uint64, error) {
	for {
		g.mu.Lock()
		up, gen, changed := g.up, g.gen, g.changed
		g.mu.Unlock()

		if up && gen > after {
			return gen, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

// interceptor holds requests while the tunnel is down, for at most wait. A
// request refused by a tunnel that died under it never reached Bitcoin Core,
// and is retried once on the next tunnel generation.
func (g *tunnelGate) interceptor(wait time.Duration) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			waitCtx, cancel := context.WithTimeout(ctx, wait)
			defer cancel()

			var seen uint64
			retried := false
			for {
				gen, err := g.waitUp(waitCtx, seen)
				if err != nil {
					// The caller gave up; connect maps this to Canceled or
					// DeadlineExceeded.
					if ctx.Err() != nil {
						return nil, err
					}
					zerolog.Ctx(ctx).Warn().
						Dur("waited", wait).
						Msg("SSH tunnel still down, giving up on request")
					return nil, connect.NewError(connect.CodeUnavailable,
						fmt.Errorf("SSH tunnel to Bitcoin Core is down: %w", err))
				}

				res, err := next(ctx, req)
				if !errors.Is(err, server.ErrUnreachable) || retried {
					return res, err
				}

				zerolog.Ctx(ctx).Warn().Err(err).
					Msg("request hit a dead SSH tunnel, waiting for repair")
				seen, retried = gen, true
			}
		}
	})
}

func startSSHTunnel(ctx context.Context, args []string) (*sshTunnel, error) {
	cmd := exec.CommandContext(ctx, sshBinary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting SSH tunnel: %w", err)
	}

	go logSSHOutput(ctx, "stdout", stdout)
	go logSSHOutput(ctx, "stderr", stderr)

	tunnel := &sshTunnel{done: make(chan struct{}), kill: cmd.Process.Kill}
	go func() {
		tunnel.err = cmd.Wait()
		close(tunnel.done)
	}()

	return tunnel, nil
}

func logSSHOutput(ctx context.Context, name string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		zerolog.Ctx(ctx).Debug().
			Msgf("SSH tunnel %s: %s", name, scanner.Text())
	}
}

// waitForSSHTunnel blocks until the local port accepts connections, ssh
// exits, or ctx is done.
func waitForSSHTunnel(ctx context.Context, localPort int, tunnel *sshTunnel) error {
	for {
		if conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", localPort)); err == nil {
			if err := conn.Close(); err != nil {
				return fmt.Errorf("close connection: %w", err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for SSH tunnel: %w", ctx.Err())
		case <-tunnel.done:
			return fmt.Errorf("SSH tunnel exited: %w", tunnel.err)
		case <-time.After(time.Second):
		}
	}
}

// superviseSSHTunnel restarts ssh with backoff whenever it exits, until ctx
// is done. A restarted ssh that has not bound the local port within
// readyTimeout is killed and restarted.
func superviseSSHTunnel(
	ctx context.Context, localPort int, args []string,
	tunnel *sshTunnel, gate *tunnelGate, readyTimeout time.Duration,
) {
	log := zerolog.Ctx(ctx)

	// maxBackoff stays below tunnelRepairWait so a held request sees at
	// least one reconnect attempt.
	const minBackoff, maxBackoff = time.Second, 10 * time.Second
	backoff := minBackoff
	started := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tunnel.done:
		}
		if ctx.Err() != nil {
			return
		}
		gate.set(false)

		// A tunnel that held for a while earns a fresh backoff.
		if time.Since(started) > time.Minute {
			backoff = minBackoff
		}
		log.Error().Err(tunnel.err).
			Dur("backoff", backoff).
			Msg("SSH tunnel exited, restarting")

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)

		next, err := startSSHTunnel(ctx, args)
		if err != nil {
			log.Err(err).Msg("restart SSH tunnel")
			continue
		}
		tunnel, started = next, time.Now()

		readyCtx, cancel := context.WithTimeout(ctx, readyTimeout)
		err = waitForSSHTunnel(readyCtx, localPort, tunnel)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				log.Err(err).Msg("SSH tunnel not ready in time, killing it")
				if err := tunnel.kill(); err != nil {
					log.Err(err).Msg("kill SSH tunnel")
				}
			}
			continue
		}
		gate.set(true)
	}
}
