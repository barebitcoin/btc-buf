package server

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"
)

// SSHTunnel configures an ssh port forward to Bitcoin Core: LocalPort on this
// host is forwarded to RemoteHost:RemotePort as seen from Host. Point the
// Bitcoin Core host passed to NewBitcoind at localhost:LocalPort.
type SSHTunnel struct {
	// Host is the ssh destination, [user@]host.
	Host string
	// KeyFile is the private key to authenticate with. Nothing else is tried.
	KeyFile string
	// KnownHosts are known_hosts lines for Host. The host key is always
	// checked strictly, against these or the user's known_hosts file.
	KnownHosts []string

	LocalPort  int
	RemotePort int
	// RemoteHost is the forward's target as seen from Host. Defaults to
	// localhost.
	RemoteHost string
}

// WithSSHTunnel reaches Bitcoin Core through an ssh port forward, restarted
// whenever it dies until Shutdown. Requests are held while it is down, and a
// request refused by a forward that died under it is retried once.
func WithSSHTunnel(tunnel SSHTunnel) Option {
	return func(c *config) {
		c.sshTunnel = &tunnel
	}
}

// sshBinary is a variable so tests can substitute a script.
var sshBinary = "ssh"

const (
	// tunnelRepairWait bounds how long a request waits for the supervisor to
	// bring the tunnel back before failing with Unavailable.
	tunnelRepairWait = 15 * time.Second

	// tunnelReadyTimeout bounds how long the supervisor lets a restarted ssh
	// take to bind the local port before killing it. ConnectTimeout only
	// covers the TCP connect and key exchange, not authentication.
	tunnelReadyTimeout = 30 * time.Second

	// tunnelPollInterval is how often we check whether ssh has bound the
	// local port. It is on the startup path, so keep it short.
	tunnelPollInterval = 50 * time.Millisecond
)

// sshArgs builds the ssh command line for conf. The returned cleanup removes
// the temporary known_hosts file, if any, and must be called once ssh is no
// longer started.
func sshArgs(conf SSHTunnel) ([]string, func(), error) {
	noCleanup := func() {}

	switch {
	case conf.Host == "":
		return nil, noCleanup, errors.New("ssh tunnel: host is required")
	case conf.KeyFile == "":
		return nil, noCleanup, errors.New("ssh tunnel: key file is required")
	case conf.LocalPort == 0 || conf.RemotePort == 0:
		return nil, noCleanup, errors.New("ssh tunnel: local and remote port are required")
	}

	args := []string{
		"-v", "-N",
		"-F", "none", // don't read the default config file
		"-o", "BatchMode=yes", // never prompt, fail instead
		"-o", "StrictHostKeyChecking=yes", // only connect to a known host key
		"-o", "PasswordAuthentication=no", // disable password authentication
		"-o", "PreferredAuthentications=publickey", // only use public key authentication
		"-o", "IdentitiesOnly=yes", // only use explicitly provided keys
		"-o", "ServerAliveInterval=60", // send keep-alive every 60 seconds
		"-o", "ServerAliveCountMax=3", // allow 3 missed keep-alive responses before disconnecting
		"-o", "TCPKeepAlive=yes", // enable TCP keep-alive
		"-o", "ConnectTimeout=10", // never hang in connect, so the supervisor can retry
		"-o", "ExitOnForwardFailure=yes", // a tunnel that can't bind the local port is useless, exit and retry
		"-i", conf.KeyFile, // specify the key file to use
		"-L", fmt.Sprintf("%d:%s:%d",
			conf.LocalPort, cmp.Or(conf.RemoteHost, "localhost"), conf.RemotePort),
	}

	cleanup := noCleanup
	if len(conf.KnownHosts) > 0 {
		tempFile, err := os.CreateTemp("", "known_hosts_*")
		if err != nil {
			return nil, noCleanup, fmt.Errorf("create known hosts file: %w", err)
		}
		cleanup = func() { _ = os.Remove(tempFile.Name()) }

		for _, host := range conf.KnownHosts {
			if _, err := fmt.Fprintln(tempFile, host); err != nil {
				_ = tempFile.Close()
				cleanup()
				return nil, noCleanup, fmt.Errorf("write known hosts file: %w", err)
			}
		}
		if err := tempFile.Close(); err != nil {
			cleanup()
			return nil, noCleanup, fmt.Errorf("close known hosts file: %w", err)
		}

		args = append(args, "-o", "UserKnownHostsFile="+tempFile.Name())
	}

	return append(args, conf.Host), cleanup, nil
}

// startTunnel starts ssh and waits until the forward accepts connections,
// bounded by waitCtx. After that, the tunnel is kept up in the background
// until ctx is done.
func startTunnel(
	ctx, waitCtx context.Context, conf SSHTunnel, gate *tunnelGate,
) error {
	args, cleanup, err := sshArgs(conf)
	if err != nil {
		return err
	}

	// Readiness is a successful dial to the local port, so something else
	// already listening there would pass for the tunnel and receive our RPC
	// credentials.
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", conf.LocalPort))
	if err != nil {
		cleanup()
		return fmt.Errorf("local port %d is already in use: %w", conf.LocalPort, err)
	}
	if err := listener.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close port check listener: %w", err)
	}

	zerolog.Ctx(ctx).Info().
		Msgf("setting up SSH tunnel: %d:%s:%d -> %s",
			conf.LocalPort, cmp.Or(conf.RemoteHost, "localhost"), conf.RemotePort, conf.Host)

	tunnel, err := startSSHTunnel(ctx, args)
	if err != nil {
		cleanup()
		return err
	}

	if err := waitForSSHTunnel(waitCtx, conf.LocalPort, tunnel); err != nil {
		_ = tunnel.kill()
		cleanup()
		return err
	}
	gate.set(true)

	go func() {
		defer cleanup()
		superviseSSHTunnel(ctx, conf.LocalPort, args, tunnel, gate, tunnelReadyTimeout)
	}()

	return nil
}

type sshTunnel struct {
	done chan struct{} // closed once ssh has exited
	// err is the exit error and stderr the last lines ssh wrote there, which
	// hold the reason it exited. Both are set before done is closed.
	err    error
	stderr string
	kill   func() error
}

// stderrTailLines is how much of ssh's stderr is kept for errors. With -v,
// the reason for an exit is in the last few lines.
const stderrTailLines = 10

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
				if !errors.Is(err, ErrUnreachable) || retried {
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

	tunnel := &sshTunnel{done: make(chan struct{}), kill: cmd.Process.Kill}

	var stderrTail []string
	var output sync.WaitGroup
	output.Go(func() { logSSHOutput(ctx, "stdout", stdout) })
	output.Go(func() { stderrTail = logSSHOutput(ctx, "stderr", stderr) })

	go func() {
		// Wait closes the pipes, so it must only run once both are drained,
		// or the last lines, the ones saying why ssh exited, can be lost.
		output.Wait()
		tunnel.err = cmd.Wait()
		tunnel.stderr = strings.Join(stderrTail, "\n")
		close(tunnel.done)
	}()

	return tunnel, nil
}

// logSSHOutput logs r line by line until it is closed, and returns the last
// stderrTailLines lines.
func logSSHOutput(ctx context.Context, name string, r io.Reader) []string {
	var tail []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		zerolog.Ctx(ctx).Debug().
			Msgf("SSH tunnel %s: %s", name, line)

		tail = append(tail, line)
		if len(tail) > stderrTailLines {
			tail = tail[1:]
		}
	}
	return tail
}

// waitForSSHTunnel blocks until the local port accepts connections, ssh
// exits, or ctx is done.
func waitForSSHTunnel(ctx context.Context, localPort int, tunnel *sshTunnel) error {
	var dialer net.Dialer
	for {
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("localhost:%d", localPort))
		if err == nil {
			if err := conn.Close(); err != nil {
				return fmt.Errorf("close connection: %w", err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for SSH tunnel: %w", ctx.Err())
		case <-tunnel.done:
			return fmt.Errorf("SSH tunnel exited: %w: %s", tunnel.err, tunnel.stderr)
		case <-time.After(tunnelPollInterval):
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
			Str("stderr", tunnel.stderr).
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
