package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"time"

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
	if cfg.SSH.Host != "" {
		zerolog.Ctx(ctx).Info().
			Msgf("setting up SSH tunnel: %d:localhost:%d -> %s",
				cfg.SSH.LocalPort, cfg.SSH.RemotePort, cfg.SSH.Host,
			)
		if err := setupSSHTunnel(ctx, cfg.SSH); err != nil {
			return fmt.Errorf("setup SSH tunnel: %w", err)
		}
	}

	clientCtx, clientCancel := context.WithTimeout(ctx, time.Second*10)
	defer clientCancel()

	var opts []server.Option
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
func setupSSHTunnel(ctx context.Context, conf sshConfig) error {
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
	if err := waitForSSHTunnel(ctx, conf.LocalPort, tunnel); err != nil {
		return err
	}

	go superviseSSHTunnel(ctx, conf.LocalPort, args, tunnel)

	return nil
}

type sshTunnel struct {
	done chan struct{} // closed once ssh has exited
	err  error         // exit error, set before done is closed
}

func startSSHTunnel(ctx context.Context, args []string) (*sshTunnel, error) {
	cmd := exec.CommandContext(ctx, "ssh", args...)

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

	tunnel := &sshTunnel{done: make(chan struct{})}
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

// waitForSSHTunnel blocks until the local port accepts connections.
func waitForSSHTunnel(ctx context.Context, localPort int, tunnel *sshTunnel) error {
	for range 10 {
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

	return fmt.Errorf("timeout waiting for SSH tunnel")
}

// superviseSSHTunnel restarts ssh with backoff whenever it exits, until ctx
// is done.
func superviseSSHTunnel(ctx context.Context, localPort int, args []string, tunnel *sshTunnel) {
	log := zerolog.Ctx(ctx)

	const minBackoff, maxBackoff = time.Second, 30 * time.Second
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

		if err := waitForSSHTunnel(ctx, localPort, tunnel); err != nil {
			// Either ssh already exited (done is closed, the loop restarts it)
			// or it is still connecting, which ConnectTimeout bounds.
			log.Err(err).Msg("restart SSH tunnel")
		}
	}
}
