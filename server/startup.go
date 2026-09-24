package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/rs/zerolog"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	"github.com/barebitcoin/btc-buf/rpcclient/btcjson"
)

// WithoutPrivateKeys fails startup unless every loaded wallet has private
// keys disabled, or Core runs without wallet functionality. For watch-only
// use. It is checked once: wallets loaded or created afterwards, including
// through this proxy's LoadWallet and CreateWallet, are not.
func WithoutPrivateKeys() Option {
	return func(c *config) {
		c.requireNoPrivateKeys = true
	}
}

// WithBackgroundStartup makes NewBitcoind return without waiting for startup:
// the SSH tunnel, the initial connection check and the private key check run
// in the background. Requests are held until startup succeeds, and fail with
// Unavailable if it doesn't. Surface the outcome through Ready.
func WithBackgroundStartup() Option {
	return func(c *config) {
		c.backgroundStartup = true
	}
}

// startupTimeout bounds startup, including the first SSH connection.
const startupTimeout = 30 * time.Second

// Ready waits for startup to finish and returns its error. Without
// WithBackgroundStartup it returns at once: NewBitcoind already waited.
func (b *Bitcoind) Ready(ctx context.Context) error {
	// A finished startup wins over a done ctx: select picks at random when
	// both are ready.
	select {
	case <-b.started:
		return b.startErr
	default:
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.started:
		return b.startErr
	}
}

// startupInterceptor holds requests until startup has finished, bounded by
// the caller's context, and fails them if startup did.
func (b *Bitcoind) startupInterceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if err := b.Ready(ctx); err != nil {
				// The caller gave up; connect maps this to Canceled or
				// DeadlineExceeded.
				if ctx.Err() != nil {
					return nil, err
				}
				return nil, connect.NewError(connect.CodeUnavailable,
					fmt.Errorf("Bitcoin Core proxy failed to start: %w", err)) // nolint:staticcheck
			}
			return next(ctx, req)
		}
	})
}

// startup brings up the SSH tunnel, if any, and runs the startup checks.
// ctx bounds startup; the tunnel is kept up until lifetime is done. The
// checks call Core directly, not through the request gates, which only open
// once startup has succeeded.
func (b *Bitcoind) startup(lifetime, ctx context.Context, tunnel *tunnelGate) error {
	if b.conf.sshTunnel != nil {
		if err := startTunnel(lifetime, ctx, *b.conf.sshTunnel, tunnel); err != nil {
			return fmt.Errorf("start SSH tunnel: %w", err)
		}
	}

	if b.conf.withoutInitialConnectionCheck {
		zerolog.Ctx(ctx).Info().Msg("initial connection check disabled")
	} else if err := b.checkConnection(ctx); err != nil {
		return err
	}

	if b.conf.requireNoPrivateKeys {
		if err := b.checkNoPrivateKeys(ctx); err != nil {
			return err
		}
	}

	return nil
}

// checkConnection verifies that Bitcoin Core is reachable with our
// credentials, and that a wallet named in the host exists and is loaded.
func (b *Bitcoind) checkConnection(ctx context.Context) error {
	log := zerolog.Ctx(ctx)

	info, err := b.GetBlockchainInfo(
		ctx, connect.NewRequest(&pb.GetBlockchainInfoRequest{}),
	)
	switch {
	case connect.CodeOf(err) == connect.CodePermissionDenied:
		return errors.New("invalid RPC client credentials")

	case err != nil:
		return fmt.Errorf("get initial blockchain info: %w", err)
	}

	log.Debug().
		Stringer("info", info.Msg).
		Msg("got bitcoind info")

	// Means a specific wallet was specified in the config. Verify that it
	// exists and is loaded.
	host := b.rpcConf.Host
	if !strings.Contains(host, "/wallet") {
		return nil
	}

	_, wallet, _ := strings.Cut(host, "/wallet/")
	log.Debug().
		Str("host", host).
		Str("wallet", wallet).
		Msg("bitcoind host contains wallet, verifying wallet exists")

	_, err = b.GetWalletInfo(ctx, connect.NewRequest(&pb.GetWalletInfoRequest{}))
	switch {
	// Great stuff, wallet exists
	case err == nil:
		return nil

	case bitcoindErrorCode(err) == btcjson.ErrRPCWalletNotFound:
		log.Debug().Err(err).Msg("could not get wallet, trying loading")

		if _, err := b.rpc.LoadWallet(ctx, wallet, nil); err == nil {
			log.Info().Msgf("loaded wallet: %s", wallet)
			return nil
		}

		return fmt.Errorf("wallet %q does not exist or is not loaded", wallet)

	case bitcoindErrorCode(err) == btcjson.ErrRPCMethodNotFound.Code:
		err := errors.New("Bitcoin Core is running without wallet functionality") // nolint:staticcheck
		return connect.NewError(connect.CodeFailedPrecondition, err)

	default:
		return fmt.Errorf("get wallet info: %w", err)
	}
}

// checkNoPrivateKeys verifies that no loaded wallet has private keys enabled.
func (b *Bitcoind) checkNoPrivateKeys(ctx context.Context) error {
	log := zerolog.Ctx(ctx)

	wallets, err := b.rpc.ListWallets(ctx)
	switch {
	case bitcoindErrorCode(err) == btcjson.ErrRPCMethodNotFound.Code:
		log.Info().Msg("verified Bitcoin Core holds no private keys: running without wallet functionality")
		return nil

	case err != nil:
		return fmt.Errorf("list wallets: %w", err)
	}

	var withKeys []string
	for _, wallet := range wallets {
		rpc, err := b.rpcForWallet(ctx, &pb.GetWalletInfoRequest{Wallet: wallet})
		if err != nil {
			return err
		}

		// Read the field we need straight off Core's response, rather than
		// through GetWalletInfo's full conversion.
		info, err := rpc.GetWalletInfo(ctx)
		if err != nil {
			return fmt.Errorf("get wallet info for %q: %w", wallet, err)
		}
		if info.PrivateKeysEnabled {
			withKeys = append(withKeys, wallet)
		}
	}

	if len(withKeys) > 0 {
		return fmt.Errorf("Bitcoin Core has wallets with private keys enabled: %s", // nolint:staticcheck
			strings.Join(withKeys, ", "))
	}

	log.Info().
		Int("wallets", len(wallets)).
		Msg("verified Bitcoin Core holds no private keys")
	return nil
}
