package server

import (
	context "context"
	"errors"
	"fmt"
	"net"
	"time"

	bitcoind "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Bitcoind struct {
	rpc    *rpcclient.Client
	server *grpc.Server
	health *health.Server
}

func NewBitcoind(
	ctx context.Context, host, user, pass string,
) (*Bitcoind, error) {
	log.Info().
		Str("host", host).
		Str("user", user).
		Msg("connecting to bitcoind")

	conf := rpcclient.ConnConfig{
		User:         user,
		Pass:         pass,
		DisableTLS:   true,
		HTTPPostMode: true,
		Host:         host,
	}

	client, err := rpcclient.New(&conf, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create RPC client: %w", err)
	}

	server := &Bitcoind{
		rpc:    client,
		health: health.NewServer(),
	}

	// Do a request, to verify we can reach Bitcoin Core
	info, err := server.GetBlockchainInfo(
		ctx, &bitcoind.GetBlockchainInfoRequest{},
	)
	if err != nil {
		return nil, fmt.Errorf("could not connect to bitcoind: %w", err)
	}

	log.Debug().
		Stringer("info", info).
		Msg("got bitcoind info")

	return server, nil
}

// By default, the rpcclient calls are not cancelable. This adds that
// capability (client-side, the actual calls will continue running in the
// background).
func withCancel[R any, M proto.Message](
	ctx context.Context, fetch func() (R, error),
	transform func(r R) M,
) (M, error) {
	ch := make(chan R)
	errs := make(chan error)

	go func() {
		info, err := fetch()
		if err != nil {
			errs <- err
		} else {
			ch <- info
		}
	}()

	var msg M
	select {
	case <-ctx.Done():
		return msg, ctx.Err()
	case err := <-errs:
		return msg, err
	case info := <-ch:
		return transform(info), nil
	}
}

// GetNewAddress implements bitcoind.Bitcoin
func (b *Bitcoind) GetNewAddress(ctx context.Context, req *bitcoind.GetNewAddressRequest) (*bitcoind.GetNewAddressResponse, error) {
	return withCancel(ctx,
		func() (btcutil.Address, error) {
			if req.AddressType != "" {
				return b.rpc.GetNewAddressType(req.Label, req.AddressType)
			}

			return b.rpc.GetNewAddress(req.Label)
		},
		func(r btcutil.Address) *bitcoind.GetNewAddressResponse {
			return &bitcoind.GetNewAddressResponse{Address: r.EncodeAddress()}
		})
}

// GetBlockchainInfo implements bitcoindv22.BitcoinServer
func (b *Bitcoind) GetBlockchainInfo(
	ctx context.Context, req *bitcoind.GetBlockchainInfoRequest,
) (*bitcoind.GetBlockchainInfoResponse, error) {
	return withCancel(ctx, b.rpc.GetBlockChainInfo,
		func(info *btcjson.GetBlockChainInfoResult) *bitcoind.GetBlockchainInfoResponse {
			return &bitcoind.GetBlockchainInfoResponse{
				BestBlockHash:        info.BestBlockHash,
				Chain:                info.Chain,
				ChainWork:            info.ChainWork,
				InitialBlockDownload: info.InitialBlockDownload,
			}
		})
}

func (b *Bitcoind) Stop() {
	if b.server == nil {
		log.Warn().Msg("gRPC: stop called on empty server")
		return
	}

	log.Info().Msg("gRPC: stopping server")
	b.health.Shutdown()
	b.server.Stop()
}

func (b *Bitcoind) RunHealthChecks(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("health check: starting")

	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	// Do an initial check before the first tick.
	b.fetchHealthCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Debug().Msg("stopping health checks")
			return nil

		case <-ticker.C:
			b.fetchHealthCheck(ctx)
		}
	}
}

func (b *Bitcoind) fetchHealthCheck(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()

	// service := bitcoind.BitcoinService_ServiceDesc.ServiceName
	service := ""

	log := zerolog.Ctx(ctx)
	start := time.Now()
	_, err := b.GetBlockchainInfo(ctx, &bitcoind.GetBlockchainInfoRequest{})
	if err != nil {
		b.health.SetServingStatus(service, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		log.Err(err).Msg("health check: could not fetch blockchain info")
		return

	}

	b.health.SetServingStatus(service, grpc_health_v1.HealthCheckResponse_SERVING)
	log.Trace().Msgf("health check: fetched blockchain info, took %s", time.Since(start))
}

func (b *Bitcoind) Listen(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	b.server = grpc.NewServer(grpc.ChainUnaryInterceptor(
		recovery.UnaryServerInterceptor(
			recovery.WithRecoveryHandlerContext(recoveryHandler),
		),
		handleBtcJsonErrors,
		serverLogger(),
	))

	log.Printf("gRPC: enabling reflection")
	reflection.Register(b.server)

	bitcoind.RegisterBitcoinServiceServer(b.server, b)
	grpc_health_v1.RegisterHealthServer(b.server, b.health)

	errChan := make(chan error, 1)

	go func() {
		log.Info().
			Stringer("address", listener.Addr()).
			Msg("gRPC: serving")

		if err := b.server.Serve(listener); err != nil {
			errChan <- fmt.Errorf("gRPC serve: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ bitcoind.BitcoinServiceServer = new(Bitcoind)

func recoveryHandler(ctx context.Context, panic any) error {
	log.Error().
		Interface("panic", panic).
		Str("panicType", fmt.Sprintf("%T", panic)).
		Msg("gRPC: panicked")

	msg := fmt.Sprintf("encountered internal error: %v", panic)

	return status.Error(codes.Internal, msg)
}

func handleBtcJsonErrors(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	resp, err = handler(ctx, req)

	rpcErr := new(btcjson.RPCError)
	if !errors.As(err, &rpcErr) {
		return resp, err
	}

	switch rpcErr.Code {
	case btcjson.ErrRPCWalletNotSpecified:
		// Actually don't think this is supported in rpcclient...
		err = status.Error(codes.Unimplemented, "support for multiple wallets not yet supported")

	case btcjson.ErrRPCWalletNotFound:
		err = status.Error(codes.FailedPrecondition, rpcErr.Message)

	default:
		log.Warn().Msgf("unknown btcjson error: %s", rpcErr)
	}

	return resp, err
}
