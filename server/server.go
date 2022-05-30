package server

import (
	context "context"
	"fmt"
	"net"

	bitcoind "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type Bitcoind struct {
	rpc    *rpcclient.Client
	server *grpc.Server
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

	server := &Bitcoind{rpc: client}

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

// GetBlockchainInfo implements bitcoindv22.BitcoinServer
func (b *Bitcoind) GetBlockchainInfo(
	ctx context.Context, req *bitcoind.GetBlockchainInfoRequest,
) (*bitcoind.GetBlockchainInfoResponse, error) {
	chainInfo := make(chan *btcjson.GetBlockChainInfoResult)
	errs := make(chan error)
	fut := b.rpc.GetBlockChainInfoAsync()

	go func() {
		info, err := fut.Receive()
		if err != nil {
			errs <- err
		} else {
			chainInfo <- info
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errs:
		return nil, err
	case info := <-chainInfo:
		res := bitcoind.GetBlockchainInfoResponse{
			BestBlockHash:        info.BestBlockHash,
			Chain:                info.Chain,
			ChainWork:            info.ChainWork,
			InitialBlockDownload: info.InitialBlockDownload,
		}

		return &res, nil
	}
}

func (b *Bitcoind) Stop() {
	if b.server == nil {
		log.Warn().Msg("gRPC: stop called on empty server")
		return
	}

	log.Info().Msg("gRPC: stopping server")
	b.server.Stop()
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
		serverLogger(),
	))

	log.Printf("gRPC: enabling reflection")
	reflection.Register(b.server)

	bitcoind.RegisterBitcoinServiceServer(b.server, b)

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
