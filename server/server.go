package server

import (
	context "context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	bitcoind "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Bitcoind struct {
	conf   rpcclient.ConnConfig
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
		return nil, err
	}

	log.Debug().Msg("created RPC client")

	server := &Bitcoind{
		conf:   conf,
		rpc:    client,
		health: health.NewServer(),
	}

	// Do a request, to verify we can reach Bitcoin Core
	info, err := server.GetBlockchainInfo(
		ctx, &bitcoind.GetBlockchainInfoRequest{},
	)
	switch {
	case status.Code(err) == codes.PermissionDenied:
		return nil, errors.New("invalid RPC client credentials")

	case err != nil:
		return nil, fmt.Errorf("could not get initial blockchain info: %w", err)
	}

	log.Debug().
		Stringer("info", info).
		Msg("got bitcoind info")

	// Means a specific wallet was specified in the config. Verify
	// that it exists and is loaded.
	if strings.Contains(host, "/wallet") {
		_, wallet, _ := strings.Cut(host, "/wallet/")
		log.Debug().
			Str("host", host).
			Str("wallet", wallet).
			Msg("bitcoind host contains wallet, verifying wallet exists")

		_, err := server.GetWalletInfo(ctx, &bitcoind.GetWalletInfoRequest{})
		switch {
		// Great stuff, wallet exists
		case err == nil:

		case bitcoindErrorCode(err) == btcjson.ErrRPCWalletNotFound:
			log.Debug().Err(err).Msg("could not get wallet, trying loading")

			if _, err := server.rpc.LoadWallet(wallet); err == nil {
				log.Info().Msgf("loaded wallet: %s", wallet)
				break
			}

			return nil, fmt.Errorf("wallet %q does not exist or is not loaded", wallet)

		default:
			return nil, fmt.Errorf("get wallet info: %w", err)
		}
	}

	return server, nil
}

func bitcoindErrorCode(err error) btcjson.RPCErrorCode {
	rpcErr := new(btcjson.RPCError)
	if !errors.As(err, &rpcErr) {
		return 0
	}

	return rpcErr.Code
}

// By default, the rpcclient calls are not cancelable. This adds that
// capability (client-side, the actual calls will continue running in the
// background).
func withCancel[R any, M proto.Message](
	ctx context.Context, fetch func() (R, error),
	transform func(r R) M,
) (M, error) {
	var msg M

	ch := make(chan R)
	errs := make(chan error)

	go func() {
		info, err := fetch()
		switch {
		case err != nil && err.Error() == `status code: 401, response: ""`:
			errs <- status.Error(codes.PermissionDenied, "permission denied")

		case err != nil:
			errs <- err

		default:
			ch <- info
		}
	}()

	select {
	case <-ctx.Done():
		return msg, ctx.Err()
	case err := <-errs:
		return msg, err
	case info := <-ch:
		return transform(info), nil
	}
}

func (b *Bitcoind) rpcForWallet(ctx context.Context, wallet string) (*rpcclient.Client, error) {
	if wallet == "" {
		return b.rpc, nil
	}

	conf := b.conf // make sure to not copy the original conf
	hostWithoutWallet, _, _ := strings.Cut(conf.Host, "/wallet")
	conf.Host = fmt.Sprintf("%s/wallet/%s", hostWithoutWallet, wallet)

	zerolog.Ctx(ctx).Debug().
		Str("wallet", wallet).
		Msg("making wallet-specific call")

	rpc, err := rpcclient.New(&conf, nil)
	if err != nil {
		return nil, err
	}

	return rpc, nil
}

// GetNewAddress implements bitcoind.Bitcoin
func (b *Bitcoind) GetNewAddress(ctx context.Context, req *bitcoind.GetNewAddressRequest) (*bitcoind.GetNewAddressResponse, error) {
	rpc, err := b.rpcForWallet(ctx, req.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func() (btcutil.Address, error) {
			if req.AddressType != "" {
				return rpc.GetNewAddressType(req.Label, req.AddressType)
			}

			return rpc.GetNewAddress(req.Label)
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

// GetWalletInfo implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetWalletInfo(
	ctx context.Context, req *bitcoind.GetWalletInfoRequest,
) (*bitcoind.GetWalletInfoResponse, error) {
	rpc, err := b.rpcForWallet(ctx, req.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx, rpc.GetWalletInfo,
		func(info *btcjson.GetWalletInfoResult) *bitcoind.GetWalletInfoResponse {
			var scanning *bitcoind.WalletScan
			if info, ok := info.Scanning.Value.(btcjson.ScanProgress); ok {
				scanning = &bitcoind.WalletScan{
					Duration: int64(info.Duration),
					Progress: info.Progress,
				}
			}
			return &bitcoind.GetWalletInfoResponse{
				WalletName:            info.WalletName,
				WalletVersion:         int64(info.WalletVersion),
				Format:                info.Format,
				TxCount:               int64(info.TransactionCount),
				KeyPoolSize:           int64(info.KeyPoolSize),
				KeyPoolSizeHdInternal: int64(*info.KeyPoolSizeHDInternal),
				PayTxFee:              info.PayTransactionFee,
				PrivateKeysEnabled:    info.PrivateKeysEnabled,
				AvoidReuse:            info.AvoidReuse,
				Scanning:              scanning,
				Descriptors:           info.Descriptors,
				ExternalSigner:        info.ExternalSigner,
			}
		},
	)
}

// GetTransaction implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetTransaction(ctx context.Context, c *bitcoind.GetTransactionRequest) (*bitcoind.GetTransactionResponse, error) {
	if c.Txid == "" {
		return nil, status.Error(codes.InvalidArgument, `"txid" is a required argument`)
	}

	hash, err := chainhash.NewHashFromStr(c.Txid)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid txid")
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func() (*btcjson.GetTransactionResult, error) {
			return rpc.GetTransactionWatchOnly(hash, c.IncludeWatchonly)
		},

		func(res *btcjson.GetTransactionResult) *bitcoind.GetTransactionResponse {
			var details []*bitcoind.GetTransactionResponse_Details
			for _, d := range res.Details {
				category := func(in string) bitcoind.GetTransactionResponse_Category {
					switch in {
					case "send":
						return bitcoind.GetTransactionResponse_CATEGORY_SEND
					case "receive":
						return bitcoind.GetTransactionResponse_CATEGORY_RECEIVE
					case "generate":
						return bitcoind.GetTransactionResponse_CATEGORY_GENERATE
					case "immature":
						return bitcoind.GetTransactionResponse_CATEGORY_IMMATURE
					case "orphan":
						return bitcoind.GetTransactionResponse_CATEGORY_ORPHAN
					default:
						return 0
					}
				}
				detail := &bitcoind.GetTransactionResponse_Details{
					InvolvesWatchOnly: d.InvolvesWatchOnly,
					Address:           d.Address,
					Category:          category(d.Category),
					Amount:            d.Amount,
					Vout:              d.Vout,
				}

				if d.Fee != nil {
					detail.Fee = *d.Fee
				}

				details = append(details, detail)
			}

			replaceable := func(in string) bitcoind.GetTransactionResponse_Replaceable {
				switch in {
				case "unknown":
					return bitcoind.GetTransactionResponse_REPLACEABLE_UNSPECIFIED
				case "yes":
					return bitcoind.GetTransactionResponse_REPLACEABLE_YES
				case "no":
					return bitcoind.GetTransactionResponse_REPLACEABLE_NO
				default:
					return 0
				}
			}

			return &bitcoind.GetTransactionResponse{
				Amount:            res.Amount,
				Fee:               res.Fee,
				Confirmations:     uint32(res.Confirmations),
				BlockHash:         res.BlockHash,
				BlockIndex:        uint32(res.BlockIndex),
				BlockTime:         timestamppb.New(time.Unix(res.BlockTime, 0)),
				Txid:              res.TxID,
				ReplacedByTxid:    res.ReplacedByTXID,
				ReplacesTxid:      res.ReplacesTXID,
				WalletConflicts:   res.WalletConflicts,
				Time:              timestamppb.New(time.Unix(res.Time, 0)),
				TimeReceived:      timestamppb.New(time.Unix(res.TimeReceived, 0)),
				Details:           details,
				Bip125Replaceable: replaceable(res.BIP125Replaceable),
			}
		},
	)
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

		// All wallet RPC requests should have a `wallet` string field.
		type hasWalletParam (interface{ GetWallet() string })
		msg := "btc-buf must be started with the --bitcoind.wallet flag"
		if _, ok := req.(hasWalletParam); ok {
			msg = `wallet must be specified either through the "wallet" parameter or the --bitcoind.wallet flag`
		}
		err = status.Error(codes.FailedPrecondition, msg)

	case btcjson.ErrRPCWalletNotFound:
		err = status.Error(codes.FailedPrecondition, rpcErr.Message)

	case btcjson.ErrRPCInvalidAddressOrKey:
		err = status.Error(codes.NotFound, rpcErr.Message)

	default:
		log.Warn().Msgf("unknown btcjson error: %s", rpcErr)
	}

	return resp, err
}
