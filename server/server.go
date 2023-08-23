package server

import (
	"bytes"
	context "context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/barebitcoin/btc-buf/connectserver"
	"github.com/barebitcoin/btc-buf/connectserver/logging"
	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha/bitcoindv1alphaconnect"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Bitcoind struct {
	conf   rpcclient.ConnConfig
	rpc    *rpcclient.Client
	server *connectserver.Server
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
		conf: conf,
		rpc:  client,
	}

	// Do a request, to verify we can reach Bitcoin Core
	info, err := server.GetBlockchainInfo(
		ctx, connect.NewRequest(&pb.GetBlockchainInfoRequest{}),
	)
	switch {
	case connect.CodeOf(err) == connect.CodePermissionDenied:
		return nil, errors.New("invalid RPC client credentials")

	case err != nil:
		return nil, fmt.Errorf("could not get initial blockchain info: %w", err)
	}

	log.Debug().
		Stringer("info", info.Msg).
		Msg("got bitcoind info")

	// Means a specific wallet was specified in the config. Verify
	// that it exists and is loaded.
	if strings.Contains(host, "/wallet") {
		_, wallet, _ := strings.Cut(host, "/wallet/")
		log.Debug().
			Str("host", host).
			Str("wallet", wallet).
			Msg("bitcoind host contains wallet, verifying wallet exists")

		_, err := server.GetWalletInfo(ctx, connect.NewRequest(&pb.GetWalletInfoRequest{}))
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
func withCancel[R any, M any](
	ctx context.Context, fetch func() (R, error),
	transform func(r R) *M,
) (*connect.Response[M], error) {
	ch := make(chan R)
	errs := make(chan error)

	go func() {
		fetchResult, err := fetch()
		switch {
		case err != nil && err.Error() == `status code: 401, response: ""`:
			errs <- connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))

		case err != nil:
			errs <- err

		default:
			ch <- fetchResult
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errs:
		return nil, err
	case fetchResult := <-ch:
		return connect.NewResponse[M](transform(fetchResult)), nil
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
func (b *Bitcoind) GetNewAddress(ctx context.Context, req *connect.Request[pb.GetNewAddressRequest]) (*connect.Response[pb.GetNewAddressResponse], error) {
	rpc, err := b.rpcForWallet(ctx, req.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func() (btcutil.Address, error) {
			if req.Msg.AddressType != "" {
				return rpc.GetNewAddressType(req.Msg.Label, req.Msg.AddressType)
			}

			return rpc.GetNewAddress(req.Msg.Label)
		},
		func(r btcutil.Address) *pb.GetNewAddressResponse {
			return &pb.GetNewAddressResponse{Address: r.EncodeAddress()}
		})
}

// GetBlockchainInfo implements bitcoindv22.BitcoinServer
func (b *Bitcoind) GetBlockchainInfo(
	ctx context.Context, req *connect.Request[pb.GetBlockchainInfoRequest],
) (*connect.Response[pb.GetBlockchainInfoResponse], error) {
	return withCancel(ctx, b.rpc.GetBlockChainInfo,
		func(info *btcjson.GetBlockChainInfoResult) *pb.GetBlockchainInfoResponse {
			return &pb.GetBlockchainInfoResponse{
				BestBlockHash:        info.BestBlockHash,
				Chain:                info.Chain,
				ChainWork:            info.ChainWork,
				InitialBlockDownload: info.InitialBlockDownload,
			}
		})
}

// GetWalletInfo implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetWalletInfo(
	ctx context.Context, req *connect.Request[pb.GetWalletInfoRequest],
) (*connect.Response[pb.GetWalletInfoResponse], error) {
	rpc, err := b.rpcForWallet(ctx, req.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx, rpc.GetWalletInfo,
		func(info *btcjson.GetWalletInfoResult) *pb.GetWalletInfoResponse {
			var scanning *pb.WalletScan
			if info, ok := info.Scanning.Value.(btcjson.ScanProgress); ok {
				scanning = &pb.WalletScan{
					Duration: int64(info.Duration),
					Progress: info.Progress,
				}
			}
			return &pb.GetWalletInfoResponse{
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

// GetRawTransaction implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetRawTransaction(ctx context.Context, c *connect.Request[pb.GetRawTransactionRequest]) (*connect.Response[pb.GetRawTransactionResponse], error) {
	if c.Msg.Txid == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := chainhash.NewHashFromStr(c.Msg.Txid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid txid"))
	}

	if !c.Msg.Verbose {
		return withCancel(ctx,
			func() (*btcutil.Tx, error) { return b.rpc.GetRawTransaction(hash) },
			func(tx *btcutil.Tx) *pb.GetRawTransactionResponse {
				var buf bytes.Buffer
				if err := tx.MsgTx().Serialize(&buf); err != nil {
					panic(err)
				}
				return &pb.GetRawTransactionResponse{
					Hex: hex.EncodeToString(buf.Bytes()),
				}
			},
		)
	}

	return withCancel(ctx,
		func() (*btcjson.TxRawResult, error) { return b.rpc.GetRawTransactionVerbose(hash) },
		func(tx *btcjson.TxRawResult) *pb.GetRawTransactionResponse {
			return &pb.GetRawTransactionResponse{
				Hex: tx.Hex,
				Vin: lo.Map(tx.Vin, func(in btcjson.Vin, idx int) *pb.GetRawTransactionResponse_Input {
					return &pb.GetRawTransactionResponse_Input{
						Txid: in.Txid,
						Vout: in.Vout,
					}
				}),

				Vout: lo.Map(tx.Vout, func(out btcjson.Vout, idx int) *pb.GetRawTransactionResponse_Output {
					// Hm, bitcoin-cli says this is a field called `address`,
					// is btcjson wrong?
					var address string
					if len(out.ScriptPubKey.Addresses) != 0 {
						address = out.ScriptPubKey.Addresses[0]
					}

					return &pb.GetRawTransactionResponse_Output{
						Amount: out.Value,
						N:      out.N,
						ScriptPubKey: &pb.GetRawTransactionResponse_ScriptPubKey{
							Type:    out.ScriptPubKey.Type,
							Address: address,
						},
					}
				}),
			}
		},
	)
}

// GetTransaction implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetTransaction(ctx context.Context, c *connect.Request[pb.GetTransactionRequest]) (*connect.Response[pb.GetTransactionResponse], error) {
	if c.Msg.Txid == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := chainhash.NewHashFromStr(c.Msg.Txid)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid txid"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func() (*btcjson.GetTransactionResult, error) {
			return rpc.GetTransactionWatchOnly(hash, c.Msg.IncludeWatchonly)
		},

		func(res *btcjson.GetTransactionResult) *pb.GetTransactionResponse {
			var details []*pb.GetTransactionResponse_Details
			for _, d := range res.Details {
				category := func(in string) pb.GetTransactionResponse_Category {
					switch in {
					case "send":
						return pb.GetTransactionResponse_CATEGORY_SEND
					case "receive":
						return pb.GetTransactionResponse_CATEGORY_RECEIVE
					case "generate":
						return pb.GetTransactionResponse_CATEGORY_GENERATE
					case "immature":
						return pb.GetTransactionResponse_CATEGORY_IMMATURE
					case "orphan":
						return pb.GetTransactionResponse_CATEGORY_ORPHAN
					default:
						return 0
					}
				}
				detail := &pb.GetTransactionResponse_Details{
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

			replaceable := func(in string) pb.GetTransactionResponse_Replaceable {
				switch in {
				case "unknown":
					return pb.GetTransactionResponse_REPLACEABLE_UNSPECIFIED
				case "yes":
					return pb.GetTransactionResponse_REPLACEABLE_YES
				case "no":
					return pb.GetTransactionResponse_REPLACEABLE_NO
				default:
					return 0
				}
			}
			var blockTime *timestamppb.Timestamp
			if res.BlockTime != 0 {
				blockTime = timestamppb.New(time.Unix(res.BlockTime, 0))
			}

			return &pb.GetTransactionResponse{
				Hex:               res.Hex,
				Amount:            res.Amount,
				Fee:               res.Fee,
				Confirmations:     int32(res.Confirmations),
				BlockHash:         res.BlockHash,
				BlockIndex:        uint32(res.BlockIndex),
				BlockTime:         blockTime,
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

func (b *Bitcoind) Shutdown(ctx context.Context) {
	if b.server == nil {
		log.Warn().Msg("shutdown called on empty server")
		return
	}

	log.Info().Msg("stopping server")
	b.server.Shutdown(ctx)
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
	_, err := b.GetBlockchainInfo(ctx, connect.NewRequest(&pb.GetBlockchainInfoRequest{}))
	if err != nil {
		b.server.SetHealthStatus(service, grpchealth.StatusNotServing)
		log.Err(err).Msg("health check: could not fetch blockchain info")
		return

	}

	b.server.SetHealthStatus(service, grpchealth.StatusNotServing)
	log.Trace().Msgf("health check: fetched blockchain info, took %s", time.Since(start))
}

func (b *Bitcoind) Listen(ctx context.Context, address string) error {
	b.server = connectserver.New(
		logging.InterceptorConf{},
		handleBtcJsonErrors(),
	)

	connectserver.Register(b.server, rpc.NewBitcoinServiceHandler, rpc.BitcoinServiceHandler(b))

	log.Info().
		Str("address", address).
		Msg("connect: serving")

	return b.server.Serve(ctx, address)
}

var _ rpc.BitcoinServiceHandler = new(Bitcoind)

func handleBtcJsonErrors() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(handler connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			resp, err := handler(ctx, req)

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
				err = connect.NewError(connect.CodeFailedPrecondition, errors.New(msg))

			case btcjson.ErrRPCWalletNotFound:
				err = connect.NewError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

			case btcjson.ErrRPCInvalidAddressOrKey:
				err = connect.NewError(connect.CodeNotFound, errors.New(rpcErr.Message))

			default:
				log.Warn().Msgf("unknown btcjson error: %s", rpcErr)
			}

			return resp, err
		}
	})
}
