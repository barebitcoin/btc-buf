package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/barebitcoin/btc-buf/connectserver"
	"github.com/barebitcoin/btc-buf/connectserver/logging"
	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha/bitcoindv1alphaconnect"
	"github.com/barebitcoin/btc-buf/server/rpclog"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btclog"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	btcjson.MustRegisterCmd("importdescriptors", new(btcjson.ImportMultiCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("bumpfee", new(bumpFeeCommand), btcjson.UFWalletOnly)
}

type bumpFeeCommand struct {
	TXID string `json:"txid"`
}
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

	rpcclient.UseLogger(func(ctx context.Context) btclog.Logger {
		return &rpclog.Logger{Logger: zerolog.Ctx(ctx)}
	})

	conf := rpcclient.ConnConfig{
		User:         user,
		Pass:         pass,
		DisableTLS:   true,
		HTTPPostMode: true,
		Host:         host,
	}

	client, err := rpcclient.New(ctx, &conf, nil)
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

			if _, err := server.rpc.LoadWallet(ctx, wallet); err == nil {
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

var (
	pendingRequestsMu sync.RWMutex
	pendingRequests   []string
)

func loadPendingRequests() []string {
	pendingRequestsMu.RLock()
	defer pendingRequestsMu.RUnlock()

	return slices.Clone(pendingRequests)
}

func addPendingRequest(id string) {
	pendingRequestsMu.Lock()
	defer pendingRequestsMu.Unlock()

	pendingRequests = append(pendingRequests, id)
}

func removePendingRequest(id string) {
	pendingRequestsMu.Lock()
	defer pendingRequestsMu.Unlock()

	pendingRequests = slices.DeleteFunc(pendingRequests, func(maybe string) bool {
		return maybe == id
	})
}

// By default, the rpcclient calls are not cancelable. This adds that
// capability (client-side, the actual calls will continue running in the
// background).
func withCancel[R any, M any](
	ctx context.Context, fetch func(ctx context.Context) (R, error),
	transform func(r R) *M,
) (*connect.Response[M], error) {
	ch := make(chan R)
	errs := make(chan error)
	requestID := connectserver.RequestID(ctx)

	if requestID != "" {
		defer removePendingRequest(requestID)
	}

	go func() {
		if requestID != "" {
			addPendingRequest(requestID)
		}

		fetchResult, err := fetch(ctx)
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

	rpc, err := rpcclient.New(ctx, &conf, nil)
	if err != nil {
		return nil, err
	}

	return rpc, nil
}

// ListSinceBlock implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ListSinceBlock(ctx context.Context, c *connect.Request[pb.ListSinceBlockRequest]) (*connect.Response[pb.ListSinceBlockResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	hash, err := newChainHash(c.Msg.Hash)
	if err != nil {
		return nil, err
	}

	return withCancel[*btcjson.ListSinceBlockResult, pb.ListSinceBlockResponse](ctx,
		func(ctx context.Context) (*btcjson.ListSinceBlockResult, error) {
			return rpc.ListSinceBlock(ctx, hash)
		},
		func(r *btcjson.ListSinceBlockResult) *pb.ListSinceBlockResponse {
			return &pb.ListSinceBlockResponse{
				Transactions: lo.Map(r.Transactions, func(tx btcjson.ListTransactionsResult, idx int) *pb.GetTransactionResponse {
					return &pb.GetTransactionResponse{
						Amount:            tx.Amount,
						Fee:               lo.FromPtr(tx.Fee),
						Confirmations:     int32(tx.Confirmations),
						BlockHash:         tx.BlockHash,
						BlockIndex:        uint32(lo.FromPtr(tx.BlockIndex)),
						BlockTime:         nil,
						Txid:              tx.TxID,
						WalletConflicts:   tx.WalletConflicts,
						ReplacedByTxid:    tx.ReplacedByTXID,
						ReplacesTxid:      tx.ReplacesTXID,
						Time:              timestamppb.New(time.Unix(tx.Time, 0)),
						TimeReceived:      timestamppb.New(time.Unix(tx.TimeReceived, 0)),
						Bip125Replaceable: parseReplaceable(tx.BIP125Replaceable),
					}
				}),
			}
		},
	)
}

// BumpFee implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) BumpFee(ctx context.Context, c *connect.Request[pb.BumpFeeRequest]) (*connect.Response[pb.BumpFeeResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	type rawBumpFeeResponse struct {
		TXID    string      `json:"txid"`
		Origfee json.Number // old fee
		Fee     json.Number // new fee
		Errors  []string    // May be empty
	}
	return withCancel[rawBumpFeeResponse, pb.BumpFeeResponse](ctx,
		func(ctx context.Context) (rawBumpFeeResponse, error) {
			cmd, err := btcjson.NewCmd("bumpfee", c.Msg.Txid)
			if err != nil {
				return rawBumpFeeResponse{}, err
			}

			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, cmd))
			if err != nil {
				return rawBumpFeeResponse{}, fmt.Errorf("send bumpfee: %w", err)
			}
			zerolog.Ctx(ctx).Err(err).
				Msgf("bumpfee response: %s", string(res))

			var parsed rawBumpFeeResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return rawBumpFeeResponse{}, fmt.Errorf("unmarshal bumpfee response: %w", err)
			}

			return parsed, nil
		},

		func(r rawBumpFeeResponse) *pb.BumpFeeResponse {
			originalFee, _ := r.Origfee.Float64()
			newFee, _ := r.Fee.Float64()
			return &pb.BumpFeeResponse{
				Txid:        r.TXID,
				OriginalFee: originalFee,
				NewFee:      newFee,
				Errors:      r.Errors,
			}
		},
	)
}

// GetNewAddress implements bitcoind.Bitcoin
func (b *Bitcoind) GetNewAddress(ctx context.Context, req *connect.Request[pb.GetNewAddressRequest]) (*connect.Response[pb.GetNewAddressResponse], error) {
	rpc, err := b.rpcForWallet(ctx, req.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (btcutil.Address, error) {
			if req.Msg.AddressType != "" {
				return rpc.GetNewAddressType(ctx, req.Msg.Label, req.Msg.AddressType)
			}

			return rpc.GetNewAddress(ctx, req.Msg.Label)
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
				Blocks:               uint32(info.Blocks),
				Headers:              uint32(info.Headers),
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

// GetBlock implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetBlock(ctx context.Context, c *connect.Request[pb.GetBlockRequest]) (*connect.Response[pb.GetBlockResponse], error) {
	if c.Msg.Hash == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`"hash" is a required argument`))
	}

	hash, err := newChainHash(c.Msg.Hash)
	if err != nil {
		return nil, err
	}

	switch c.Msg.Verbosity {
	case pb.GetBlockRequest_VERBOSITY_RAW_DATA:
	block, err := b.rpc.GetBlock(ctx, hash)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	if err := block.Serialize(&out); err != nil {
		return nil, fmt.Errorf("serialize block: %w", err)
	}

	return connect.NewResponse(&pb.GetBlockResponse{
		Hex: hex.EncodeToString(out.Bytes()),
	}), nil

	case pb.GetBlockRequest_VERBOSITY_BLOCK_INFO:
		block, err := b.rpc.GetBlockVerbose(ctx, hash)
		if err != nil {
			return nil, err
		}

		return connect.NewResponse(&pb.GetBlockResponse{
			Hex:               "",
			Hash:              block.Hash,
			Confirmations:     int32(block.Confirmations),
			Height:            uint32(block.Height),
			Version:           block.Version,
			VersionHex:        block.VersionHex,
			Bits:              block.Bits,
			MerkleRoot:        block.MerkleRoot,
			Time:              &timestamppb.Timestamp{Seconds: block.Time},
			Nonce:             block.Nonce,
			Difficulty:        block.Difficulty,
			PreviousBlockHash: block.PreviousHash,
			NextBlockHash:     block.NextHash,
			StrippedSize:      block.StrippedSize,
			Size:              block.Size,
			Weight:            block.Weight,
			Txids:             block.Tx,
		}), nil

	default:
		return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("bad verbosity: %s", c.Msg.Verbosity))
	}
}

// GetRawTransaction implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetRawTransaction(ctx context.Context, c *connect.Request[pb.GetRawTransactionRequest]) (*connect.Response[pb.GetRawTransactionResponse], error) {
	if c.Msg.Txid == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := newChainHash(c.Msg.Txid)
	if err != nil {
		return nil, err
	}

	if !c.Msg.Verbose {
		return withCancel(ctx,
			func(ctx context.Context) (*btcutil.Tx, error) { return b.rpc.GetRawTransaction(ctx, hash) },
			func(tx *btcutil.Tx) *pb.GetRawTransactionResponse {
				var buf bytes.Buffer
				if err := tx.MsgTx().Serialize(&buf); err != nil {
					panic(err)
				}
				return &pb.GetRawTransactionResponse{
					Tx: rawTransaction(buf.Bytes()),
				}
			},
		)
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.TxRawResult, error) {
			return b.rpc.GetRawTransactionVerbose(ctx, hash)
		},
		func(tx *btcjson.TxRawResult) *pb.GetRawTransactionResponse {
			decoded, _ := hex.DecodeString(tx.Hex)
			return &pb.GetRawTransactionResponse{
				Tx:            rawTransaction(decoded),
				Blockhash:     tx.BlockHash,
				Confirmations: uint32(tx.Confirmations),
				Time:          tx.Time,
				Blocktime:     tx.Blocktime,
				Inputs:        lo.Map(tx.Vin, inputProto),
				Outputs:       lo.Map(tx.Vout, outputProto),
			}
		},
	)
}

func rawTransaction(bytes []byte) *pb.RawTransaction {
	return &pb.RawTransaction{
		Data: bytes,
		Hex:  hex.EncodeToString(bytes),
	}
}

func inputProto(input btcjson.Vin, _ int) *pb.Input {
	return &pb.Input{
		Txid: input.Txid,
		Vout: input.Vout,
	}
}

func outputProto(output btcjson.Vout, _ int) *pb.Output {
	if len(output.ScriptPubKey.Addresses) != 0 {
		output.ScriptPubKey.Address = output.ScriptPubKey.Addresses[0]
	}

	return &pb.Output{
		Amount: output.Value,
		N:      output.N,
		ScriptPubKey: &pb.ScriptPubKey{
			Type:    output.ScriptPubKey.Type,
			Address: output.ScriptPubKey.Address,
		},
	}
}

// GetTransaction implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetTransaction(ctx context.Context, c *connect.Request[pb.GetTransactionRequest]) (*connect.Response[pb.GetTransactionResponse], error) {
	if c.Msg.Txid == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := newChainHash(c.Msg.Txid)
	if err != nil {
		return nil, err
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.GetTransactionResult, error) {
			return rpc.GetTransactionWatchOnly(ctx, hash, c.Msg.IncludeWatchonly)
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
				Bip125Replaceable: parseReplaceable(res.BIP125Replaceable),
			}
		},
	)
}

// Send implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) Send(ctx context.Context, c *connect.Request[pb.SendRequest]) (*connect.Response[pb.SendResponse], error) {
	if len(c.Msg.Destinations) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("'destinations' is a required argument"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	return withCancel[*btcjson.SendResult, pb.SendResponse](ctx,
		func(ctx context.Context) (*btcjson.SendResult, error) {
			var outputs []btcjson.SendDestination
			for addr, amount := range c.Msg.Destinations {
				btcAmount, err := btcutil.NewAmount(amount)
				if err != nil {
					return nil, err
				}

				outputs = append(outputs, btcjson.SendDestination{
					Address: addr,
					Amount:  btcAmount,
				})
			}

			var opts []rpcclient.WalletSendOpt
			if c.Msg.ConfTarget != 0 {
				opts = append(opts, rpcclient.WithWalletSendConfirmationTarget(
					int(c.Msg.ConfTarget),
				))

				// conf target implies need for estimation mode
				// TODO: do this properly
				opts = append(opts, func(sc *btcjson.SendCmd) {
					sc.EstimateMode = lo.ToPtr(btcjson.EstimateModeEconomical)
				})
			}

			if c.Msg.IncludeUnsafe {
				opts = append(opts, rpcclient.WithWalletSendIncludeUnsafe())
			}

			var subOutputs []int
			for _, addr := range c.Msg.SubtractFeeFromOutputs {
				_, idx, ok := lo.FindIndexOf(outputs, func(item btcjson.SendDestination) bool {
					return item.Address == addr
				})

				if !ok {
					err := fmt.Errorf("unable to find output index for %q", addr)
					return nil, connect.NewError(connect.CodeInvalidArgument, err)
				}

				subOutputs = append(subOutputs, idx)
			}

			if len(subOutputs) != 0 {
				opts = append(opts,
					rpcclient.WithWalletSendSubtractFeeFromOutputs(subOutputs),
				)
			}

			if c.Msg.AddToWallet != nil {
				opts = append(opts,
					rpcclient.WithWalletSendAddToWallet(c.Msg.AddToWallet.Value),
				)
			}

			if c.Msg.FeeRate != 0 {
				opts = append(opts,
					rpcclient.WithWalletSendFeeRate(c.Msg.FeeRate),
				)
			}

			return rpc.WalletSend(ctx, outputs, opts...)
		},

		func(r *btcjson.SendResult) *pb.SendResponse {
			decoded, _ := hex.DecodeString(r.Hex)
			return &pb.SendResponse{
				Tx:   rawTransaction(decoded),
				Txid: r.TxID,
			}
		},
	)
}

// DecodeRawTransaction implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) DecodeRawTransaction(ctx context.Context, c *connect.Request[pb.DecodeRawTransactionRequest]) (*connect.Response[pb.DecodeRawTransactionResponse], error) {
	if (len(c.Msg.GetTx().GetHex()) == 0) == (len(c.Msg.GetTx().GetData()) == 0) {
		err := errors.New("must specify transaction bytes as either raw or hex-encoded")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	if c.Msg.Tx.Hex != "" {
		decoded, err := hex.DecodeString(c.Msg.Tx.Hex)
		if err != nil {
			err := fmt.Errorf("invalid hex data: %w", err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}

		c.Msg.Tx.Data = decoded
	}

	return withCancel[*btcjson.TxRawResult, pb.DecodeRawTransactionResponse](
		ctx,
		func(ctx context.Context) (*btcjson.TxRawResult, error) {
			return b.rpc.DecodeRawTransaction(ctx, c.Msg.Tx.Data)
		},

		func(r *btcjson.TxRawResult) *pb.DecodeRawTransactionResponse {
			return &pb.DecodeRawTransactionResponse{
				Txid:        r.Txid,
				Hash:        r.Hash,
				Size:        uint32(r.Size),
				VirtualSize: uint32(r.Vsize),
				Weight:      uint32(r.Weight),
				Version:     r.Version,
				Locktime:    r.LockTime,
				Inputs:      lo.Map(r.Vin, inputProto),
				Outputs:     lo.Map(r.Vout, outputProto),
			}
		},
	)
}

// EstimateSmartFee implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) EstimateSmartFee(ctx context.Context, c *connect.Request[pb.EstimateSmartFeeRequest]) (*connect.Response[pb.EstimateSmartFeeResponse], error) {
	return withCancel[*btcjson.EstimateSmartFeeResult, pb.EstimateSmartFeeResponse](
		ctx,
		func(ctx context.Context) (*btcjson.EstimateSmartFeeResult, error) {
			var estimateMode *btcjson.EstimateSmartFeeMode
			if c.Msg.EstimateMode != pb.EstimateSmartFeeRequest_ESTIMATE_MODE_UNSPECIFIED {
				switch c.Msg.EstimateMode {
				case pb.EstimateSmartFeeRequest_ESTIMATE_MODE_ECONOMICAL:
					estimateMode = &btcjson.EstimateModeEconomical
				case pb.EstimateSmartFeeRequest_ESTIMATE_MODE_CONSERVATIVE:
					estimateMode = &btcjson.EstimateModeConservative
				default:
					return nil, fmt.Errorf("unexpected estimate mode: %s", c.Msg.EstimateMode)
				}
			}
			return b.rpc.EstimateSmartFee(ctx, c.Msg.ConfTarget, estimateMode)
		},

		func(r *btcjson.EstimateSmartFeeResult) *pb.EstimateSmartFeeResponse {
			return &pb.EstimateSmartFeeResponse{
				Errors:  r.Errors,
				Blocks:  r.Blocks,
				FeeRate: lo.FromPtr(r.FeeRate),
			}
		},
	)
}

// GetBalances implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetBalances(ctx context.Context, c *connect.Request[pb.GetBalancesRequest]) (*connect.Response[pb.GetBalancesResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}
	return withCancel[*btcjson.GetBalancesResult, pb.GetBalancesResponse](
		ctx, rpc.GetBalances,
		func(r *btcjson.GetBalancesResult) *pb.GetBalancesResponse {
			var watchonly *pb.GetBalancesResponse_Watchonly
			if r.WatchOnly != nil {
				watchonly = &pb.GetBalancesResponse_Watchonly{
					Trusted:          r.WatchOnly.Trusted,
					UntrustedPending: r.WatchOnly.UntrustedPending,
					Immature:         r.WatchOnly.Immature,
				}
			}
			return &pb.GetBalancesResponse{
				Mine: &pb.GetBalancesResponse_Mine{
					Trusted:          r.Mine.Trusted,
					UntrustedPending: r.Mine.UntrustedPending,
					Immature:         r.Mine.Immature,
					// TODO: not present in rpcclient?
					// Used: ,
				},
				Watchonly: watchonly,
			}
		})
}

// ImportDescriptors implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ImportDescriptors(ctx context.Context, c *connect.Request[pb.ImportDescriptorsRequest]) (*connect.Response[pb.ImportDescriptorsResponse], error) {
	if len(c.Msg.GetRequests()) == 0 {
		err := errors.New("must provide at least one request")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	for _, req := range c.Msg.Requests {
		if req.Descriptor_ == "" {
			err := errors.New("descriptors must be non-empty")
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg.Wallet)
	if err != nil {
		return nil, err
	}

	type jsonRpcError struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	type parsedDescriptorResponse struct {
		Success  bool         `json:"success"`
		Warnings []string     `json:"warnings"`
		Error    jsonRpcError `json:"error"`
	}

	return withCancel[[]parsedDescriptorResponse, pb.ImportDescriptorsResponse](
		ctx, func(ctx context.Context) ([]parsedDescriptorResponse, error) {
			cmd := btcjson.ImportMultiCmd{
				Requests: lo.Map(c.Msg.Requests, func(req *pb.ImportDescriptorsRequest_Request, idx int) btcjson.ImportMultiRequest {
					return btcjson.ImportMultiRequest{
						Descriptor: &req.Descriptor_,
						Timestamp: lo.If(req.Timestamp == nil,
							btcjson.TimestampOrNow{
								Value: "now",
							}).
							ElseF(func() btcjson.TimestampOrNow {
								return btcjson.TimestampOrNow{
									Value: req.Timestamp.AsTime().Unix(),
								}
							}),
					}
				}),
			}
			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, &cmd))
			zerolog.Ctx(ctx).Err(err).
				Msgf("importdescriptors response: %s", string(res))

			var parsed []parsedDescriptorResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return nil, fmt.Errorf("unmarshal importdescriptors response: %w", err)
			}

			return parsed, err
		},
		func(r []parsedDescriptorResponse) *pb.ImportDescriptorsResponse {
			return &pb.ImportDescriptorsResponse{
				Responses: lo.Map(r, func(r parsedDescriptorResponse, idx int) *pb.ImportDescriptorsResponse_Response {
					return &pb.ImportDescriptorsResponse_Response{
						Success:  r.Success,
						Warnings: r.Warnings,
						Error: &pb.ImportDescriptorsResponse_Error{
							Code:    int32(r.Error.Code),
							Message: r.Error.Message,
						},
					}
				}),
			}
		})
}

// GetDescriptorInfo implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetDescriptorInfo(ctx context.Context, c *connect.Request[pb.GetDescriptorInfoRequest]) (*connect.Response[pb.GetDescriptorInfoResponse], error) {
	return withCancel[*btcjson.GetDescriptorInfoResult, pb.GetDescriptorInfoResponse](
		ctx, func(ctx context.Context) (*btcjson.GetDescriptorInfoResult, error) {
			return b.rpc.GetDescriptorInfo(ctx, c.Msg.Descriptor_)
		},
		func(r *btcjson.GetDescriptorInfoResult) *pb.GetDescriptorInfoResponse {
			return &pb.GetDescriptorInfoResponse{
				Descriptor_:    r.Descriptor,
				Checksum:       r.Checksum,
				IsRange:        r.IsRange,
				IsSolvable:     r.IsSolvable,
				HasPrivateKeys: r.HasPrivateKeys,
			}
		})
}

// GetRawMempool implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetRawMempool(ctx context.Context, c *connect.Request[pb.GetRawMempoolRequest]) (*connect.Response[pb.GetRawMempoolResponse], error) {
	type maybeVerbose struct {
		txids        []*chainhash.Hash
		transactions map[string]btcjson.GetMempoolEntryResult
	}
	return withCancel[maybeVerbose, pb.GetRawMempoolResponse](
		ctx, func(ctx context.Context) (maybeVerbose, error) {
			if !c.Msg.Verbose {
				res, err := b.rpc.GetRawMempool(ctx)
				if err != nil {
					return maybeVerbose{}, err
				}

				return maybeVerbose{res, nil}, nil

			}
			res, err := b.rpc.GetRawMempoolVerbose(ctx)
			if err != nil {
				return maybeVerbose{}, err
			}

			return maybeVerbose{nil, res}, nil
		},
		func(res maybeVerbose) *pb.GetRawMempoolResponse {
			return &pb.GetRawMempoolResponse{
				Transactions: lo.MapValues(res.transactions,
					func(value btcjson.GetMempoolEntryResult, key string) *pb.MempoolEntry {
						return &pb.MempoolEntry{
							VirtualSize:     uint32(value.VSize),
							Weight:          uint32(value.Weight),
							Time:            &timestamppb.Timestamp{Seconds: value.Time},
							DescendantCount: uint32(value.DescendantCount),
							DescendantSize:  uint32(value.DescendantSize),
							AncestorCount:   uint32(value.AncestorCount),
							AncestorSize:    uint32(value.AncestorSize),
							WitnessTxid:     value.WTxId,
							Fees: &pb.MempoolEntry_Fees{
								Base:       value.Fees.Base,
								Modified:   value.Fees.Modified,
								Ancestor:   value.Fees.Ancestor,
								Descendant: value.Fees.Descendant,
							},
							Depends:           value.Depends,
							SpentBy:           value.SpentBy,
							Bip125Replaceable: value.BIP125Replaceable,
							Unbroadcast:       value.Unbroadcast,
						}
					},
				),
				Txids: lo.Map(res.txids,
					func(txid *chainhash.Hash, idx int) string {
						return txid.String()
					}),
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

			switch {
			case err == nil:
				return resp, nil

			case strings.Contains(err.Error(), "Work queue depth exceeded"):
				zerolog.Ctx(ctx).Info().
					Strs("requests", loadPendingRequests()).
					Msgf("handle error: work queue depth exceeded")

				err = connect.NewError(connect.CodeResourceExhausted, errors.New("RPC work queue depth exceeded"))

			case errors.As(err, &rpcErr):
				switch {
				// This is a -4 in the btcd lib, but a -6 in Bitcoin Core...
				case rpcErr.Message == "Insufficient funds":
					err = connect.NewError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWallet && rpcErr.Message == "Transaction amount too small":
					err = connect.NewError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWallet && strings.Contains(rpcErr.Message, "which was already bumped by transaction"):
					err = connect.NewError(connect.CodeAlreadyExists, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCMisc && strings.Contains(rpcErr.Message, "is already spent"):
					err = connect.NewError(connect.CodeAlreadyExists, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWalletNotSpecified:

					// All wallet RPC requests should have a `wallet` string field.
					type hasWalletParam interface{ GetWallet() string }
					msg := "btc-buf must be started with the --bitcoind.wallet flag"
					if _, ok := req.Any().(hasWalletParam); ok {
						msg = `wallet must be specified either through the "wallet" parameter or the --bitcoind.wallet flag`
					}
					err = connect.NewError(connect.CodeFailedPrecondition, errors.New(msg))

				case rpcErr.Code == btcjson.ErrRPCWalletNotFound:
					err = connect.NewError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCInvalidAddressOrKey:
					err = connect.NewError(connect.CodeNotFound, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCInvalidParameter:
					err = connect.NewError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCDecodeHexString:
					err = connect.NewError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				default:
					log.Warn().Msgf("unknown btcjson error: %s", rpcErr)
				}
			}

			return resp, err
		}
	})
}

func newChainHash(in string) (*chainhash.Hash, error) {
	if in == "" {
		return nil, nil
	}

	hash, err := chainhash.NewHashFromStr(in)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	return hash, nil
}

func parseReplaceable(in string) pb.GetTransactionResponse_Replaceable {
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
