package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/barebitcoin/btcd/rpcclient"
	"github.com/barebitcoin/btcd/rpcclient/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btclog"
	"github.com/rs/zerolog"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/barebitcoin/btc-buf/connectserver"
	"github.com/barebitcoin/btc-buf/connectserver/logging"
	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha/bitcoindv1alphaconnect"
	"github.com/barebitcoin/btc-buf/server/commands"
	"github.com/barebitcoin/btc-buf/server/rpclog"
)

func init() {
	btcjson.MustRegisterCmd("importdescriptors", new(btcjson.ImportMultiCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("bumpfee", new(commands.BumpFee), btcjson.UFWalletOnly)
}

type Bitcoind struct {
	conf   rpcclient.ConnConfig
	rpc    *rpcclient.Client
	server *connectserver.Server
}

func NewBitcoind(
	ctx context.Context, host, user, pass string,
) (*Bitcoind, error) {
	log := zerolog.Ctx(ctx)
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
		HTTPPostMode: true, // Core only handles POST requests
		Host:         host,
	}

	client, err := rpcclient.New(ctx, &conf, nil)
	if err != nil {
		return nil, fmt.Errorf("new RPC client: %w", err)
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
		return nil, fmt.Errorf("get initial blockchain info: %w", err)
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
	log := zerolog.Ctx(ctx)

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

		start := time.Now()
		log.Debug().Msgf("rpc: starting fetch")

		fetchResult, err := fetch(ctx)
		log.Err(err).Msgf("rpc: fetch completed in %s", time.Since(start))
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
		start := time.Now()
		transformed := transform(fetchResult)

		log.Debug().
			Msgf("rpc: transformed raw result in %s", time.Since(start))

		return connect.NewResponse[M](transformed), nil
	}
}

// Common interface implemented for all wallet RPCs
type walletRequest interface {
	GetWallet() string
}

func (b *Bitcoind) rpcForWallet(ctx context.Context, req walletRequest) (*rpcclient.Client, error) {
	if req.GetWallet() == "" {
		return b.rpc, nil
	}

	conf := b.conf // make sure to not copy the original conf
	hostWithoutWallet, _, _ := strings.Cut(conf.Host, "/wallet")
	conf.Host = fmt.Sprintf("%s/wallet/%s", hostWithoutWallet, req.GetWallet())

	zerolog.Ctx(ctx).Debug().
		Str("wallet", req.GetWallet()).
		Msg("making wallet-specific call")

	rpc, err := rpcclient.New(ctx, &conf, nil)
	if err != nil {
		return nil, err
	}

	return rpc, nil
}

// ListTransactions implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ListTransactions(ctx context.Context, c *connect.Request[pb.ListTransactionsRequest]) (*connect.Response[pb.ListTransactionsResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}
	const (
		label        = "*"
		defaultCount = 10
	)
	return withCancel(ctx,
		func(ctx context.Context) ([]btcjson.ListTransactionsResult, error) {
			return rpc.ListTransactionsCountFrom(
				ctx, label,
				cmp.Or(int(c.Msg.Count), defaultCount),
				int(c.Msg.Skip),
			)
		},
		func(r []btcjson.ListTransactionsResult) *pb.ListTransactionsResponse {
			return &pb.ListTransactionsResponse{
				Transactions: lo.Map(r, func(
					tx btcjson.ListTransactionsResult, idx int,
				) *pb.GetTransactionResponse {
					return txListEntryToProto(tx)
				}),
			}
		},
	)
}

// ListWallets implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ListWallets(ctx context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[pb.ListWalletsResponse], error) {
	wallets, err := b.rpc.ListWallets(ctx)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&pb.ListWalletsResponse{
		Wallets: wallets,
	}), nil
}

// ListSinceBlock implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ListSinceBlock(ctx context.Context, c *connect.Request[pb.ListSinceBlockRequest]) (*connect.Response[pb.ListSinceBlockResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	hash, err := newChainHash(c.Msg.Hash)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.ListSinceBlockResult, error) {
			return rpc.ListSinceBlock(ctx, hash)
		},
		func(r *btcjson.ListSinceBlockResult) *pb.ListSinceBlockResponse {
			return &pb.ListSinceBlockResponse{
				Transactions: lo.Map(r.Transactions, func(tx btcjson.ListTransactionsResult, idx int) *pb.GetTransactionResponse {
					return txListEntryToProto(tx)
				}),
			}
		},
	)
}

func txListEntryToProto(tx btcjson.ListTransactionsResult) *pb.GetTransactionResponse {
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
		// Clunk town...
		Details: []*pb.GetTransactionResponse_Details{{
			Address:           tx.Address,
			InvolvesWatchOnly: tx.InvolvesWatchOnly,
			Category:          categoryFromString(tx.Category),
			Amount:            tx.Amount,
			Vout:              tx.Vout,
			Fee:               lo.FromPtr(tx.Fee),
		}},
	}
}

// BumpFee implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) BumpFee(ctx context.Context, c *connect.Request[pb.BumpFeeRequest]) (*connect.Response[pb.BumpFeeResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	type rawBumpFeeResponse struct {
		TXID    string      `json:"txid"`
		Origfee json.Number // old fee
		Fee     json.Number // new fee
		Errors  []string    // May be empty
	}
	return withCancel(ctx,
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
	rpc, err := b.rpcForWallet(ctx, req.Msg)
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
				BestBlockHash:        info.BestBlockHash,
				Blocks:               uint32(info.Blocks),
				Headers:              uint32(info.Headers),
				Chain:                info.Chain,
				ChainWork:            info.ChainWork,
				InitialBlockDownload: info.InitialBlockDownload,
				VerificationProgress: info.VerificationProgress,
			}
		})
}

// GetPeerInfo implements bitcoindv22.BitcoinServer
func (b *Bitcoind) GetPeerInfo(
	ctx context.Context, req *connect.Request[pb.GetPeerInfoRequest],
) (*connect.Response[pb.GetPeerInfoResponse], error) {
	return withCancel(ctx, b.rpc.GetPeerInfo,
		func(info []btcjson.GetPeerInfoResult) *pb.GetPeerInfoResponse {
			return &pb.GetPeerInfoResponse{
				Peers: lo.Map(info, func(peer btcjson.GetPeerInfoResult, idx int) *pb.Peer {
					// Create a peer object with all available fields from the GetPeerInfoResult struct
					p := &pb.Peer{
						Id:                  peer.ID,
						Addr:                peer.Addr,
						AddrLocal:           peer.AddrLocal,
						BytesSent:           peer.BytesSent,
						BytesReceived:       peer.BytesRecv,
						AddrBind:            "",                                     // Not in the RPC client
						Network:             pb.Peer_NETWORK_UNSPECIFIED,            // Not in the RPC client
						MappedAs:            0,                                      // Not in the RPC client
						ConnectionType:      pb.Peer_CONNECTION_TYPE_UNSPECIFIED,    // Not in the RPC client
						TransportProtocol:   pb.Peer_TRANSPORT_PROTOCOL_UNSPECIFIED, // Not in the RPC client
						LastTransactionAt:   nil,                                    // Not in the RPC client
						LastBlockAt:         nil,                                    // Not in the RPC client
						BytesSentPerMsg:     map[string]int64{},                     // Not in the RPC client
						BytesReceivedPerMsg: map[string]int64{},                     // Not in the RPC client
						MinPing:             nil,                                    // Not in the RPC client
						Bip152HbTo:          false,                                  // Not in the RPC client
						Bip152HbFrom:        false,                                  // Not in the RPC client
						PresyncedHeaders:    0,                                      // Not in the RPC client
						SyncedHeaders:       0,                                      // Not in the RPC client
						SyncedBlocks:        0,                                      // Not in the RPC client
						Inflight:            []int32{},                              // Not in the RPC client
						AddrRelayEnabled:    false,                                  // Not in the RPC client
						AddrProcessed:       0,                                      // Not in the RPC client
						AddrRateLimited:     0,                                      // Not in the RPC client
						Permissions:         []string{},                             // Not in the RPC client
						MinFeeFilter:        0,                                      // Not in the RPC client
						SessionId:           "",                                     // Not in the RPC client
						ConnectedAt:         timestamppb.New(time.Unix(peer.ConnTime, 0)),
						LastSendAt:          timestamppb.New(time.Unix(peer.LastSend, 0)),
						LastRecvAt:          timestamppb.New(time.Unix(peer.LastRecv, 0)),
						Version:             peer.Version,
						Subver:              peer.SubVer,
						Inbound:             peer.Inbound,
						StartingHeight:      peer.StartingHeight,
						TimeOffset:          durationpb.New(time.Duration(peer.TimeOffset) * time.Second),
						Services:            peer.Services,
						ServicesNames:       []string{}, // Not in the RPC client
						RelayTransactions:   peer.RelayTxes,
						PingTime:            durationpb.New(time.Millisecond * time.Duration(peer.PingTime)),
						PingWait:            durationpb.New(time.Millisecond * time.Duration(peer.PingWait)),
					}

					return p
				}),
			}
		})
}

// GetWalletInfo implements bitcoindv1alpha.BitcoinServiceServer
func (b *Bitcoind) GetWalletInfo(
	ctx context.Context, req *connect.Request[pb.GetWalletInfoRequest],
) (*connect.Response[pb.GetWalletInfoResponse], error) {
	rpc, err := b.rpcForWallet(ctx, req.Msg)
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

// GetBlockHash implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetBlockHash(ctx context.Context, c *connect.Request[pb.GetBlockHashRequest]) (*connect.Response[pb.GetBlockHashResponse], error) {
	res, err := b.rpc.GetBlockHash(ctx, int64(c.Msg.Height))
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&pb.GetBlockHashResponse{Hash: res.String()}), nil
}

// GetBlock implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetBlock(ctx context.Context, c *connect.Request[pb.GetBlockRequest]) (*connect.Response[pb.GetBlockResponse], error) {
	if (c.Msg.Hash == "" && c.Msg.Height == nil) || (c.Msg.Hash != "" && c.Msg.Height != nil) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New(`must set one of "hash" or "height"`))
	}

	hash, err := newChainHash(c.Msg.Hash)
	if err != nil {
		return nil, fmt.Errorf("new chain hash: %w", err)
	}

	if c.Msg.Height != nil {
		hash, err = b.rpc.GetBlockHash(ctx, int64(*c.Msg.Height))
		if err != nil {
			return nil, fmt.Errorf("get block hash from height: %w", err)
		}
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

	case pb.GetBlockRequest_VERBOSITY_BLOCK_INFO, pb.GetBlockRequest_VERBOSITY_BLOCK_TX_INFO, pb.GetBlockRequest_VERBOSITY_BLOCK_TX_PREVOUT_INFO:
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
				Size:          tx.Size,
				Vsize:         tx.Vsize,
				Weight:        tx.Weight,
				Version:       tx.Version,
				Locktime:      tx.LockTime,
				Txid:          tx.Txid,
				Hash:          tx.Hash,
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
	var scriptSig *pb.ScriptSig
	if input.ScriptSig != nil {
		scriptSig = &pb.ScriptSig{
			Asm: input.ScriptSig.Asm,
			Hex: input.ScriptSig.Hex,
		}
	}

	return &pb.Input{
		Txid:      input.Txid,
		Vout:      input.Vout,
		Coinbase:  input.Coinbase,
		ScriptSig: scriptSig,
		Sequence:  input.Sequence,
		Witness:   input.Witness,
	}
}

func outputProto(output btcjson.Vout, _ int) *pb.Output {
	if len(output.ScriptPubKey.Addresses) != 0 {
		output.ScriptPubKey.Address = output.ScriptPubKey.Addresses[0]
	}

	var scriptSig *pb.ScriptSig
	if output.ScriptPubKey.Asm != "" || output.ScriptPubKey.Hex != "" {
		scriptSig = &pb.ScriptSig{
			Asm: output.ScriptPubKey.Asm,
			Hex: output.ScriptPubKey.Hex,
		}
	}

	return &pb.Output{
		Amount:    output.Value,
		Vout:      output.N,
		ScriptSig: scriptSig,
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

	rpc, err := b.rpcForWallet(ctx, c.Msg)
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
				detail := &pb.GetTransactionResponse_Details{
					InvolvesWatchOnly: d.InvolvesWatchOnly,
					Address:           d.Address,
					Category:          categoryFromString(d.Category),
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

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
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

// SendToAddress implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) SendToAddress(ctx context.Context, c *connect.Request[pb.SendToAddressRequest]) (*connect.Response[pb.SendToAddressResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	if c.Msg.Address == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("address is a required argument"))
	}

	address, err := btcutil.DecodeAddress(c.Msg.Address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("address has invalid format: %w", err)
	}

	amount, err := btcutil.NewAmount(c.Msg.Amount)
	if err != nil {
		return nil, fmt.Errorf("amount has invalid format: %w", err)
	}
	if amount <= 0 {
		return nil, fmt.Errorf("amount must be greater than 0: %w", err)
	}

	return withCancel(ctx,
		func(ctx context.Context) (*chainhash.Hash, error) {
			if c.Msg.Comment != "" || c.Msg.CommentTo != "" {
				return rpc.SendToAddressComment(ctx, address, amount, c.Msg.Comment, c.Msg.CommentTo)
			}

			return rpc.SendToAddress(ctx, address, amount)
		},

		func(r *chainhash.Hash) *pb.SendToAddressResponse {
			return &pb.SendToAddressResponse{
				Txid: r.String(),
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

	return withCancel(
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
	return withCancel(
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
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}
	return withCancel(
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

	rpc, err := b.rpcForWallet(ctx, c.Msg)
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

	return withCancel(
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

// GetAddressInfo implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetAddressInfo(ctx context.Context, c *connect.Request[pb.GetAddressInfoRequest]) (*connect.Response[pb.GetAddressInfoResponse], error) {
	if c.Msg.Address == "" {
		err := errors.New("address is required")
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel[*btcjson.GetAddressInfoResult, pb.GetAddressInfoResponse](
		ctx, func(ctx context.Context) (*btcjson.GetAddressInfoResult, error) {
			return rpc.GetAddressInfo(ctx, c.Msg.Address)
		},
		func(r *btcjson.GetAddressInfoResult) *pb.GetAddressInfoResponse {
			return &pb.GetAddressInfoResponse{
				Address:        r.Address,
				ScriptPubKey:   r.ScriptPubKey,
				IsMine:         r.IsMine,
				IsWatchOnly:    r.IsWatchOnly,
				Solvable:       r.Solvable,
				IsScript:       r.IsScript,
				IsChange:       r.IsChange,
				IsWitness:      r.IsWitness,
				WitnessVersion: uint32(r.WitnessVersion),
				WitnessProgram: lo.FromPtr(r.WitnessProgram),
				ScriptType:     lo.FromPtr(r.ScriptType).String(),
				IsCompressed:   lo.FromPtr(r.IsCompressed),
			}
		},
	)
}

// GetDescriptorInfo implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetDescriptorInfo(ctx context.Context, c *connect.Request[pb.GetDescriptorInfoRequest]) (*connect.Response[pb.GetDescriptorInfoResponse], error) {
	return withCancel(
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
	return withCancel(
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

// AddMultisigAddress implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) AddMultisigAddress(ctx context.Context, c *connect.Request[pb.AddMultisigAddressRequest]) (*connect.Response[pb.AddMultisigAddressResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	// Convert string keys to btcutil.Address
	addresses := make([]btcutil.Address, len(c.Msg.Keys))
	for i, key := range c.Msg.Keys {
		addr, err := btcutil.DecodeAddress(key, &chaincfg.MainNetParams)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid address %s: %w", key, err))
		}
		addresses[i] = addr
	}

	return withCancel(ctx,
		func(ctx context.Context) (btcutil.Address, error) {
			return rpc.AddMultisigAddress(ctx, int(c.Msg.RequiredSigs), addresses, c.Msg.Label)
		},
		func(r btcutil.Address) *pb.AddMultisigAddressResponse {
			return &pb.AddMultisigAddressResponse{
				Address: r.String(),
			}
		})
}

// BackupWallet implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) BackupWallet(ctx context.Context, c *connect.Request[pb.BackupWalletRequest]) (*connect.Response[pb.BackupWalletResponse], error) {
	if c.Msg.Destination == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("destination is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.BackupWallet(ctx, c.Msg.Destination)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.BackupWalletResponse {
			return &pb.BackupWalletResponse{}
		})
}

// CreateMultisig implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) CreateMultisig(ctx context.Context, c *connect.Request[pb.CreateMultisigRequest]) (*connect.Response[pb.CreateMultisigResponse], error) {
	// Convert string keys to btcutil.Address
	addresses := make([]btcutil.Address, len(c.Msg.Keys))
	for i, key := range c.Msg.Keys {
		addr, err := btcutil.DecodeAddress(key, &chaincfg.MainNetParams)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid address %s: %w", key, err))
		}
		addresses[i] = addr
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.CreateMultiSigResult, error) {
			return b.rpc.CreateMultisig(ctx, int(c.Msg.RequiredSigs), addresses)
		},
		func(r *btcjson.CreateMultiSigResult) *pb.CreateMultisigResponse {
			return &pb.CreateMultisigResponse{
				Address:      r.Address,
				RedeemScript: r.RedeemScript,
			}
		})
}

// CreateWallet implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) CreateWallet(ctx context.Context, c *connect.Request[pb.CreateWalletRequest]) (*connect.Response[pb.CreateWalletResponse], error) {
	if c.Msg.Name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("wallet name is required"))
	}

	var opts []rpcclient.CreateWalletOpt
	if c.Msg.Blank {
		opts = append(opts, rpcclient.WithCreateWalletBlank())
	}
	if c.Msg.DisablePrivateKeys {
		opts = append(opts, rpcclient.WithCreateWalletDisablePrivateKeys())
	}
	if c.Msg.Passphrase != "" {
		opts = append(opts, rpcclient.WithCreateWalletPassphrase(c.Msg.Passphrase))
	}
	if c.Msg.AvoidReuse {
		opts = append(opts, rpcclient.WithCreateWalletAvoidReuse())
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.CreateWalletResult, error) {
			return b.rpc.CreateWallet(ctx, c.Msg.Name, opts...)
		},
		func(r *btcjson.CreateWalletResult) *pb.CreateWalletResponse {
			return &pb.CreateWalletResponse{
				Name:    r.Name,
				Warning: r.Warning,
			}
		})
}

// DumpPrivKey implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) DumpPrivKey(ctx context.Context, c *connect.Request[pb.DumpPrivKeyRequest]) (*connect.Response[pb.DumpPrivKeyResponse], error) {
	if c.Msg.Address == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("address is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (*btcutil.WIF, error) {
			address, err := btcutil.DecodeAddress(c.Msg.Address, &chaincfg.MainNetParams)
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid address %s: %w", c.Msg.Address, err))
			}
			return rpc.DumpPrivKey(ctx, address)
		},
		func(r *btcutil.WIF) *pb.DumpPrivKeyResponse {
			return &pb.DumpPrivKeyResponse{
				PrivateKey: r.String(),
			}
		})
}

// DumpWallet implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) DumpWallet(ctx context.Context, c *connect.Request[pb.DumpWalletRequest]) (*connect.Response[pb.DumpWalletResponse], error) {
	if c.Msg.Filename == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("filename is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	// For now return just the filename since that's all we know is definitely there
	return withCancel(ctx,
		func(ctx context.Context) (*btcjson.DumpWalletResult, error) {
			return rpc.DumpWallet(ctx, c.Msg.Filename)
		},
		func(r *btcjson.DumpWalletResult) *pb.DumpWalletResponse {
			return &pb.DumpWalletResponse{
				Filename: r.Filename,
			}
		})
}

// GetAccount implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetAccount(ctx context.Context, c *connect.Request[pb.GetAccountRequest]) (*connect.Response[pb.GetAccountResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetAccount is deprecated in Bitcoin Core"))
}

// GetAddressesByAccount implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) GetAddressesByAccount(ctx context.Context, c *connect.Request[pb.GetAddressesByAccountRequest]) (*connect.Response[pb.GetAddressesByAccountResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetAddressesByAccount is deprecated in Bitcoin Core"))
}

// ImportAddress implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ImportAddress(ctx context.Context, c *connect.Request[pb.ImportAddressRequest]) (*connect.Response[pb.ImportAddressResponse], error) {
	if c.Msg.Address == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("address is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	// Convert string address to btcutil.Address
	address, err := btcutil.DecodeAddress(c.Msg.Address, &chaincfg.MainNetParams)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid address %s: %w", c.Msg.Address, err))
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.ImportAddress(ctx, address.EncodeAddress())
			return struct{}{}, err
		},
		func(_ struct{}) *pb.ImportAddressResponse {
			return &pb.ImportAddressResponse{}
		})
}

// ImportPrivKey implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ImportPrivKey(ctx context.Context, c *connect.Request[pb.ImportPrivKeyRequest]) (*connect.Response[pb.ImportPrivKeyResponse], error) {
	if c.Msg.PrivateKey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("private key is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	// Convert string private key to WIF
	wif, err := btcutil.DecodeWIF(c.Msg.PrivateKey)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid private key: %w", err))
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.ImportPrivKey(ctx, wif)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.ImportPrivKeyResponse {
			return &pb.ImportPrivKeyResponse{}
		})
}

// ImportPubKey implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ImportPubKey(ctx context.Context, c *connect.Request[pb.ImportPubKeyRequest]) (*connect.Response[pb.ImportPubKeyResponse], error) {
	if c.Msg.Pubkey == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("public key is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.ImportPubKey(ctx, c.Msg.Pubkey)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.ImportPubKeyResponse {
			return &pb.ImportPubKeyResponse{}
		})
}

// ImportWallet implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ImportWallet(ctx context.Context, c *connect.Request[pb.ImportWalletRequest]) (*connect.Response[pb.ImportWalletResponse], error) {
	if c.Msg.Filename == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("filename is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.ImportWallet(ctx, c.Msg.Filename)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.ImportWalletResponse {
			return &pb.ImportWalletResponse{}
		})
}

// KeyPoolRefill implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) KeyPoolRefill(ctx context.Context, c *connect.Request[pb.KeyPoolRefillRequest]) (*connect.Response[pb.KeyPoolRefillResponse], error) {
	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.KeyPoolRefill(ctx)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.KeyPoolRefillResponse {
			return &pb.KeyPoolRefillResponse{}
		})
}

// ListAccounts implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) ListAccounts(ctx context.Context, c *connect.Request[pb.ListAccountsRequest]) (*connect.Response[pb.ListAccountsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("ListAccounts is deprecated in Bitcoin Core"))
}

// SetAccount implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) SetAccount(ctx context.Context, c *connect.Request[pb.SetAccountRequest]) (*connect.Response[pb.SetAccountResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("SetAccount is deprecated in Bitcoin Core"))
}

// UnloadWallet implements bitcoindv1alphaconnect.BitcoinServiceHandler.
func (b *Bitcoind) UnloadWallet(ctx context.Context, c *connect.Request[pb.UnloadWalletRequest]) (*connect.Response[pb.UnloadWalletResponse], error) {
	if c.Msg.WalletName == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("wallet name is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Msg)
	if err != nil {
		return nil, err
	}

	walletName := c.Msg.WalletName
	return withCancel(ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.UnloadWallet(ctx, &walletName)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.UnloadWalletResponse {
			return &pb.UnloadWalletResponse{}
		})
}

func (b *Bitcoind) Shutdown(ctx context.Context) {
	log := zerolog.Ctx(ctx)

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

	zerolog.Ctx(ctx).Info().
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
					zerolog.Ctx(ctx).Warn().Msgf("unknown btcjson error: %s", rpcErr)
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

func categoryFromString(in string) pb.GetTransactionResponse_Category {
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
