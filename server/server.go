package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1/bitcoindv1connect"
	"github.com/barebitcoin/btc-buf/rpcclient"
	"github.com/barebitcoin/btc-buf/rpcclient/btcjson"
	"github.com/barebitcoin/btc-buf/server/commands"
)

func init() {
	btcjson.MustRegisterCmd("rescanblockchain", new(commands.RescanBlockchainCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("abortrescan", new(commands.AbortRescanCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("listdescriptors", new(commands.ListDescriptorsCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("importdescriptors", new(commands.ImportDescriptorsCmd), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("bumpfee", new(commands.BumpFee), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("analyzepsbt", new(commands.AnalyzePsbt), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("combinepsbt", new(commands.CombinePsbt), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("decodepsbt", new(commands.DecodePsbt), btcjson.UFWalletOnly)
	btcjson.MustRegisterCmd("joinpsbts", new(commands.JoinPsbts), btcjson.UFWalletOnly)
}

type Bitcoind struct {
	conf    config
	rpcConf rpcclient.ConnConfig
	rpc     *rpcclient.Client
	server  *connect.Server

	// One client per wallet, created on first use. See rpcForWallet.
	walletClientsMu sync.Mutex
	walletClients   map[string]*rpcclient.Client

	// stop ends the SSH tunnel and any background startup. Called by
	// Shutdown.
	stop context.CancelFunc
	// started is closed once startup has finished. startErr is its outcome,
	// written before started is closed and read only after.
	started  chan struct{}
	startErr error
}

type config struct {
	enableTLS                     bool
	allowPrivateDescriptorsExport bool // default to the safe option, denying
	logging                       func(ctx context.Context) *slog.Logger
	withoutInitialConnectionCheck bool
	cookiePath                    string
	interceptors                  []connect.ServerInterceptor
	sshTunnel                     *SSHTunnel
	requireNoPrivateKeys          bool
	backgroundStartup             bool
	requestID                     func(ctx context.Context) string
}

func newConfig(opts []Option) config {
	conf := config{
		logging: func(context.Context) *slog.Logger { return slog.Default() },
	}

	for _, opt := range opts {
		opt(&conf)
	}
	return conf
}

type Option func(*config)

// WithTLS enables TLS for the RPC connection. Use this if the RPC server
// you're connecting to is available over HTTPS.
func WithTLS() Option {
	return func(c *config) {
		c.enableTLS = true
	}
}

func WithAllowPrivateDescriptorsExport() Option {
	return func(c *config) {
		c.allowPrivateDescriptorsExport = true
	}
}

// WithCookiePath authenticates via Core's cookie file instead of a static
// user/pass. The cookie is re-read when it changes, so callers survive a Core
// restart (which rewrites the cookie) without reconnecting. Ignored when a
// non-empty pass is also supplied.
func WithCookiePath(path string) Option {
	return func(c *config) {
		c.cookiePath = path
	}
}

// WithoutInitialConnectionCheck disables the initial connection check to
// Bitcoin Core. This allows you to succeed in starting up the server, even
// if the underlying Core node is not reachable.
func WithoutInitialConnectionCheck() Option {
	return func(c *config) {
		c.withoutInitialConnectionCheck = true
	}
}

// WithInterceptors runs the given interceptors innermost, after logging and
// error mapping, so they see the handler's errors as-is.
func WithInterceptors(interceptors ...connect.ServerInterceptor) Option {
	return func(c *config) {
		c.interceptors = append(c.interceptors, interceptors...)
	}
}

// WithRequestID tells the server how to find the ID of the request a context
// belongs to. The ID is logged, and forwarded to Bitcoin Core as the JSON-RPC
// id, so a request can be followed into Core's debug log. fn returns the
// empty string for a context without an ID.
//
// The server doesn't create IDs itself. Put them in the context before
// calling: in an HTTP middleware, in the context passed to an in-process
// client, or in an interceptor.
//
// Without this, requests have no ID, and Core gets numeric JSON-RPC ids.
func WithRequestID(fn func(ctx context.Context) string) Option {
	return func(c *config) {
		c.requestID = fn
	}
}

// WithLogging sets the logger to use. fn is called with the context passed to
// NewBitcoind, and with the context of each request. Request logs are tagged
// with the endpoint and request ID.
//
// The default is slog.Default. To log through zerolog:
//
//	WithLogging(func(ctx context.Context) *slog.Logger {
//		return slog.New(zerolog.NewSlogHandler(*zerolog.Ctx(ctx)))
//	})
func WithLogging(fn func(ctx context.Context) *slog.Logger) Option {
	return func(c *config) {
		c.logging = fn
	}
}

func NewBitcoind(
	ctx context.Context, host, user, pass string,
	opts ...Option,
) (*Bitcoind, error) {
	conf := newConfig(opts)

	// Startup and the SSH tunnel log through ctx.
	log := conf.logging(ctx)
	ctx = withLogger(ctx, log)
	log.InfoContext(ctx, "connecting to bitcoind", "host", host, "user", user)

	rpcConf := rpcclient.ConnConfig{
		User:       user,
		Pass:       pass,
		CookiePath: conf.cookiePath,
		DisableTLS: !conf.enableTLS,
		Host:       host,

		// Forward the request ID as the JSON-RPC id, so a request can be
		// correlated all the way into bitcoind's debug log
		RequestID: conf.requestID,
		Logger:    logFrom,
	}

	client, err := rpcclient.New(&rpcConf)
	if err != nil {
		return nil, fmt.Errorf("new RPC client: %w", err)
	}

	log.DebugContext(ctx, "created RPC client")

	// The SSH tunnel and a background startup outlive ctx, which may only
	// bound construction. Shutdown ends them. The logger on ctx is kept.
	lifetime, stop := context.WithCancel(context.WithoutCancel(ctx))

	server := &Bitcoind{
		conf:    conf,
		rpcConf: rpcConf,
		rpc:     client,
		stop:    stop,
		started: make(chan struct{}),
	}

	// Requests wait for startup first, then for the tunnel, and only then
	// reach the caller's interceptors and the handler.
	gates := []connect.ServerInterceptor{server.startupInterceptor()}
	var tunnel *tunnelGate
	if conf.sshTunnel != nil {
		tunnel = newTunnelGate()
		gates = append(gates, tunnel.interceptor(tunnelRepairWait))
	}
	server.conf.interceptors = append(gates, conf.interceptors...)

	// Ordering of interceptors matter! First interceptors in the list get
	// called first.
	interceptors := []connect.ServerInterceptor{
		loggingInterceptor(conf.logging, conf.requestID),
		panicInterceptor(),
		handleBtcJsonErrors(),
	}
	server.server = connect.NewServer(append(interceptors, server.conf.interceptors...)...)
	rpc.RegisterBitcoinServiceHandler(server.server, rpc.BitcoinServiceHandler(server))

	go func() {
		// Bounded on its own, so a caller without a deadline can't be held
		// forever by, say, an ssh stuck in authentication.
		startCtx, cancel := context.WithTimeout(lifetime, startupTimeout)
		defer cancel()

		err := server.startup(lifetime, startCtx, tunnel)
		switch {
		case err == nil:
		case lifetime.Err() != nil:
			log.DebugContext(lifetime, "shut down during startup", "error", err)
		default:
			log.ErrorContext(lifetime, "Bitcoin Core proxy failed to start", "error", err)
			// Nothing can use the tunnel once startup has failed.
			stop()
		}

		server.startErr = err
		close(server.started)
	}()

	if conf.backgroundStartup {
		return server, nil
	}

	if err := server.Ready(ctx); err != nil {
		stop()
		return nil, err
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

// callRPC fetches a result from Bitcoin Core, and transforms it into our
// response type. Errors are translated into Connect errors.
func callRPC[R any, M any](
	ctx context.Context,
	fetch func(ctx context.Context) (R, error), transform func(r R) *M,
) (*M, error) {
	log := logFrom(ctx)

	start := time.Now()
	log.Log(ctx, levelTrace, "rpc: starting fetch")

	fetchResult, err := fetch(ctx)
	log.Log(ctx, levelTrace, "rpc: fetch completed", "duration", time.Since(start), "error", err)
	switch {
	// If the request was cancelled, report that, rather than however the
	// fetch failed because of it.
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()

	case err != nil:
		return nil, transformError(ctx, err)
	}

	start = time.Now()
	transformed := transform(fetchResult)

	log.DebugContext(ctx, "rpc: transformed raw result", "duration", time.Since(start))

	return transformed, nil
}

// call sends method to Core with positional params, and unmarshals the result
// into T. Trailing nil params are left out, and other nils are sent as null,
// which Core reads as "use the default".
func call[T any](ctx context.Context, rpc *rpcclient.Client, method string, params ...any) (T, error) {
	var out T
	for len(params) > 0 && isNil(params[len(params)-1]) {
		params = params[:len(params)-1]
	}
	raw := make([]json.RawMessage, len(params))
	for i, param := range params {
		marshalled, err := json.Marshal(param)
		if err != nil {
			return out, fmt.Errorf("marshal %s param %d: %w", method, i, err)
		}
		raw[i] = marshalled
	}

	res, err := rpc.RawRequest(ctx, method, raw)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return out, fmt.Errorf("unmarshal %s response: %w", method, err)
	}
	return out, nil
}

// isNil reports whether v is nil, or a nil pointer, slice or map.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map:
		return rv.IsNil()
	}
	return false
}

// ErrUnreachable is the cause of CodeUnavailable when the dial to Bitcoin Core
// is refused. It only comes from a failed dial, and rpcclient sends every
// request on a fresh connection, so a request with this error never reached
// Core and is safe to retry.
var ErrUnreachable = errors.New("unable to connect to Bitcoin Core")

func transformError(ctx context.Context, err error) error {
	if err == nil {
		panic("PROGRAMMER ERROR: transformError called with nil")
	}

	if errors.Is(err, rpcclient.ErrUnauthorized) {
		return newConnectError(connect.CodePermissionDenied, errors.New("permission denied"))
	}

	if netErr, ok := errors.AsType[*net.OpError](err); ok &&
		strings.Contains(netErr.Error(), "connection refused") {

		logFrom(ctx).DebugContext(ctx, "transform error: returning connect.CodeUnavailable", "error", err)

		cErr := newConnectError(connect.CodeUnavailable, ErrUnreachable)

		if detail, detailErr := connectproto.NewErrorDetail(wrapperspb.String(err.Error())); detailErr == nil {
			cErr = cErr.WithDetail(detail)
		}

		return cErr
	}

	return err
}

// rpcForWallet returns the client for a wallet, creating it on first use and
// reusing it after that, so requests share its HTTP transport and cookie cache.
// The empty wallet gives the default client.
func (b *Bitcoind) rpcForWallet(ctx context.Context, wallet string) (*rpcclient.Client, error) {
	if wallet == "" {
		return b.rpc, nil
	}

	b.walletClientsMu.Lock()
	defer b.walletClientsMu.Unlock()

	if rpc, ok := b.walletClients[wallet]; ok {
		return rpc, nil
	}

	rpcConf := b.rpcConf // make sure to not copy the original conf
	hostWithoutWallet, _, _ := strings.Cut(rpcConf.Host, "/wallet")
	rpcConf.Host = fmt.Sprintf("%s/wallet/%s", hostWithoutWallet, wallet)

	logFrom(ctx).InfoContext(ctx, "creating wallet-specific client", "wallet", wallet, "host", rpcConf.Host)

	rpc, err := rpcclient.New(&rpcConf)
	if err != nil {
		return nil, err
	}

	if b.walletClients == nil {
		b.walletClients = make(map[string]*rpcclient.Client)
	}
	b.walletClients[wallet] = rpc

	return rpc, nil
}

// ListTransactions implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) ListTransactions(ctx context.Context, c *pb.ListTransactionsRequest) (*pb.ListTransactionsResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}
	const (
		label        = "*"
		defaultCount = 10
	)
	return callRPC(ctx,
		func(ctx context.Context) ([]btcjson.ListTransactionsResult, error) {
			return rpc.ListTransactionsCountFrom(
				ctx, label,
				cmp.Or(int(c.Count), defaultCount),
				int(c.Skip),
			)
		},
		func(r []btcjson.ListTransactionsResult) *pb.ListTransactionsResponse {
			return &pb.ListTransactionsResponse{
				Transactions: mapSlice(r, func(
					tx btcjson.ListTransactionsResult, idx int,
				) *pb.GetTransactionResponse {
					return txListEntryToProto(tx)
				}),
			}
		},
	)
}

func (b *Bitcoind) ListUnspent(ctx context.Context, c *pb.ListUnspentRequest) (*pb.ListUnspentResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) ([]btcjson.ListUnspentResult, error) {
			return call[[]btcjson.ListUnspentResult](ctx, rpc, "listunspent",
				c.MinimumConfirmations, c.MaximumConfirmations, c.Addresses, c.IncludeUnsafe)
		},
		func(r []btcjson.ListUnspentResult) *pb.ListUnspentResponse {
			return &pb.ListUnspentResponse{
				Unspent: mapSlice(r, func(
					unspent btcjson.ListUnspentResult, idx int,
				) *pb.UnspentOutput {
					return &pb.UnspentOutput{
						Txid:          unspent.TxID,
						Vout:          unspent.Vout,
						Address:       unspent.Address,
						ScriptPubKey:  unspent.ScriptPubKey,
						Spendable:     unspent.Spendable,
						Safe:          unspent.Safe,
						Amount:        unspent.Amount,
						Confirmations: uint32(unspent.Confirmations),
						RedeemScript:  unspent.RedeemScript,
					}
				}),
			}
		},
	)
}

// ListWallets implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) ListWallets(ctx context.Context, _ *emptypb.Empty) (*pb.ListWalletsResponse, error) {
	return callRPC(ctx, b.rpc.ListWallets,
		func(wallets []string) *pb.ListWalletsResponse {
			return &pb.ListWalletsResponse{Wallets: wallets}
		})
}

// ListSinceBlock implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) ListSinceBlock(ctx context.Context, c *pb.ListSinceBlockRequest) (*pb.ListSinceBlockResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	hash, err := newChainHash(c.Hash)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) (*btcjson.ListSinceBlockResult, error) {
			return rpc.ListSinceBlock(ctx, hash)
		},
		func(r *btcjson.ListSinceBlockResult) *pb.ListSinceBlockResponse {
			return &pb.ListSinceBlockResponse{
				Transactions: mapSlice(r.Transactions, func(tx btcjson.ListTransactionsResult, idx int) *pb.GetTransactionResponse {
					return txListEntryToProto(tx)
				}),
			}
		},
	)
}

func txListEntryToProto(tx btcjson.ListTransactionsResult) *pb.GetTransactionResponse {
	return &pb.GetTransactionResponse{
		Amount:            tx.Amount,
		Fee:               deref(tx.Fee),
		Confirmations:     int32(tx.Confirmations),
		BlockHash:         tx.BlockHash,
		BlockIndex:        uint32(deref(tx.BlockIndex)),
		BlockTime:         newTimestamp(tx.BlockTime),
		Txid:              tx.TxID,
		WalletConflicts:   tx.WalletConflicts,
		ReplacedByTxid:    tx.ReplacedByTXID,
		ReplacesTxid:      tx.ReplacesTXID,
		Time:              newTimestamp(tx.Time),
		TimeReceived:      newTimestamp(tx.TimeReceived),
		Bip125Replaceable: parseReplaceable(tx.BIP125Replaceable),
		// Clunk town...
		Details: []*pb.GetTransactionResponse_Details{{
			Address:           tx.Address,
			InvolvesWatchOnly: tx.InvolvesWatchOnly,
			Category:          categoryFromString(tx.Category),
			Amount:            tx.Amount,
			Vout:              tx.Vout,
			Fee:               deref(tx.Fee),
		}},
	}
}

// BumpFee implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) BumpFee(ctx context.Context, c *pb.BumpFeeRequest) (*pb.BumpFeeResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	type rawBumpFeeResponse struct {
		TXID    string      `json:"txid"`
		Origfee json.Number // old fee
		Fee     json.Number // new fee
		Errors  []string    // May be empty
	}
	return callRPC(ctx,
		func(ctx context.Context) (rawBumpFeeResponse, error) {
			cmd, err := btcjson.NewCmd("bumpfee", c.Txid)
			if err != nil {
				return rawBumpFeeResponse{}, err
			}

			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, cmd))
			if err != nil {
				return rawBumpFeeResponse{}, fmt.Errorf("send bumpfee: %w", err)
			}
			logFrom(ctx).DebugContext(ctx, "bumpfee response", "response", string(res))

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
func (b *Bitcoind) GetNewAddress(ctx context.Context, req *pb.GetNewAddressRequest) (*pb.GetNewAddressResponse, error) {
	rpc, err := b.rpcForWallet(ctx, req.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) (address.Address, error) {
			if req.AddressType != "" {
				return rpc.GetNewAddressType(ctx, req.Label, req.AddressType)
			}

			return rpc.GetNewAddress(ctx, req.Label)
		},
		func(r address.Address) *pb.GetNewAddressResponse {
			return &pb.GetNewAddressResponse{Address: r.EncodeAddress()}
		})
}

// GetBlockchainInfo implements bitcoindv22.BitcoinServer
func (b *Bitcoind) GetBlockchainInfo(
	ctx context.Context, req *pb.GetBlockchainInfoRequest,
) (*pb.GetBlockchainInfoResponse, error) {
	return callRPC(ctx, b.rpc.GetBlockChainInfo,
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
	ctx context.Context, req *pb.GetPeerInfoRequest,
) (*pb.GetPeerInfoResponse, error) {
	return callRPC(ctx, b.rpc.GetPeerInfo,
		func(info []btcjson.GetPeerInfoResult) *pb.GetPeerInfoResponse {
			return &pb.GetPeerInfoResponse{
				Peers: mapSlice(info, func(peer btcjson.GetPeerInfoResult, idx int) *pb.Peer {
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
						ConnectedAt:         newTimestamp(peer.ConnTime),
						LastSendAt:          newTimestamp(peer.LastSend),
						LastRecvAt:          newTimestamp(peer.LastRecv),
						Version:             peer.Version,
						Subver:              peer.SubVer,
						Inbound:             peer.Inbound,
						StartingHeight:      peer.StartingHeight,
						TimeOffset:          durationpb.New(time.Duration(peer.TimeOffset) * time.Second),
						Services:            peer.Services,
						ServicesNames:       []string{}, // Not in the RPC client
						RelayTransactions:   peer.RelayTxes,
						PingTime:            secondsDuration(peer.PingTime),
						MinPing:             secondsDuration(peer.MinPing),
						PingWait:            secondsDuration(peer.PingWait),
					}

					return p
				}),
			}
		})
}

// GetNetworkInfo implements bitcoindv1connect.BitcoinServiceHandler
func (b *Bitcoind) GetNetworkInfo(
	ctx context.Context, req *pb.GetNetworkInfoRequest,
) (*pb.GetNetworkInfoResponse, error) {
	return callRPC(ctx, b.rpc.GetNetworkInfo,
		func(info *btcjson.GetNetworkInfoResult) *pb.GetNetworkInfoResponse {
			// Convert warnings - handle both single string and array formats
			warnings := []string{}
			for _, w := range info.Warnings {
				warnings = append(warnings, w)
			}

			return &pb.GetNetworkInfoResponse{
				Version:            info.Version,
				Subversion:         info.SubVersion,
				ProtocolVersion:    info.ProtocolVersion,
				LocalServices:      info.LocalServices,
				LocalServicesNames: []string{}, // Not in the RPC client result struct
				LocalRelay:         info.LocalRelay,
				TimeOffset:         info.TimeOffset,
				Connections:        info.Connections,
				ConnectionsIn:      info.ConnectionsIn,
				ConnectionsOut:     info.ConnectionsOut,
				NetworkActive:      info.NetworkActive,
				Networks: mapSlice(info.Networks, func(n btcjson.NetworksResult, _ int) *pb.GetNetworkInfoResponse_Network {
					return &pb.GetNetworkInfoResponse_Network{
						Name:                      n.Name,
						Limited:                   n.Limited,
						Reachable:                 n.Reachable,
						Proxy:                     n.Proxy,
						ProxyRandomizeCredentials: n.ProxyRandomizeCredentials,
					}
				}),
				RelayFee:       info.RelayFee,
				IncrementalFee: info.IncrementalFee,
				LocalAddresses: mapSlice(info.LocalAddresses, func(a btcjson.LocalAddressesResult, _ int) *pb.GetNetworkInfoResponse_LocalAddress {
					return &pb.GetNetworkInfoResponse_LocalAddress{
						Address: a.Address,
						Port:    uint32(a.Port),
						Score:   a.Score,
					}
				}),
				Warnings: warnings,
			}
		})
}

// GetNetTotals implements bitcoindv1connect.BitcoinServiceHandler
func (b *Bitcoind) GetNetTotals(
	ctx context.Context, req *pb.GetNetTotalsRequest,
) (*pb.GetNetTotalsResponse, error) {
	return callRPC(ctx, b.rpc.GetNetTotals,
		func(totals *btcjson.GetNetTotalsResult) *pb.GetNetTotalsResponse {
			return &pb.GetNetTotalsResponse{
				TotalBytesRecv: totals.TotalBytesRecv,
				TotalBytesSent: totals.TotalBytesSent,
				TimeMillis:     totals.TimeMillis,
			}
		})
}

// GetWalletInfo implements bitcoindv1connect.BitcoinServiceHandler
func (b *Bitcoind) GetWalletInfo(
	ctx context.Context, req *pb.GetWalletInfoRequest,
) (*pb.GetWalletInfoResponse, error) {
	rpc, err := b.rpcForWallet(ctx, req.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		rpc.GetWalletInfo,
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
				KeyPoolSizeHdInternal: int64(deref(info.KeyPoolSizeHDInternal)),
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

// GetBlockHash implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetBlockHash(ctx context.Context, c *pb.GetBlockHashRequest) (*pb.GetBlockHashResponse, error) {
	return callRPC(ctx,
		func(ctx context.Context) (*chainhash.Hash, error) {
			return b.rpc.GetBlockHash(ctx, int64(c.Height))
		},
		func(hash *chainhash.Hash) *pb.GetBlockHashResponse {
			return &pb.GetBlockHashResponse{Hash: hash.String()}
		},
	)
}

// GetBlock implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetBlock(ctx context.Context, c *pb.GetBlockRequest) (*pb.GetBlockResponse, error) {
	if (c.Hash == "" && c.Height == nil) || (c.Hash != "" && c.Height != nil) {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New(`must set one of "hash" or "height"`))
	}

	hash, err := newChainHash(c.Hash)
	if err != nil {
		return nil, fmt.Errorf("new chain hash: %w", err)
	}

	if c.Height != nil {
		res, err := callRPC(ctx,
			func(ctx context.Context) (*chainhash.Hash, error) {
				return b.rpc.GetBlockHash(ctx, int64(*c.Height))
			},
			func(hash *chainhash.Hash) *chainhash.Hash { return hash })
		if err != nil {
			return nil, fmt.Errorf("get block hash from height: %w", err)
		}
		hash = res
	}

	// Bitcoin Core default
	if c.Verbosity == pb.GetBlockRequest_VERBOSITY_UNSPECIFIED {
		c.Verbosity = pb.GetBlockRequest_VERBOSITY_BLOCK_INFO
	}

	// The Bitcoin Core `getblock` results has different types for the same fields
	// depending on the verbosity level. Classic horrible API design.
	type getBlockResult struct {
		Hash         string
		PreviousHash *string `json:"previousblockhash,omitempty"`
		NextHash     *string `json:"nextblockhash,omitempty"`

		Confirmations int32
		Height        uint32
		Version       int32
		VersionHex    string
		Bits          string
		MerkleRoot    string
		Time          int64
		MedianTime    int64
		Nonce         uint32
		Difficulty    float64
		Target        string
		Chainwork     string
		StrippedSize  int32 `json:"strippedsize"`
		Size          int32
		Weight        int32

		// Only set for verbosity level 1
		Txids        []string              `json:"-"`
		Transactions []btcjson.TxRawResult `json:"-"`
	}
	switch c.Verbosity {
	case pb.GetBlockRequest_VERBOSITY_RAW_DATA:
		return callRPC(ctx,
			func(ctx context.Context) (string, error) {
				return call[string](ctx, b.rpc, "getblock", hash.String(), 0)
			},
			func(blockHex string) *pb.GetBlockResponse {
				return &pb.GetBlockResponse{Hex: blockHex}
			},
		)

	case pb.GetBlockRequest_VERBOSITY_BLOCK_INFO,
		pb.GetBlockRequest_VERBOSITY_BLOCK_TX_INFO,
		pb.GetBlockRequest_VERBOSITY_BLOCK_TX_PREVOUT_INFO:
		return callRPC(ctx,
			func(ctx context.Context) (getBlockResult, error) {
				coreVerbosities := map[pb.GetBlockRequest_Verbosity]int{
					pb.GetBlockRequest_VERBOSITY_BLOCK_INFO:            1,
					pb.GetBlockRequest_VERBOSITY_BLOCK_TX_INFO:         2,
					pb.GetBlockRequest_VERBOSITY_BLOCK_TX_PREVOUT_INFO: 3,
				}
				res, err := call[json.RawMessage](ctx, b.rpc, "getblock", hash.String(), coreVerbosities[c.Verbosity])
				if err != nil {
					return getBlockResult{}, err
				}

				var blockResult getBlockResult
				if err := json.Unmarshal(res, &blockResult); err != nil {
					return getBlockResult{}, err
				}

				// The shape of "tx" depends on the verbosity.
				var rawTx struct {
					Tx json.RawMessage `json:"tx"`
				}
				if err := json.Unmarshal(res, &rawTx); err != nil {
					return getBlockResult{}, err
				}

				switch c.Verbosity {
				case pb.GetBlockRequest_VERBOSITY_BLOCK_INFO:
					if err := json.Unmarshal(rawTx.Tx, &blockResult.Txids); err != nil {
						return getBlockResult{}, fmt.Errorf("unmarshal txids: %w", err)
					}
				case pb.GetBlockRequest_VERBOSITY_BLOCK_TX_INFO,
					pb.GetBlockRequest_VERBOSITY_BLOCK_TX_PREVOUT_INFO:

					if err := json.Unmarshal(rawTx.Tx, &blockResult.Transactions); err != nil {
						return getBlockResult{}, fmt.Errorf("unmarshal transactions: %w", err)
					}
				}

				return blockResult, nil
			},
			func(block getBlockResult) *pb.GetBlockResponse {
				return &pb.GetBlockResponse{
					Hash:              block.Hash,
					Confirmations:     block.Confirmations,
					Height:            block.Height,
					Version:           block.Version,
					VersionHex:        block.VersionHex,
					MerkleRoot:        block.MerkleRoot,
					Time:              newTimestamp(block.Time),
					MedianTime:        newTimestamp(block.MedianTime),
					Nonce:             block.Nonce,
					PreviousBlockHash: deref(block.PreviousHash),
					NextBlockHash:     deref(block.NextHash),
					Bits:              block.Bits,
					Target:            block.Target,
					StrippedSize:      block.StrippedSize,
					Size:              block.Size,
					Weight:            block.Weight,
					Difficulty:        block.Difficulty,
					Chainwork:         block.Chainwork,
					Txids:             block.Txids,
					Transactions:      mapSlice(block.Transactions, blockTransactionProto),
				}
			},
		)

	default:
		return nil, newConnectError(connect.CodeInvalidArgument, fmt.Errorf("invalid verbosity: %q", c.Verbosity))
	}
}

// GetRawTransaction implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetRawTransaction(ctx context.Context, c *pb.GetRawTransactionRequest) (*pb.GetRawTransactionResponse, error) {
	if c.Txid == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := newChainHash(c.Txid)
	if err != nil {
		return nil, err
	}
	blockHash, err := newChainHash(c.Blockhash)
	if err != nil {
		return nil, err
	}
	var blockHashParam any
	if blockHash != nil {
		blockHashParam = blockHash.String()
	}

	if c.Verbosity == pb.GetRawTransactionRequest_VERBOSITY_UNSPECIFIED ||
		c.Verbosity == pb.GetRawTransactionRequest_VERBOSITY_RAW_DATA {
		return callRPC(ctx,
			func(ctx context.Context) (string, error) {
				return call[string](ctx, b.rpc, "getrawtransaction", hash.String(), 0, blockHashParam)
			},
			func(txHex string) *pb.GetRawTransactionResponse {
				decoded, _ := hex.DecodeString(txHex)
				return &pb.GetRawTransactionResponse{
					Tx: rawTransaction(decoded),
				}
			},
		)
	}

	coreVerbosities := map[pb.GetRawTransactionRequest_Verbosity]int{
		pb.GetRawTransactionRequest_VERBOSITY_TX_INFO:         1,
		pb.GetRawTransactionRequest_VERBOSITY_TX_PREVOUT_INFO: 2,
	}
	rpcVerbosity, ok := coreVerbosities[c.Verbosity]
	if !ok {
		return nil, newConnectError(connect.CodeInvalidArgument, fmt.Errorf("invalid verbosity: %q", c.Verbosity))
	}

	return callRPC(ctx,
		func(ctx context.Context) (btcjson.TxRawResult, error) {
			return call[btcjson.TxRawResult](ctx, b.rpc, "getrawtransaction", hash.String(), rpcVerbosity, blockHashParam)
		},
		func(tx btcjson.TxRawResult) *pb.GetRawTransactionResponse {
			decoded, _ := hex.DecodeString(tx.Hex)
			return &pb.GetRawTransactionResponse{
				Tx:            rawTransaction(decoded),
				Blockhash:     tx.BlockHash,
				Confirmations: uint32(tx.Confirmations),
				BlockTime:     newTimestamp(tx.Blocktime),
				Inputs:        mapSlice(tx.Vin, inputProto),
				Outputs:       mapSlice(tx.Vout, outputProto),
				Fee:           tx.Fee,
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

func blockTransactionProto(tx btcjson.TxRawResult, _ int) *pb.GetBlockResponse_Transaction {
	return &pb.GetBlockResponse_Transaction{
		Txid:     tx.Txid,
		Hash:     tx.Hash,
		Size:     tx.Size,
		Vsize:    tx.Vsize,
		Weight:   tx.Weight,
		Version:  tx.Version,
		Locktime: tx.LockTime,
		Inputs:   mapSlice(tx.Vin, inputProto),
		Outputs:  mapSlice(tx.Vout, outputProto),
		Fee:      tx.Fee,
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

	var previousOutput *pb.PreviousOutput
	if input.Prevout != nil {
		previousOutput = &pb.PreviousOutput{
			Generated: input.Prevout.Generated,
			Height:    input.Prevout.Height,
			Amount:    input.Prevout.Value,
		}

		if input.Prevout.ScriptPubKey != nil {
			previousOutput.ScriptPubKey = &pb.ScriptPubKey{
				Type:    input.Prevout.ScriptPubKey.Type,
				Address: input.Prevout.ScriptPubKey.Address,
				Asm:     input.Prevout.ScriptPubKey.Asm,
				Hex:     input.Prevout.ScriptPubKey.Hex,
			}
		}
	}

	return &pb.Input{
		Txid:           input.Txid,
		Vout:           input.Vout,
		Coinbase:       input.Coinbase,
		ScriptSig:      scriptSig,
		Sequence:       input.Sequence,
		Witness:        input.Witness,
		PreviousOutput: previousOutput,
	}
}

func outputProto(output btcjson.Vout, _ int) *pb.Output {
	return &pb.Output{
		Amount: output.Value,
		Vout:   output.N,
		ScriptPubKey: &pb.ScriptPubKey{
			Type:    output.ScriptPubKey.Type,
			Address: output.ScriptPubKey.Address,
			Asm:     output.ScriptPubKey.Asm,
			Hex:     output.ScriptPubKey.Hex,
		},
	}
}

// GetTransaction implements bitcoindv1connect.BitcoinServiceHandler
func (b *Bitcoind) GetTransaction(ctx context.Context, c *pb.GetTransactionRequest) (*pb.GetTransactionResponse, error) {
	if c.Txid == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New(`"txid" is a required argument`))
	}

	hash, err := newChainHash(c.Txid)
	if err != nil {
		return nil, err
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	type getTransactionResult struct {
		btcjson.GetTransactionResult
		// Only set if verbose.
		Decoded *btcjson.TxRawResult `json:"decoded"`
	}
	return callRPC(ctx,
		func(ctx context.Context) (getTransactionResult, error) {
			// Leave include_watchonly to Core's default.
			return call[getTransactionResult](ctx, rpc, "gettransaction", hash.String(), nil, nonZeroPtr(c.Verbose))
		},

		func(res getTransactionResult) *pb.GetTransactionResponse {
			var decoded *pb.DecodeRawTransactionResponse
			if res.Decoded != nil {
				decoded = decodedTransactionProto(*res.Decoded)
			}

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

			return &pb.GetTransactionResponse{
				Hex:               res.Hex,
				Amount:            res.Amount,
				Fee:               res.Fee,
				Confirmations:     int32(res.Confirmations),
				BlockHash:         res.BlockHash,
				BlockIndex:        uint32(res.BlockIndex),
				BlockTime:         newTimestamp(res.BlockTime),
				Txid:              res.TxID,
				ReplacedByTxid:    res.ReplacedByTXID,
				ReplacesTxid:      res.ReplacesTXID,
				WalletConflicts:   res.WalletConflicts,
				Time:              newTimestamp(res.Time),
				TimeReceived:      newTimestamp(res.TimeReceived),
				Details:           details,
				Bip125Replaceable: parseReplaceable(res.BIP125Replaceable),
				Decoded:           decoded,
			}
		},
	)
}

// Send implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) Send(ctx context.Context, c *pb.SendRequest) (*pb.SendResponse, error) {
	if len(c.Destinations) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("'destinations' is a required argument"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) (*btcjson.SendResult, error) {
			var outputs []btcjson.SendDestination
			for addr, amount := range c.Destinations {
				btcAmount, err := btcutil.NewAmount(amount)
				if err != nil || btcAmount <= 0 {
					return nil, newConnectError(connect.CodeInvalidArgument,
						fmt.Errorf("invalid amount for %q: %v", addr, amount))
				}

				outputs = append(outputs, btcjson.SendDestination{
					Address: addr,
					Amount:  btcAmount,
				})
			}

			var opts []rpcclient.WalletSendOpt
			if c.ConfTarget != 0 {
				opts = append(opts, rpcclient.WithWalletSendConfirmationTarget(
					int(c.ConfTarget),
				))

				// conf target implies need for estimation mode
				// TODO: do this properly
				opts = append(opts, func(sc *btcjson.SendCmd) {
					sc.EstimateMode = new(btcjson.EstimateModeEconomical)
				})
			}

			if c.IncludeUnsafe {
				opts = append(opts, rpcclient.WithWalletSendIncludeUnsafe())
			}

			var subOutputs []int
			for _, addr := range c.SubtractFeeFromOutputs {
				idx := slices.IndexFunc(outputs, func(item btcjson.SendDestination) bool {
					return item.Address == addr
				})

				if idx == -1 {
					err := fmt.Errorf("unable to find output index for %q", addr)
					return nil, newConnectError(connect.CodeInvalidArgument, err)
				}

				subOutputs = append(subOutputs, idx)
			}

			if len(subOutputs) != 0 {
				opts = append(opts,
					rpcclient.WithWalletSendSubtractFeeFromOutputs(subOutputs),
				)
			}

			if c.AddToWallet != nil {
				opts = append(opts,
					rpcclient.WithWalletSendAddToWallet(c.AddToWallet.Value),
				)
			}

			if c.FeeRate != 0 {
				opts = append(opts,
					rpcclient.WithWalletSendFeeRate(c.FeeRate),
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

// SendToAddress implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) SendToAddress(ctx context.Context, c *pb.SendToAddressRequest) (*pb.SendToAddressResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	if c.Address == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("address is a required argument"))
	}

	amount, err := btcutil.NewAmount(c.Amount)
	if err != nil || amount <= 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("amount must be a positive number of BTC"))
	}

	return callRPC(ctx,
		func(ctx context.Context) (string, error) {
			// Core validates the address, against the network it runs on.
			return call[string](ctx, rpc, "sendtoaddress",
				c.Address, amount.ToBTC(), nonZeroPtr(c.Comment), nonZeroPtr(c.CommentTo))
		},

		func(txid string) *pb.SendToAddressResponse {
			return &pb.SendToAddressResponse{Txid: txid}
		},
	)
}

// DecodeRawTransaction implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) DecodeRawTransaction(ctx context.Context, c *pb.DecodeRawTransactionRequest) (*pb.DecodeRawTransactionResponse, error) {
	data, err := getRawTransactionBytes(c.Tx)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (*btcjson.TxRawResult, error) {
			return b.rpc.DecodeRawTransaction(ctx, data)
		},

		func(r *btcjson.TxRawResult) *pb.DecodeRawTransactionResponse {
			return decodedTransactionProto(*r)
		},
	)
}

func decodedTransactionProto(r btcjson.TxRawResult) *pb.DecodeRawTransactionResponse {
	return &pb.DecodeRawTransactionResponse{
		Txid:        r.Txid,
		Hash:        r.Hash,
		Size:        uint32(r.Size),
		VirtualSize: uint32(r.Vsize),
		Weight:      uint32(r.Weight),
		Version:     r.Version,
		Locktime:    r.LockTime,
		Inputs:      mapSlice(r.Vin, inputProto),
		Outputs:     mapSlice(r.Vout, outputProto),
	}
}

// EstimateSmartFee implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) EstimateSmartFee(ctx context.Context, c *pb.EstimateSmartFeeRequest) (*pb.EstimateSmartFeeResponse, error) {
	return callRPC(
		ctx,
		func(ctx context.Context) (*btcjson.EstimateSmartFeeResult, error) {
			var estimateMode *btcjson.EstimateSmartFeeMode
			if c.EstimateMode != pb.EstimateSmartFeeRequest_ESTIMATE_MODE_UNSPECIFIED {
				switch c.EstimateMode {
				case pb.EstimateSmartFeeRequest_ESTIMATE_MODE_ECONOMICAL:
					estimateMode = &btcjson.EstimateModeEconomical
				case pb.EstimateSmartFeeRequest_ESTIMATE_MODE_CONSERVATIVE:
					estimateMode = &btcjson.EstimateModeConservative
				default:
					return nil, fmt.Errorf("unexpected estimate mode: %s", c.EstimateMode)
				}
			}
			return b.rpc.EstimateSmartFee(ctx, c.ConfTarget, estimateMode)
		},

		func(r *btcjson.EstimateSmartFeeResult) *pb.EstimateSmartFeeResponse {
			return &pb.EstimateSmartFeeResponse{
				Errors:  r.Errors,
				Blocks:  r.Blocks,
				FeeRate: deref(r.FeeRate),
			}
		},
	)
}

// GetBalances implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetBalances(ctx context.Context, c *pb.GetBalancesRequest) (*pb.GetBalancesResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}
	return callRPC(
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

func (b *Bitcoind) ListDescriptors(ctx context.Context, c *pb.ListDescriptorsRequest) (*pb.ListDescriptorsResponse, error) {
	if c.IncludePrivateDescriptors && !b.conf.allowPrivateDescriptorsExport {
		return nil, newConnectError(connect.CodePermissionDenied, errors.New("private descriptor export is not allowed"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx, func(ctx context.Context) (commands.ListDescriptorsResponse, error) {
			cmd := commands.ListDescriptorsCmd{
				Private: c.IncludePrivateDescriptors,
			}
			// Make sure to NOT log the contents here. May include private keys!
			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, &cmd))
			if err != nil {
				return commands.ListDescriptorsResponse{}, err
			}

			var parsed commands.ListDescriptorsResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return commands.ListDescriptorsResponse{}, fmt.Errorf("unmarshal listdescriptors response: %w", err)
			}

			return parsed, err
		},
		func(r commands.ListDescriptorsResponse) *pb.ListDescriptorsResponse {
			return &pb.ListDescriptorsResponse{
				Descriptors: mapSlice(r.Descriptors, func(r commands.ListDescriptorsResponseDescriptor, idx int) *pb.ListDescriptorsResponse_Descriptor {
					// Only set for ranged descriptors.
					var descriptorRange *pb.DescriptorRange
					if len(r.Range) == 2 {
						descriptorRange = &pb.DescriptorRange{
							Begin: uint32(r.Range[0]),
							End:   uint32(r.Range[1]),
						}
					}
					return &pb.ListDescriptorsResponse_Descriptor{
						Descriptor_: r.Descriptor,
						Timestamp:   timestamppb.New(time.Unix(r.Timestamp, 0)),
						Active:      r.Active,
						Internal:    r.Internal,
						Range:       descriptorRange,
						NextIndex:   uint32(r.NextIndex),
					}
				}),
			}
		})
}

// ImportDescriptors implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) ImportDescriptors(ctx context.Context, c *pb.ImportDescriptorsRequest) (*pb.ImportDescriptorsResponse, error) {
	if len(c.GetRequests()) == 0 {
		err := errors.New("must provide at least one request")
		return nil, newConnectError(connect.CodeInvalidArgument, err)
	}

	for _, req := range c.Requests {
		if req.Descriptor_ == "" {
			err := errors.New("descriptors must be non-empty")
			return nil, newConnectError(connect.CodeInvalidArgument, err)
		}
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	type jsonRpcError struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	type parsedDescriptorResponse struct {
		Success  bool          `json:"success"`
		Warnings []string      `json:"warnings"`
		Error    *jsonRpcError `json:"error"`
	}

	return callRPC(
		ctx, func(ctx context.Context) ([]parsedDescriptorResponse, error) {
			cmd := commands.ImportDescriptorsCmd{
				Requests: mapSlice(c.Requests, func(req *pb.ImportDescriptorsRequest_Request, idx int) commands.ImportDescriptorsRequestItem {
					importReq := commands.ImportDescriptorsRequestItem{
						Descriptor: &req.Descriptor_,
					}

					// Set timestamp
					if req.Timestamp == nil {
						importReq.Timestamp = "now"
					} else {
						importReq.Timestamp = req.Timestamp.AsTime().Unix()
					}

					if req.Range != nil {
						importReq.Range = []uint32{req.Range.Begin, req.Range.End}
					}

					if req.NextIndex != 0 {
						nextIndex := int(req.NextIndex)
						importReq.NextIndex = &nextIndex
					}

					// Add internal flag
					if req.Internal {
						internal := req.Internal
						importReq.Internal = &internal
					}

					// Add label if provided
					if req.Label != "" {
						label := req.Label
						importReq.Label = &label
					}

					if req.Active {
						active := req.Active
						importReq.Active = &active
					}

					return importReq
				}),
			}
			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, &cmd))
			if err != nil {
				return nil, err
			}
			logFrom(ctx).DebugContext(ctx, "importdescriptors response", "response", string(res))

			var parsed []parsedDescriptorResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return nil, fmt.Errorf("unmarshal importdescriptors response: %w", err)
			}

			return parsed, nil
		},
		func(r []parsedDescriptorResponse) *pb.ImportDescriptorsResponse {
			return &pb.ImportDescriptorsResponse{
				Responses: mapSlice(r, func(r parsedDescriptorResponse, idx int) *pb.ImportDescriptorsResponse_Response {
					var importErr *pb.ImportDescriptorsResponse_Error
					if r.Error != nil {
						importErr = &pb.ImportDescriptorsResponse_Error{
							Code:    int32(r.Error.Code),
							Message: r.Error.Message,
						}
					}
					return &pb.ImportDescriptorsResponse_Response{
						Success:  r.Success,
						Warnings: r.Warnings,
						Error:    importErr,
					}
				}),
			}
		})
}

// GetAddressInfo implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetAddressInfo(ctx context.Context, c *pb.GetAddressInfoRequest) (*pb.GetAddressInfoResponse, error) {
	if c.Address == "" {
		err := errors.New("address is required")
		return nil, newConnectError(connect.CodeInvalidArgument, err)
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx, func(ctx context.Context) (*btcjson.GetAddressInfoResult, error) {
			return rpc.GetAddressInfo(ctx, c.Address)
		},
		func(r *btcjson.GetAddressInfoResult) *pb.GetAddressInfoResponse {
			return &pb.GetAddressInfoResponse{
				Address:        r.Address,
				ScriptPubKey:   r.ScriptPubKey,
				IsMine:         r.IsMine,
				Solvable:       r.Solvable,
				IsScript:       r.IsScript,
				IsChange:       r.IsChange,
				IsWitness:      r.IsWitness,
				WitnessVersion: uint32(r.WitnessVersion),
				WitnessProgram: deref(r.WitnessProgram),
				ScriptType:     deref(r.ScriptType),
				IsCompressed:   deref(r.IsCompressed),
			}
		},
	)
}

// GetDescriptorInfo implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetDescriptorInfo(ctx context.Context, c *pb.GetDescriptorInfoRequest) (*pb.GetDescriptorInfoResponse, error) {
	return callRPC(
		ctx, func(ctx context.Context) (*btcjson.GetDescriptorInfoResult, error) {
			return b.rpc.GetDescriptorInfo(ctx, c.Descriptor_)
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

// GetRawMempool implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) GetRawMempool(ctx context.Context, c *pb.GetRawMempoolRequest) (*pb.GetRawMempoolResponse, error) {
	type maybeVerbose struct {
		txids        []*chainhash.Hash
		transactions map[string]btcjson.GetMempoolEntryResult
	}
	return callRPC(
		ctx, func(ctx context.Context) (maybeVerbose, error) {
			if !c.Verbose {
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
				Transactions: mapValues(res.transactions,
					func(value btcjson.GetMempoolEntryResult, key string) *pb.MempoolEntry {
						return &pb.MempoolEntry{
							VirtualSize:     uint32(value.VSize),
							Weight:          uint32(value.Weight),
							Time:            newTimestamp(value.Time),
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
				Txids: mapSlice(res.txids,
					func(txid *chainhash.Hash, idx int) string {
						return txid.String()
					}),
			}
		},
	)
}

// BackupWallet implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) BackupWallet(ctx context.Context, c *pb.BackupWalletRequest) (*pb.BackupWalletResponse, error) {
	if c.Destination == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("destination is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (struct{}, error) {
			err := rpc.BackupWallet(ctx, c.Destination)
			return struct{}{}, err
		},
		func(_ struct{}) *pb.BackupWalletResponse {
			return &pb.BackupWalletResponse{}
		})
}

// CreateMultisig implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) CreateMultisig(ctx context.Context, c *pb.CreateMultisigRequest) (*pb.CreateMultisigResponse, error) {
	// Bitcoin Core only accepts hex-encoded public keys: compressed (33
	// bytes) or uncompressed (65 bytes).
	for _, key := range c.Keys {
		decoded, err := hex.DecodeString(key)
		if err != nil || (len(decoded) != 33 && len(decoded) != 65) {
			return nil, newConnectError(connect.CodeInvalidArgument,
				fmt.Errorf("invalid public key %q: must be hex-encoded, 33 or 65 bytes", key))
		}
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (*btcjson.CreateMultiSigResult, error) {
			return b.rpc.CreateMultisig(ctx, int(c.RequiredSigs), c.Keys)
		},
		func(r *btcjson.CreateMultiSigResult) *pb.CreateMultisigResponse {
			return &pb.CreateMultisigResponse{
				Address:      r.Address,
				RedeemScript: r.RedeemScript,
			}
		})
}

// AnalyzePsbt implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) AnalyzePsbt(ctx context.Context, c *pb.AnalyzePsbtRequest) (*pb.AnalyzePsbtResponse, error) {
	if c.Psbt == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("psbt is required"))
	}

	type rawAnalyzePsbtResponse struct {
		Inputs []struct {
			HasUtxo bool `json:"has_utxo"`
			IsFinal bool `json:"is_final"`
			Missing struct {
				Pubkeys       []string `json:"pubkeys,omitempty"`
				Signatures    []string `json:"signatures,omitempty"`
				RedeemScript  string   `json:"redeemscript,omitempty"`
				WitnessScript string   `json:"witnessscript,omitempty"`
			} `json:"missing,omitempty"`
			Next string `json:"next,omitempty"`
		} `json:"inputs"`
		EstimatedVsize   *float64 `json:"estimated_vsize,omitempty"`
		EstimatedFeerate *float64 `json:"estimated_feerate,omitempty"`
		Fee              *float64 `json:"fee,omitempty"`
		Next             string   `json:"next"`
		Error            string   `json:"error,omitempty"`
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (rawAnalyzePsbtResponse, error) {
			cmd, err := btcjson.NewCmd("analyzepsbt", c.Psbt)
			if err != nil {
				return rawAnalyzePsbtResponse{}, err
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return rawAnalyzePsbtResponse{}, fmt.Errorf("send analyzepsbt: %w", err)
			}
			logFrom(ctx).DebugContext(ctx, "analyzepsbt response", "response", string(res))

			var parsed rawAnalyzePsbtResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return rawAnalyzePsbtResponse{}, fmt.Errorf("unmarshal analyzepsbt response: %w", err)
			}

			return parsed, nil
		},
		func(r rawAnalyzePsbtResponse) *pb.AnalyzePsbtResponse {
			inputs := make([]*pb.AnalyzePsbtResponse_Input, len(r.Inputs))
			for i, input := range r.Inputs {
				inputs[i] = &pb.AnalyzePsbtResponse_Input{
					HasUtxo: input.HasUtxo,
					IsFinal: input.IsFinal,
					Missing: &pb.AnalyzePsbtResponse_Input_Missing{
						Pubkeys:       input.Missing.Pubkeys,
						Signatures:    input.Missing.Signatures,
						RedeemScript:  input.Missing.RedeemScript,
						WitnessScript: input.Missing.WitnessScript,
					},
					Next: input.Next,
				}
			}

			return &pb.AnalyzePsbtResponse{
				Inputs:           inputs,
				EstimatedVsize:   deref(r.EstimatedVsize),
				EstimatedFeerate: deref(r.EstimatedFeerate),
				Fee:              deref(r.Fee),
				Next:             r.Next,
				Error:            r.Error,
			}
		})
}

// CombinePsbt implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) CombinePsbt(ctx context.Context, c *pb.CombinePsbtRequest) (*pb.CombinePsbtResponse, error) {
	if len(c.Psbts) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("at least one PSBT is required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			cmd, err := btcjson.NewCmd("combinepsbt", c.Psbts)
			if err != nil {
				return "", err
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return "", fmt.Errorf("send combinepsbt: %w", err)
			}
			logFrom(ctx).DebugContext(ctx, "combinepsbt response", "response", string(res))

			var psbt string
			if err := json.Unmarshal(res, &psbt); err != nil {
				return "", fmt.Errorf("unmarshal combinepsbt response: %w", err)
			}

			return psbt, nil
		},
		func(r string) *pb.CombinePsbtResponse {
			return &pb.CombinePsbtResponse{
				Psbt: r,
			}
		})
}

// CreatePsbt implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) CreatePsbt(ctx context.Context, c *pb.CreatePsbtRequest) (*pb.CreatePsbtResponse, error) {
	if len(c.Inputs) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("inputs are required"))
	}
	if len(c.Outputs) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("outputs are required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			return call[string](ctx, b.rpc, "createpsbt",
				transactionInputs(c.Inputs), c.Outputs, c.Locktime, c.Replaceable)
		},
		func(r string) *pb.CreatePsbtResponse {
			return &pb.CreatePsbtResponse{
				Psbt: r,
			}
		})
}

// CreateRawTransaction implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) CreateRawTransaction(ctx context.Context, c *pb.CreateRawTransactionRequest) (*pb.CreateRawTransactionResponse, error) {
	if len(c.Inputs) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("inputs are required"))
	}
	if len(c.Outputs) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("outputs are required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			return call[string](ctx, b.rpc, "createrawtransaction",
				transactionInputs(c.Inputs), c.Outputs, c.Locktime, c.Replaceable)
		},
		func(txHex string) *pb.CreateRawTransactionResponse {
			decoded, _ := hex.DecodeString(txHex)
			return &pb.CreateRawTransactionResponse{
				Tx: rawTransaction(decoded),
			}
		})
}

// transactionInputs converts inputs to what createrawtransaction and
// createpsbt take.
func transactionInputs(inputs []*pb.TransactionInput) []map[string]any {
	return mapSlice(inputs, func(in *pb.TransactionInput, _ int) map[string]any {
		out := map[string]any{"txid": in.Txid, "vout": in.Vout}
		if in.Sequence != nil {
			out["sequence"] = *in.Sequence
		}
		return out
	})
}

// SendRawTransaction implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) SendRawTransaction(ctx context.Context, c *pb.SendRawTransactionRequest) (*pb.SendRawTransactionResponse, error) {
	data, err := getRawTransactionBytes(c.Tx)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			return call[string](ctx, b.rpc, "sendrawtransaction",
				hex.EncodeToString(data), c.MaxFeeRate, c.MaxBurnAmount)
		},
		func(r string) *pb.SendRawTransactionResponse {
			return &pb.SendRawTransactionResponse{
				Txid: r,
			}
		})
}

// SignRawTransactionWithWallet implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) SignRawTransactionWithWallet(ctx context.Context, c *pb.SignRawTransactionWithWalletRequest) (*pb.SignRawTransactionWithWalletResponse, error) {
	if c.HexString == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("hex_string is required"))
	}

	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (btcjson.SignRawTransactionWithWalletResult, error) {
			cmd, err := btcjson.NewCmd("signrawtransactionwithwallet", c.HexString)
			if err != nil {
				return btcjson.SignRawTransactionWithWalletResult{}, err
			}

			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, cmd))
			if err != nil {
				return btcjson.SignRawTransactionWithWalletResult{}, fmt.Errorf("send signrawtransactionwithwallet: %w", err)
			}

			var result btcjson.SignRawTransactionWithWalletResult
			if err := json.Unmarshal(res, &result); err != nil {
				return btcjson.SignRawTransactionWithWalletResult{}, fmt.Errorf("unmarshal signrawtransactionwithwallet response: %w", err)
			}

			return result, nil
		},
		func(r btcjson.SignRawTransactionWithWalletResult) *pb.SignRawTransactionWithWalletResponse {
			var errors []*pb.SignRawTransactionWithWalletResponse_Error
			for _, e := range r.Errors {
				errors = append(errors, &pb.SignRawTransactionWithWalletResponse_Error{
					Txid:      e.TxID,
					Vout:      e.Vout,
					ScriptSig: e.ScriptSig,
					Sequence:  e.Sequence,
					Error:     e.Error,
				})
			}
			return &pb.SignRawTransactionWithWalletResponse{
				Hex:      r.Hex,
				Complete: r.Complete,
				Errors:   errors,
			}
		})
}

// DecodePsbt implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) DecodePsbt(ctx context.Context, c *pb.DecodePsbtRequest) (*pb.DecodePsbtResponse, error) {
	if c.Psbt == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("psbt is required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (rawDecodePsbtResponse, error) {
			cmd, err := btcjson.NewCmd("decodepsbt", c.Psbt)
			if err != nil {
				return rawDecodePsbtResponse{}, err
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return rawDecodePsbtResponse{}, fmt.Errorf("send decodepsbt: %w", err)
			}
			logFrom(ctx).DebugContext(ctx, "decodepsbt response", "response", string(res))

			var parsed rawDecodePsbtResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return rawDecodePsbtResponse{}, fmt.Errorf("unmarshal decodepsbt response: %w", err)
			}

			return parsed, nil
		},
		func(r rawDecodePsbtResponse) *pb.DecodePsbtResponse {
			inputs := make([]*pb.DecodePsbtResponse_Input, len(r.Inputs))
			for i, in := range r.Inputs {
				var nonWitnessUtxo *pb.DecodeRawTransactionResponse
				if in.NonWitnessUtxo.Txid != "" {
					nonWitnessUtxo = &pb.DecodeRawTransactionResponse{
						Txid:        in.NonWitnessUtxo.Txid,
						Hash:        in.NonWitnessUtxo.Hash,
						Size:        in.NonWitnessUtxo.Size,
						VirtualSize: in.NonWitnessUtxo.VirtualSize,
						Weight:      in.NonWitnessUtxo.Weight,
						Version:     in.NonWitnessUtxo.Version,
						Locktime:    in.NonWitnessUtxo.Locktime,
						Inputs: mapSlice(in.NonWitnessUtxo.Vin, func(in input, _ int) *pb.Input {
							return &pb.Input{
								Txid: in.Txid,
								Vout: in.Vout,
								ScriptSig: &pb.ScriptSig{
									Asm: in.ScriptSig.Asm,
									Hex: in.ScriptSig.Hex,
								},
								Sequence: in.Sequence,
								Witness:  in.TxInWitness,
							}
						}),
						Outputs: mapSlice(in.NonWitnessUtxo.Vout, func(out output, _ int) *pb.Output {
							return &pb.Output{
								Amount: out.Value,
								Vout:   out.N,
								ScriptPubKey: &pb.ScriptPubKey{
									Asm:     out.ScriptPubKey.Asm,
									Hex:     out.ScriptPubKey.Hex,
									Type:    out.ScriptPubKey.Type,
									Address: out.ScriptPubKey.Address,
								},
							}
						}),
					}
				}

				var witnessUtxo *pb.DecodePsbtResponse_WitnessUtxo
				if in.WitnessUtxo.ScriptPubKey.Hex != "" {
					witnessUtxo = &pb.DecodePsbtResponse_WitnessUtxo{
						Amount: in.WitnessUtxo.Amount,
						ScriptPubKey: &pb.ScriptPubKey{
							Asm:     in.WitnessUtxo.ScriptPubKey.Asm,
							Hex:     in.WitnessUtxo.ScriptPubKey.Hex,
							Type:    in.WitnessUtxo.ScriptPubKey.Type,
							Address: in.WitnessUtxo.ScriptPubKey.Address,
						},
					}
				}

				var redeemScript *pb.DecodePsbtResponse_RedeemScript
				if in.RedeemScript.Hex != "" {
					redeemScript = &pb.DecodePsbtResponse_RedeemScript{
						Asm:  in.RedeemScript.Asm,
						Hex:  in.RedeemScript.Hex,
						Type: in.RedeemScript.Type,
					}
				}

				var witnessScript *pb.DecodePsbtResponse_RedeemScript
				if in.WitnessScript.Hex != "" {
					witnessScript = &pb.DecodePsbtResponse_RedeemScript{
						Asm:  in.WitnessScript.Asm,
						Hex:  in.WitnessScript.Hex,
						Type: in.WitnessScript.Type,
					}
				}

				var finalScriptSig *pb.ScriptSig
				if in.FinalScriptSig.Hex != "" {
					finalScriptSig = &pb.ScriptSig{
						Asm: in.FinalScriptSig.Asm,
						Hex: in.FinalScriptSig.Hex,
					}
				}

				inputs[i] = &pb.DecodePsbtResponse_Input{
					NonWitnessUtxo:    nonWitnessUtxo,
					WitnessUtxo:       witnessUtxo,
					PartialSignatures: in.PartialSignatures,
					Sighash:           in.Sighash,
					RedeemScript:      redeemScript,
					WitnessScript:     witnessScript,
					Bip32Derivs: mapSlice(in.Bip32Derivs, func(deriv rawBip32Deriv, _ int) *pb.DecodePsbtResponse_Bip32Deriv {
						return &pb.DecodePsbtResponse_Bip32Deriv{
							MasterFingerprint: deriv.MasterFingerprint,
							Path:              deriv.Path,
						}
					}),
					FinalScriptsig:     finalScriptSig,
					FinalScriptwitness: in.FinalScriptWitness,
					Unknown:            in.Unknown,
				}
			}

			outputs := make([]*pb.DecodePsbtResponse_Output, len(r.Outputs))
			for i, output := range r.Outputs {
				var redeemScript *pb.DecodePsbtResponse_RedeemScript
				if output.RedeemScript.Hex != "" {
					redeemScript = &pb.DecodePsbtResponse_RedeemScript{
						Asm:  output.RedeemScript.Asm,
						Hex:  output.RedeemScript.Hex,
						Type: output.RedeemScript.Type,
					}
				}

				var witnessScript *pb.DecodePsbtResponse_RedeemScript
				if output.WitnessScript.Hex != "" {
					witnessScript = &pb.DecodePsbtResponse_RedeemScript{
						Asm:  output.WitnessScript.Asm,
						Hex:  output.WitnessScript.Hex,
						Type: output.WitnessScript.Type,
					}
				}

				outputs[i] = &pb.DecodePsbtResponse_Output{
					RedeemScript:  redeemScript,
					WitnessScript: witnessScript,
					Bip32Derivs: mapSlice(output.Bip32Derivs, func(deriv rawBip32Deriv, _ int) *pb.DecodePsbtResponse_Bip32Deriv {
						return &pb.DecodePsbtResponse_Bip32Deriv{
							Pubkey:            deriv.Pubkey,
							MasterFingerprint: deriv.MasterFingerprint,
							Path:              deriv.Path,
						}
					}),
					Unknown: output.Unknown,
				}
			}

			return &pb.DecodePsbtResponse{
				Tx: &pb.DecodeRawTransactionResponse{
					Txid:        r.Tx.Txid,
					Hash:        r.Tx.Hash,
					Size:        r.Tx.Size,
					VirtualSize: r.Tx.VirtualSize,
					Weight:      r.Tx.Weight,
					Version:     r.Tx.Version,
					Locktime:    r.Tx.Locktime,
					Inputs: mapSlice(r.Tx.Vin, func(in input, _ int) *pb.Input {
						return &pb.Input{
							Txid: in.Txid,
							Vout: in.Vout,
							ScriptSig: &pb.ScriptSig{
								Asm: in.ScriptSig.Asm,
								Hex: in.ScriptSig.Hex,
							},
							Sequence: in.Sequence,
							Witness:  in.TxInWitness,
						}
					}),
					Outputs: mapSlice(r.Tx.Vout, func(out output, _ int) *pb.Output {
						return &pb.Output{
							Amount: out.Value,
							Vout:   out.N,
							ScriptPubKey: &pb.ScriptPubKey{
								Asm:     out.ScriptPubKey.Asm,
								Hex:     out.ScriptPubKey.Hex,
								Type:    out.ScriptPubKey.Type,
								Address: out.ScriptPubKey.Address,
							},
						}
					}),
				},
				Unknown: r.Unknown,
				Inputs:  inputs,
				Outputs: outputs,
				Fee:     r.Fee,
			}
		})
}

// JoinPsbts implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) JoinPsbts(ctx context.Context, c *pb.JoinPsbtsRequest) (*pb.JoinPsbtsResponse, error) {
	if len(c.Psbts) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("at least one PSBT is required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			cmd, err := btcjson.NewCmd("joinpsbts", c.Psbts)
			if err != nil {
				return "", fmt.Errorf("create joinpsbts command: %w", err)
			}

			res, err := rpcclient.ReceiveFuture(b.rpc.SendCmd(ctx, cmd))
			if err != nil {
				return "", fmt.Errorf("send joinpsbts: %w", err)
			}

			var psbt string
			if err := json.Unmarshal(res, &psbt); err != nil {
				return "", fmt.Errorf("unmarshal joinpsbts response: %w", err)
			}

			return psbt, nil
		},
		func(r string) *pb.JoinPsbtsResponse {
			return &pb.JoinPsbtsResponse{
				Psbt: r,
			}
		})
}

// TestMempoolAccept implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) TestMempoolAccept(ctx context.Context, c *pb.TestMempoolAcceptRequest) (*pb.TestMempoolAcceptResponse, error) {
	if len(c.Rawtxs) == 0 {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("at least one raw transaction is required"))
	}

	return callRPC(
		ctx,
		func(ctx context.Context) ([]*btcjson.TestMempoolAcceptResult, error) {
			msgTxs := make([]*wire.MsgTx, len(c.Rawtxs))
			for i, tx := range c.Rawtxs {
				rawTx, err := hex.DecodeString(tx)
				if err != nil {
					return nil, newConnectError(connect.CodeInvalidArgument, fmt.Errorf("raw transaction %d is not hex: %w", i, err))
				}
				msgTx := wire.NewMsgTx(wire.TxVersion)
				if err := msgTx.Deserialize(bytes.NewReader(rawTx)); err != nil {
					return nil, newConnectError(connect.CodeInvalidArgument, fmt.Errorf("could not deserialize raw transaction %d: %w", i, err))
				}
				msgTxs[i] = msgTx
			}
			return b.rpc.TestMempoolAccept(ctx, msgTxs, c.MaxFeeRate)
		},
		func(results []*btcjson.TestMempoolAcceptResult) *pb.TestMempoolAcceptResponse {
			return &pb.TestMempoolAcceptResponse{
				Results: mapSlice(results, func(r *btcjson.TestMempoolAcceptResult, _ int) *pb.TestMempoolAcceptResponse_Result {
					var fees float64
					if r.Fees != nil {
						fees = r.Fees.Base
					}
					return &pb.TestMempoolAcceptResponse_Result{
						Txid:         r.Txid,
						Allowed:      r.Allowed,
						RejectReason: r.RejectReason,
						Vsize:        uint32(r.Vsize),
						Fees:         fees,
					}
				}),
			}
		})
}

// UtxoUpdatePsbt implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) UtxoUpdatePsbt(ctx context.Context, c *pb.UtxoUpdatePsbtRequest) (*pb.UtxoUpdatePsbtResponse, error) {
	if c.Psbt == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("psbt is required"))
	}

	var descriptors []map[string]any
	for _, desc := range c.Descriptors {
		obj := map[string]any{"desc": desc.Desc}
		if desc.Range != nil {
			obj["range"] = []uint32{desc.Range.Begin, desc.Range.End}
		}
		descriptors = append(descriptors, obj)
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (string, error) {
			return call[string](ctx, b.rpc, "utxoupdatepsbt", c.Psbt, descriptors)
		},
		func(r string) *pb.UtxoUpdatePsbtResponse {
			return &pb.UtxoUpdatePsbtResponse{
				Psbt: r,
			}
		})
}

// CreateWallet implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) CreateWallet(ctx context.Context, c *pb.CreateWalletRequest) (*pb.CreateWalletResponse, error) {
	if c.Name == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("wallet name is required"))
	}

	var opts []rpcclient.CreateWalletOpt
	if c.Blank {
		opts = append(opts, rpcclient.WithCreateWalletBlank())
	}
	if c.DisablePrivateKeys {
		opts = append(opts, rpcclient.WithCreateWalletDisablePrivateKeys())
	}
	if c.Passphrase != "" {
		opts = append(opts, rpcclient.WithCreateWalletPassphrase(c.Passphrase))
	}
	if c.AvoidReuse {
		opts = append(opts, rpcclient.WithCreateWalletAvoidReuse())
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (*btcjson.CreateWalletResult, error) {
			return b.rpc.CreateWallet(ctx, c.Name, opts...)
		},
		func(r *btcjson.CreateWalletResult) *pb.CreateWalletResponse {
			return &pb.CreateWalletResponse{
				Name:     r.Name,
				Warnings: r.Warnings,
			}
		})
}

// KeyPoolRefill implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) KeyPoolRefill(ctx context.Context, c *pb.KeyPoolRefillRequest) (*pb.KeyPoolRefillResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (struct{}, error) {
			if c.NewSize != 0 {
				return struct{}{}, rpc.KeyPoolRefillSize(ctx, uint(c.NewSize))
			}
			return struct{}{}, rpc.KeyPoolRefill(ctx)
		},
		func(_ struct{}) *pb.KeyPoolRefillResponse {
			return &pb.KeyPoolRefillResponse{}
		})
}

// LoadWallet implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) LoadWallet(ctx context.Context, c *pb.LoadWalletRequest) (*pb.LoadWalletResponse, error) {
	if c.Filename == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("filename is required"))
	}

	var loadOnStartup *bool
	if c.LoadOnStartup {
		loadOnStartup = &c.LoadOnStartup
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (*btcjson.LoadWalletResult, error) {
			return b.rpc.LoadWallet(ctx, c.Filename, loadOnStartup)
		},
		func(r *btcjson.LoadWalletResult) *pb.LoadWalletResponse {
			return &pb.LoadWalletResponse{
				Name:     r.Name,
				Warnings: r.Warnings,
			}
		})
}

// AbortRescan implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) AbortRescan(ctx context.Context, c *pb.AbortRescanRequest) (*pb.AbortRescanResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) (bool, error) {
			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, &commands.AbortRescanCmd{}))
			if err != nil {
				return false, err
			}

			var parsed bool
			if err := json.Unmarshal(res, &parsed); err != nil {
				return false, fmt.Errorf("unmarshal abortrescan response: %w", err)
			}
			return parsed, nil
		},
		func(aborted bool) *pb.AbortRescanResponse {
			return &pb.AbortRescanResponse{
				Aborted: aborted,
			}
		})
}

// RescanBlockchain implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) RescanBlockchain(ctx context.Context, c *pb.RescanBlockchainRequest) (*pb.RescanBlockchainResponse, error) {
	rpc, err := b.rpcForWallet(ctx, c.Wallet)
	if err != nil {
		return nil, err
	}

	return callRPC(ctx,
		func(ctx context.Context) (*commands.RescanBlockchainResponse, error) {
			cmd := commands.RescanBlockchainCmd{
				StartHeight: nonZeroPtr(c.StartHeight),
				EndHeight:   nonZeroPtr(c.EndHeight),
			}
			res, err := rpcclient.ReceiveFuture(rpc.SendCmd(ctx, &cmd))
			if err != nil {
				return nil, err
			}

			var parsed commands.RescanBlockchainResponse
			if err := json.Unmarshal(res, &parsed); err != nil {
				return nil, fmt.Errorf("unmarshal rescanblockchain response: %w", err)
			}
			return &parsed, err
		},
		func(r *commands.RescanBlockchainResponse) *pb.RescanBlockchainResponse {
			return &pb.RescanBlockchainResponse{
				StartHeight: r.StartHeight,
				StopHeight:  r.StopHeight,
			}
		})
}

// UnloadWallet implements bitcoindv1connect.BitcoinServiceHandler.
func (b *Bitcoind) UnloadWallet(ctx context.Context, c *pb.UnloadWalletRequest) (*pb.UnloadWalletResponse, error) {
	if c.WalletName == "" {
		return nil, newConnectError(connect.CodeInvalidArgument, errors.New("wallet name is required"))
	}

	// On the wallet's own endpoint, Core takes the wallet from the URL.
	// The default endpoint may name some other wallet.
	rpc, err := b.rpcForWallet(ctx, c.WalletName)
	if err != nil {
		return nil, err
	}

	return callRPC(
		ctx,
		func(ctx context.Context) (struct{}, error) {
			return struct{}{}, rpc.UnloadWallet(ctx, nil)
		},
		func(_ struct{}) *pb.UnloadWalletResponse {
			return &pb.UnloadWalletResponse{}
		})
}

func (b *Bitcoind) GetZmqNotifications(ctx context.Context, c *emptypb.Empty) (*pb.GetZmqNotificationsResponse, error) {
	return callRPC(ctx,
		func(ctx context.Context) (btcjson.GetZmqNotificationResult, error) {
			return b.rpc.GetZmqNotifications(ctx)
		},
		func(res btcjson.GetZmqNotificationResult) *pb.GetZmqNotificationsResponse {
			var notifications []*pb.GetZmqNotificationsResponse_Notification

			for _, notification := range res {
				notifications = append(notifications, &pb.GetZmqNotificationsResponse_Notification{
					Type:          notification.Type,
					Address:       notification.Address.String(),
					HighWaterMark: int64(notification.HighWaterMark),
				})
			}
			return &pb.GetZmqNotificationsResponse{Notifications: notifications}
		})
}

// Shutdown ends the SSH tunnel and any background startup.
func (b *Bitcoind) Shutdown(ctx context.Context) {
	logFrom(ctx).DebugContext(ctx, "shutting down")
	b.stop()
}

// Server returns the dispatcher for the Bitcoind API, with all interceptors
// (including error transformation) applied. Call it in memory through
// connectinprocess, or serve it over HTTP with connecthttp.Mount.
//
// Don't register further services on it after it's been mounted on HTTP:
// they won't be served.
func (b *Bitcoind) Server() *connect.Server {
	return b.server
}

var _ rpc.BitcoinServiceHandler = new(Bitcoind)

func newConnectError(code connect.Code, err error) *connect.Error {
	return connect.NewError(code, err.Error()).WithCause(err)
}

func handleBtcJsonErrors() connect.ServerInterceptor {
	return func(handler connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			err := handler(ctx, spec, stream)

			rpcErr := new(btcjson.RPCError)

			switch {
			case err == nil:
				return nil

			case strings.Contains(err.Error(), "Work queue depth exceeded"):
				logFrom(ctx).InfoContext(ctx, "handle error: work queue depth exceeded")

				err = newConnectError(connect.CodeResourceExhausted, errors.New("RPC work queue depth exceeded"))

			case errors.As(err, &rpcErr):
				switch {
				// This is a -4 in the btcd lib, but a -6 in Bitcoin Core...
				case rpcErr.Message == "Insufficient funds":
					err = newConnectError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWallet && strings.Contains(rpcErr.Message, "Wallet is currently rescanning"):
					err = newConnectError(connect.CodeAlreadyExists, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWallet && rpcErr.Message == "Transaction amount too small":
					err = newConnectError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWallet && strings.Contains(rpcErr.Message, "which was already bumped by transaction"):
					err = newConnectError(connect.CodeAlreadyExists, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCMisc && strings.Contains(rpcErr.Message, "is already spent"):
					err = newConnectError(connect.CodeAlreadyExists, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCWalletNotSpecified:
					msg := `wallet must be specified either through the "wallet" parameter or the --bitcoind.wallet flag`
					err = newConnectError(connect.CodeFailedPrecondition, errors.New(msg))

				case rpcErr.Code == btcjson.ErrRPCWalletNotFound:
					err = newConnectError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCInvalidAddressOrKey:
					err = newConnectError(connect.CodeNotFound, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCInvalidParameter:
					err = newConnectError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCDecodeHexString:
					err = newConnectError(connect.CodeInvalidArgument, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCInWarmup:
					err = newConnectError(connect.CodeFailedPrecondition, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCMisc && strings.Contains(rpcErr.Message, "Block not available (not fully downloaded)"):
					err = newConnectError(connect.CodeUnavailable, errors.New(rpcErr.Message))

				case rpcErr.Code == btcjson.ErrRPCMethodNotFound.Code:

					err = newConnectError(
						connect.CodeFailedPrecondition,
						errors.New("Bitcoin Core is running without wallet functionality"), // nolint:staticcheck
					)

				default:
					logFrom(ctx).WarnContext(ctx, "unknown btcjson error", "error", rpcErr)
				}
			}

			return err
		}
	}
}

func newChainHash(in string) (*chainhash.Hash, error) {
	if in == "" {
		return nil, nil
	}

	hash, err := chainhash.NewHashFromStr(in)
	if err != nil {
		return nil, newConnectError(connect.CodeInvalidArgument, err)
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

type rawDecodeTransactionResponse struct {
	Txid        string   `json:"txid"`
	Hash        string   `json:"hash"`
	Size        uint32   `json:"size"`
	VirtualSize uint32   `json:"vsize"`
	Weight      uint32   `json:"weight"`
	Version     uint32   `json:"version"`
	Locktime    uint32   `json:"locktime"`
	Vin         []input  `json:"vin"`
	Vout        []output `json:"vout"`
}

type input struct {
	Txid        string    `json:"txid"`
	Vout        uint32    `json:"vout"`
	ScriptSig   scriptSig `json:"scriptSig"`
	TxInWitness []string  `json:"txinwitness,omitempty"`
	Sequence    uint32    `json:"sequence"`
}

type scriptSig struct {
	Asm string `json:"asm"`
	Hex string `json:"hex"`
}

type output struct {
	Value        float64      `json:"value"`
	N            uint32       `json:"n"`
	ScriptPubKey scriptPubKey `json:"scriptPubKey"`
}

type scriptPubKey struct {
	Asm     string `json:"asm"`
	Hex     string `json:"hex"`
	Type    string `json:"type"`
	Address string `json:"address,omitempty"`
}

type rawDecodePsbtResponse struct {
	Tx      rawDecodeTransactionResponse `json:"tx"`
	Unknown map[string]string            `json:"unknown"`
	Inputs  []struct {
		NonWitnessUtxo rawDecodeTransactionResponse `json:"non_witness_utxo"`
		WitnessUtxo    struct {
			Amount       float64 `json:"amount"`
			ScriptPubKey struct {
				Asm     string `json:"asm"`
				Hex     string `json:"hex"`
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"scriptPubKey"`
		} `json:"witness_utxo"`
		PartialSignatures map[string]string `json:"partial_signatures"`
		Sighash           string            `json:"sighash"`
		RedeemScript      struct {
			Asm  string `json:"asm"`
			Hex  string `json:"hex"`
			Type string `json:"type"`
		} `json:"redeem_script"`
		WitnessScript struct {
			Asm  string `json:"asm"`
			Hex  string `json:"hex"`
			Type string `json:"type"`
		} `json:"witness_script"`
		Bip32Derivs    []rawBip32Deriv `json:"bip32_derivs"`
		FinalScriptSig struct {
			Asm string `json:"asm"`
			Hex string `json:"hex"`
		} `json:"final_scriptsig"`
		FinalScriptWitness []string          `json:"final_scriptwitness"`
		Unknown            map[string]string `json:"unknown"`
	} `json:"inputs"`
	Outputs []struct {
		RedeemScript struct {
			Asm  string `json:"asm"`
			Hex  string `json:"hex"`
			Type string `json:"type"`
		} `json:"redeem_script"`
		WitnessScript struct {
			Asm  string `json:"asm"`
			Hex  string `json:"hex"`
			Type string `json:"type"`
		} `json:"witness_script"`
		Bip32Derivs []rawBip32Deriv   `json:"bip32_derivs"`
		Unknown     map[string]string `json:"unknown"`
	} `json:"outputs"`
	Fee float64 `json:"fee"`
}

type rawBip32Deriv struct {
	Pubkey            string `json:"pubkey"`
	MasterFingerprint string `json:"master_fingerprint"`
	Path              string `json:"path"`
}

func newTimestamp(unix int64) *timestamppb.Timestamp {
	if unix == 0 {
		return nil
	}
	return timestamppb.New(time.Unix(unix, 0))
}

func getRawTransactionBytes(tx *pb.RawTransaction) ([]byte, error) {
	if (len(tx.GetHex()) == 0) == (len(tx.GetData()) == 0) {
		err := errors.New("must specify transaction bytes as either raw or hex-encoded")
		return nil, newConnectError(connect.CodeInvalidArgument, err)
	}

	if len(tx.GetHex()) > 0 {
		decoded, err := hex.DecodeString(tx.GetHex())
		if err != nil {
			err := fmt.Errorf("invalid hex data: %w", err)
			return nil, newConnectError(connect.CodeInvalidArgument, err)
		}

		return decoded, nil
	}

	return tx.GetData(), nil
}
