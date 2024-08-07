// Code generated by protoc-gen-connect-go. DO NOT EDIT.
//
// Source: bitcoin/bitcoind/v1alpha/bitcoin.proto

package bitcoindv1alphaconnect

import (
	connect "connectrpc.com/connect"
	context "context"
	errors "errors"
	v1alpha "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1alpha"
	http "net/http"
	strings "strings"
)

// This is a compile-time assertion to ensure that this generated file and the connect package are
// compatible. If you get a compiler error that this constant is not defined, this code was
// generated with a version of connect newer than the one compiled into your binary. You can fix the
// problem by either regenerating this code with an older version of connect or updating the connect
// version compiled into your binary.
const _ = connect.IsAtLeastVersion1_13_0

const (
	// BitcoinServiceName is the fully-qualified name of the BitcoinService service.
	BitcoinServiceName = "bitcoin.bitcoind.v1alpha.BitcoinService"
)

// These constants are the fully-qualified names of the RPCs defined in this package. They're
// exposed at runtime as Spec.Procedure and as the final two segments of the HTTP route.
//
// Note that these are different from the fully-qualified method names used by
// google.golang.org/protobuf/reflect/protoreflect. To convert from these constants to
// reflection-formatted method names, remove the leading slash and convert the remaining slash to a
// period.
const (
	// BitcoinServiceGetBlockchainInfoProcedure is the fully-qualified name of the BitcoinService's
	// GetBlockchainInfo RPC.
	BitcoinServiceGetBlockchainInfoProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetBlockchainInfo"
	// BitcoinServiceGetTransactionProcedure is the fully-qualified name of the BitcoinService's
	// GetTransaction RPC.
	BitcoinServiceGetTransactionProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetTransaction"
	// BitcoinServiceListSinceBlockProcedure is the fully-qualified name of the BitcoinService's
	// ListSinceBlock RPC.
	BitcoinServiceListSinceBlockProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/ListSinceBlock"
	// BitcoinServiceGetNewAddressProcedure is the fully-qualified name of the BitcoinService's
	// GetNewAddress RPC.
	BitcoinServiceGetNewAddressProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetNewAddress"
	// BitcoinServiceGetWalletInfoProcedure is the fully-qualified name of the BitcoinService's
	// GetWalletInfo RPC.
	BitcoinServiceGetWalletInfoProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetWalletInfo"
	// BitcoinServiceGetBalancesProcedure is the fully-qualified name of the BitcoinService's
	// GetBalances RPC.
	BitcoinServiceGetBalancesProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetBalances"
	// BitcoinServiceSendProcedure is the fully-qualified name of the BitcoinService's Send RPC.
	BitcoinServiceSendProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/Send"
	// BitcoinServiceBumpFeeProcedure is the fully-qualified name of the BitcoinService's BumpFee RPC.
	BitcoinServiceBumpFeeProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/BumpFee"
	// BitcoinServiceEstimateSmartFeeProcedure is the fully-qualified name of the BitcoinService's
	// EstimateSmartFee RPC.
	BitcoinServiceEstimateSmartFeeProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/EstimateSmartFee"
	// BitcoinServiceImportDescriptorsProcedure is the fully-qualified name of the BitcoinService's
	// ImportDescriptors RPC.
	BitcoinServiceImportDescriptorsProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/ImportDescriptors"
	// BitcoinServiceGetDescriptorInfoProcedure is the fully-qualified name of the BitcoinService's
	// GetDescriptorInfo RPC.
	BitcoinServiceGetDescriptorInfoProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetDescriptorInfo"
	// BitcoinServiceGetRawTransactionProcedure is the fully-qualified name of the BitcoinService's
	// GetRawTransaction RPC.
	BitcoinServiceGetRawTransactionProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetRawTransaction"
	// BitcoinServiceDecodeRawTransactionProcedure is the fully-qualified name of the BitcoinService's
	// DecodeRawTransaction RPC.
	BitcoinServiceDecodeRawTransactionProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/DecodeRawTransaction"
	// BitcoinServiceGetBlockProcedure is the fully-qualified name of the BitcoinService's GetBlock RPC.
	BitcoinServiceGetBlockProcedure = "/bitcoin.bitcoind.v1alpha.BitcoinService/GetBlock"
)

// These variables are the protoreflect.Descriptor objects for the RPCs defined in this package.
var (
	bitcoinServiceServiceDescriptor                    = v1alpha.File_bitcoin_bitcoind_v1alpha_bitcoin_proto.Services().ByName("BitcoinService")
	bitcoinServiceGetBlockchainInfoMethodDescriptor    = bitcoinServiceServiceDescriptor.Methods().ByName("GetBlockchainInfo")
	bitcoinServiceGetTransactionMethodDescriptor       = bitcoinServiceServiceDescriptor.Methods().ByName("GetTransaction")
	bitcoinServiceListSinceBlockMethodDescriptor       = bitcoinServiceServiceDescriptor.Methods().ByName("ListSinceBlock")
	bitcoinServiceGetNewAddressMethodDescriptor        = bitcoinServiceServiceDescriptor.Methods().ByName("GetNewAddress")
	bitcoinServiceGetWalletInfoMethodDescriptor        = bitcoinServiceServiceDescriptor.Methods().ByName("GetWalletInfo")
	bitcoinServiceGetBalancesMethodDescriptor          = bitcoinServiceServiceDescriptor.Methods().ByName("GetBalances")
	bitcoinServiceSendMethodDescriptor                 = bitcoinServiceServiceDescriptor.Methods().ByName("Send")
	bitcoinServiceBumpFeeMethodDescriptor              = bitcoinServiceServiceDescriptor.Methods().ByName("BumpFee")
	bitcoinServiceEstimateSmartFeeMethodDescriptor     = bitcoinServiceServiceDescriptor.Methods().ByName("EstimateSmartFee")
	bitcoinServiceImportDescriptorsMethodDescriptor    = bitcoinServiceServiceDescriptor.Methods().ByName("ImportDescriptors")
	bitcoinServiceGetDescriptorInfoMethodDescriptor    = bitcoinServiceServiceDescriptor.Methods().ByName("GetDescriptorInfo")
	bitcoinServiceGetRawTransactionMethodDescriptor    = bitcoinServiceServiceDescriptor.Methods().ByName("GetRawTransaction")
	bitcoinServiceDecodeRawTransactionMethodDescriptor = bitcoinServiceServiceDescriptor.Methods().ByName("DecodeRawTransaction")
	bitcoinServiceGetBlockMethodDescriptor             = bitcoinServiceServiceDescriptor.Methods().ByName("GetBlock")
)

// BitcoinServiceClient is a client for the bitcoin.bitcoind.v1alpha.BitcoinService service.
type BitcoinServiceClient interface {
	GetBlockchainInfo(context.Context, *connect.Request[v1alpha.GetBlockchainInfoRequest]) (*connect.Response[v1alpha.GetBlockchainInfoResponse], error)
	// Fetches in-wallet transactions
	GetTransaction(context.Context, *connect.Request[v1alpha.GetTransactionRequest]) (*connect.Response[v1alpha.GetTransactionResponse], error)
	ListSinceBlock(context.Context, *connect.Request[v1alpha.ListSinceBlockRequest]) (*connect.Response[v1alpha.ListSinceBlockResponse], error)
	// Wallet stuff
	GetNewAddress(context.Context, *connect.Request[v1alpha.GetNewAddressRequest]) (*connect.Response[v1alpha.GetNewAddressResponse], error)
	GetWalletInfo(context.Context, *connect.Request[v1alpha.GetWalletInfoRequest]) (*connect.Response[v1alpha.GetWalletInfoResponse], error)
	GetBalances(context.Context, *connect.Request[v1alpha.GetBalancesRequest]) (*connect.Response[v1alpha.GetBalancesResponse], error)
	Send(context.Context, *connect.Request[v1alpha.SendRequest]) (*connect.Response[v1alpha.SendResponse], error)
	BumpFee(context.Context, *connect.Request[v1alpha.BumpFeeRequest]) (*connect.Response[v1alpha.BumpFeeResponse], error)
	EstimateSmartFee(context.Context, *connect.Request[v1alpha.EstimateSmartFeeRequest]) (*connect.Response[v1alpha.EstimateSmartFeeResponse], error)
	// Import a descriptor. If importing a watch-only descriptor, the wallet itself needs
	// to be watch-only as well. The descriptor also needs to be normalized, with a
	// checksum. This can be obtained by running it through GetDescriptorInfo.
	ImportDescriptors(context.Context, *connect.Request[v1alpha.ImportDescriptorsRequest]) (*connect.Response[v1alpha.ImportDescriptorsResponse], error)
	GetDescriptorInfo(context.Context, *connect.Request[v1alpha.GetDescriptorInfoRequest]) (*connect.Response[v1alpha.GetDescriptorInfoResponse], error)
	// Raw TX stuff
	GetRawTransaction(context.Context, *connect.Request[v1alpha.GetRawTransactionRequest]) (*connect.Response[v1alpha.GetRawTransactionResponse], error)
	DecodeRawTransaction(context.Context, *connect.Request[v1alpha.DecodeRawTransactionRequest]) (*connect.Response[v1alpha.DecodeRawTransactionResponse], error)
	GetBlock(context.Context, *connect.Request[v1alpha.GetBlockRequest]) (*connect.Response[v1alpha.GetBlockResponse], error)
}

// NewBitcoinServiceClient constructs a client for the bitcoin.bitcoind.v1alpha.BitcoinService
// service. By default, it uses the Connect protocol with the binary Protobuf Codec, asks for
// gzipped responses, and sends uncompressed requests. To use the gRPC or gRPC-Web protocols, supply
// the connect.WithGRPC() or connect.WithGRPCWeb() options.
//
// The URL supplied here should be the base URL for the Connect or gRPC server (for example,
// http://api.acme.com or https://acme.com/grpc).
func NewBitcoinServiceClient(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) BitcoinServiceClient {
	baseURL = strings.TrimRight(baseURL, "/")
	return &bitcoinServiceClient{
		getBlockchainInfo: connect.NewClient[v1alpha.GetBlockchainInfoRequest, v1alpha.GetBlockchainInfoResponse](
			httpClient,
			baseURL+BitcoinServiceGetBlockchainInfoProcedure,
			connect.WithSchema(bitcoinServiceGetBlockchainInfoMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getTransaction: connect.NewClient[v1alpha.GetTransactionRequest, v1alpha.GetTransactionResponse](
			httpClient,
			baseURL+BitcoinServiceGetTransactionProcedure,
			connect.WithSchema(bitcoinServiceGetTransactionMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		listSinceBlock: connect.NewClient[v1alpha.ListSinceBlockRequest, v1alpha.ListSinceBlockResponse](
			httpClient,
			baseURL+BitcoinServiceListSinceBlockProcedure,
			connect.WithSchema(bitcoinServiceListSinceBlockMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getNewAddress: connect.NewClient[v1alpha.GetNewAddressRequest, v1alpha.GetNewAddressResponse](
			httpClient,
			baseURL+BitcoinServiceGetNewAddressProcedure,
			connect.WithSchema(bitcoinServiceGetNewAddressMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getWalletInfo: connect.NewClient[v1alpha.GetWalletInfoRequest, v1alpha.GetWalletInfoResponse](
			httpClient,
			baseURL+BitcoinServiceGetWalletInfoProcedure,
			connect.WithSchema(bitcoinServiceGetWalletInfoMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getBalances: connect.NewClient[v1alpha.GetBalancesRequest, v1alpha.GetBalancesResponse](
			httpClient,
			baseURL+BitcoinServiceGetBalancesProcedure,
			connect.WithSchema(bitcoinServiceGetBalancesMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		send: connect.NewClient[v1alpha.SendRequest, v1alpha.SendResponse](
			httpClient,
			baseURL+BitcoinServiceSendProcedure,
			connect.WithSchema(bitcoinServiceSendMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		bumpFee: connect.NewClient[v1alpha.BumpFeeRequest, v1alpha.BumpFeeResponse](
			httpClient,
			baseURL+BitcoinServiceBumpFeeProcedure,
			connect.WithSchema(bitcoinServiceBumpFeeMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		estimateSmartFee: connect.NewClient[v1alpha.EstimateSmartFeeRequest, v1alpha.EstimateSmartFeeResponse](
			httpClient,
			baseURL+BitcoinServiceEstimateSmartFeeProcedure,
			connect.WithSchema(bitcoinServiceEstimateSmartFeeMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		importDescriptors: connect.NewClient[v1alpha.ImportDescriptorsRequest, v1alpha.ImportDescriptorsResponse](
			httpClient,
			baseURL+BitcoinServiceImportDescriptorsProcedure,
			connect.WithSchema(bitcoinServiceImportDescriptorsMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getDescriptorInfo: connect.NewClient[v1alpha.GetDescriptorInfoRequest, v1alpha.GetDescriptorInfoResponse](
			httpClient,
			baseURL+BitcoinServiceGetDescriptorInfoProcedure,
			connect.WithSchema(bitcoinServiceGetDescriptorInfoMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getRawTransaction: connect.NewClient[v1alpha.GetRawTransactionRequest, v1alpha.GetRawTransactionResponse](
			httpClient,
			baseURL+BitcoinServiceGetRawTransactionProcedure,
			connect.WithSchema(bitcoinServiceGetRawTransactionMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		decodeRawTransaction: connect.NewClient[v1alpha.DecodeRawTransactionRequest, v1alpha.DecodeRawTransactionResponse](
			httpClient,
			baseURL+BitcoinServiceDecodeRawTransactionProcedure,
			connect.WithSchema(bitcoinServiceDecodeRawTransactionMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
		getBlock: connect.NewClient[v1alpha.GetBlockRequest, v1alpha.GetBlockResponse](
			httpClient,
			baseURL+BitcoinServiceGetBlockProcedure,
			connect.WithSchema(bitcoinServiceGetBlockMethodDescriptor),
			connect.WithClientOptions(opts...),
		),
	}
}

// bitcoinServiceClient implements BitcoinServiceClient.
type bitcoinServiceClient struct {
	getBlockchainInfo    *connect.Client[v1alpha.GetBlockchainInfoRequest, v1alpha.GetBlockchainInfoResponse]
	getTransaction       *connect.Client[v1alpha.GetTransactionRequest, v1alpha.GetTransactionResponse]
	listSinceBlock       *connect.Client[v1alpha.ListSinceBlockRequest, v1alpha.ListSinceBlockResponse]
	getNewAddress        *connect.Client[v1alpha.GetNewAddressRequest, v1alpha.GetNewAddressResponse]
	getWalletInfo        *connect.Client[v1alpha.GetWalletInfoRequest, v1alpha.GetWalletInfoResponse]
	getBalances          *connect.Client[v1alpha.GetBalancesRequest, v1alpha.GetBalancesResponse]
	send                 *connect.Client[v1alpha.SendRequest, v1alpha.SendResponse]
	bumpFee              *connect.Client[v1alpha.BumpFeeRequest, v1alpha.BumpFeeResponse]
	estimateSmartFee     *connect.Client[v1alpha.EstimateSmartFeeRequest, v1alpha.EstimateSmartFeeResponse]
	importDescriptors    *connect.Client[v1alpha.ImportDescriptorsRequest, v1alpha.ImportDescriptorsResponse]
	getDescriptorInfo    *connect.Client[v1alpha.GetDescriptorInfoRequest, v1alpha.GetDescriptorInfoResponse]
	getRawTransaction    *connect.Client[v1alpha.GetRawTransactionRequest, v1alpha.GetRawTransactionResponse]
	decodeRawTransaction *connect.Client[v1alpha.DecodeRawTransactionRequest, v1alpha.DecodeRawTransactionResponse]
	getBlock             *connect.Client[v1alpha.GetBlockRequest, v1alpha.GetBlockResponse]
}

// GetBlockchainInfo calls bitcoin.bitcoind.v1alpha.BitcoinService.GetBlockchainInfo.
func (c *bitcoinServiceClient) GetBlockchainInfo(ctx context.Context, req *connect.Request[v1alpha.GetBlockchainInfoRequest]) (*connect.Response[v1alpha.GetBlockchainInfoResponse], error) {
	return c.getBlockchainInfo.CallUnary(ctx, req)
}

// GetTransaction calls bitcoin.bitcoind.v1alpha.BitcoinService.GetTransaction.
func (c *bitcoinServiceClient) GetTransaction(ctx context.Context, req *connect.Request[v1alpha.GetTransactionRequest]) (*connect.Response[v1alpha.GetTransactionResponse], error) {
	return c.getTransaction.CallUnary(ctx, req)
}

// ListSinceBlock calls bitcoin.bitcoind.v1alpha.BitcoinService.ListSinceBlock.
func (c *bitcoinServiceClient) ListSinceBlock(ctx context.Context, req *connect.Request[v1alpha.ListSinceBlockRequest]) (*connect.Response[v1alpha.ListSinceBlockResponse], error) {
	return c.listSinceBlock.CallUnary(ctx, req)
}

// GetNewAddress calls bitcoin.bitcoind.v1alpha.BitcoinService.GetNewAddress.
func (c *bitcoinServiceClient) GetNewAddress(ctx context.Context, req *connect.Request[v1alpha.GetNewAddressRequest]) (*connect.Response[v1alpha.GetNewAddressResponse], error) {
	return c.getNewAddress.CallUnary(ctx, req)
}

// GetWalletInfo calls bitcoin.bitcoind.v1alpha.BitcoinService.GetWalletInfo.
func (c *bitcoinServiceClient) GetWalletInfo(ctx context.Context, req *connect.Request[v1alpha.GetWalletInfoRequest]) (*connect.Response[v1alpha.GetWalletInfoResponse], error) {
	return c.getWalletInfo.CallUnary(ctx, req)
}

// GetBalances calls bitcoin.bitcoind.v1alpha.BitcoinService.GetBalances.
func (c *bitcoinServiceClient) GetBalances(ctx context.Context, req *connect.Request[v1alpha.GetBalancesRequest]) (*connect.Response[v1alpha.GetBalancesResponse], error) {
	return c.getBalances.CallUnary(ctx, req)
}

// Send calls bitcoin.bitcoind.v1alpha.BitcoinService.Send.
func (c *bitcoinServiceClient) Send(ctx context.Context, req *connect.Request[v1alpha.SendRequest]) (*connect.Response[v1alpha.SendResponse], error) {
	return c.send.CallUnary(ctx, req)
}

// BumpFee calls bitcoin.bitcoind.v1alpha.BitcoinService.BumpFee.
func (c *bitcoinServiceClient) BumpFee(ctx context.Context, req *connect.Request[v1alpha.BumpFeeRequest]) (*connect.Response[v1alpha.BumpFeeResponse], error) {
	return c.bumpFee.CallUnary(ctx, req)
}

// EstimateSmartFee calls bitcoin.bitcoind.v1alpha.BitcoinService.EstimateSmartFee.
func (c *bitcoinServiceClient) EstimateSmartFee(ctx context.Context, req *connect.Request[v1alpha.EstimateSmartFeeRequest]) (*connect.Response[v1alpha.EstimateSmartFeeResponse], error) {
	return c.estimateSmartFee.CallUnary(ctx, req)
}

// ImportDescriptors calls bitcoin.bitcoind.v1alpha.BitcoinService.ImportDescriptors.
func (c *bitcoinServiceClient) ImportDescriptors(ctx context.Context, req *connect.Request[v1alpha.ImportDescriptorsRequest]) (*connect.Response[v1alpha.ImportDescriptorsResponse], error) {
	return c.importDescriptors.CallUnary(ctx, req)
}

// GetDescriptorInfo calls bitcoin.bitcoind.v1alpha.BitcoinService.GetDescriptorInfo.
func (c *bitcoinServiceClient) GetDescriptorInfo(ctx context.Context, req *connect.Request[v1alpha.GetDescriptorInfoRequest]) (*connect.Response[v1alpha.GetDescriptorInfoResponse], error) {
	return c.getDescriptorInfo.CallUnary(ctx, req)
}

// GetRawTransaction calls bitcoin.bitcoind.v1alpha.BitcoinService.GetRawTransaction.
func (c *bitcoinServiceClient) GetRawTransaction(ctx context.Context, req *connect.Request[v1alpha.GetRawTransactionRequest]) (*connect.Response[v1alpha.GetRawTransactionResponse], error) {
	return c.getRawTransaction.CallUnary(ctx, req)
}

// DecodeRawTransaction calls bitcoin.bitcoind.v1alpha.BitcoinService.DecodeRawTransaction.
func (c *bitcoinServiceClient) DecodeRawTransaction(ctx context.Context, req *connect.Request[v1alpha.DecodeRawTransactionRequest]) (*connect.Response[v1alpha.DecodeRawTransactionResponse], error) {
	return c.decodeRawTransaction.CallUnary(ctx, req)
}

// GetBlock calls bitcoin.bitcoind.v1alpha.BitcoinService.GetBlock.
func (c *bitcoinServiceClient) GetBlock(ctx context.Context, req *connect.Request[v1alpha.GetBlockRequest]) (*connect.Response[v1alpha.GetBlockResponse], error) {
	return c.getBlock.CallUnary(ctx, req)
}

// BitcoinServiceHandler is an implementation of the bitcoin.bitcoind.v1alpha.BitcoinService
// service.
type BitcoinServiceHandler interface {
	GetBlockchainInfo(context.Context, *connect.Request[v1alpha.GetBlockchainInfoRequest]) (*connect.Response[v1alpha.GetBlockchainInfoResponse], error)
	// Fetches in-wallet transactions
	GetTransaction(context.Context, *connect.Request[v1alpha.GetTransactionRequest]) (*connect.Response[v1alpha.GetTransactionResponse], error)
	ListSinceBlock(context.Context, *connect.Request[v1alpha.ListSinceBlockRequest]) (*connect.Response[v1alpha.ListSinceBlockResponse], error)
	// Wallet stuff
	GetNewAddress(context.Context, *connect.Request[v1alpha.GetNewAddressRequest]) (*connect.Response[v1alpha.GetNewAddressResponse], error)
	GetWalletInfo(context.Context, *connect.Request[v1alpha.GetWalletInfoRequest]) (*connect.Response[v1alpha.GetWalletInfoResponse], error)
	GetBalances(context.Context, *connect.Request[v1alpha.GetBalancesRequest]) (*connect.Response[v1alpha.GetBalancesResponse], error)
	Send(context.Context, *connect.Request[v1alpha.SendRequest]) (*connect.Response[v1alpha.SendResponse], error)
	BumpFee(context.Context, *connect.Request[v1alpha.BumpFeeRequest]) (*connect.Response[v1alpha.BumpFeeResponse], error)
	EstimateSmartFee(context.Context, *connect.Request[v1alpha.EstimateSmartFeeRequest]) (*connect.Response[v1alpha.EstimateSmartFeeResponse], error)
	// Import a descriptor. If importing a watch-only descriptor, the wallet itself needs
	// to be watch-only as well. The descriptor also needs to be normalized, with a
	// checksum. This can be obtained by running it through GetDescriptorInfo.
	ImportDescriptors(context.Context, *connect.Request[v1alpha.ImportDescriptorsRequest]) (*connect.Response[v1alpha.ImportDescriptorsResponse], error)
	GetDescriptorInfo(context.Context, *connect.Request[v1alpha.GetDescriptorInfoRequest]) (*connect.Response[v1alpha.GetDescriptorInfoResponse], error)
	// Raw TX stuff
	GetRawTransaction(context.Context, *connect.Request[v1alpha.GetRawTransactionRequest]) (*connect.Response[v1alpha.GetRawTransactionResponse], error)
	DecodeRawTransaction(context.Context, *connect.Request[v1alpha.DecodeRawTransactionRequest]) (*connect.Response[v1alpha.DecodeRawTransactionResponse], error)
	GetBlock(context.Context, *connect.Request[v1alpha.GetBlockRequest]) (*connect.Response[v1alpha.GetBlockResponse], error)
}

// NewBitcoinServiceHandler builds an HTTP handler from the service implementation. It returns the
// path on which to mount the handler and the handler itself.
//
// By default, handlers support the Connect, gRPC, and gRPC-Web protocols with the binary Protobuf
// and JSON codecs. They also support gzip compression.
func NewBitcoinServiceHandler(svc BitcoinServiceHandler, opts ...connect.HandlerOption) (string, http.Handler) {
	bitcoinServiceGetBlockchainInfoHandler := connect.NewUnaryHandler(
		BitcoinServiceGetBlockchainInfoProcedure,
		svc.GetBlockchainInfo,
		connect.WithSchema(bitcoinServiceGetBlockchainInfoMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetTransactionHandler := connect.NewUnaryHandler(
		BitcoinServiceGetTransactionProcedure,
		svc.GetTransaction,
		connect.WithSchema(bitcoinServiceGetTransactionMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceListSinceBlockHandler := connect.NewUnaryHandler(
		BitcoinServiceListSinceBlockProcedure,
		svc.ListSinceBlock,
		connect.WithSchema(bitcoinServiceListSinceBlockMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetNewAddressHandler := connect.NewUnaryHandler(
		BitcoinServiceGetNewAddressProcedure,
		svc.GetNewAddress,
		connect.WithSchema(bitcoinServiceGetNewAddressMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetWalletInfoHandler := connect.NewUnaryHandler(
		BitcoinServiceGetWalletInfoProcedure,
		svc.GetWalletInfo,
		connect.WithSchema(bitcoinServiceGetWalletInfoMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetBalancesHandler := connect.NewUnaryHandler(
		BitcoinServiceGetBalancesProcedure,
		svc.GetBalances,
		connect.WithSchema(bitcoinServiceGetBalancesMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceSendHandler := connect.NewUnaryHandler(
		BitcoinServiceSendProcedure,
		svc.Send,
		connect.WithSchema(bitcoinServiceSendMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceBumpFeeHandler := connect.NewUnaryHandler(
		BitcoinServiceBumpFeeProcedure,
		svc.BumpFee,
		connect.WithSchema(bitcoinServiceBumpFeeMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceEstimateSmartFeeHandler := connect.NewUnaryHandler(
		BitcoinServiceEstimateSmartFeeProcedure,
		svc.EstimateSmartFee,
		connect.WithSchema(bitcoinServiceEstimateSmartFeeMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceImportDescriptorsHandler := connect.NewUnaryHandler(
		BitcoinServiceImportDescriptorsProcedure,
		svc.ImportDescriptors,
		connect.WithSchema(bitcoinServiceImportDescriptorsMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetDescriptorInfoHandler := connect.NewUnaryHandler(
		BitcoinServiceGetDescriptorInfoProcedure,
		svc.GetDescriptorInfo,
		connect.WithSchema(bitcoinServiceGetDescriptorInfoMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetRawTransactionHandler := connect.NewUnaryHandler(
		BitcoinServiceGetRawTransactionProcedure,
		svc.GetRawTransaction,
		connect.WithSchema(bitcoinServiceGetRawTransactionMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceDecodeRawTransactionHandler := connect.NewUnaryHandler(
		BitcoinServiceDecodeRawTransactionProcedure,
		svc.DecodeRawTransaction,
		connect.WithSchema(bitcoinServiceDecodeRawTransactionMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	bitcoinServiceGetBlockHandler := connect.NewUnaryHandler(
		BitcoinServiceGetBlockProcedure,
		svc.GetBlock,
		connect.WithSchema(bitcoinServiceGetBlockMethodDescriptor),
		connect.WithHandlerOptions(opts...),
	)
	return "/bitcoin.bitcoind.v1alpha.BitcoinService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case BitcoinServiceGetBlockchainInfoProcedure:
			bitcoinServiceGetBlockchainInfoHandler.ServeHTTP(w, r)
		case BitcoinServiceGetTransactionProcedure:
			bitcoinServiceGetTransactionHandler.ServeHTTP(w, r)
		case BitcoinServiceListSinceBlockProcedure:
			bitcoinServiceListSinceBlockHandler.ServeHTTP(w, r)
		case BitcoinServiceGetNewAddressProcedure:
			bitcoinServiceGetNewAddressHandler.ServeHTTP(w, r)
		case BitcoinServiceGetWalletInfoProcedure:
			bitcoinServiceGetWalletInfoHandler.ServeHTTP(w, r)
		case BitcoinServiceGetBalancesProcedure:
			bitcoinServiceGetBalancesHandler.ServeHTTP(w, r)
		case BitcoinServiceSendProcedure:
			bitcoinServiceSendHandler.ServeHTTP(w, r)
		case BitcoinServiceBumpFeeProcedure:
			bitcoinServiceBumpFeeHandler.ServeHTTP(w, r)
		case BitcoinServiceEstimateSmartFeeProcedure:
			bitcoinServiceEstimateSmartFeeHandler.ServeHTTP(w, r)
		case BitcoinServiceImportDescriptorsProcedure:
			bitcoinServiceImportDescriptorsHandler.ServeHTTP(w, r)
		case BitcoinServiceGetDescriptorInfoProcedure:
			bitcoinServiceGetDescriptorInfoHandler.ServeHTTP(w, r)
		case BitcoinServiceGetRawTransactionProcedure:
			bitcoinServiceGetRawTransactionHandler.ServeHTTP(w, r)
		case BitcoinServiceDecodeRawTransactionProcedure:
			bitcoinServiceDecodeRawTransactionHandler.ServeHTTP(w, r)
		case BitcoinServiceGetBlockProcedure:
			bitcoinServiceGetBlockHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// UnimplementedBitcoinServiceHandler returns CodeUnimplemented from all methods.
type UnimplementedBitcoinServiceHandler struct{}

func (UnimplementedBitcoinServiceHandler) GetBlockchainInfo(context.Context, *connect.Request[v1alpha.GetBlockchainInfoRequest]) (*connect.Response[v1alpha.GetBlockchainInfoResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetBlockchainInfo is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetTransaction(context.Context, *connect.Request[v1alpha.GetTransactionRequest]) (*connect.Response[v1alpha.GetTransactionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetTransaction is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) ListSinceBlock(context.Context, *connect.Request[v1alpha.ListSinceBlockRequest]) (*connect.Response[v1alpha.ListSinceBlockResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.ListSinceBlock is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetNewAddress(context.Context, *connect.Request[v1alpha.GetNewAddressRequest]) (*connect.Response[v1alpha.GetNewAddressResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetNewAddress is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetWalletInfo(context.Context, *connect.Request[v1alpha.GetWalletInfoRequest]) (*connect.Response[v1alpha.GetWalletInfoResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetWalletInfo is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetBalances(context.Context, *connect.Request[v1alpha.GetBalancesRequest]) (*connect.Response[v1alpha.GetBalancesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetBalances is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) Send(context.Context, *connect.Request[v1alpha.SendRequest]) (*connect.Response[v1alpha.SendResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.Send is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) BumpFee(context.Context, *connect.Request[v1alpha.BumpFeeRequest]) (*connect.Response[v1alpha.BumpFeeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.BumpFee is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) EstimateSmartFee(context.Context, *connect.Request[v1alpha.EstimateSmartFeeRequest]) (*connect.Response[v1alpha.EstimateSmartFeeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.EstimateSmartFee is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) ImportDescriptors(context.Context, *connect.Request[v1alpha.ImportDescriptorsRequest]) (*connect.Response[v1alpha.ImportDescriptorsResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.ImportDescriptors is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetDescriptorInfo(context.Context, *connect.Request[v1alpha.GetDescriptorInfoRequest]) (*connect.Response[v1alpha.GetDescriptorInfoResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetDescriptorInfo is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetRawTransaction(context.Context, *connect.Request[v1alpha.GetRawTransactionRequest]) (*connect.Response[v1alpha.GetRawTransactionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetRawTransaction is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) DecodeRawTransaction(context.Context, *connect.Request[v1alpha.DecodeRawTransactionRequest]) (*connect.Response[v1alpha.DecodeRawTransactionResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.DecodeRawTransaction is not implemented"))
}

func (UnimplementedBitcoinServiceHandler) GetBlock(context.Context, *connect.Request[v1alpha.GetBlockRequest]) (*connect.Response[v1alpha.GetBlockResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("bitcoin.bitcoind.v1alpha.BitcoinService.GetBlock is not implemented"))
}
