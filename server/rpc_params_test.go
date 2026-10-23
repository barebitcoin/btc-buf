package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
	rpc "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1/bitcoindv1connect"
)

const (
	testTxid      = "aa00000000000000000000000000000000000000000000000000000000000001"
	testBlockHash = "bb00000000000000000000000000000000000000000000000000000000000002"
)

// Each request reaches Core with the positional params Core's help describes.
func TestRequestParams(t *testing.T) {
	tests := []struct {
		name   string
		key    string // response key: method, plus @wallet for a wallet endpoint
		result any
		call   func(ctx context.Context, client rpc.BitcoinServiceClient) error
		want   string
	}{
		{
			name: "createpsbt", key: "createpsbt", result: "cHNidP8=",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.CreatePsbt(ctx, &pb.CreatePsbtRequest{
					Inputs:  []*pb.TransactionInput{{Txid: testTxid, Vout: 1, Sequence: new(uint32(0))}, {Txid: testTxid, Vout: 2}},
					Outputs: map[string]float64{"bcrt1qexample": 0.1},
				})
				return err
			},
			want: `[[{"sequence":0,"txid":"` + testTxid + `","vout":1},{"txid":"` + testTxid + `","vout":2}],{"bcrt1qexample":0.1},0]`,
		},
		{
			name: "createpsbt not replaceable", key: "createpsbt", result: "cHNidP8=",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.CreatePsbt(ctx, &pb.CreatePsbtRequest{
					Inputs:      []*pb.TransactionInput{{Txid: testTxid}},
					Outputs:     map[string]float64{"bcrt1qexample": 0.1},
					Locktime:    100,
					Replaceable: new(false),
				})
				return err
			},
			want: `[[{"txid":"` + testTxid + `","vout":0}],{"bcrt1qexample":0.1},100,false]`,
		},
		{
			name: "createrawtransaction", key: "createrawtransaction", result: "0200",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				res, err := client.CreateRawTransaction(ctx, &pb.CreateRawTransactionRequest{
					Inputs:  []*pb.TransactionInput{{Txid: testTxid, Vout: 1, Sequence: new(uint32(5))}},
					Outputs: map[string]float64{"bcrt1qexample": 0.1},
				})
				if err == nil && !bytes.Equal(res.Tx.Data, []byte{0x02, 0x00}) {
					t.Errorf("createrawtransaction: unexpected tx %v", res.Tx)
				}
				return err
			},
			want: `[[{"sequence":5,"txid":"` + testTxid + `","vout":1}],{"bcrt1qexample":0.1},0]`,
		},
		{
			name: "sendrawtransaction", key: "sendrawtransaction", result: testTxid,
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.SendRawTransaction(ctx, &pb.SendRawTransactionRequest{
					Tx:            &pb.RawTransaction{Hex: "0200"},
					MaxBurnAmount: new(0.5),
				})
				return err
			},
			want: `["0200",null,0.5]`,
		},
		{
			name: "sendrawtransaction max fee rate", key: "sendrawtransaction", result: testTxid,
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.SendRawTransaction(ctx, &pb.SendRawTransactionRequest{
					Tx:         &pb.RawTransaction{Hex: "0200"},
					MaxFeeRate: new(0.2),
				})
				return err
			},
			want: `["0200",0.2]`,
		},
		{
			name: "utxoupdatepsbt", key: "utxoupdatepsbt", result: "cHNidP8=",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.UtxoUpdatePsbt(ctx, &pb.UtxoUpdatePsbtRequest{
					Psbt: "cHNidP8=",
					Descriptors: []*pb.Descriptor{
						{Desc: "addr(bcrt1qexample)"},
						{Desc: "wpkh(xpub/0/*)", Range: &pb.DescriptorRange{Begin: 1, End: 5}},
					},
				})
				return err
			},
			want: `["cHNidP8=",[{"desc":"addr(bcrt1qexample)"},{"desc":"wpkh(xpub/0/*)","range":[1,5]}]]`,
		},
		{
			name: "utxoupdatepsbt without descriptors", key: "utxoupdatepsbt", result: "cHNidP8=",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.UtxoUpdatePsbt(ctx, &pb.UtxoUpdatePsbtRequest{Psbt: "cHNidP8="})
				return err
			},
			want: `["cHNidP8="]`,
		},
		{
			name: "listunspent", key: "listunspent", result: []any{},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.ListUnspent(ctx, &pb.ListUnspentRequest{})
				return err
			},
			want: `[]`,
		},
		{
			name: "listunspent excluding unsafe", key: "listunspent", result: []any{},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.ListUnspent(ctx, &pb.ListUnspentRequest{
					MinimumConfirmations: new(uint32(0)),
					IncludeUnsafe:        new(false),
				})
				return err
			},
			want: `[0,null,null,false]`,
		},
		{
			name: "gettransaction", key: "gettransaction", result: map[string]any{"txid": testTxid},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.GetTransaction(ctx, &pb.GetTransactionRequest{Txid: testTxid})
				return err
			},
			want: `["` + testTxid + `"]`,
		},
		{
			name: "gettransaction verbose", key: "gettransaction",
			result: map[string]any{"txid": testTxid, "decoded": map[string]any{"txid": testTxid, "vsize": 141}},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				res, err := client.GetTransaction(ctx, &pb.GetTransactionRequest{Txid: testTxid, Verbose: true})
				if err == nil && (res.Decoded == nil || res.Decoded.VirtualSize != 141) {
					t.Errorf("gettransaction: unexpected decoded transaction %v", res.Decoded)
				}
				return err
			},
			want: `["` + testTxid + `",null,true]`,
		},
		{
			name: "getrawtransaction in block", key: "getrawtransaction", result: "0200",
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.GetRawTransaction(ctx, &pb.GetRawTransactionRequest{Txid: testTxid, Blockhash: testBlockHash})
				return err
			},
			want: `["` + testTxid + `",0,"` + testBlockHash + `"]`,
		},
		{
			name: "getrawtransaction verbose", key: "getrawtransaction", result: map[string]any{"txid": testTxid},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.GetRawTransaction(ctx, &pb.GetRawTransactionRequest{
					Txid: testTxid, Verbosity: pb.GetRawTransactionRequest_VERBOSITY_TX_PREVOUT_INFO,
				})
				return err
			},
			want: `["` + testTxid + `",2]`,
		},
		{
			name: "keypoolrefill", key: "keypoolrefill", result: nil,
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.KeyPoolRefill(ctx, &pb.KeyPoolRefillRequest{NewSize: 50})
				return err
			},
			want: `[50]`,
		},
		{
			// The wallet's own endpoint, whatever wallet the default one names.
			name: "unloadwallet", key: "unloadwallet@w", result: map[string]any{},
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.UnloadWallet(ctx, &pb.UnloadWalletRequest{WalletName: "w"})
				return err
			},
			want: `[]`,
		},
		{
			// Not a mainnet address: Core validates it, against its own network.
			name: "sendtoaddress", key: "sendtoaddress", result: testTxid,
			call: func(ctx context.Context, client rpc.BitcoinServiceClient) error {
				_, err := client.SendToAddress(ctx, &pb.SendToAddressRequest{
					Address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Amount: 0.1, CommentTo: "bob",
				})
				return err
			},
			want: `["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",0.1,null,"bob"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core := &fakeCore{responses: map[string]fakeResponse{tt.key: {result: tt.result}}}
			b, err := newTestBitcoind(t, core)
			if err != nil {
				t.Fatal(err)
			}

			if err := tt.call(t.Context(), inProcessClient(b)); err != nil {
				t.Fatal(err)
			}
			if got := core.lastParams(tt.key); got != tt.want {
				t.Errorf("params:\n got %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestInvalidAmounts(t *testing.T) {
	b, err := newTestBitcoind(t, &fakeCore{})
	if err != nil {
		t.Fatal(err)
	}
	client := inProcessClient(b)

	_, err = client.Send(t.Context(), &pb.SendRequest{Destinations: map[string]float64{"bcrt1qexample": 0}})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("send: expected invalid argument, got %v", err)
	}
	_, err = client.SendToAddress(t.Context(), &pb.SendToAddressRequest{Address: "bcrt1qexample", Amount: -1})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("sendtoaddress: expected invalid argument, got %v", err)
	}
}

// Core answers bad credentials with a bare HTTP 401.
func TestUnauthorized(t *testing.T) {
	b, err := newTestBitcoind(t, &fakeCore{unauthorized: true})
	if err != nil {
		t.Fatal(err)
	}
	client := inProcessClient(b)

	_, err = client.GetBlockchainInfo(t.Context(), &pb.GetBlockchainInfoRequest{})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("getblockchaininfo: expected permission denied, got %v", err)
	}
	_, err = client.ImportDescriptors(t.Context(), &pb.ImportDescriptorsRequest{
		Requests: []*pb.ImportDescriptorsRequest_Request{{Descriptor_: "addr(bcrt1qexample)"}},
	})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("importdescriptors: expected permission denied, got %v", err)
	}
}

func TestImportDescriptors(t *testing.T) {
	const secret = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
	var logs bytes.Buffer
	core := &fakeCore{responses: map[string]fakeResponse{
		"importdescriptors": {result: []any{
			map[string]any{"success": true},
			map[string]any{"success": false, "error": map[string]any{"code": -5, "message": "bad descriptor"}},
		}},
	}}
	b, err := newTestBitcoind(t, core, WithLogging(func(context.Context) *slog.Logger {
		return slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: levelTrace}))
	}))
	if err != nil {
		t.Fatal(err)
	}

	res, err := inProcessClient(b).ImportDescriptors(t.Context(), &pb.ImportDescriptorsRequest{
		Requests: []*pb.ImportDescriptorsRequest_Request{
			{Descriptor_: "wpkh(" + secret + "/0/*)", Range: &pb.DescriptorRange{Begin: 0, End: 10}},
			{Descriptor_: "addr(bcrt1qexample)"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := core.lastParams("importdescriptors"),
		`[[{"desc":"wpkh(`+secret+`/0/*)","range":[0,10],"timestamp":"now"},{"desc":"addr(bcrt1qexample)","timestamp":"now"}]]`; got != want {
		t.Errorf("params:\n got %s\nwant %s", got, want)
	}
	if len(res.Responses) != 2 || res.Responses[0].Error != nil || res.Responses[1].Error.GetMessage() != "bad descriptor" {
		t.Errorf("unexpected responses: %v", res.Responses)
	}
	if strings.Contains(logs.String(), secret) {
		t.Errorf("private key was logged:\n%s", logs.String())
	}
}

func TestListTransactionsBlockTime(t *testing.T) {
	core := &fakeCore{responses: map[string]fakeResponse{
		"listtransactions": {result: []any{map[string]any{"txid": testTxid, "category": "receive", "blocktime": 1700000000}}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).ListTransactions(t.Context(), &pb.ListTransactionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transactions) != 1 || res.Transactions[0].BlockTime.GetSeconds() != 1700000000 {
		t.Fatalf("unexpected transactions: %v", res.Transactions)
	}
}
