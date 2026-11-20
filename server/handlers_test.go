package server

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/btcsuite/btcd/wire/v2"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
)

// Core only reports a range for ranged descriptors.
func TestListDescriptorsWithoutRange(t *testing.T) {
	core := &fakeCore{responses: map[string]fakeResponse{
		"listdescriptors": {result: map[string]any{
			"wallet_name": "w",
			"descriptors": []any{
				map[string]any{"desc": "wpkh(xpub/0/*)#ranged", "timestamp": 1, "active": true, "range": []int{0, 999}, "next_index": 5},
				map[string]any{"desc": "addr(bc1qexample)#single", "timestamp": 1, "active": false},
			},
		}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).ListDescriptors(t.Context(), &pb.ListDescriptorsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Descriptors) != 2 {
		t.Fatalf("expected 2 descriptors, got %v", res.Descriptors)
	}
	if r := res.Descriptors[0].Range; r == nil || r.Begin != 0 || r.End != 999 {
		t.Errorf("ranged descriptor: unexpected range %v", r)
	}
	if r := res.Descriptors[1].Range; r != nil {
		t.Errorf("single descriptor: expected no range, got %v", r)
	}
}

// Core leaves out keypoolsize_hd_internal for wallets without HD split.
func TestGetWalletInfoWithoutHDInternalKeypool(t *testing.T) {
	core := &fakeCore{responses: map[string]fakeResponse{
		"getwalletinfo": {result: map[string]any{"walletname": "w", "keypoolsize": 1000, "scanning": false}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).GetWalletInfo(t.Context(), &pb.GetWalletInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.KeyPoolSize != 1000 || res.KeyPoolSizeHdInternal != 0 {
		t.Fatalf("unexpected keypool sizes: %v", res)
	}
}

func TestTestMempoolAccept(t *testing.T) {
	var tx bytes.Buffer
	msgTx := wire.NewMsgTx(wire.TxVersion)
	msgTx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: 0}, nil, nil))
	msgTx.AddTxOut(wire.NewTxOut(1000, []byte{0x6a}))
	if err := msgTx.Serialize(&tx); err != nil {
		t.Fatal(err)
	}
	rawTx := hex.EncodeToString(tx.Bytes())

	core := &fakeCore{responses: map[string]fakeResponse{
		"getnetworkinfo": {result: map[string]any{"version": 280000, "subversion": "/Satoshi:28.0.0/"}},
		// Core only reports fees for transactions it would accept.
		"testmempoolaccept": {result: []any{map[string]any{
			"txid": msgTx.TxHash().String(), "allowed": false, "reject-reason": "missing-inputs",
		}}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	client := inProcessClient(b)

	res, err := client.TestMempoolAccept(t.Context(), &pb.TestMempoolAcceptRequest{Rawtxs: []string{rawTx}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Results) != 1 || res.Results[0].Allowed || res.Results[0].RejectReason != "missing-inputs" || res.Results[0].Fees != 0 {
		t.Fatalf("unexpected results: %v", res.Results)
	}

	_, err = client.TestMempoolAccept(t.Context(), &pb.TestMempoolAcceptRequest{Rawtxs: []string{"not hex"}})
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("non-hex transaction: expected invalid argument, got %v", err)
	}
}

func TestGetMempoolEntry(t *testing.T) {
	const txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

	t.Run("returns the entry of a transaction in the mempool", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{
			"getmempoolentry": {result: map[string]any{
				"vsize": 141, "weight": 561, "time": 1700000000, "height": 900000,
				"descendantcount": 1, "descendantsize": 141, "ancestorcount": 2, "ancestorsize": 282,
				"wtxid":   "wtxid",
				"fees":    map[string]any{"base": 0.00001, "modified": 0.00001, "ancestor": 0.00002, "descendant": 0.00001},
				"depends": []any{"parent"}, "spentby": []any{},
				"bip125-replaceable": true, "unbroadcast": false,
			}},
		}}
		b, err := newTestBitcoind(t, core)
		if err != nil {
			t.Fatal(err)
		}
		res, err := inProcessClient(b).GetMempoolEntry(t.Context(), &pb.GetMempoolEntryRequest{Txid: txid})
		if err != nil {
			t.Fatal(err)
		}
		if got := core.lastParams("getmempoolentry"); got != `["`+txid+`"]` {
			t.Errorf("params: got %s", got)
		}
		entry := res.GetEntry()
		if entry.GetVirtualSize() != 141 || entry.GetAncestorCount() != 2 || entry.GetTime().GetSeconds() != 1700000000 {
			t.Errorf("unexpected entry: %v", entry)
		}
		if entry.GetFees().GetAncestor() != 0.00002 || len(entry.GetDepends()) != 1 || !entry.GetBip125Replaceable() {
			t.Errorf("unexpected entry: %v", entry)
		}
	})

	// Core: RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool".
	t.Run("a transaction outside the mempool is not found", func(t *testing.T) {
		core := &fakeCore{responses: map[string]fakeResponse{"getmempoolentry": {code: -5}}}
		b, err := newTestBitcoind(t, core)
		if err != nil {
			t.Fatal(err)
		}
		_, err = inProcessClient(b).GetMempoolEntry(t.Context(), &pb.GetMempoolEntryRequest{Txid: txid})
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Fatalf("expected not found, got %v", err)
		}
	})

	t.Run("rejects a missing or malformed txid", func(t *testing.T) {
		b, err := newTestBitcoind(t, &fakeCore{})
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"", "not a txid"} {
			_, err = inProcessClient(b).GetMempoolEntry(t.Context(), &pb.GetMempoolEntryRequest{Txid: bad})
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Errorf("txid %q: expected invalid argument, got %v", bad, err)
			}
		}
	})
}

// Core reports ping times in decimal seconds. Its help text said ms until v30.
func TestGetPeerInfoPingTimes(t *testing.T) {
	core := &fakeCore{responses: map[string]fakeResponse{
		"getpeerinfo": {result: []any{map[string]any{"id": 1, "pingtime": 0.042, "minping": 0.0105}}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).GetPeerInfo(t.Context(), &pb.GetPeerInfoRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %v", res.Peers)
	}
	peer := res.Peers[0]
	if got := peer.PingTime.AsDuration(); got != 42*time.Millisecond {
		t.Errorf("ping time: got %s, want 42ms", got)
	}
	if got := peer.MinPing.AsDuration(); got != 10500*time.Microsecond {
		t.Errorf("min ping: got %s, want 10.5ms", got)
	}
	if peer.PingWait != nil {
		t.Errorf("ping wait: expected none, got %s", peer.PingWait.AsDuration())
	}
}
