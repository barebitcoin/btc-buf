package server

import (
	"testing"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
)

// The reply's shape is Core 32.1's listsinceblock (help listsinceblock): a
// confirmed receive with parent_descs, an unconfirmed send with
// trusted/mempoolconflicts, and a removed transaction from a detached block.
func TestListSinceBlockMapsCoreFields(t *testing.T) {
	const (
		desc       = "wpkh([d34db33f/84h/0h/0h]xpub6Cexample/0/*)#abcdefgh"
		otherTxid  = "cc00000000000000000000000000000000000000000000000000000000000003"
		lastBlock  = "dd00000000000000000000000000000000000000000000000000000000000004"
		conflictTx = "ee00000000000000000000000000000000000000000000000000000000000005"
	)
	result := map[string]any{
		"transactions": []any{
			map[string]any{
				"address": "bc1qexample", "category": "receive", "amount": 0.5, "vout": 1,
				"confirmations": 3, "blockhash": testBlockHash, "blockheight": 900000,
				"blockindex": 7, "blocktime": 1700000000, "txid": testTxid, "wtxid": testTxid,
				"walletconflicts": []any{}, "mempoolconflicts": []any{}, "time": 1700000000,
				"timereceived": 1700000000, "bip125-replaceable": "no", "abandoned": false,
				"parent_descs": []any{desc},
			},
			map[string]any{
				"address": "bc1qother", "category": "send", "amount": -0.1, "vout": 0, "fee": -0.0001,
				"confirmations": 0, "trusted": false, "txid": otherTxid, "wtxid": otherTxid,
				"walletconflicts": []any{}, "mempoolconflicts": []any{conflictTx}, "time": 1700000100,
				"timereceived": 1700000100, "bip125-replaceable": "yes", "abandoned": true,
			},
		},
		"removed": []any{
			map[string]any{
				"address": "bc1qexample", "category": "receive", "amount": 0.2, "vout": 0,
				"confirmations": 0, "trusted": true, "txid": conflictTx, "wtxid": conflictTx,
				"walletconflicts": []any{}, "mempoolconflicts": []any{}, "time": 1700000050,
				"timereceived": 1700000050, "bip125-replaceable": "unknown", "abandoned": false,
				"parent_descs": []any{desc},
			},
		},
		"lastblock": lastBlock,
	}

	core := &fakeCore{responses: map[string]fakeResponse{"listsinceblock@w": {result: result}}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).ListSinceBlock(t.Context(), &pb.ListSinceBlockRequest{
		Wallet: "w", Hash: testBlockHash, TargetConfirmations: 6, IncludeChange: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.GetLastBlock() != lastBlock {
		t.Errorf("last_block: got %q, want %q", res.GetLastBlock(), lastBlock)
	}
	if len(res.GetTransactions()) != 2 || len(res.GetRemoved()) != 1 {
		t.Fatalf("got %d transactions and %d removed, want 2 and 1", len(res.GetTransactions()), len(res.GetRemoved()))
	}

	receive := res.GetTransactions()[0]
	if receive.BlockHeight == nil || receive.GetBlockHeight() != 900000 {
		t.Errorf("block_height: got %v, want 900000", receive.BlockHeight)
	}
	if receive.Trusted != nil {
		t.Error("trusted is set for a confirmed transaction; Core leaves it out")
	}
	if receive.GetWtxid() != testTxid {
		t.Errorf("wtxid: got %q", receive.GetWtxid())
	}
	if got := receive.GetDetails()[0].GetParentDescs(); len(got) != 1 || got[0] != desc {
		t.Errorf("parent_descs: got %v", got)
	}

	send := res.GetTransactions()[1]
	if send.BlockHeight != nil {
		t.Error("block_height is set for an unconfirmed transaction")
	}
	if send.Trusted == nil || send.GetTrusted() {
		t.Errorf("trusted: got %v, want false", send.Trusted)
	}
	if !send.GetAbandoned() {
		t.Error("abandoned: got false")
	}
	if got := send.GetMempoolConflicts(); len(got) != 1 || got[0] != conflictTx {
		t.Errorf("mempool_conflicts: got %v", got)
	}

	removed := res.GetRemoved()[0]
	if removed.GetTxid() != conflictTx || !removed.GetTrusted() {
		t.Errorf("removed: got txid %q trusted %v", removed.GetTxid(), removed.GetTrusted())
	}
}
