package server

import (
	"encoding/json"
	"testing"

	"github.com/barebitcoin/btc-buf/rpcclient/btcjson"
)

// One transaction of a getblock verbosity 3 answer.
const blockTransactionJSON = `{
  "txid": "6c8a1a2d5f4f4d6a9b0f1e2c3d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6",
  "hash": "6c8a1a2d5f4f4d6a9b0f1e2c3d4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c7",
  "version": 2,
  "size": 226,
  "vsize": 144,
  "weight": 574,
  "locktime": 0,
  "fee": 0.00012345,
  "vin": [
    {
      "txid": "1111111111111111111111111111111111111111111111111111111111111111",
      "vout": 0,
      "scriptSig": {"asm": "sig", "hex": "483045"},
      "sequence": 4294967293,
      "prevout": {
        "generated": false,
        "height": 800000,
        "value": 0.5,
        "scriptPubKey": {"type": "witness_v0_keyhash", "hex": "0014abcd"}
      }
    }
  ],
  "vout": [
    {
      "value": 0,
      "n": 0,
      "scriptPubKey": {"type": "nulldata", "asm": "OP_RETURN 6a4c", "hex": "6a4c0568656c6c6f"}
    }
  ]
}`

func TestBlockTransactionProto(t *testing.T) {
	var raw btcjson.TxRawResult
	if err := json.Unmarshal([]byte(blockTransactionJSON), &raw); err != nil {
		t.Fatal(err)
	}

	tx := blockTransactionProto(raw, 0)

	if tx.Fee != 0.00012345 {
		t.Errorf("fee: got %v, want 0.00012345", tx.Fee)
	}
	if tx.Txid != raw.Txid {
		t.Errorf("txid: got %q, want %q", tx.Txid, raw.Txid)
	}
	if tx.Vsize != 144 {
		t.Errorf("vsize: got %d, want 144", tx.Vsize)
	}
	if len(tx.Outputs) != 1 {
		t.Fatalf("outputs: got %d, want 1", len(tx.Outputs))
	}
	// An OP_RETURN reader takes the script off the output itself.
	if got := tx.Outputs[0].ScriptPubKey.Hex; got != "6a4c0568656c6c6f" {
		t.Errorf("output script hex: got %q", got)
	}
	if got := tx.Outputs[0].ScriptPubKey.Type; got != "nulldata" {
		t.Errorf("output script type: got %q", got)
	}
	if len(tx.Inputs) != 1 {
		t.Fatalf("inputs: got %d, want 1", len(tx.Inputs))
	}
	if got := tx.Inputs[0].PreviousOutput.GetAmount(); got != 0.5 {
		t.Errorf("prevout amount: got %v, want 0.5", got)
	}
}

// A coinbase carries no fee, and Core leaves the field out.
func TestBlockTransactionProtoCoinbase(t *testing.T) {
	const coinbase = `{
      "txid": "aa",
      "vin": [{"coinbase": "03", "sequence": 4294967295}],
      "vout": [{"value": 3.125, "n": 0, "scriptPubKey": {"type": "witness_v0_keyhash", "hex": "0014ff"}}]
    }`

	var raw btcjson.TxRawResult
	if err := json.Unmarshal([]byte(coinbase), &raw); err != nil {
		t.Fatal(err)
	}

	tx := blockTransactionProto(raw, 0)
	if tx.Fee != 0 {
		t.Errorf("fee: got %v, want 0", tx.Fee)
	}
	if tx.Inputs[0].Coinbase != "03" {
		t.Errorf("coinbase: got %q, want %q", tx.Inputs[0].Coinbase, "03")
	}
}
