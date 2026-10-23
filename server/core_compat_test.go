package server

import (
	"slices"
	"testing"

	"connectrpc.com/connect/v2"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
)

// Bitcoin Core 26 replaced createwallet's warning string with an array.
func TestCreateWalletWarnings(t *testing.T) {
	core := &fakeCore{responses: map[string]fakeResponse{
		"createwallet": {result: map[string]any{"name": "w", "warnings": []string{"first", "second"}}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).CreateWallet(t.Context(), &pb.CreateWalletRequest{Name: "w"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "w" || !slices.Equal(res.Warnings, []string{"first", "second"}) {
		t.Fatalf("unexpected response: %v", res)
	}
}

// Bitcoin Core's createmultisig only takes hex-encoded public keys.
func TestCreateMultisig(t *testing.T) {
	const pubKey = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc"
	core := &fakeCore{responses: map[string]fakeResponse{
		"createmultisig": {result: map[string]any{"address": "bc1qmultisig", "redeemScript": "5121ae"}},
	}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	client := inProcessClient(b)

	res, err := client.CreateMultisig(t.Context(), &pb.CreateMultisigRequest{RequiredSigs: 1, Keys: []string{pubKey}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Address != "bc1qmultisig" || res.RedeemScript != "5121ae" {
		t.Fatalf("unexpected response: %v", res)
	}

	for _, key := range []string{"bc1qexample", "02a1", "zz"} {
		_, err := client.CreateMultisig(t.Context(), &pb.CreateMultisigRequest{RequiredSigs: 1, Keys: []string{key}})
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("key %q: expected invalid argument, got %v", key, err)
		}
	}
}
