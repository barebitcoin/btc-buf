package server

import (
	"testing"

	pb "github.com/barebitcoin/btc-buf/gen/bitcoin/bitcoind/v1"
)

// The reply's shape is Core 32.1's getaddressinfo (help getaddressinfo), for
// an address a watch-only descriptor wallet derived from a ranged descriptor.
func TestGetAddressInfoMapsDerivation(t *testing.T) {
	const (
		address    = "bc1qexample"
		desc       = "wpkh([d34db33f/84h/0h/0h/1/7]02abcdef)#aaaaaaaa"
		parentDesc = "wpkh([d34db33f/84h/0h/0h]xpub6Cexample/1/*)#bbbbbbbb"
	)
	result := map[string]any{
		"address": address, "scriptPubKey": "0014abcd", "ismine": true, "iswatchonly": false,
		"solvable": true, "desc": desc, "parent_desc": parentDesc, "iswitness": true,
		"witness_version": 0, "witness_program": "abcd", "ischange": true,
		"timestamp": 1700000000, "hdkeypath": "m/84h/0h/0h/1/7", "hdmasterfingerprint": "d34db33f",
		"labels": []any{},
	}

	core := &fakeCore{responses: map[string]fakeResponse{"getaddressinfo@w": {result: result}}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).GetAddressInfo(t.Context(), &pb.GetAddressInfoRequest{Wallet: "w", Address: address})
	if err != nil {
		t.Fatal(err)
	}

	if res.GetDesc() != desc || res.GetParentDesc() != parentDesc {
		t.Errorf("desc %q, parent_desc %q", res.GetDesc(), res.GetParentDesc())
	}
	if res.GetHdKeyPath() != "m/84h/0h/0h/1/7" || res.GetHdMasterFingerprint() != "d34db33f" {
		t.Errorf("hd_key_path %q, hd_master_fingerprint %q", res.GetHdKeyPath(), res.GetHdMasterFingerprint())
	}
	if !res.GetIsChange() {
		t.Error("is_change: got false")
	}
	if res.GetTimestamp().GetSeconds() != 1700000000 {
		t.Errorf("timestamp: got %v", res.GetTimestamp())
	}
}

// Core leaves the derivation fields out for an address with none.
func TestGetAddressInfoWithoutDerivation(t *testing.T) {
	result := map[string]any{
		"address": "bc1qexample", "scriptPubKey": "0014abcd", "ismine": false, "iswatchonly": false,
		"solvable": false, "iswitness": true, "ischange": false, "labels": []any{},
	}
	core := &fakeCore{responses: map[string]fakeResponse{"getaddressinfo@w": {result: result}}}
	b, err := newTestBitcoind(t, core)
	if err != nil {
		t.Fatal(err)
	}
	res, err := inProcessClient(b).GetAddressInfo(t.Context(), &pb.GetAddressInfoRequest{Wallet: "w", Address: "bc1qexample"})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetParentDesc() != "" || res.GetHdKeyPath() != "" || res.Timestamp != nil {
		t.Errorf("got parent_desc %q, hd_key_path %q, timestamp %v", res.GetParentDesc(), res.GetHdKeyPath(), res.Timestamp)
	}
}
