module github.com/barebitcoin/btc-buf/cmd/btc-buf

go 1.27.3

require (
	connectrpc.com/connect/v2 v2.0.0
	connectrpc.com/grpchealth/v2 v2.0.0
	connectrpc.com/grpcreflect/v2 v2.0.0
	github.com/barebitcoin/btc-buf v0.0.0
	github.com/oklog/ulid/v2 v2.1.2
	github.com/rs/zerolog v1.35.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/btcsuite/btcd/address/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1 // indirect
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/wire/v2 v2.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// The CLI always builds against the library at the same commit.
replace github.com/barebitcoin/btc-buf => ../..
