module github.com/barebitcoin/btc-buf

go 1.20

replace github.com/btcsuite/btcd => github.com/barebitcoin/btcd v0.23.5-0.20240104102729-54d89f81a6cf

require (
	connectrpc.com/connect v1.14.0
	connectrpc.com/grpchealth v1.3.0
	connectrpc.com/grpcreflect v1.2.0
	github.com/btcsuite/btcd v0.23.5-0.20231215221805-96c9fd8078fd
	github.com/btcsuite/btcd/btcutil v1.1.4
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/gorilla/mux v1.8.1
	github.com/jessevdk/go-flags v1.5.0
	github.com/oklog/ulid/v2 v2.1.0
	github.com/rs/zerolog v1.31.0
	github.com/samber/lo v1.39.0
	golang.org/x/net v0.19.0
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/crypto v0.17.0 // indirect
	golang.org/x/exp v0.0.0-20231226003508-02704c960a9b // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
