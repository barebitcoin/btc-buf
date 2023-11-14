module github.com/barebitcoin/btc-buf

go 1.20

replace github.com/btcsuite/btcd => github.com/barebitcoin/btcd v0.23.5-0.20231114074550-41887b757ddd

require (
	connectrpc.com/connect v1.11.1
	connectrpc.com/grpchealth v1.3.0
	connectrpc.com/grpcreflect v1.2.0
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcutil v1.1.3
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.2
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/gorilla/mux v1.8.0
	github.com/jessevdk/go-flags v1.5.0
	github.com/oklog/ulid/v2 v2.1.0
	github.com/rs/zerolog v1.31.0
	github.com/samber/lo v1.38.1
	golang.org/x/net v0.17.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2 // indirect
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd // indirect
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/exp v0.0.0-20220303212507-bbda1eaf7a17 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
)
