# `btc-buf`

`btc-buf` is a lightweight wrapper that sits in front of a Bitcoin Core node,
and serves its API over [Connect](https://connectrpc.com/) and gRPC, making it
easy to consume the Bitcoin Core API in any language.

Not all RPCs are implemented, tailored to the needs of the author.

## Running

Build from source with `just build` (or `go build -C cmd/btc-buf`), or use the
Docker image
[`barebitcoin/btc-buf`](https://hub.docker.com/repository/docker/barebitcoin/btc-buf/general).

The command line lives in its own module under `cmd/btc-buf`, so using
`btc-buf` as a library doesn't pull in its dependencies.

```bash
$ btc-buf --bitcoind.network=signet --listen=localhost:5080
```

Run `btc-buf -h` for all options.

## Consuming

The server supports gRPC reflection, so clients like `buf curl` and `grpcurl`
can discover the API without the schema:

```bash
$ buf curl --list-methods http://localhost:5080
$ buf curl http://localhost:5080/bitcoin.bitcoind.v1.BitcoinService/GetBlockchainInfo
```

From Go, `server.NewBitcoind` runs the proxy in-process: call it through
`connectinprocess.New(b.Server())`, without any network hop.
