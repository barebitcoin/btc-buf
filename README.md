# `btc-buf`

| The last goddamn time I'm coding up a RPC client for Bitcoin Core.

`btc-buf` is a lightweight wrapper that sits in front of a Bitcoin Core node,
and serves its API over gRPC. It's intended to follow best-practice gRPC
standards, and make it easy to consume the Bitcoin Core API in any language.

This project was created so that I could scratch an itch I've been having for
some time, and finally get an opportunity to play with the
[Buf Schema Registry](https://docs.buf.build/bsr/introduction).

## Ideas

- Auth. Would macaroons make sense? Could expose access to certain parts of the
  API. Read-only, for example. Could even expose the node publicly, with that
  enabled?
- Only expose _some_ APIs over the gRPC interface. Lower the attack surface for
  what can go wrong.
- Add metrics for increased insights into what's going on with your Bitcoin Core
  node.
- Transport layer security. Easily serve Bitcoin Core with SSL!
