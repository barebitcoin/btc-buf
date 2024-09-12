SHELL=bash

.PHONY: rpc

PROTO_IN = $(shell find proto -name '*.proto')

rpc: $(wildcard buf.*) $(PROTO_IN)
	buf format -w proto
	buf generate --template buf.gen.yaml
	cd gen && go mod tidy

format: format-go format-proto

format-go:
	WRITE=1 bash scripts/check-goimports.sh
	WRITE=1 bash scripts/check-gogroup.sh

format-proto:
	buf format -w proto