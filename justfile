bin := "btc-buf"

gen:
    buf format -w proto
    buf generate --template buf.gen.yaml
    go mod tidy
    cd cmd/btc-buf && go mod tidy

build: 
	go build -C cmd/btc-buf -v -o {{ justfile_directory() }}/{{ bin }} .

run *args:
	go run -C cmd/btc-buf -v . {{ args }}

test *args:
	go test -race {{ args }} ./...
	go test -C cmd/btc-buf -race {{ args }} ./...

lint args='': 
	golangci-lint run {{ args }}
	cd cmd/btc-buf && golangci-lint run {{ args }}

format: format-go format-proto

format-go:
	WRITE=1 bash scripts/check-goimports.sh
	WRITE=1 bash scripts/check-gogroup.sh

format-proto:
	buf format -w proto

clean: 
	rm -rf {{ bin }} gen
	
image: 
	docker buildx build --progress plain --platform linux/amd64 -t barebitcoin/btc-buf:$(git rev-parse --short HEAD) .
	
image-push: image
	docker push barebitcoin/btc-buf:$(git rev-parse --short HEAD) 

[positional-arguments]
curl *args='':
  #!/usr/bin/env bash
  set -euo pipefail

  url=""
  rest=()

  for a in "$@"; do
    if [[ -z "$url" && "$a" == /* ]]; then
      url="http://localhost:5080$a"
    else
      rest+=("$a")
    fi
  done

  [[ -n "$url" ]] || { echo "Error: No service URL found" >&2; exit 1; }

  buf curl --schema . --timeout=30m --emit-defaults "$url" "${rest[@]}"
