bin := "btc-buf"

gen:
    buf format -w proto
    buf generate --template buf.gen.yaml
    cd gen && go mod tidy

build: 
	go build -v -o ./{{ bin }} .

lint: 
	golangci-lint run --exclude-dirs gen

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

