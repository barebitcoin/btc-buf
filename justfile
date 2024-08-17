bin := "btc-buf"

gen: 
	buf generate

build: 
	go build -v -o ./{{ bin }} .

lint: 
	golangci-lint run .

proto-format: 
	buf format -w proto

clean: 
	rm -rf {{ bin }} gen
	
image: 
	docker buildx build --progress plain --platform linux/amd64 -t barebitcoin/btc-buf:$(git rev-parse --short HEAD) .
	
image-push: image
	docker push barebitcoin/btc-buf:$(git rev-parse --short HEAD) 
