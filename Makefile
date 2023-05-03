BIN := btc-buf

build: 
	go build -v -o ./$(BIN) .

proto-format: 
	buf format -w proto

clean: 
	rm -rf $(BIN) gen
	
image: 
	docker buildx build --platform linux/amd64 -t barebitcoin/btc-buf:$(shell git rev-parse --short HEAD) .