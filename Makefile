BIN := btc-buf

build: 
	go build -v -o ./$(BIN) .

proto-format: 
	buf format -w proto

clean: 
	rm -rf $(BIN) gen
	
image: 
	docker build -t barebitcoin/btc-buf:$(shell git rev-parse --short HEAD) .