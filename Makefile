BIN := btc-buf

build: 
	go build -v -o ./$(BIN) .

proto-format: 
	buf format -w barebitcoin

clean: 
	rm -rf $(BIN) gen