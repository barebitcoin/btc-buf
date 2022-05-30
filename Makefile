BIN := btc-buf

build: 
	go build -v -o ./$(BIN) .

proto-format: 
	buf format -w proto

clean: 
	rm -rf $(BIN) gen