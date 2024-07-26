bin := "btc-buf"

build: 
	go build -v -o ./{{ bin }} .

proto-format: 
	buf format -w proto

clean: 
	rm -rf {{ bin }} gen
	
image: 
	docker buildx build --platform linux/amd64 -t barebitcoin/btc-buf:$(shell git rev-parse --short HEAD) .
	
image-push: image
	docker push barebitcoin/btc-buf:$(shell git rev-parse --short HEAD) 