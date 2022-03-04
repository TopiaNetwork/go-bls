BINARY_NAME="bls.elf"

default:
	echo ${BINARY_NAME}
	
lib:
	cd ./bls && make -C mcl lib/libmcl.a && make BLS_ETH=1 lib/libbls384_256.a
	
build: lib
	go build -o ./bin/$(BINARY_NAME)
	./bin/$(BINARY_NAME)

test: lib
	go test -v ./bls_go