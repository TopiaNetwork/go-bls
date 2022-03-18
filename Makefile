BINARY_NAME="bls.elf"
CTAG_256=bn256
CTAG_384=bn384
CTAG_384_256=bn384_256
	
lib:
	cd ./bls && make -C mcl lib/libmcl.a && make BLS_ETH=1 lib/libbls256.a \
	&& make BLS_ETH=1 lib/libbls384.a && make BLS_ETH=1 lib/libbls384_256.a
	
lib256:
	cd ./bls && make -C mcl lib/libmcl.a && make BLS_ETH=1 lib/libbls256.a
	
lib384:
	cd ./bls && make -C mcl lib/libmcl.a && make BLS_ETH=1 lib/libbls384.a
	
lib384_256:
	cd ./bls && make -C mcl lib/libmcl.a && make BLS_ETH=1 lib/libbls384_256.a
	
build256:
	cd ./testMain && go build -tags=$(CTAG_256) -o ../bin/$(BINARY_NAME)
build384:
	cd ./testMain && go build -tags=$(CTAG_384) -o ../bin/$(BINARY_NAME)
build384_256:
	cd ./testMain && go build -tags=$(CTAG_384_256) -o ../bin/$(BINARY_NAME)
	
build: build384_256
	echo "Use build384_256 as default \nIf you need to build with other Lib, try other command such as \"make build384\" "

test:
	echo "Test Lib256:"
	go test -tags=$(CTAG_256) -v
	echo "Test Lib384:"
	go test -tags=$(CTAG_384) -v
	echo "Test Lib384_256:"
	go test -tags=$(CTAG_384_256) -v

test256:
	echo "Test Lib256:"
	go test -tags=$(CTAG_256) -v

test384:
	echo "Test Lib384:"
	go test -tags=$(CTAG_384) -v

test384_256:
	echo "Test Lib384_256:"
	go test -tags=$(CTAG_384_256) -v
	
benchmark:
	echo "Benchmark Lib256:"
	go test -tags=$(CTAG_256) -bench=.
	echo "Benchmark Lib384:"
	go test -tags=$(CTAG_384) -bench=.
	echo "Benchmark Lib384_256:"
	go test -tags=$(CTAG_384_256) -bench=.

benchmark256:
	echo "Benchmark Lib256:"
	go test -tags=$(CTAG_256) -bench=.
	
benchmark384:
	echo "Benchmark Lib384:"
	go test -tags=$(CTAG_384) -bench=.
	
benchmark384_256:
	echo "Benchmark Lib384_256:"
	go test -tags=$(CTAG_384_256) -bench=.