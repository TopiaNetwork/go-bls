package main

import (
	"fmt"
	"github.com/TopiaNetwork/go-bls"
)

func main() {

	bls.Initialization(bls.MCL_BN254)
	fmt.Println("main func output ok")

}
