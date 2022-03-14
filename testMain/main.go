package main

import (
	"fmt"
	"github.com/TopiaNetwork/go-bls"
)

func main() {

	bls.Initialization(bls.MCL_BN254)
	var sec bls.SecretKey
	sec = *bls.CreateSecretKey()
	fmt.Printf("sec:%s\n", sec.SerializeToHexStr())
	pub := sec.GetPublicKey()
	fmt.Printf("pub:%s\n", pub.SerializeToHexStr())

	var sec2 bls.SecretKey
	//sec = *bls.CreateSecretKey()
	fmt.Printf("sec2:%s\n", sec2.SerializeToHexStr())
	pub2 := sec2.GetPublicKey()
	fmt.Printf("pub2:%s\n", pub2.SerializeToHexStr())
	fmt.Println("sec2 is zero: ", sec2.IsZero())
	fmt.Println("sec2 is zero: ", pub2.IsZero())
	msg := "msg"
	sig2 := sec2.Sign(msg)
	fmt.Printf("sig2:%s\n", sig2.SerializeToHexStr())
	fmt.Println("sig2 is zero: ", sig2.IsZero())
	func(i interface{}) {

	}(pub2)

	msgTbl := []string{"abc", "def", "123"}
	n := len(msgTbl)
	sigVec := make([]*bls.Signature, n)
	for i := 0; i < n; i++ {
		m := msgTbl[i]
		sigVec[i] = sec.Sign(m)
		fmt.Printf("%d. sign(%s)=%s\n", i, m, sigVec[i].SerializeToHexStr())
	}
	for i := range sigVec {
		if sigVec[i].Verify(pub, msgTbl[i]) == true {
			fmt.Printf("Verify sign for msg %d success.\n", i)
		} else {
			fmt.Printf("Verify sign for msg %d failed.\n", i)
		}

	}

	aggN := 6
	var secVecForAgg = make([]bls.SecretKey, aggN)
	var pubVecForAgg = make([]bls.PublicKey, aggN)
	var sigVecForAgg = make([]bls.Signature, aggN)

	for k, v := range msgTbl {
		for i := 0; i < aggN; i++ {
			secVecForAgg[i] = *bls.CreateSecretKey()
			pubVecForAgg[i] = *(secVecForAgg[i].GetPublicKey())
			sigVecForAgg[i] = *(secVecForAgg[i].Sign(msgTbl[k]))
		}

		var aggSig bls.Signature
		aggSig.AggregateSignature(sigVecForAgg)

		if aggSig.FastAggregateVerify(pubVecForAgg, []byte(v)) == true {
			fmt.Printf("msgTblIndex: <%d> AggregateVerify success\n", k)
		} else {
			fmt.Printf("msgTblIndex: <%d> AggregateVerify failed\n", k)
		}
	}
}
