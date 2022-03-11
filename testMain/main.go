package main

import (
	"fmt"
	"github.com/TopiaNetwork/go-bls"
)

func main() {

	bls.Initialization(bls.MCL_BN254)
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	fmt.Printf("sec:%s\n", sec.SerializeToHexStr())
	pub := sec.GetPublicKey()
	fmt.Printf("pub:%s\n", pub.SerializeToHexStr())

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
			secVecForAgg[i].SetByCSPRNG()
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