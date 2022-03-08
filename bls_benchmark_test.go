package bls

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"
)

func BenchmarkInitialization(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Initialization(MCL_BN254)
	}
}

func BenchmarkSetSecKey(b *testing.B) {
	Initialization(MCL_BN254)
	var sec SecretKey
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sec.SetByCSPRNG()
	}
}

func BenchmarkGetPubKey(b *testing.B) {
	Initialization(MCL_BN254)
	var sec SecretKey
	sec.SetByCSPRNG()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sec.GetPublicKey()
	}
}

func BenchmarkSign(b *testing.B) {
	Initialization(MCL_BN254)
	var sec SecretKey
	sec.SetByCSPRNG()
	msg := "msg for sign"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sec.Sign(msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	Initialization(MCL_BN254)
	var sec SecretKey
	sec.SetByCSPRNG()
	var pub PublicKey = *sec.GetPublicKey()
	msg := "msg for sign"
	var sig Signature = *sec.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sig.Verify(&pub, msg)
	}
}

//Performance Test--Test for n pairs of sec keys, pub keys and signatures
func BenchmarkAggSign(b *testing.B) {
	benchmarkAggSign(b, 10)
}

func benchmarkAggSign(b *testing.B, n int) {
	Initialization(MCL_BN254)

	var secVec = make([]SecretKey, n)
	var pubVec = make([]PublicKey, n)
	var sigVec = make([]Signature, n)

	msg := "msg to test"

	for i := 0; i < n; i++ {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *(secVec[i].GetPublicKey())
		sigVec[i] = *(secVec[i].Sign(msg))
	}

	var aggSig Signature
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggSig.AggregateSignature(sigVec)
	}

}

func BenchmarkAggVerify(b *testing.B) {
	benchmarkAggVerify(b, 10)
}

func benchmarkAggVerify(b *testing.B, n int) {
	Initialization(MCL_BN254)

	var secVec = make([]SecretKey, n)
	var pubVec = make([]PublicKey, n)
	var sigVec = make([]Signature, n)

	msg := "msg to test"

	for i := 0; i < n; i++ {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *(secVec[i].GetPublicKey())
		sigVec[i] = *(secVec[i].Sign(msg))
	}

	var aggSig Signature
	aggSig.AggregateSignature(sigVec)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if aggSig.FastAggregateVerify(pubVec[:], []byte(msg)) != true {
			b.Errorf("FastAggregateVerify err")
		}
	}

}

func BenchmarkSignHash(b *testing.B) {
	algo := "sha256"
	msgToHash := "msg to hash"
	Initialization(MCL_BN254)

	var sk SecretKey
	sk.SetByCSPRNG()

	var msgHash hash.Hash
	switch algo {
	case "sha1":
		msgHash = sha1.New()
	case "sha256":
		msgHash = sha256.New()
	case "sha512":
		msgHash = sha512.New()
	case "md5":
		msgHash = md5.New()
	default:
		b.Error("Input encrypt algo err or not support\n")
		return
	}
	_, err := msgHash.Write([]byte(msgToHash))
	if err != nil {
		b.Error("Algorithm:", algo, "hash err\n")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.SignHash(msgHash.Sum(nil))
	}

}

func BenchmarkVerifyHash(b *testing.B) {
	algo := "sha256"
	msgToHash := "msg to hash"
	Initialization(MCL_BN254)

	var sk SecretKey
	var pk PublicKey
	var sig Signature

	sk.SetByCSPRNG()
	pk = *sk.GetPublicKey()

	var msgHash hash.Hash
	switch algo {
	case "sha1":
		msgHash = sha1.New()
	case "sha256":
		msgHash = sha256.New()
	case "sha512":
		msgHash = sha512.New()
	case "md5":
		msgHash = md5.New()
	default:
		b.Error("Input encrypt algo err or not support\n")
		return
	}
	_, err := msgHash.Write([]byte(msgToHash))
	if err != nil {
		b.Error("Algorithm:", algo, "hash err\n")
	}

	sig = *sk.SignHash(msgHash.Sum(nil))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if sig.VerifyHash(&pk, msgHash.Sum(nil)) != true {
			b.Error("Algorithm:", algo, "SignHash and VerifyHash err\n")
		}
	}

}

func BenchmarkVerifyAggHashes(b *testing.B) {
	benchmarkVerifyAggHashes(b, 10, "sha256")
}

func benchmarkVerifyAggHashes(b *testing.B, n int, algo string) {
	Initialization(MCL_BN254)

	var secVec = make([]SecretKey, n)
	var pubVec = make([]PublicKey, n)
	var MsgHashVec = make([][]byte, n)
	var sigVec = make([]Signature, n)
	var aggSig Signature

	var msg = make([]string, n)
	for i := 0; i < n; i++ {
		msg[i] = fmt.Sprintf("this is msg %d", i)
	}

	for i := range secVec {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *secVec[i].GetPublicKey()
		MsgHashVec[i] = hashSelect([]byte(msg[i]), algo)
		sigVec[i] = *secVec[i].SignHash(MsgHashVec[i])
	}

	aggSig = sigVec[0]
	for i := 1; i < n; i++ {
		aggSig.Add(&sigVec[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if aggSig.VerifyAggregateHashes(pubVec, MsgHashVec) != true {
			b.Error("testVerifyAggregateHashes err")
		}
	}
}

func BenchmarkKofNSetSec(b *testing.B) {
	benchmarkKofNSetSec(b, 10, 50)
}

func benchmarkKofNSetSec(b *testing.B, k int, n int) {
	var msk = make([]SecretKey, k)

	Initialization(MCL_BN254)

	for i := range msk {
		msk[i].SetByCSPRNG()
	}

	var nSk = make([]SecretKey, n)
	var ids = make([]ID, n)
	for i := range ids {
		ids[i].SetInt(i + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nSk[0].Set(msk, &ids[0])
	}
}

func BenchmarkKofNVerify(b *testing.B) {
	benchmarkKofNVerify(b, 10, 50)
}

func benchmarkKofNVerify(b *testing.B, k int, n int) {
	var msk = make([]SecretKey, k)

	Initialization(MCL_BN254)

	for i := range msk {
		msk[i].SetByCSPRNG()
	}

	var nSk = make([]SecretKey, n)
	var ids = make([]ID, n)
	var nPk = make([]PublicKey, n)
	var nSig = make([]Signature, n)
	for i := range ids {
		ids[i].SetInt(i + 1)
	}
	msg := "test msg"
	for i := range nSk {
		nSk[i].Set(msk, &ids[i])
		nPk[i] = *nSk[i].GetPublicKey()
		nSig[i] = *nSk[i].Sign(msg)
	}

	var tempSig Signature

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if tempSig.Recover(nSig[:k], ids[:k]) != nil {
			b.Error("test: Test KofN recover failed.")
		}
	}
}
