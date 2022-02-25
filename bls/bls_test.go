package bls

import (
	"testing"
)

/*
to do:
	test isZero
	test isEqual
	test blsSecretKeyShare blsPublicKeyShare ps:id怎么生成

	blsSecretKeyRecover
	blsPublicKeyRecover
	blsSignatureRecover

*/

//测试签名、验签
func TestSignAndVerify(t *testing.T) {
	Initialization()

	var sec SecretKey
	var pub *PublicKey
	var sig *Signature
	var msg []string = []string{
		0: "msg string 0",
		1: "msg string 1",
		2: "msg string 2",
		3: "to be add...",
	}
	for k, _ := range msg {
		sec.SetByCSPRNG()
		pub = sec.GetPublicKey()
		sig = sec.Sign(msg[k])
		if ok := sig.Verify(pub, msg[k]); !ok {
			t.Error("message:<", msg[k], "> sign and verify failed\n")
		}
	}

}

//需增加ID部分
func TestSerializeAndDe(t *testing.T) {
	Initialization()

	var sec SecretKey
	var pub *PublicKey
	var sig *Signature

	sec.SetByCSPRNG()
	pub = sec.GetPublicKey()
	msg := "test msg"
	sig = sec.Sign(msg)

	if sec.Deserialize(sec.Serialize()) != nil {
		t.Error("Secret Key deserialized err")
	}
	if pub.Deserialize(pub.Serialize()) != nil {
		t.Error("Public Key deserialized err")
	}
	if sig.Deserialize(sig.Serialize()) != nil {
		t.Error("Signature Key deserialized err")
	}
}

//测试合签、合验
func TestAggSigAndVerify(t *testing.T) {
	Initialization()

	var secVec [3]SecretKey
	var pubVec [3]PublicKey
	var sigVec [3]Signature

	msg := []string{
		"test msg1",
		"test msg2",
		"test msg3",
		"to be add...",
	}

	for k, v := range msg {
		for i := 0; i < 3; i++ {
			secVec[i].SetByCSPRNG()
			pubVec[i] = *(secVec[i].GetPublicKey())
			sigVec[i] = *(secVec[i].Sign(msg[k]))
		}

		var aggSig Signature
		aggSig.AggregateSignature(sigVec[:])

		if aggSig.FastAggregateVerify(pubVec[:], []byte(v)) != true {
			t.Errorf("msgIndex: <%d> failed", k)
		}
	}
}

func TestKofN(t *testing.T) {
	var msk [5]SecretKey //k

	Initialization()

	for k, _ := range msk {
		msk[k].SetByCSPRNG()
	}

	var nSk [10]SecretKey //n
	var ids [10]ID
	var nPk [10]PublicKey
	var nSig [10]Signature
	for k, _ := range ids {
		ids[k].SetInt(k + 1)
	}
	msg := "test msg"
	for k, _ := range nSk {
		nSk[k].Set(msk[:], &ids[k])
		nPk[k] = *nSk[k].GetPublicKey()
		nSig[k] = *nSk[k].Sign(msg)
	}

	var tempSig Signature
	if tempSig.Recover(nSig[:5], ids[:5]) != nil {
		t.Error("test: TestKofN failed.")
	}
}

//性能测试--入口
func TestPerformance(t *testing.T) {
	testInitializationForXTimes(t, 10000)
}

//性能测试--测试X次初始化需要的时间
func testInitializationForXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testInitializationForXTimes. Wrong Input Number")
		return
	}
	//timeStart := time.Now().Second()
	for i := 0; i < x; i++ {
		Initialization()
	}
	//timeEnd := time.Now().Second()
	//fmt.Println("1万次初始化循环用时:", timeEnd-timeStart, "s")
}
