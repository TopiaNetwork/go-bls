package bls_go

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math"
	"strings"
	"testing"
	"time"
)

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

	for i, _ := range msk {
		msk[i].SetByCSPRNG()
	}

	var nSk [10]SecretKey //n
	var ids [10]ID
	var nPk [10]PublicKey
	var nSig [10]Signature
	for i, _ := range ids {
		ids[i].SetInt(i + 1)
	}
	msg := "test msg"
	for i, _ := range nSk {
		err := nSk[i].Set(msk[:], &ids[i])
		if err != nil {
			t.Error("secretKey made by k msk err")
		}
		nPk[i] = *nSk[i].GetPublicKey()
		nSig[i] = *nSk[i].Sign(msg)
	}

	var tempSig Signature
	if tempSig.Recover(nSig[:5], ids[:5]) != nil {
		t.Error("test: Test KofN failed.")
	}
}

func TestSignHashAndVerifyHash(t *testing.T) {
	algos := []string{"sha1", "sha256", "sha512", "md5"}
	msgToHash := "test msg to hash"
	n := 100 //构造n个公私钥以及信息
	for _, algo := range algos {
		testSignHashAndVerifyHash(t, algo, msgToHash)
		testVerifyAggregateHashes(t, algo, n)
	}
}

func testSignHashAndVerifyHash(t *testing.T, algo string, msgToHash string) {
	algo = strings.ToLower(algo)

	Initialization()

	var sk SecretKey
	var pk PublicKey
	var sig Signature
	//var ids [10]bls.ID
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
		t.Error("Input encrypt algo err or not support\n")
		return
	}
	_, err := msgHash.Write([]byte(msgToHash))
	if err != nil {
		t.Error("Algorithm:", algo, "hash err\n")
	}
	sig = *sk.SignHash(msgHash.Sum(nil))
	if sig.VerifyHash(&pk, msgHash.Sum(nil)) != true {
		t.Error("Algorithm:", algo, "SignHash and VerifyHash err\n")
	}

}
func testVerifyAggregateHashes(t *testing.T, algo string, n int) {
	Initialization()

	var secVec []SecretKey = make([]SecretKey, n)
	var pubVec []PublicKey = make([]PublicKey, n)
	var MsgHashVec [][]byte = make([][]byte, n)
	var sigVec []Signature = make([]Signature, n)
	var aggSig Signature

	var msg []string = make([]string, n)
	for i := 0; i < n; i++ {
		msg[i] = fmt.Sprintf("this is msg %d", i)
	}

	for i, _ := range secVec {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *secVec[i].GetPublicKey()
		MsgHashVec[i] = hashSelect([]byte(msg[i]), algo)
		sigVec[i] = *secVec[i].SignHash(MsgHashVec[i])
	}

	aggSig = sigVec[0]
	for i := 1; i < n; i++ {
		aggSig.Add(&sigVec[i])
	}
	if aggSig.VerifyAggregateHashes(pubVec, MsgHashVec) != true {
		t.Error("testVerifyAggregateHashes err")
	}
}
func hashSelect(input []byte, algo string) []byte {
	var hashMsg hash.Hash
	switch algo {
	case "sha1":
		hashMsg = sha1.New()
	case "sha256":
		hashMsg = sha256.New()
	case "sha512":
		hashMsg = sha512.New()
	case "md5":
		hashMsg = md5.New()
	default:
		hashMsg = sha256.New() //默认256
		return nil
	}
	hashMsg.Write(input)
	return hashMsg.Sum(nil)
}

func TestSerializeAndDe(t *testing.T) {
	Initialization()

	var sec SecretKey
	var pub *PublicKey
	var sig *Signature
	var id ID

	sec.SetByCSPRNG()
	pub = sec.GetPublicKey()
	msg := "test msg"
	sig = sec.Sign(msg)

	id.SetInt(10)
	if id.Deserialize(id.Serialize()) != nil {
		t.Error("id deserialized err")
	}

	if sec.Deserialize(sec.Serialize()) != nil {
		t.Error("SecretKey deserialized err")
	}
	if pub.Deserialize(pub.Serialize()) != nil {
		t.Error("PublicKey deserialized err")
	}
	if sig.Deserialize(sig.Serialize()) != nil {
		t.Error("SignatureKey deserialized err")
	}
}

func TestIsZero(t *testing.T) {
	Initialization()
	var sec SecretKey
	var pub PublicKey
	var sig Signature
	var id ID
	if sec.IsZero() && pub.IsZero() && sig.IsZero() && id.IsZero() == false {
		t.Error("function <IsZero> has problem")
	}
	sec.SetByCSPRNG()
	pub = *sec.GetPublicKey()
	msg := "test msg"
	sig = *sec.Sign(msg)
	id.SetInt(10)
	if sec.IsZero() || pub.IsZero() || sig.IsZero() || id.IsZero() == true {
		t.Error("function <IsZero> has problem")
	}
}

func TestIsEqual(t *testing.T) {

	var sec, sec2 SecretKey
	var pub, pub2 PublicKey
	var sig, sig2 Signature
	var id, id2 ID

	sec.SetByCSPRNG()
	sec2 = sec
	pub = *sec.GetPublicKey()
	pub2 = *sec2.GetPublicKey()
	msg := "test msg"
	sig = *sec.Sign(msg)
	sig2 = *sec2.Sign(msg)
	id.SetInt(10)
	id2.SetInt(10)

	if sec.IsEqual(&sec2) && pub.IsEqual(&pub2) && sig.IsEqual(&sig2) && id.IsEqual(&id2) != true {
		t.Error("function <IsEqual> has problem")
	}
}

func TestSetByMskMpkIDAndRecover(t *testing.T) {
	Initialization()

	var msk [10]SecretKey
	var sk SecretKey
	var mpk [10]PublicKey
	var pk PublicKey
	var ids [10]ID

	for i, _ := range msk {
		msk[i].SetByCSPRNG()
		mpk[i] = *msk[i].GetPublicKey()
		ids[i].SetInt(i + 1)
	}
	if sk.SetByMskAndID(msk[:], &ids[0]) != nil {
		t.Error("function <SetByMskAndID> err")
	}

	if pk.SetByMpkAndID(mpk[:], &ids[0]) != nil {
		t.Error("function <SetByMpkAndID> err")
	}

	if sk.Recover(msk[:], ids[:]) != nil {
		t.Error("function <Recover ByMskAndIDs> err")
	}

	if pk.Recover(mpk[:], ids[:]) != nil {
		t.Error("function <Recover ByMpkAndIDs> err")
	}
}

//性能测试--入口
func TestPerformance(t *testing.T) {
	testInitializationForXTimes(t, 10000)
	testSetSecKeyXTimes(t, 10000)
	testGetPubKeyXTimes(t, 10000)
	testSignXTimes(t, 10000)
	testVerifyXTimes(t, 10000)
	testAggSignAndVeriXTimes(t, 10, 10000)
	testSignHashAndVerifyXTimes(t, 10000)
	testVerifyAggregateHashesXTimes(t, "sha256", 10, 10000)
	testKofNVerifyXTimes(t, 10, 50, 10000)
}

//性能测试--测试X次初始化需要的时间
func testInitializationForXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testInitializationForXTimes. Wrong Input Number")
		return
	}
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		Initialization()
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次初始化循环用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")
}

//性能测试--测试X次生成私钥需要的时间
func testSetSecKeyXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testSetSecKeyXTimes. Wrong Input Number")
		return
	}
	Initialization()
	var sec SecretKey
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		sec.SetByCSPRNG()
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次生成私钥用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次获取公钥需要的时间
func testGetPubKeyXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testGetPubKeyXTimes. Wrong Input Number")
		return
	}
	Initialization()
	var sec SecretKey
	sec.SetByCSPRNG()
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		sec.GetPublicKey()
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次获取公钥用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次签名需要的时间
func testSignXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testSignXTimes. Wrong Input Number")
		return
	}
	Initialization()
	var sec SecretKey
	sec.SetByCSPRNG()
	msg := "msg for sign"
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		sec.Sign(msg)
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次签名用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次验签需要的时间
func testVerifyXTimes(t *testing.T, x int) {
	if x < 1 {
		t.Error("test: testVerifyXTimes. Wrong Input Number")
		return
	}
	Initialization()
	var sec SecretKey
	sec.SetByCSPRNG()
	var pub PublicKey = *sec.GetPublicKey()
	msg := "msg for sign"
	var sig Signature = *sec.Sign(msg)
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		sig.Verify(&pub, msg)
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次验签用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次合签、合验需要的时间(n组公私钥)
func testAggSignAndVeriXTimes(t *testing.T, n int, x int) {
	Initialization()

	var secVec []SecretKey = make([]SecretKey, n)
	var pubVec []PublicKey = make([]PublicKey, n)
	var sigVec []Signature = make([]Signature, n)

	msg := "msg to test"

	for i := 0; i < n; i++ {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *(secVec[i].GetPublicKey())
		sigVec[i] = *(secVec[i].Sign(msg))
	}

	var aggSig Signature
	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		aggSig.AggregateSignature(sigVec)
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次合签用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

	timeStart = time.Now().UnixNano()
	for i := 0; i < x; i++ {
		if aggSig.FastAggregateVerify(pubVec[:], []byte(msg)) != true {
			t.Errorf("FastAggregateVerify err")
		}
	}
	timeEnd = time.Now().UnixNano()
	fmt.Printf("%d次合验用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次签名哈希的时间
func testSignHashAndVerifyXTimes(t *testing.T, x int) {

	algo := "sha256"
	msgToHash := "msg to hash"
	Initialization()

	var sk SecretKey
	var pk PublicKey
	var sig Signature
	//var ids [10]bls.ID
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
		t.Error("Input encrypt algo err or not support\n")
		return
	}
	_, err := msgHash.Write([]byte(msgToHash))
	if err != nil {
		t.Error("Algorithm:", algo, "hash err\n")
	}

	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		sk.SignHash(msgHash.Sum(nil))
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次对哈希签名用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

	sig = *sk.SignHash(msgHash.Sum(nil))

	timeStart = time.Now().UnixNano()
	for i := 0; i < x; i++ {
		if sig.VerifyHash(&pk, msgHash.Sum(nil)) != true {
			t.Error("Algorithm:", algo, "SignHash and VerifyHash err\n")
		}
	}
	timeEnd = time.Now().UnixNano()
	fmt.Printf("%d次对哈希签名进行验签用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试X次合验签名哈希的时间
func testVerifyAggregateHashesXTimes(t *testing.T, algo string, n int, x int) {
	Initialization()

	var secVec []SecretKey = make([]SecretKey, n)
	var pubVec []PublicKey = make([]PublicKey, n)
	var MsgHashVec [][]byte = make([][]byte, n)
	var sigVec []Signature = make([]Signature, n)
	var aggSig Signature

	var msg []string = make([]string, n)
	for i := 0; i < n; i++ {
		msg[i] = fmt.Sprintf("this is msg %d", i)
	}

	for i, _ := range secVec {
		secVec[i].SetByCSPRNG()
		pubVec[i] = *secVec[i].GetPublicKey()
		MsgHashVec[i] = hashSelect([]byte(msg[i]), algo)
		sigVec[i] = *secVec[i].SignHash(MsgHashVec[i])
	}

	aggSig = sigVec[0]
	for i := 1; i < n; i++ {
		aggSig.Add(&sigVec[i])
	}

	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		if aggSig.VerifyAggregateHashes(pubVec, MsgHashVec) != true {
			t.Error("testVerifyAggregateHashes err")
		}
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次对哈希签名进行合验用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

//性能测试--测试k of n门限签名
func testKofNVerifyXTimes(t *testing.T, k int, n int, x int) {
	var msk []SecretKey = make([]SecretKey, k) //k

	Initialization()

	for i, _ := range msk {
		msk[i].SetByCSPRNG()
	}

	var nSk []SecretKey = make([]SecretKey, n) //n
	var ids []ID = make([]ID, n)
	var nPk []PublicKey = make([]PublicKey, n)
	var nSig []Signature = make([]Signature, n)
	for i, _ := range ids {
		ids[i].SetInt(i + 1)
	}
	msg := "test msg"
	for i, _ := range nSk {
		nSk[i].Set(msk, &ids[i])
		nPk[i] = *nSk[i].GetPublicKey()
		nSig[i] = *nSk[i].Sign(msg)
	}

	timeStart := time.Now().UnixNano()
	for i := 0; i < x; i++ {
		nSk[0].Set(msk, &ids[0])
	}
	timeEnd := time.Now().UnixNano()
	fmt.Printf("%d次k of n 生成私钥用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

	var tempSig Signature

	timeStart = time.Now().UnixNano()
	for i := 0; i < x; i++ {
		if tempSig.Recover(nSig[:k], ids[:k]) != nil {
			t.Error("test: Test KofN failed.")
		}
	}
	timeEnd = time.Now().UnixNano()
	fmt.Printf("%d次k of n 恢复主签名用时:", x)
	fmt.Println(nanoToMilli(timeEnd-timeStart), "ms")

}

func nanoToMilli(x int64) float64 {
	return float64(x) / math.Pow10(6)
}

//func dontCare(in interface{}) {
//
//}
