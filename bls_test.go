package bls

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	Initialization(MCL_BN254)

	var sec SecretKey
	var pub *PublicKey
	var sig *Signature
	var msg = []string{
		0: "msg string 0",
		1: "msg string 1",
		2: "msg string 2",
		3: "to be add...",
	}
	for k := range msg {
		sec.SetByCSPRNG()
		pub = sec.GetPublicKey()
		sig = sec.Sign(msg[k])
		if ok := sig.Verify(pub, msg[k]); !ok {
			t.Error("message:<", msg[k], "> sign and verify failed\n")
		}
	}
}

func TestAggSigAndVerify(t *testing.T) {
	Initialization(MCL_BN254)

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

	Initialization(MCL_BN254)

	for i := range msk {
		msk[i].SetByCSPRNG()
	}

	var nSk [10]SecretKey //n
	var ids [10]ID
	var nPk [10]PublicKey
	var nSig [10]Signature
	for i := range ids {
		ids[i].SetInt(i + 1)
	}
	msg := "test msg"
	for i := range nSk {
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
	n := 100
	for _, algo := range algos {
		testSignHashAndVerifyHash(t, algo, msgToHash)
		testVerifyAggregateHashes(t, algo, n)
	}
}

func testSignHashAndVerifyHash(t *testing.T, algo string, msgToHash string) {
	algo = strings.ToLower(algo)

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
		hashMsg = sha256.New() //use sha256 as default
		return nil
	}
	hashMsg.Write(input)
	return hashMsg.Sum(nil)
}

func TestSerializeAndDe(t *testing.T) {
	Initialization(MCL_BN254)

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
	Initialization(MCL_BN254)
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
	Initialization(MCL_BN254)
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
	Initialization(MCL_BN254)

	var msk [10]SecretKey
	var sk SecretKey
	var mpk [10]PublicKey
	var pk PublicKey
	var ids [10]ID

	for i := range msk {
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
