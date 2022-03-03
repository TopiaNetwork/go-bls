package bls_go

/*此文件封装对bls C库的调用*/
/*
-DMCLBN_FP_UNIT_SIZE=4 -DMCLBN_FR_UNIT_SIZE=4 ------- bls256.a
-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=6 ------- bls384.a
-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 ------- bls384_256.a
-DMCLBN_FP_UNIT_SIZE=8 -DMCLBN_FR_UNIT_SIZE=8 ------- bls512.a
*/

/*
#cgo CFLAGS:-DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo CFLAGS: -I/home/sz/bls/bls/mcl/include
#cgo CFLAGS: -I/home/sz/bls/bls/include

#cgo LDFLAGS: -L/home/sz/bls/bls/mcl/lib
#cgo LDFLAGS: -L/home/sz/bls/bls/lib
#cgo LDFLAGS: -lbls384_256 -lmcl -lstdc++
#include "mcl/bn.h"
#include "bls/bls.h"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

type SecretKey struct {
	v C.blsSecretKey
}
type PublicKey struct {
	v C.blsPublicKey
}
type Signature struct {
	v C.blsSignature
}
type ID struct {
	v C.blsId
}

func getPointer(msg []byte) unsafe.Pointer {
	if len(msg) == 0 {
		return nil
	}
	return unsafe.Pointer(&msg[0])
}

func Initialization() {
	//for i := 0; i < 1000000; i++ {
	//	err := C.blsInit(C.MCL_BN254, C.int(i))
	//	if err == 0 {
	//		fmt.Printf("正确的i是：%v\n", i)
	//		//break
	//	}
	//}

	//for i := 0; i < 111; i++ {
	//	err := C.blsInit(C.int(i), C.MCLBN_COMPILED_TIME_VAR)
	//	if err == 0 {
	//		fmt.Println("support curve:", i)
	//	}
	//}

	err := C.blsInit(C.MCL_BN254, C.MCLBN_COMPILED_TIME_VAR)
	if err != 0 {
		fmt.Printf("blsInit err %v\n", err)
		panic("")
	}

	C.blsSetETHmode(C.BLS_ETH_MODE_LATEST)
}

func (id *ID) SetInt(x int) {
	C.blsIdSetInt(&id.v, C.int(x))
}

// Serialize --
func (id *ID) Serialize() []byte {
	buf := make([]byte, 2048)
	n := C.blsIdSerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdSerialize")
	}
	return buf[:n]
}

// Deserialize --
func (id *ID) Deserialize(buf []byte) error {
	n := C.blsIdDeserialize(&id.v, getPointer(buf), C.mclSize(len(buf)))
	if n == 0 || int(n) != len(buf) {
		return fmt.Errorf("err blsIdDeserialize %x", buf)
	}
	return nil
}

// GetLittleEndian -- alias of Serialize
func (id *ID) GetLittleEndian() []byte {
	return id.Serialize()
}

// SetLittleEndian --
func (id *ID) SetLittleEndian(buf []byte) error {
	err := C.blsIdSetLittleEndian(&id.v, getPointer(buf), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetLittleEndian %x", err)
	}
	return nil
}

// SerializeToHexStr --
func (id *ID) SerializeToHexStr() string {
	return hex.EncodeToString(id.Serialize())
}

// GetHexString --
func (id *ID) GetHexString() string {
	buf := make([]byte, 2048)
	n := C.blsIdGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetHexStr")
	}
	return string(buf[:n])
}

// GetDecString --
func (id *ID) GetDecString() string {
	buf := make([]byte, 2048)
	n := C.blsIdGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetDecStr")
	}
	return string(buf[:n])
}

// SetHexString --
func (id *ID) SetHexString(s string) error {
	buf := []byte(s)
	err := C.blsIdSetHexStr(&id.v, (*C.char)(getPointer(buf)), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetHexStr %s", s)
	}
	return nil
}

// SetDecString --
func (id *ID) SetDecString(s string) error {
	buf := []byte(s)
	err := C.blsIdSetDecStr(&id.v, (*C.char)(getPointer(buf)), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetDecStr %s", s)
	}
	return nil
}

func (id *ID) IsEqual(rhs *ID) bool {
	if id == nil || rhs == nil {
		return false
	}
	return C.blsIdIsEqual(&id.v, &rhs.v) == 1
}

func (s *SecretKey) IsEqual(rhs *SecretKey) bool {
	if s == nil || rhs == nil {
		return false
	}
	return C.blsSecretKeyIsEqual(&s.v, &rhs.v) == 1
}

func (p *PublicKey) IsEqual(rhs *PublicKey) bool {
	if p == nil || rhs == nil {
		return false
	}
	return C.blsPublicKeyIsEqual(&p.v, &rhs.v) == 1
}

func (sig *Signature) IsEqual(rhs *Signature) bool {
	if sig == nil || rhs == nil {
		return false
	}
	return C.blsSignatureIsEqual(&sig.v, &rhs.v) == 1
}

func (id *ID) IsZero() bool {
	return C.blsIdIsZero(&id.v) == 1
}

func (s *SecretKey) IsZero() bool {
	return C.blsSecretKeyIsZero(&s.v) == 1
}

func (p *PublicKey) IsZero() bool {
	return C.blsPublicKeyIsZero(&p.v) == 1
}

func (sig *Signature) IsZero() bool {
	return C.blsSignatureIsZero(&sig.v) == 1
}

func (s *SecretKey) SetByCSPRNG() { //√
	i := C.blsSecretKeySetByCSPRNG(&s.v)
	if i != 0 {
		panic("err blsSecretKeySetByCSPRNG")
	}
	if s.IsZero() {
		panic("err blsSecretKeySetByCSPRNG zero")
	}
}

func (s *SecretKey) GetPublicKey() (p *PublicKey) {
	p = new(PublicKey)
	C.blsGetPublicKey(&p.v, &s.v)
	return p
}

func (s *SecretKey) Sign(msg string) (sig *Signature) {
	sig = new(Signature) //
	temp := []byte(msg)
	C.blsSign(&sig.v, &s.v, unsafe.Pointer(&temp[0]), C.mclSize(len(temp))) //C.mclSize
	return sig
}

func (s *SecretKey) SetByMskAndID(msk []SecretKey, id *ID) error {
	if len(msk) == 0 {
		return fmt.Errorf("Set zero msk")
	}
	ret := C.blsSecretKeyShare(&s.v, &msk[0].v, (C.mclSize)(len(msk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyShare")
	}
	return nil
}

func (s *SecretKey) Recover(secVec []SecretKey, idVec []ID) error {
	n := len(secVec)
	if n == 0 {
		return fmt.Errorf("Recover zero secVec")
	}
	if n != len(idVec) {
		return fmt.Errorf("err SecretKey.Recover bad size")
	}
	ret := C.blsSecretKeyRecover(&s.v, &secVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(n))
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyRecover")
	}
	return nil
}

func (p *PublicKey) SetByMpkAndID(mpk []PublicKey, id *ID) error {
	if len(mpk) == 0 {
		return fmt.Errorf("Set zero mpk")
	}
	ret := C.blsPublicKeyShare(&p.v, &mpk[0].v, (C.mclSize)(len(mpk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyShare")
	}
	return nil
}

func (p *PublicKey) Recover(pubVec []PublicKey, idVec []ID) error {
	n := len(pubVec)
	if n == 0 {
		return fmt.Errorf("Recover zero pubVec")
	}
	if n != len(idVec) {
		return fmt.Errorf("err PublicKey.Recover bad size")
	}
	ret := C.blsPublicKeyRecover(&p.v, &pubVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(n))
	if ret != 0 {
		return fmt.Errorf("err blsPublicKeyRecover")
	}
	return nil
}

func (sig *Signature) Verify(p *PublicKey, msg string) bool {
	if sig == nil || p == nil {
		return false
	}
	temp := []byte(msg)
	return C.blsVerify(&sig.v, &p.v, unsafe.Pointer(&temp[0]), C.mclSize(len(temp))) == 1
}

func (sig *Signature) AggregateSignature(sigVec []Signature) {
	var temp *C.blsSignature
	if len(sigVec) == 0 {
		temp = nil
	} else {
		temp = &(sigVec[0].v)
	}
	C.blsAggregateSignature(&sig.v, temp, C.mclSize(len(sigVec)))
}

func (sig *Signature) FastAggregateVerify(pubVec []PublicKey, msg []byte) bool {
	if pubVec == nil || len(pubVec) == 0 {
		return false
	}
	return C.blsFastAggregateVerify(&sig.v, &pubVec[0].v, C.mclSize(len(pubVec)), getPointer(msg), C.mclSize(len(msg))) == 1
}

func (s *SecretKey) SetLittleEndian(buf []byte) error {
	err := C.blsSecretKeySetLittleEndian(&s.v, getPointer(buf), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndian %x", err)
	}
	return nil
}

func (s *SecretKey) SetLittleEndianMod(buf []byte) error {
	err := C.blsSecretKeySetLittleEndianMod(&s.v, getPointer(buf), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsSecretKeySetLittleEndianMod %x", err)
	}
	return nil
}

func (s *SecretKey) Serialize() []byte {
	buf := make([]byte, 32) //secret key长度：64 * 4 bit
	n := C.blsSecretKeySerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &s.v)
	if n == 0 {
		panic("err blsSecretKeySerialize")
	}
	return buf[:n]
}
func (s *SecretKey) Deserialize(serialBuf []byte) error {
	n := C.blsSecretKeyDeserialize(&s.v, getPointer(serialBuf), C.mclSize(len(serialBuf)))
	if n == 0 || int(n) != len(serialBuf) {
		return fmt.Errorf("err blsSecretKeyDeserialize %x", serialBuf)
	}
	return nil
}

func (p *PublicKey) Serialize() []byte {
	buf := make([]byte, 48) //public key长度：96 * 4 bit
	n := C.blsPublicKeySerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &p.v)
	if n == 0 {
		panic("err blsPublicKeySerialize")
	}
	return buf[:n]
}
func (p *PublicKey) Deserialize(serialBuf []byte) error {
	n := C.blsPublicKeyDeserialize(&p.v, getPointer(serialBuf), C.mclSize(len(serialBuf)))
	if n == 0 || int(n) != len(serialBuf) {
		return fmt.Errorf("err blsPublicKeyDeserialize %x", serialBuf)
	}
	return nil
}

func (sig *Signature) Serialize() []byte {
	buf := make([]byte, 96) //signature长度：192 * 4 bit
	n := C.blsSignatureSerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &sig.v)
	if n == 0 {
		panic("err blsSignatureSerialize")
	}
	return buf[:n]
}
func (sig *Signature) Deserialize(serialBuf []byte) error {
	n := C.blsSignatureDeserialize(&sig.v, getPointer(serialBuf), C.mclSize(len(serialBuf)))
	if n == 0 || int(n) != len(serialBuf) {
		return fmt.Errorf("err blsSignatureDeserialize %x", serialBuf)
	}
	return nil
}

func (s *SecretKey) SerializeToHexStr() string {
	return hex.EncodeToString(s.Serialize())
}
func (p *PublicKey) SerializeToHexStr() string {
	return hex.EncodeToString(p.Serialize())
}
func (sig *Signature) SerializeToHexStr() string {
	return hex.EncodeToString(sig.Serialize())
}

func (sig *Signature) IsValidOrder() bool {
	return C.blsSignatureIsValidOrder(&sig.v) == 1
}

func (p *PublicKey) IsValidOrder() bool {
	return C.blsPublicKeyIsValidOrder(&p.v) == 1
}

func (s *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(&s.v, &rhs.v)
}
func (p *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(&p.v, &rhs.v)
}
func (sig *Signature) Add(rhs *Signature) {
	C.blsSignatureAdd(&sig.v, &rhs.v)
}

func (s *SecretKey) SignHash(hash []byte) *Signature {
	ret := new(Signature)
	err := C.blsSignHash(&ret.v, &s.v, getPointer(hash), C.mclSize(len(hash)))
	if err == 0 {
		return ret
	}
	return nil
}

func (sig *Signature) VerifyHash(p *PublicKey, hash []byte) bool {
	if p == nil {
		return false
	}
	return C.blsVerifyHash(&sig.v, &p.v, getPointer(hash), C.mclSize(len(hash))) == 1
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// VerifyAggregateHashes --
func (sig *Signature) VerifyAggregateHashes(pubVec []PublicKey, hash [][]byte) bool {
	if pubVec == nil {
		return false
	}
	n := len(hash)
	if n == 0 || len(pubVec) != n {
		return false
	}
	hashByte := len(hash[0])
	if hashByte == 0 {
		return false
	}
	h := make([]byte, n*hashByte)
	for i := 0; i < n; i++ {
		hn := len(hash[i])
		copy(h[i*hashByte:(i+1)*hashByte], hash[i][0:min(hn, hashByte)])
	}
	return C.blsVerifyAggregatedHashes(&sig.v, &pubVec[0].v, unsafe.Pointer(&h[0]), C.mclSize(hashByte), C.mclSize(n)) == 1
}

// Set API for k-of-n threshold signature
func (s *SecretKey) Set(msk []SecretKey, id *ID) error {
	if len(msk) == 0 {
		return fmt.Errorf("Set zero mask")
	}
	ret := C.blsSecretKeyShare(&s.v, &msk[0].v, (C.mclSize)(len(msk)), &id.v)
	if ret != 0 {
		return fmt.Errorf("err blsSecretKeyShare")
	}
	return nil
}

func (sig *Signature) Recover(sigVec []Signature, idVec []ID) error {
	if len(sigVec) == 0 {
		return fmt.Errorf("Recover zero sigVec")
	}
	if len(sigVec) != len(idVec) {
		return fmt.Errorf("err Sign.Recover bad size")
	}
	ret := C.blsSignatureRecover(&sig.v, &sigVec[0].v, (*C.blsId)(&idVec[0].v), (C.mclSize)(len(idVec)))
	if ret != 0 {
		return fmt.Errorf("err blsSignatureRecover")
	}
	return nil
}
