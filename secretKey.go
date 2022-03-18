package bls

/*
#cgo bn256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=4 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo bn384 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=6 -DBLS_ETH=1
#cgo bn384_256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo CFLAGS: -I${SRCDIR}/bls/mcl/include
#cgo CFLAGS: -I${SRCDIR}/bls/include

#cgo LDFLAGS: -L${SRCDIR}/bls/mcl/lib
#cgo LDFLAGS: -L${SRCDIR}/bls/lib
#cgo bn256 LDFLAGS: -lbls256
#cgo bn384 LDFLAGS: -lbls384
#cgo bn384_256 LDFLAGS: -lbls384_256
#cgo LDFLAGS: -lmcl -lstdc++
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

func (s *SecretKey) IsEqual(rhs *SecretKey) bool {
	if s == nil || rhs == nil {
		return false
	}
	return C.blsSecretKeyIsEqual(&s.v, &rhs.v) == 1
}

func (s *SecretKey) IsZero() bool {
	return C.blsSecretKeyIsZero(&s.v) == 1
}

func CreateSecretKey() *SecretKey {
	var s SecretKey
	i := C.blsSecretKeySetByCSPRNG(&s.v)
	if i != 0 {
		panic("err blsSecretKeySetByCSPRNG")
	}
	if s.IsZero() {
		panic(fmt.Sprintf("err blsSecretKeySetByCSPRNG : %v", i))
	}
	return &s
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
	buf := make([]byte, 32) //secret key length：64 * 4 bit
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

func (s *SecretKey) SerializeToHexStr() string {
	return hex.EncodeToString(s.Serialize())
}

func (s *SecretKey) Add(rhs *SecretKey) {
	C.blsSecretKeyAdd(&s.v, &rhs.v)
}

func (s *SecretKey) SignHash(hash []byte) *Signature {
	ret := new(Signature)
	err := C.blsSignHash(&ret.v, &s.v, getPointer(hash), C.mclSize(len(hash)))
	if err == 0 {
		return ret
	}
	return nil
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
