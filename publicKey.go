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

type PublicKey struct {
	v C.blsPublicKey
}

func (p *PublicKey) IsEqual(rhs *PublicKey) bool {
	if p == nil || rhs == nil {
		return false
	}
	return C.blsPublicKeyIsEqual(&p.v, &rhs.v) == 1
}

func (p *PublicKey) IsZero() bool {
	return C.blsPublicKeyIsZero(&p.v) == 1
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

func (p *PublicKey) Serialize() []byte {
	buf := make([]byte, 64)
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

func (p *PublicKey) SerializeToHexStr() string {
	return hex.EncodeToString(p.Serialize())
}

func (p *PublicKey) IsValidOrder() bool {
	return C.blsPublicKeyIsValidOrder(&p.v) == 1
}

func (p *PublicKey) Add(rhs *PublicKey) {
	C.blsPublicKeyAdd(&p.v, &rhs.v)
}

// Mul for asymmetric cryptography
func (p *PublicKey) Mul(sec *SecretKey) {
	C.blsPublicKeyMul(&p.v, &sec.v)
}
