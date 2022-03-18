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

type Signature struct {
	v C.blsSignature
}

func (sig *Signature) IsEqual(rhs *Signature) bool {
	if sig == nil || rhs == nil {
		return false
	}
	return C.blsSignatureIsEqual(&sig.v, &rhs.v) == 1
}

func (sig *Signature) IsZero() bool {
	return C.blsSignatureIsZero(&sig.v) == 1
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

func (sig *Signature) Serialize() []byte {
	buf := make([]byte, 96) //signature length：192 * 4 bit
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

func (sig *Signature) SerializeToHexStr() string {
	return hex.EncodeToString(sig.Serialize())
}

func (sig *Signature) IsValidOrder() bool {
	return C.blsSignatureIsValidOrder(&sig.v) == 1
}

func (sig *Signature) Add(rhs *Signature) {
	C.blsSignatureAdd(&sig.v, &rhs.v)
}

func (sig *Signature) VerifyHash(p *PublicKey, hash []byte) bool {
	if p == nil {
		return false
	}
	return C.blsVerifyHash(&sig.v, &p.v, getPointer(hash), C.mclSize(len(hash))) == 1
}

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

//Recover API for k-of-n threshold signature
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
