package bls

/*
#cgo bn256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=4 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo bn384 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=6 -DBLS_ETH=1
#cgo bn384_256 CFLAGS: -DMCLBN_FP_UNIT_SIZE=6 -DMCLBN_FR_UNIT_SIZE=4 -DBLS_ETH=1
#cgo bn512 CFLAGS: -DMCLBN_FP_UNIT_SIZE=8 -DMCLBN_FR_UNIT_SIZE=8 -DBLS_ETH=1
#cgo CFLAGS: -I/${SRCDIR}/bls/mcl/include
#cgo CFLAGS: -I/${SRCDIR}/bls/include

#cgo LDFLAGS: -L/${SRCDIR}/bls/mcl/lib
#cgo LDFLAGS: -L/${SRCDIR}/bls/lib
#cgo bn256 LDFLAGS: -lbls256
#cgo bn384 LDFLAGS: -lbls384
#cgo bn384_256 LDFLAGS: -lbls384_256
#cgo bn512 LDFLAGS: -lbls512
#cgo LDFLAGS: -lmcl -lstdc++
#include "mcl/bn.h"
#include "bls/bls.h"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

type ID struct {
	v C.blsId
}

func (id *ID) SetInt(x int) {
	C.blsIdSetInt(&id.v, C.int(x))
}

func (id *ID) Serialize() []byte {
	buf := make([]byte, 2048)
	n := C.blsIdSerialize(unsafe.Pointer(&buf[0]), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdSerialize")
	}
	return buf[:n]
}

func (id *ID) Deserialize(buf []byte) error {
	n := C.blsIdDeserialize(&id.v, getPointer(buf), C.mclSize(len(buf)))
	if n == 0 || int(n) != len(buf) {
		return fmt.Errorf("err blsIdDeserialize %x", buf)
	}
	return nil
}

func (id *ID) GetLittleEndian() []byte {
	return id.Serialize()
}

func (id *ID) SetLittleEndian(buf []byte) error {
	err := C.blsIdSetLittleEndian(&id.v, getPointer(buf), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetLittleEndian %x", err)
	}
	return nil
}

func (id *ID) SerializeToHexStr() string {
	return hex.EncodeToString(id.Serialize())
}

func (id *ID) GetHexString() string {
	buf := make([]byte, 2048)
	n := C.blsIdGetHexStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetHexStr")
	}
	return string(buf[:n])
}

func (id *ID) GetDecString() string {
	buf := make([]byte, 2048)
	n := C.blsIdGetDecStr((*C.char)(unsafe.Pointer(&buf[0])), C.mclSize(len(buf)), &id.v)
	if n == 0 {
		panic("err blsIdGetDecStr")
	}
	return string(buf[:n])
}

func (id *ID) SetHexString(s string) error {
	buf := []byte(s)
	err := C.blsIdSetHexStr(&id.v, (*C.char)(getPointer(buf)), C.mclSize(len(buf)))
	if err != 0 {
		return fmt.Errorf("err blsIdSetHexStr %s", s)
	}
	return nil
}

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

func (id *ID) IsZero() bool {
	return C.blsIdIsZero(&id.v) == 1
}
