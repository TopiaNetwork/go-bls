# go-bls
## Introduction
The go-bls module provides APIs of several Golang-packaged bls library.

The core APIs are as follows:
```
Initialization(c CurveType)

(s *SecretKey) SetByCSPRNG()

(s *SecretKey) GetPublicKey() (p *PublicKey)

(s *SecretKey) Sign(msg string) (sig *Signature)

(sig *Signature) Verify(p *PublicKey, msg string) bool

(sig *Signature) AggregateSignature(sigVec []Signature)

(sig *Signature) FastAggregateVerify(pubVec []PublicKey, msg []byte) bool

(s *SecretKey) SignHash(hash []byte) *Signature

(sig *Signature) VerifyHash(p *PublicKey, hash []byte) bool

//k-of-n threshold sign: Generate secret key
(s *SecretKey) Set(msk []SecretKey, id *ID) error

//k-of-n threshold sign: Recover the master signature from any k subset of n signatures
(sig *Signature) Recover(sigVec []Signature, idVec []ID) error
```
## How to use
### Build library
If you are not sure which library to use, you can:  
`make lib`  
It will help you prepare all the bls libraries(bls256, bls384, bls384_256, bls512) you need.

If you have identified the bls library you need to use, such as bls384, you can:  
`make lib384`

Similarly, you can also:  
`make lib256` or `make lib384_256` or `make lib512`

### Function test and benchmark
After building libraries you need, you can do some functional testing and performance testing.

If you have built all libraries(bls256, bls384, bls384_256, bls512), you can:  
`make test`  
It will help you test functions for all libraries.  
And also, you can:  
`make benchmark`  
It will help you test performances for all libraries.

If you have built the bls library you need to test, such as bls384, you can:  
`make test384` for function test  
and `make benchmark384` for performance test.

Similarly, you can also: `make test256`, `make benchmark256` and so on.

### Build ELF
After building libraries you need, you can build an ELF file for `./testMain/main.go` after:  
`make build256` or `make build384` or `make build384_256` or `make build512` (It depends on which library you need to use).  
The output is `./bin/bls.elf`.

`make build` is also fine. It does the same thing as `make build384_256`