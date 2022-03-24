# go-bls
The go-bls module provides APIs of several Golang-packaged bls library.  

## Introduction

The core APIs are as follows:
```
//Init with the curve you need to use.
Initialization(c CurveType)

//Create Secret Key
CreateSecretKey() *SecretKey

//Get public key
(s *SecretKey) GetPublicKey() (p *PublicKey)

//Sign message with secret key
(s *SecretKey) Sign(msg string) (sig *Signature)

//Verify signature with public key and message
(sig *Signature) Verify(p *PublicKey, msg string) bool

//Get aggregate signature with several signatures for the same message
(sig *Signature) AggregateSignature(sigVec []Signature)

//Verify the aggregate signature with the corresponding public keys and message
(sig *Signature) FastAggregateVerify(pubVec []PublicKey, msg []byte) bool

//Sign message's hash value with secret key
(s *SecretKey) SignHash(hash []byte) *Signature

//Verify signature with public key and message's hash
(sig *Signature) VerifyHash(p *PublicKey, hash []byte) bool

//k-of-n threshold sign: Generate secret key
(s *SecretKey) Set(msk []SecretKey, id *ID) error

//k-of-n threshold sign: Recover the master signature from any k subset of n signatures
(sig *Signature) Recover(sigVec []Signature, idVec []ID) error
```
## How to use

Go 1.14 or later is recommended.  
If you use macOS, macOS 11.0 or later is recommended.

1. `import "github.com/TopiaNetwork/go-bls"`in the file where you need to use this module.  
2. `go mod init [yourProjectModule]` If your project already has project module, skip this step.
3. Execute `go mod tidy` in your project directory.
4. `cd $GOPATH/pkg/mod/github.com/TopiaNetwork/go-bls`  
*Note: You need to replace `$GOPATH` with your own configured gopath.*  
`sudo git clone --recursive https://github.com/herumi/bls`  
If clone failed, you can `rm -rf bls` and clone again.
5. **For Linux & macOS:**  
`make lib` will help you prepare all the bls libraries(bls256, bls384, bls384_256) you need.  
If you have identified the bls library you need to use, such as bls384, you can: `make lib384`.
Similarly, you can also: `make lib256` or `make lib384_256`.These operations will not interfere with each other, you can use them in any order.  
*Note: If these operations "Permission denied", try `sudo make lib`*.  
**For Windows:**  
`mkdll` will help you prepare all the bls libraries(bls256.dll, bls384.dll, bls384_256.dll) for Windows and they are under the path of `.\windowsdll`  
*Note: It is recommended to use `x64 Native Tools Command Prompt for VS` to execute`mkdll`.*
6. Use these APIs according to your needs in your project.  
7. **For Linux & macOS:**  
If you need to run your project or build ELF for your project with bls384_256 in this module, you should add compile parameter: **-tags=bn384_256**  
for example:`go run -tags=bn384_256 xxx/xxx.go` or `go build -tags=bn384_256 -o xxx/xxx.elf`.  
If you use other library such as bls256, just switch the compile parameter to **-tags=bn256**. The same goes for other libraries.  
**For Windows:**  
The operation is basically the same as Linux, but you should notice that the .dll file should under the same path of your `go run ...` or the path of the built .exe file. So don't forget to copy the .dll file from `.\windowsdll` to the corresponding path.

### Function test and benchmark
After building libraries you need, you can do some functional testing and performance testing for this module.

Make sure you are under the path of this module. If you are not, `cd $GOPATH/pkg/mod/github.com/TopiaNetwork/go-bls`  

**For Linux & macOS:**  
If you have built all libraries(bls256, bls384, bls384_256), you can:  
`make test`  
It will help you test functions for all libraries.  
And also, you can:  
`make benchmark`  
It will help you test performances for all libraries.  
If you have built the bls library you need to test, such as bls384, you can:  
`make test384` for function test  
and `make benchmark384` for performance test.  
Similarly, you can also: `make test256`, `make benchmark256` and so on.  
*Note: If these operations "Permission denied", try `sudo make`, such as `sudo make test`*.

**For Windows:**  
If you have built all libraries(bls256.dll, bls384.dll, bls384_256.dll), you can:  
`mktest test`  
It will help you test functions for all libraries.  
And also, you can:  
`mktest benchmark`  
It will help you test performances for all libraries.

### Build Test .ELF or .EXE 

Make sure you are under the path of this module. If you are not, `cd $GOPATH/pkg/mod/github.com/TopiaNetwork/go-bls`  

**For Linux & macOS:**  
After building libraries you need, you can build an ELF file for `./testMain/main.go` using:  
`make build256` or `make build384` or `make build384_256` (It depends on which library you need to use).  
The output is `./bin/bls.elf`.  
`make build` is also fine. It does the same thing as `make build384_256`  

**For Windows:**  
After building libraries you need, you can build an EXE file for `.\testMain\main.go` using:  
`mktest build256` or `mktest build384` or `mktest build384_256` (It depends on which library you need to use).  
The output is `.\bin\test256.exe` or `.\bin\test384.exe` or `.\bin\test384_256.exe`.  
`mktest build` is also fine. It does the same thing as `mktest build384_256` 