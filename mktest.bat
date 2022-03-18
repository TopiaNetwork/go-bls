@echo off

if "%1"=="test" (
	copy windowsdll\bls256.dll .\bls256.dll
	copy windowsdll\bls384.dll .\bls384.dll
	copy windowsdll\bls384_256.dll .\bls384_256.dll

	echo Test Lib256:
	go test -tags=bn256 -v
	echo Test Lib384:
	go test -tags=bn384 -v
	echo Test Lib384_256:
	go test -tags=bn384_256 -v
) 
if "%1"=="benchmark" (
	copy .\windowsdll\bls256.dll .\bls256.dll
	copy .\windowsdll\bls384.dll .\bls384.dll
	copy .\windowsdll\bls384_256.dll .\bls384_256.dll
	
	echo Benchmark Lib256:
	go test -tags=bn256 -bench=.
	echo Benchmark Lib384:
	go test -tags=bn384 -bench=.
	echo Benchmark Lib384_256:
	go test -tags=bn384_256 -bench=.
)
if "%1"=="build" (
	copy .\windowsdll\bls384_256.dll .\bin\bls384_256.dll
	
	echo build .\bin\test384_256.exe:
	go build -tags=bn384_256 -o .\bin\test384_256.exe .\testMain\main.go
)
if "%1"=="build256" (
	copy .\windowsdll\bls256.dll .\bin\bls256.dll
	
	echo build .\bin\test256.exe:
	go build -tags=bn256 -o .\bin\test256.exe .\testMain\main.go
)
if "%1"=="build384" (
	copy .\windowsdll\bls384.dll .\bin\bls384.dll
	
	echo build .\bin\test384.exe:
	go build -tags=bn384 -o .\bin\test384.exe .\testMain\main.go
)
if "%1"=="build384_256" (
	copy .\windowsdll\bls384_256.dll .\bin\bls384_256.dll
	
	echo build .\bin\test384_256.exe:
	go build -tags=bn384_256 -o .\bin\test384_256.exe .\testMain\main.go
)
if "%1"=="clr" (
	del .\bls256.dll .\bls384.dll .\bls384_256.dll 
	del .\bin\*.dll
	del .\bin\*.exe
)


