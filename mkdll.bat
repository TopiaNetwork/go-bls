@echo off
set MCL_DIR=.\bls\mcl

call %MCL_DIR%\setvar.bat

set BLS_CFLAGS=%CFLAGS% /I %MCL_DIR%\include /I .\bls\include
set BLS_LDFLAGS=%LDFLAGS%
echo BLS_CFLAGS=%BLS_CFLAGS%
echo BLS_LDFLAGS=%BLS_LDFLAGS%

echo make ETH mode
set BLS_CFLAGS=%BLS_CFLAGS% -DBLS_ETH=1
shift

set BLS_CFLAGS=%BLS_CFLAGS% /DMCL_NO_AUTOLINK

echo make dynamic library DLL
cl /c %BLS_CFLAGS% /Fobls/obj/bls_c256.obj bls/src/bls_c256.cpp /DBLS_NO_AUTOLINK
cl /c %BLS_CFLAGS% /Fobls/obj/bls_c384.obj bls/src/bls_c384.cpp /DBLS_NO_AUTOLINK
cl /c %BLS_CFLAGS% /Fobls/obj/bls_c384_256.obj bls/src/bls_c384_256.cpp /DBLS_NO_AUTOLINK
cl /c %BLS_CFLAGS% /Fobls/obj/fp.obj %MCL_DIR%/src/fp.cpp
link /nologo /DLL /OUT:windowsdll\bls256.dll bls\obj\bls_c256.obj bls\obj\fp.obj %LDFLAGS% /implib:bls\lib\bls256.lib
link /nologo /DLL /OUT:windowsdll\bls384.dll bls\obj\bls_c384.obj bls\obj\fp.obj %LDFLAGS% /implib:bls\lib\bls384.lib
link /nologo /DLL /OUT:windowsdll\bls384_256.dll bls\obj\bls_c384_256.obj bls\obj\fp.obj %LDFLAGS% /implib:bls\lib\bls384_256.lib

dlltool -dllname windowsdll/bls256.dll --def windowsdll/bls256.def --output-lib bls/lib/libbls256.a
dlltool -dllname windowsdll/bls384.dll --def windowsdll/bls384.def --output-lib bls/lib/libbls384.a
dlltool -dllname windowsdll/bls384_256.dll --def windowsdll/bls384_256.def --output-lib bls/lib/libbls384_256.a