@echo off
setlocal enabledelayedexpansion

set build_path=.\_build
set deps_path=.\vcpkg\installed\x64-windows

set cl_definitions= /DSSC_OS_WINDOWS=1 /DSSC_CRYPTO_OPENSSL=1 /D_CRT_SECURE_NO_WARNINGS=1
set cl_include_path= /I.\src /I%deps_path%\include
set cl_common_flags= /std:c11 /nologo /W3 /FC /Z7 %cl_include_path% %cl_definitions%
set cl_debug_flags= /Od /Ob1 /DBUILD_DEBUG=1
set cl_release_flags= /O2 /DBUILD_DEBUG=0
set cl_link_flags= /link /MANIFEST:EMBED /INCREMENTAL:NO /LIBPATH:%deps_path%\debug\lib ^
    /out:%build_path%\ssc-local.exe

if not exist %build_path% mkdir %build_path%

call cl /LD .\config.c /link /out:%build_path%\config.dll
call cl %cl_common_flags% %cl_debug_flags% .\src\local_build.c %cl_link_flags%

xcopy "%deps_path%\bin\*.dll" "%build_path%" /D /Y /I
