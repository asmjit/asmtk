@echo off

set CURRENT_DIR=%CD%
set BUILD_DIR="build_vs_x64"

mkdir ..\%BUILD_DIR%
cd ..\%BUILD_DIR%
cmake .. -G"Visual Studio 16" -A x64 -DCMAKE_BUILD_TYPE=Release -DASMJIT_STATIC=1 -DASMTK_STATIC=1 -DASMTK_TEST=1
cd %CURRENT_DIR%
