#!/bin/sh

CURRENT_DIR=`pwd`
BUILD_DIR="build_makefiles_rel"

mkdir -p ../${BUILD_DIR}
cd ../${BUILD_DIR}
cmake .. -G"Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Release \
  -DASMJIT_DIR="../../asmjit" \
  -DASMTK_BUILD_TEST=1
cd ${CURRENT_DIR}
