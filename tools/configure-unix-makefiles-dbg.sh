#!/bin/sh

ASMTK_CURRENT_DIR=`pwd`
ASMTK_BUILD_DIR="build_makefiles_dbg"

mkdir ../${ASMTK_BUILD_DIR}
cd ../${ASMTK_BUILD_DIR}
cmake .. -G"Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DASMJIT_DIR="../asmjit" \
  -DASMTK_BUILD_TEST=1
cd ${ASMTK_CURRENT_DIR}
