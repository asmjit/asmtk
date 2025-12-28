#!/bin/sh

CURRENT_DIR="`pwd`"
BUILD_DIR="${CURRENT_DIR}/../build"
BUILD_OPTIONS="-DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DASMTK_TEST=1"

if [ -n "${ASMJIT_DIR}" ]; then
  BUILD_OPTIONS="${BUILD_OPTIONS} -DASMJIT_DIR=\"${ASMJIT_DIR}\""
fi

echo "== [configure debug] =="
eval cmake "${CURRENT_DIR}/.." -B "${BUILD_DIR}/Debug" -DCMAKE_BUILD_TYPE=Debug ${BUILD_OPTIONS}
echo ""

echo "== [configure release] =="
eval cmake "${CURRENT_DIR}/.." -B "${BUILD_DIR}/Release" -DCMAKE_BUILD_TYPE=Release ${BUILD_OPTIONS}
echo ""
