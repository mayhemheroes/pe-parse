#!/usr/bin/env bash
#
# mayhem/build.sh — build pe-parse (sanitized), the fuzz-parse libFuzzer harness, its
# standalone reproducer, and the upstream Catch2/CTest test suite. Idempotent + offline
# (Catch2 is vendored at /opt/vendor/Catch2; the corkami PE dataset is baked into
# tests/assets/corkami-poc-dataset by the Dockerfile).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
CATCH2_SRC="${CATCH2_SRC:-/opt/vendor/Catch2}"
INC=pe-parser-library/include

# ---- 1) sanitized static pe-parse library (fuzzed code is instrumented) ------------
cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_COMMAND_LINE_TOOLS=OFF \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS"
FUZZ_LIB=build-fuzz/pe-parser-library/libpe-parse.a

# ---- 2) libFuzzer harness + standalone reproducer ----------------------------------
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++17 -I"$INC" $LIB_FUZZING_ENGINE \
  mayhem/fuzz_lib.cpp "$FUZZ_LIB" -licuuc -o "$SRC/fuzz-parse"

# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -std=c++17 -I"$INC" -DSTANDALONE \
  mayhem/fuzz_lib.cpp /tmp/standalone_main.o "$FUZZ_LIB" -licuuc -o "$SRC/fuzz-parse-standalone"

# ---- 3) upstream test suite (project's normal flags; run by mayhem/test.sh) --------
cmake -S . -B build-tests \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_COMMAND_LINE_TOOLS=OFF \
  -DPEPARSE_ENABLE_TESTING=ON \
  -DFETCHCONTENT_SOURCE_DIR_CATCH2="$CATCH2_SRC" \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS"

echo "build.sh: done"
