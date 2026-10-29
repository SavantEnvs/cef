#!/usr/bin/env bash
#
# mayhem/build.sh — build CEF's installer fuzz harnesses (in-tree, libcef_dll/bootstrap/installer/)
# against the REAL installer_archive.cc / installer_xz_index.cc / installer_crc.cc sources, a vendored
# LZMA SDK (mayhem/third_party/lzma_sdk) and a minimal stand-in for the slice of Chromium //base they
# use (mayhem/shim). Fully offline: everything compiled here is in the repo.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
B="$M/build"
INST="$SRC/libcef_dll/bootstrap/installer"
LZ="$M/third_party/lzma_sdk/src/C"

rm -rf "$B"
mkdir -p "$B/inc" "$B/fuzz" "$B/standalone" "$B/test"
# The in-tree sources include "cef/libcef_dll/..."; $SRC is the `cef` directory.
ln -s "$SRC" "$B/inc/cef"

INCLUDES="-I$B/inc -I$M/shim -I$M"
LZ_DEFS="-DZ7_LZMA_PROB32 -DZ7_NO_METHODS_FILTERS -DZ7_ST -D_LZMA_PROB32 -DZ7_NO_CRC_HW_FORCE"
CXX_DEFS="-std=c++20 -O1 -D_GLIBCXX_ASSERTIONS"
CXX_SRCS=("$INST/installer_archive.cc" "$INST/installer_xz_index.cc" "$INST/installer_crc.cc" "$M/shim/shim.cc")
HARNESSES=(installer_tar_fuzzer installer_xz_block_fuzzer installer_xz_index_fuzzer)

# compile_set <dir> <flags...>: compile every source into <dir>/*.o (parallel).
compile_set() {
  local dir="$1"; shift
  local flags=("$@")
  {
    for f in "$LZ"/*.c; do
      printf '%s\0' "$CC|${flags[*]} $LZ_DEFS $INCLUDES -O1 -w|$f|$dir/lz_$(basename "$f" .c).o"
    done
    for f in "${CXX_SRCS[@]}" "${HARNESSES[@]/#/$INST/}"; do
      f="${f%.cc}.cc"
      printf '%s\0' "$CXX|${flags[*]} $CXX_DEFS $INCLUDES|$f|$dir/$(basename "$f" .cc).o"
    done
  } | xargs -0 -P "$MAYHEM_JOBS" -n1 bash -c '
      IFS="|" read -r cc fl src out <<<"$1"
      $cc $fl -c "$src" -o "$out"' _
}

# 2a) fuzz objects: sanitized + coverage for libFuzzer
compile_set "$B/fuzz" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link
# 2b) standalone objects: sanitized, no libFuzzer instrumentation
compile_set "$B/standalone" $SANITIZER_FLAGS $DEBUG_FLAGS

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

link_set() {
  local dir="$1" h="$2"
  local common=()
  for o in "$dir"/*.o; do
    case "$(basename "$o")" in installer_*_fuzzer.o) ;; *) common+=("$o") ;; esac
  done
  printf '%s\n' "${common[@]}" "$dir/$h.o"
}

for h in "${HARNESSES[@]}"; do
  mapfile -t objs < <(link_set "$B/fuzz" "$h")
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "${objs[@]}" "$B/lsan_off.o" -o "/mayhem/$h"
  mapfile -t objs < <(link_set "$B/standalone" "$h")
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "${objs[@]}" "$B/standalone_main.o" "$B/lsan_off.o" -o "/mayhem/$h-standalone"
done

# 3) test suite: known-answer probe built with NORMAL flags (no sanitizers) against the same sources.
{
  for f in "$LZ"/*.c; do
    printf '%s\0' "$CC|$COVERAGE_FLAGS $LZ_DEFS $INCLUDES -O2 -w|$f|$B/test/lz_$(basename "$f" .c).o"
  done
  for f in "${CXX_SRCS[@]}" "$M/kat.cc"; do
    printf '%s\0' "$CXX|$COVERAGE_FLAGS -std=c++20 -O2 $INCLUDES|$f|$B/test/$(basename "$f" .cc).o"
  done
} | xargs -0 -P "$MAYHEM_JOBS" -n1 bash -c '
    IFS="|" read -r cc fl src out <<<"$1"
    $cc $fl -c "$src" -o "$out"' _
$CXX $COVERAGE_FLAGS "$B"/test/*.o -o /mayhem/kat
