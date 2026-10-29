#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# 1) Upstream's own gtest suites for the fuzzed code (installer_archive_unittest.cc,
#    installer_xz_index_unittest.cc; built by build.sh as /mayhem/cef_installer_unittests, normal flags).
#    The fixtures are upstream's libcef_dll/bootstrap/installer/testdata/*.tar.xz, reached through the
#    shim's PathService via MAYHEM_SRC_TEST_DATA_ROOT (a dir holding `cef` -> the source tree).
UT=/mayhem/cef_installer_unittests
if [ ! -x "$UT" ]; then
  echo "missing $UT — mayhem/build.sh must build it" >&2
  emit_ctrf "cef-installer-gtest" 0 1 0
  exit 1
fi
export MAYHEM_SRC_TEST_DATA_ROOT="$SRC/mayhem/build/inc"
if [ ! -d "$MAYHEM_SRC_TEST_DATA_ROOT/cef/libcef_dll/bootstrap/installer/testdata" ]; then
  echo "missing $MAYHEM_SRC_TEST_DATA_ROOT/cef — mayhem/build.sh must create it" >&2
  emit_ctrf "cef-installer-gtest" 0 1 0
  exit 1
fi
ut_log="$(mktemp)"
"$UT" >"$ut_log" 2>&1
ut_rc=$?
cat "$ut_log"
ut_passed=$(grep -c '^\[       OK \] .* ([0-9]* ms)$' "$ut_log")
ut_failed=$(grep -c '^\[  FAILED  \] .* ([0-9]* ms)$' "$ut_log")
ut_skipped=$(grep -c '^\[  SKIPPED \] .* ([0-9]* ms)$' "$ut_log")
# Upstream's DISABLED_ tests are reported as skipped.
ut_disabled=$(sed -n 's/^  YOU HAVE \([0-9]*\) DISABLED TEST.*/\1/p' "$ut_log")
ut_ran=$(sed -n 's/^\[==========\] \([0-9]*\) tests\? from .* ran\..*/\1/p' "$ut_log")
# A run that did not report its summary (crash, or neutered to exit 0) or whose per-test lines do not
# add up to the reported total is a failure, whatever the exit status.
if [ -z "$ut_ran" ] || [ "$ut_ran" -eq 0 ] || [ $((ut_passed + ut_failed + ut_skipped)) -ne "$ut_ran" ]; then
  echo "gtest run incomplete: ran=[${ut_ran:-none}] ok=$ut_passed failed=$ut_failed skipped=$ut_skipped" >&2
  ut_failed=$((ut_failed + 1))
elif [ "$ut_rc" -ne 0 ] && [ "$ut_failed" -eq 0 ]; then
  echo "gtest exited $ut_rc with no failed tests" >&2
  ut_failed=1
fi
rm -f "$ut_log"

# 2) Supplement: /mayhem/kat (agent-written, normal flags, POSIX branches) runs the real installer tar /
#    xz-index / xz-block / tar.xz code over committed fixtures and prints one line per check; every line
#    must equal the golden mayhem/testdata/kat.expected line.
KAT=/mayhem/kat
EXPECTED="$SRC/mayhem/testdata/kat.expected"
if [ ! -x "$KAT" ]; then
  echo "missing $KAT — mayhem/build.sh must build it" >&2
  emit_ctrf "cef-installer-gtest+kat" "$ut_passed" $((ut_failed + 1)) $((ut_skipped + ${ut_disabled:-0}))
  exit 1
fi
out="$(mktemp)"
"$KAT" "$SRC/mayhem/testdata" >"$out" 2>"$out.err" || echo "kat exited non-zero" >&2
kat_passed=0 kat_failed=0
mapfile -t want <"$EXPECTED"
mapfile -t got <"$out"
for i in "${!want[@]}"; do
  if [ "${got[$i]:-}" == "${want[$i]}" ]; then
    kat_passed=$((kat_passed + 1))
  else
    kat_failed=$((kat_failed + 1))
    echo "MISMATCH line $((i + 1)): want [${want[$i]}] got [${got[$i]:-<missing>}]" >&2
  fi
done
if [ "${#got[@]}" -gt "${#want[@]}" ]; then
  kat_failed=$((kat_failed + ${#got[@]} - ${#want[@]}))
  echo "kat printed ${#got[@]} lines, expected ${#want[@]}" >&2
fi
rm -f "$out" "$out.err"

emit_ctrf "cef-installer-gtest+kat" $((ut_passed + kat_passed)) $((ut_failed + kat_failed)) \
  $((ut_skipped + ${ut_disabled:-0}))
