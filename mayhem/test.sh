#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the upstream Catch2 test suite that mayhem/build.sh compiled
# (tests/: simple_test, pr_153_test, corkami_test over the corkami PE poc dataset).
# The Catch2 binary asserts parsed-header values and malformed-input behavior, so a
# patch that no-ops the library fails here. Counts are mapped from Catch2's own
# summary (test cases), and we additionally require assertions > 0 so an empty /
# neutered run can never pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

RUNNER=build-tests/tests/tests
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing — mayhem/build.sh must build the suite" >&2
  emit_ctrf "catch2" 0 1
  exit 1
fi

# The Catch2 binary resolves assets via compile-time absolute paths (ASSETS_DIR / CORKAMI_PE_PATH).
out="$("$RUNNER" 2>&1)"; rc=$?
printf '%s\n' "$out"

passed=0; failed=0
if summary="$(printf '%s\n' "$out" | grep -m1 -E '^All tests passed \([0-9]+ assertions? in [0-9]+ test cases?\)')"; then
  assertions="$(printf '%s\n' "$summary" | sed -E 's/^All tests passed \(([0-9]+) assertions?.*/\1/')"
  cases="$(printf '%s\n' "$summary" | sed -E 's/.* in ([0-9]+) test cases?\)$/\1/')"
  if [ "$rc" -eq 0 ] && [ "${assertions:-0}" -gt 0 ] && [ "${cases:-0}" -gt 0 ]; then
    passed=$cases; failed=0
  else
    passed=0; failed=${cases:-1}
  fi
elif tcline="$(printf '%s\n' "$out" | grep -m1 -E '^test cases:')"; then
  passed="$(printf '%s\n' "$tcline" | sed -nE 's/.*\|[[:space:]]*([0-9]+) passed.*/\1/p')"
  failed="$(printf '%s\n' "$tcline" | sed -nE 's/.*\|[[:space:]]*([0-9]+) failed.*/\1/p')"
  passed=${passed:-0}; failed=${failed:-1}
  [ "$failed" -gt 0 ] || failed=1   # a Catch2 failure summary means something failed
else
  echo "test.sh: no Catch2 summary in output — suite did not actually run" >&2
  passed=0; failed=1
fi

emit_ctrf "catch2" "$passed" "$failed"
