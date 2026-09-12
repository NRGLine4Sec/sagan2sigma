#!/usr/bin/env bash
# Run every engine check and report a single verdict.
#
# Each check is independent and prints its own pass/fail lines, so a failure
# tells you which belief about Sagan no longer holds. Expect a few minutes:
# every case starts a real Sagan process inside a nix-shell.
#
#   ./run-all.sh              run everything
#   ./run-all.sh matching     run one family (substring match on the filename)

set -u
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${LAB_PYTHON:-$(command -v python3 || true)}"

if [ ! -x "${PYTHON:-}" ]; then
    echo "no python found; set LAB_PYTHON to an interpreter" >&2
    exit 2
fi

BIN="${SAGAN2SIGMA_LAB_BIN:-$LAB/bin}"

if [ ! -x "$BIN/sagan-upstream" ]; then
    echo "missing $BIN/sagan-upstream; run build/build-sagan.sh first" >&2
    exit 2
fi

# The other two builds need local patches this repository does not carry. Their
# absence is not an error: each check that needs one skips itself and says so,
# and this warning is here so that a short run is not mistaken for a full one.
if [ ! -x "$BIN/sagan-patched" ] || [ ! -x "$BIN/sagan-sane" ]; then
    echo "note: the patched builds are absent, so the checks that measure the" >&2
    echo "      'after' correlation path will skip. See docs/LAB.md." >&2
fi

filter="${1:-}"
failed=0
ran=0

# Which files this run will cover, counted up front so progress can say
# "3/13" rather than leaving the reader guessing how much is left.
selected=()
for check in "$LAB"/checks/check_*.py; do
    name="$(basename "$check" .py)"
    if [ -n "$filter" ] && [[ "$name" != *"$filter"* ]]; then
        continue
    fi
    selected+=("$check")
done
total="${#selected[@]}"

started="$(date +%s)"

for check in "${selected[@]+"${selected[@]}"}"; do
    name="$(basename "$check" .py)"
    ran=$((ran + 1))

    # A progress line before the file runs, not after. Each check takes tens of
    # seconds (every case starts a real Sagan inside a nix-shell), so without
    # this the terminal sits silent and there is no way to tell a slow run from
    # a stuck one. Flushed immediately, because a pipe into grep or tee buffers
    # otherwise and the whole point is lost.
    printf '[%d/%d] %s ...\n' "$ran" "$total" "${name#check_}"

    if "$PYTHON" "$check"; then
        verdict="ok"
    else
        verdict="FAILED"
        failed=$((failed + 1))
    fi
    printf '[%d/%d] %s %s (%ds elapsed)\n' \
        "$ran" "$total" "${name#check_}" "$verdict" "$(( $(date +%s) - started ))"
done

echo
if [ "$ran" -eq 0 ]; then
    echo "no check matched '$filter'"
    exit 2
elif [ "$failed" -eq 0 ]; then
    echo "ALL $ran CHECK FILES PASSED"
else
    echo "$failed of $ran CHECK FILES FAILED"
fi
exit "$failed"
