#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Mirage counterfeit-route e2e.  Compiles the verdict workload twice — once clean
# and once with the Mirage hub's route pinned to the counterfeit path at emission
# time (force_route = "fake") — then requires that the forced-fake build:
#
#   1. runs to completion WITHOUT a trap/crash (exit status 0), proving dirty-
#      seal routing yields a plausible denial rather than a fault, and
#   2. produces DIFFERENT output than the clean reference, proving the
#      counterfeit algorithms are actually wired in and computed instead of the
#      real ones.
#
# This deterministically exercises the counterfeit path without needing a live
# runtime seal producer (which is platform-specific).  The force_route knob is a
# build-time diagnostic that changes only the emitted IR, never a shipped binary.
#
# Usage: mirage_forced_fake.sh <clang> <plugin> <sdk> <source> <fake_config> [seed]
set -euo pipefail

CLANG="$1"; PLUGIN="$2"; SDK="$3"; SRC="$4"; FAKE_CFG="$5"; SEED="${6:-4242}"

if [ -z "$SDK" ] && command -v xcrun >/dev/null 2>&1; then
  SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
fi
SYSROOT=()
[ -n "$SDK" ] && SYSROOT=(-isysroot "$SDK")

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$CLANG" "${SYSROOT[@]}" -O2 "$SRC" -o "$TMP/ref"
REF="$("$TMP/ref")"

env MOROK_ENABLE=1 MOROK_SEED="$SEED" MOROK_CONFIG="$FAKE_CFG" \
    "$CLANG" "${SYSROOT[@]}" -O2 -fpass-plugin="$PLUGIN" "$SRC" -o "$TMP/fake"

set +e
FAKE="$("$TMP/fake")"
STATUS=$?
set -e

if [ "$STATUS" -ne 0 ]; then
  echo "FAIL forced-fake build trapped/crashed (exit $STATUS)" >&2
  exit 1
fi

if [ "$REF" = "$FAKE" ]; then
  echo "FAIL forced-fake output matched the real reference — counterfeit not wired" >&2
  echo "  ref='$REF'" >&2
  exit 1
fi

echo "OK   forced-fake diverged without trapping  ref='$REF'  fake='$FAKE'"
exit 0
