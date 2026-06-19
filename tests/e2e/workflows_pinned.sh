#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Regression for issue #36: privileged CI jobs (contents:write release upload,
# Pages deploy, PR creation) must not run third-party actions by mutable tag —
# a moved tag or compromised maintainer would run attacker code with the job's
# write token.  Every external `uses:` reference in .github/ must be pinned to a
# full 40-hex commit SHA.  Local composite actions (./…) and reusable workflows
# are exempt.
set -euo pipefail

gh_dir="${1:?usage: workflows_pinned.sh <path-to-.github>}"

# Every action reference, comment stripped.
refs="$(grep -rhE '^[[:space:]]*-?[[:space:]]*uses:' "$gh_dir" \
        | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]*#.*$//; s/[[:space:]]*$//')"

fail=0
while IFS= read -r ref; do
  [ -z "$ref" ] && continue
  case "$ref" in
    ./*) continue ;; # local composite action, lives in the repo
  esac
  if ! printf '%s' "$ref" | grep -qE '@[0-9a-f]{40}$'; then
    echo "UNPINNED external action (must use a full commit SHA): $ref"
    fail=1
  fi
done <<EOF
$refs
EOF

[ "$fail" -eq 0 ] || { echo "FAIL: unpinned actions found"; exit 1; }
echo "PASS: all external GitHub Actions are pinned to commit SHAs"
