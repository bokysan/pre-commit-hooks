#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# The starter policies in README.md are meant to be pasted into .licensing.conf
# as they stand. Each one is loaded here, alone, into a real run: it must be
# accepted by the script, and no licence may be on both lists (a licence on both
# is denied, which is never what a policy means).

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

README_MD="${BATS_TEST_DIRNAME}/../README.md"

# Every ```bash block in the LICENSING_ALLOW / LICENSING_DENY entry that sets
# LICENSING_ALLOW, one file per block, into $1.
split_policies() {
  awk -v out="$1" '
    /^####? `LICENSING_ALLOW` and `LICENSING_DENY`$/ { inentry = 1; next }
    inentry && !inblock && /^#+ / { exit }
    inentry && $0 == "```bash" { inblock = 1; buf = ""; next }
    inblock && $0 == "```" { inblock = 0; if (buf ~ /LICENSING_ALLOW=\(/) { n++; print buf > (out "/" n) ; close(out "/" n) }; next }
    inblock { buf = buf $0 "\n" }
  ' "$README_MD"
}

@test "every starter policy is accepted by the script and lists no licence twice" {
  P="$(mktemp -d)"
  split_policies "$P"
  [ "$(find "$P" -type f | wc -l | tr -d ' ')" -eq 6 ]
  for f in "$P"/*; do
    title="$(head -1 "$f")"
    new_repo
    cp "$f" "$ROOT/.licensing.conf"
    run bash -c '. "$1"; comm -12 <(printf "%s\n" "${LICENSING_ALLOW[@]}" | sort) <(printf "%s\n" "${LICENSING_DENY[@]}" | sort)' _ "$f"
    [ "$status" -eq 0 ] || { echo "$title: does not source: $output"; return 1; }
    [ -z "$output" ] || { echo "$title: on both lists: $output"; return 1; }
    EXTRA_ENV=(LICENSING_CACHE=0)
    licensing check --only deps --mode full
    [ "$status" -eq 0 ] || { echo "$title: the script refused it: $output"; return 1; }
    rm -rf "$ROOT" "$CACHE_DIR"
  done
  rm -rf "$P"
}
