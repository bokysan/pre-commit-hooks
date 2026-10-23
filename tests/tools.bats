#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# The hook fails at the START, loudly, when syft or reuse is unavailable through
# every channel (mise and PATH), instead of passing or failing later.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

setup() {
  new_repo
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT)
LICENSING_DENY=(GPL-3.0-only)
'
  # A PATH holding only what the script itself needs, no syft, no reuse, no mise.
  EMPTY_BIN="$(mktemp -d)"
  for t in bash git env sed awk grep cat cut sort tr head tail wc mkdir rm mktemp dirname basename date uname find xargs cksum ls cp mv tee od id stat; do
    p="$(command -v "$t" || true)"; [[ -n "$p" ]] && ln -s "$p" "$EMPTY_BIN/$t"
  done
}

teardown() {
  rm -rf "$EMPTY_BIN" "$ROOT" "$CACHE_DIR"
}

@test "missing syft fails first with the mise and PATH remedy" {
  run env -C "$ROOT" CI= LICENSING_CACHE=0 PATH="$EMPTY_BIN" "$EMPTY_BIN/bash" "$LICENSING" check --mode delta
  [ "$status" -eq 2 ]
  [[ "$output" == *"syft not found, neither through mise nor on PATH"* ]] || false
}

@test "missing reuse fails first when only syft is available" {
  command -v syft >/dev/null || skip "syft not installed"
  ln -s "$(command -v syft)" "$EMPTY_BIN/syft"
  run env -C "$ROOT" CI= LICENSING_CACHE=0 PATH="$EMPTY_BIN" "$EMPTY_BIN/bash" "$LICENSING" check --mode delta
  [ "$status" -eq 2 ]
  [[ "$output" == *"reuse not found, neither through mise nor on PATH"* ]] || false
}

@test "LICENSING_REUSE=0 in the policy does not demand reuse" {
  command -v syft >/dev/null || skip "syft not installed"
  ln -s "$(command -v syft)" "$EMPTY_BIN/syft"
  printf 'LICENSING_REUSE=0\n' >> "$ROOT/.licensing.conf"
  # --only lint is the part that needs reuse; without the setting it fails on
  # the missing tool (the test above), with it the lint is skipped and says so.
  run env -C "$ROOT" CI= LICENSING_CACHE=0 PATH="$EMPTY_BIN" "$EMPTY_BIN/bash" "$LICENSING" check --only lint --mode full
  [ "$status" -eq 0 ]
  [[ "$output" == *"REUSE lint is switched OFF"* ]] || false
}
