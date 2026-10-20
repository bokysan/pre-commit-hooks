#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

setup() {
  new_repo
  EXTRA_ENV=(LICENSING_CACHE=0)
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT Apache-2.0)
LICENSING_DENY=(GPL-3.0-only)
'
}

@test "--version prints the script version and nothing dated" {
  run bash "$LICENSING" --version
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^licensing\.sh\ [0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "refuses to run without a policy file" {
  rm "$ROOT/.licensing.conf"
  licensing check --only deps --mode full
  [ "$status" -ne 0 ]
  [[ "$output" == *".licensing.conf"* ]]
}

@test "a policy file that is a copy of the script is refused, not recursed into" {
  cp "$LICENSING" "$ROOT/.licensing.conf"
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [[ "$output" == *"looks like a copy"* ]]
}

@test "a policy file missing LICENSING_DENY is refused" {
  put .licensing.conf 'LICENSING_ALLOW=(MIT)
'
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [[ "$output" == *"LICENSING_DENY"* ]]
}
