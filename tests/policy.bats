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

# The version is the tag of the checkout licensing.sh runs from, never a number
# written into the script.
hooks_checkout() { # hooks_checkout <dir>: a repository holding licensing.sh, tagged v9.9.9
  mkdir -p "$1"
  cp "$LICENSING" "$1/licensing.sh"
  git -C "$1" init -q .
  git -C "$1" add licensing.sh
  git -C "$1" -c user.name=t -c user.email=t@t commit -qm "feat: x"
  git -C "$1" tag v9.9.9
}

@test "--version prints the tag of a tagged checkout" {
  H="$(mktemp -d)"
  hooks_checkout "$H/hooks"
  run bash "$H/hooks/licensing.sh" --version
  rm -rf "$H"
  [ "$status" -eq 0 ]
  [ "$output" = "licensing.sh v9.9.9" ]
}

@test "--version prints the tag pre-commit fetched into a clone without tags" {
  H="$(mktemp -d)"
  hooks_checkout "$H/hooks"
  # What pre-commit does: init, fetch the rev shallowly, check it out.
  git -C "$H" init -q clone
  git -C "$H/clone" fetch -q --depth=1 "file://$H/hooks" v9.9.9
  git -C "$H/clone" checkout -q FETCH_HEAD
  [ -z "$(git -C "$H/clone" tag)" ]
  run bash "$H/clone/licensing.sh" --version
  rm -rf "$H"
  [ "$status" -eq 0 ]
  [ "$output" = "licensing.sh v9.9.9" ]
}

@test "--version prints the commit of an untagged checkout" {
  H="$(mktemp -d)"
  hooks_checkout "$H/hooks"
  git -C "$H/hooks" tag -d v9.9.9 >/dev/null
  sha="$(git -C "$H/hooks" rev-parse --short HEAD)"
  run bash "$H/hooks/licensing.sh" --version
  rm -rf "$H"
  [ "$output" = "licensing.sh ${sha}" ]
}

@test "refuses to run without a policy file" {
  rm "$ROOT/.licensing.conf"
  licensing check --only deps --mode full
  [ "$status" -ne 0 ]
  [[ "$output" == *".licensing.conf"* ]] || false
}

@test "a policy file that is a copy of the script is refused, not recursed into" {
  cp "$LICENSING" "$ROOT/.licensing.conf"
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [[ "$output" == *"looks like a copy"* ]] || false
}

@test "a policy file missing LICENSING_DENY is refused" {
  put .licensing.conf 'LICENSING_ALLOW=(MIT)
'
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [[ "$output" == *"LICENSING_DENY"* ]] || false
}
