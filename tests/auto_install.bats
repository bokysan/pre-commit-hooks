#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# LICENSING_AUTO_INSTALL=1 in the environment turns on the install step for one
# run, so a CI job can install dependencies without changing .licensing.conf for
# every developer. The ecosystem here is made up: its install command creates
# the directory the preflight looks for.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

setup() {
  new_repo
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT)
LICENSING_DENY=(GPL-3.0-only)
LICENSING_INSTALL_CHECKS=("fake|fake.lock|fake_modules|mkdir fake_modules")
'
  put fake.lock 'demo 1.0.0
'
}

@test "without auto-install an uninstalled manifest stops the check" {
  EXTRA_ENV=(LICENSING_CACHE=0)
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [ ! -d "$ROOT/fake_modules" ]
}

@test "LICENSING_AUTO_INSTALL=1 in the environment runs the install command" {
  EXTRA_ENV=(LICENSING_CACHE=0 LICENSING_AUTO_INSTALL=1)
  licensing check --only deps --mode full
  [ -d "$ROOT/fake_modules" ]
  [ "$status" -eq 0 ]
}
