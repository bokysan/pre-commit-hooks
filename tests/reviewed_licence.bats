#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# A licence a person found by READING, for a component the scan read nothing for:
# `<name> = <SPDX expression>` in .license-exceptions.txt. It is applied to the
# inventory itself, after the scan and before either half reads it, so the gate,
# --obligations, --porcelain, the SBOM and the REUSE.toml annotations give one
# answer. Three properties keep it a gap-fill and not an override, one test each:
#   - it FILLS A GAP and nothing else; a licence the scan read keeps the scan's answer
#   - the filled licence is GATED like any other (deny list still fails)
#   - it is applied AFTER the cache, so editing the file costs a re-read, not a re-scan

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

# The repository's own root package.json is the project, not something it absorbs.
SELF_LINE='root   # reviewed: the project itself, not a dependency
'

setup() {
  new_repo
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT Apache-2.0)
LICENSING_DENY=(GPL-3.0-only)
'
  put package.json '{ "name": "root", "version": "0.0.0", "dependencies": { "silent-pkg": "1.0.0", "talkative-pkg": "2.0.0" } }'
  # silent-pkg declares no licence at all; talkative-pkg states MIT.
  put node_modules/silent-pkg/package.json '{ "name": "silent-pkg", "version": "1.0.0" }'
  put node_modules/talkative-pkg/package.json '{ "name": "talkative-pkg", "version": "2.0.0", "license": "MIT" }'
  EXTRA_ENV=(LICENSING_CACHE=0)
}

deps_check() { licensing check --only deps --mode full "$@"; }

@test "a reviewed licence fills a gap the scan left, in the gate and the inventory" {
  put .license-exceptions.txt "$SELF_LINE"
  deps_check
  # Control: with nothing recorded the dependency with no licence fails, so the
  # run below has a verdict to flip.
  [ "$status" -ne 0 ]
  [[ "$output" == *"silent-pkg"* ]] || false

  put .license-exceptions.txt "${SELF_LINE}silent-pkg = MIT   # reviewed: ships no LICENSE, MIT upstream
"
  deps_check
  [ "$status" -eq 0 ]

  # The inventory, not just the gate.
  licensing --obligations
  [[ "$output" == *"MIT"* ]] || false
}

@test "a reviewed licence never overrules the one the package states" {
  put .license-exceptions.txt "${SELF_LINE}silent-pkg = MIT
talkative-pkg = Apache-2.0   # deliberately wrong: the package itself says MIT
"
  deps_check --porcelain
  [[ "$output" == *"warning"* ]] || false
  [[ "$output" == *"talkative-pkg"* ]] || false
  [[ "$output" == *"the scan's answer stands"* ]] || false
}

@test "a reviewed licence on the deny list still fails" {
  put .license-exceptions.txt "${SELF_LINE}silent-pkg = GPL-3.0-only   # reviewed: it really is GPL
"
  deps_check
  [ "$status" -ne 0 ]
  [[ "$output" == *"GPL-3.0-only"* ]] || false
}

@test "recording a reviewed licence costs a re-read, not a re-scan" {
  EXTRA_ENV=(LICENSING_VERBOSE=1)
  put .license-exceptions.txt "$SELF_LINE"
  deps_check
  [ "$status" -ne 0 ]   # cold run: no licence recorded

  put .license-exceptions.txt "${SELF_LINE}silent-pkg = MIT   # reviewed: MIT in the upstream repo
"
  deps_check
  [ "$status" -eq 0 ]
  [[ "$output" == *"from cache"* ]] || false
}
