#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# `init` seeds a repository with no policy and no git identity, and REUSE.toml
# records the syft that generated it: a different syft warns, never fails.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

setup() {
  new_repo
  EXTRA_ENV=(LICENSING_CACHE=0)
}

@test "init writes all three files in a repository with no git user.name" {
  # HOME and the global config are emptied so `git config user.name` fails, as
  # it does on a fresh CI runner or in a container.
  EXTRA_ENV=(HOME="$ROOT" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null)
  licensing init
  [ "$status" -eq 0 ]
  [ -f "$ROOT/.licensing.conf" ]
  [ -f "$ROOT/REUSE.toml" ]
  [ -f "$ROOT/.license-exceptions.txt" ]
}

@test "init does not write a syft version setting into the policy file" {
  licensing init
  [ "$status" -eq 0 ]
  run grep -q SYFT_VERSION "$ROOT/.licensing.conf"
  [ "$status" -ne 0 ]
}

# A tree with one MIT dependency and a REUSE.toml with a generated section.
toml_tree() {
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT)
LICENSING_DENY=(GPL-3.0-only)
LICENSING_LICENSE=MPL-2.0
LICENSING_DOC_LICENSE=CC-BY-4.0
LICENSING_COPYRIGHT="2026 Test"
'
  put package.json '{ "name": "root", "version": "0.0.0", "dependencies": { "dep": "1.0.0" } }'
  put node_modules/dep/package.json '{ "name": "dep", "version": "1.0.0", "license": "MIT" }'
  put .license-exceptions.txt 'root
'
  # The licence texts the tree uses are already here, so download fetches nothing.
  cp "${BATS_TEST_DIRNAME}/../LICENSES/MPL-2.0.txt" "${BATS_TEST_DIRNAME}/../LICENSES/CC-BY-4.0.txt" "$ROOT/" 2>/dev/null || true
  mkdir -p "$ROOT/LICENSES"
  mv "$ROOT/MPL-2.0.txt" "$ROOT/CC-BY-4.0.txt" "$ROOT/LICENSES/"
  put LICENSES/MIT.txt 'MIT License
'
  licensing init
  licensing download
}

@test "download records the syft version in the generated section" {
  toml_tree
  grep -q '^# generated with syft [0-9]' "$ROOT/REUSE.toml"
}

@test "a different syft than the one recorded warns and does not fail" {
  toml_tree
  sed -i.bak 's/^# generated with syft .*/# generated with syft 0.0.1/' "$ROOT/REUSE.toml"
  licensing check --only toml --mode full
  [ "$status" -eq 0 ]
  [[ "$output" == *"generated with 0.0.1"* ]]
}

@test "a REUSE.toml with no syft record checks clean and says nothing" {
  toml_tree
  sed -i.bak '/^# generated with syft /d' "$ROOT/REUSE.toml"
  licensing check --only toml --mode full
  [ "$status" -eq 0 ]
  [[ "$output" != *"warning: syft"* ]]
}

@test "run as a hook, hints name the pre-commit command and committed files name no path" {
  EXTRA_ENV=(PRE_COMMIT=1)
  licensing init
  [ "$status" -eq 0 ]
  [[ "$output" == *"pre-commit run licensing-download --hook-stage manual"* ]]
  [[ "$output" != *"$LICENSING download"* ]]
  run grep -l "$BATS_TEST_DIRNAME" "$ROOT/.licensing.conf" "$ROOT/REUSE.toml" "$ROOT/.license-exceptions.txt"
  [ "$status" -ne 0 ]
}

@test "run by hand, hints name the script as it was invoked" {
  licensing init
  [ "$status" -eq 0 ]
  [[ "$output" == *"$LICENSING download"* ]]
}

@test "the identity init is given in the environment is kept in .licensing.conf" {
  EXTRA_ENV=(LICENSING_COPYRIGHT="2026 ACME Inc." LICENSING_LICENSE=MIT LICENSING_DOC_LICENSE=CC-BY-4.0)
  licensing init
  [ "$status" -eq 0 ]
  grep -qx 'LICENSING_COPYRIGHT="2026 ACME Inc."' "$ROOT/.licensing.conf"
  grep -qx 'LICENSING_LICENSE="MIT"' "$ROOT/.licensing.conf"
  grep -qx 'LICENSING_DOC_LICENSE="CC-BY-4.0"' "$ROOT/.licensing.conf"
}

@test "without an identity in the environment init leaves the settings commented out" {
  licensing init
  [ "$status" -eq 0 ]
  run grep -cE '^LICENSING_(COPYRIGHT|LICENSE|DOC_LICENSE)=' "$ROOT/.licensing.conf"
  [ "$output" = "0" ]
}
