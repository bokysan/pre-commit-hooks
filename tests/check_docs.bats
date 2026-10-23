#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# scripts/check-docs.sh holds README.md and licensing.sh together. Each test
# breaks one copy of the pair in one way and expects the gate to name it; the
# first test is the control that the untouched pair passes.

# shellcheck disable=SC2016 # the ${...} and backticks below are text inserted into a file, not expansions.

GATE="${BATS_TEST_DIRNAME}/../scripts/check-docs.sh"

setup() {
  W="$(mktemp -d)"
  cp "${BATS_TEST_DIRNAME}/../licensing.sh" "${BATS_TEST_DIRNAME}/../README.md" "${BATS_TEST_DIRNAME}/../.pre-commit-hooks.yaml" "$W/"
}

teardown() {
  rm -rf "$W"
}

gate() { run "$GATE" "$W/licensing.sh" "$W/README.md" "$W/.pre-commit-hooks.yaml"; }

# insert_before <file> <line that exists> <text>: add text on the line above it.
insert_before() {
  awk -v at="$2" -v add="$3" '$0 == at && !done { print add; done = 1 } { print }' "$1" > "$1.new" && mv "$1.new" "$1"
}

@test "the repository's own pair passes" {
  gate
  [ "$status" -eq 0 ]
}

@test "a new setting without a README entry fails" {
  insert_before "$W/licensing.sh" 'LICENSING_LOCAL_MODE="full"' 'LICENSING_BRAND_NEW="x"'
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"setting LICENSING_BRAND_NEW has no entry"* ]] || false
}

@test "a setting read only from the environment without a README entry fails" {
  insert_before "$W/licensing.sh" 'LICENSING_LOCAL_MODE="full"' ': "${LICENSING_FROM_ENV:-}"'
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"setting LICENSING_FROM_ENV has no entry"* ]] || false
}

@test "a README row for a setting the script does not have fails" {
  insert_before "$W/README.md" '## Machine-readable output for scripts' '| `LICENSING_GONE` | 1 | stale |'
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"documents LICENSING_GONE, which"* ]] || false
}

@test "a new option without a README row or a --help line fails" {
  insert_before "$W/licensing.sh" '    --no-cache) NO_CACHE=1; shift ;;' '    --brand-new) shift ;;'
  grep -q -- '--brand-new' "$W/licensing.sh"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"option --brand-new has no row"* ]] || false
  [[ "$output" == *"option --brand-new is not listed by"* ]] || false
}

@test "a new hook without a README row fails" {
  printf '\n- id: licensing-brand-new\n  name: x\n  entry: licensing.sh\n  language: script\n' >> "$W/.pre-commit-hooks.yaml"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"hook licensing-brand-new"* ]] || false
}

@test "a new environment variable the README does not name fails" {
  insert_before "$W/licensing.sh" 'LICENSING_LOCAL_MODE="full"' ': "${SOME_TOOL_HOME:-}"'
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"environment variable SOME_TOOL_HOME"* ]] || false
}

@test "a default file name the README does not name fails" {
  sed -i.bak 's/^LICENSING_NOTICE_FILE="THIRD-PARTY-LICENSES.md"$/LICENSING_NOTICE_FILE="NOTICE.txt"/' "$W/licensing.sh"
  grep -q 'NOTICE.txt' "$W/licensing.sh"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"file NOTICE.txt"* ]] || false
}

@test "an in-page link to a heading that does not exist fails" {
  insert_before "$W/README.md" '## Machine-readable output for scripts' 'See [nowhere](#no-such-heading).'
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"links to #no-such-heading"* ]] || false
}

@test "a README default that differs from the script's fails" {
  sed -i.bak 's/^LICENSING_MAX_FINDINGS=0$/LICENSING_MAX_FINDINGS=50/' "$W/licensing.sh"
  grep -q '^LICENSING_MAX_FINDINGS=50$' "$W/licensing.sh"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"default shown for LICENSING_MAX_FINDINGS"* ]] || false
}

@test "an optional setting labelled as required fails" {
  awk '/^#### `LICENSING_MAX_FINDINGS`/ { hit = 1 } hit && /^[*_]Optional\.[*_]/ { sub(/^[*_]Optional\.[*_]/, "*Required.*"); hit = 0 } { print }' "$W/README.md" > "$W/README.new"
  mv "$W/README.new" "$W/README.md"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"LICENSING_MAX_FINDINGS is under \"Settings the defaults cover\""* ]] || false
}

@test "a new command without a hook that runs it fails" {
  sed -i.bak 's/^LICENSING_COMMANDS="check download sbom init"$/LICENSING_COMMANDS="check download sbom init report"/' "$W/licensing.sh"
  grep -q 'init report"$' "$W/licensing.sh"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"command report has no hook"* ]] || false
}

@test "a hook entry with a command or option the script lacks fails" {
  sed -i.bak 's/^  entry: licensing.sh sbom$/  entry: licensing.sh sbomb --format=x/' "$W/.pre-commit-hooks.yaml"
  grep -q 'sbomb' "$W/.pre-commit-hooks.yaml"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"hook licensing-sbom runs command 'sbomb'"* ]] || false
  [[ "$output" == *"passes option '--format=x'"* ]] || false
}

@test "a short default shown as (…) fails" {
  sed -i.bak 's/^LICENSING_MAX_FINDINGS=0$/LICENSING_MAX_FINDINGS=(…)/' "$W/README.md"
  grep -q '^LICENSING_MAX_FINDINGS=(…)$' "$W/README.md"
  gate
  [ "$status" -eq 1 ]
  [[ "$output" == *"shortens the default of LICENSING_MAX_FINDINGS"* ]] || false
}

@test "a long default shown as (…) passes" {
  grep -q '^LICENSING_LICENSE_ALIASES=(…)' "$W/README.md"
  gate
  [ "$status" -eq 0 ]
}
