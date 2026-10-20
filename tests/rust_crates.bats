#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# syft catalogues a Rust dependency from Cargo.lock alone, and Cargo.lock carries
# no licence. The licence is in the crate's own Cargo.toml, which cargo unpacks
# into $CARGO_HOME/registry/src/<index>/<name>-<version>/, so that is where the
# script reads it. Without that every crate was "named only in a lockfile" and
# exempt, and a GPL crate passed the gate unseen.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

INDEX=registry/src/index.crates.io-1949cf8c6b5b557f
MIT_TEXT='Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
'

setup() {
  new_repo
  CARGO_HOME="$(mktemp -d)"
  EXTRA_ENV=(LICENSING_CACHE=0 "CARGO_HOME=$CARGO_HOME")
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT Apache-2.0)
LICENSING_DENY=(GPL-3.0-only)
LICENSING_SELF_NAMES=("root-crate")
'
  put Cargo.toml '[package]
name = "root-crate"
version = "0.1.0"

[dependencies]
gpl-crate = "2"
mit-crate = "1"
'
  put Cargo.lock 'version = 4

[[package]]
name = "gpl-crate"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000002"

[[package]]
name = "mit-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000001"

[[package]]
name = "root-crate"
version = "0.1.0"
dependencies = [
 "gpl-crate",
 "mit-crate",
]
'
}

teardown() {
  rm -rf "$CARGO_HOME" "$ROOT" "$CACHE_DIR"
}

# crate <name> <version> <licence-line>: unpack a crate the way cargo would.
crate() {
  mkdir -p "$CARGO_HOME/$INDEX/$1-$2"
  printf '[package]\nname = "%s"\nversion = "%s"\n%s\n\n[dependencies]\n' "$1" "$2" "$3" \
    > "$CARGO_HOME/$INDEX/$1-$2/Cargo.toml"
}

deps_check() { licensing check --only deps --mode full; }

@test "a crate's licence is read from the registry: the GPL crate fails" {
  crate mit-crate 1.0.0 'license = "MIT OR Apache-2.0"'
  crate gpl-crate 2.0.0 'license = "GPL-3.0-only"'
  deps_check
  [ "$status" -ne 0 ]
  [[ "$output" == *"gpl-crate"* ]]
  [[ "$output" == *"GPL-3.0-only"* ]]
  [[ "$output" != *"mit-crate"* ]]
}

@test "the crate licence reaches the SBOM, not the gate alone" {
  crate mit-crate 1.0.0 'license = "MIT OR Apache-2.0"'
  crate gpl-crate 2.0.0 'license = "GPL-3.0-only"'
  licensing sbom -o "$ROOT.sbom.json"
  [ "$status" -eq 0 ]
  run jq -r '.packages[] | select(.name=="mit-crate") | .licenseDeclared + .licenseConcluded' "$ROOT.sbom.json"
  rm -f "$ROOT.sbom.json"
  [ "$status" -eq 0 ]
  [[ "$output" == *"MIT"* ]]
}

@test "a crate naming a license-file is read as text" {
  crate mit-crate 1.0.0 'license-file = "COPYING.txt"'
  printf '%s' "$MIT_TEXT" > "$CARGO_HOME/$INDEX/mit-crate-1.0.0/COPYING.txt"
  crate gpl-crate 2.0.0 'license = "GPL-3.0-only"'
  deps_check
  [[ "$output" != *"mit-crate"* ]]
}

@test "a crate cargo never unpacked stays lockfile-only and exempt" {
  crate mit-crate 1.0.0 'license = "MIT"'
  deps_check
  [ "$status" -eq 0 ]
}

@test "the SBOM lists components even when none has a licence" {
  licensing sbom -o "$ROOT.sbom.json"
  [ "$status" -eq 0 ]
  run cat "$ROOT.sbom.json"
  rm -f "$ROOT.sbom.json"
  [[ "$output" == *'"mit-crate"'* ]]
  [[ "$output" == *"NOASSERTION"* ]]
}

@test "a crate unpacked after a cached run is not served from the stale cache" {
  EXTRA_ENV=("CARGO_HOME=$CARGO_HOME")   # cache ON for this one
  crate mit-crate 1.0.0 'license = "MIT"'
  deps_check
  [ "$status" -eq 0 ]
  crate gpl-crate 2.0.0 'license = "GPL-3.0-only"'
  deps_check
  [ "$status" -ne 0 ]
}

@test "LICENSING_CACHE=0 in the environment turns the cache off" {
  EXTRA_ENV=(LICENSING_CACHE=0 LICENSING_VERBOSE=1 "CARGO_HOME=$CARGO_HOME")
  deps_check
  deps_check
  [[ "$output" != *"from cache"* ]]
}
