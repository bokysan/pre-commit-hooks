#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# A licence with an SPDX exception, "Apache-2.0 WITH LLVM-exception" (common in
# Rust crates), needs two texts in LICENSES/: the licence and the exception.
# `reuse download` fetches both, so `download` must ask for both rather than
# treat the whole expression as a LicenseRef- for a person to write by hand.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

INDEX=registry/src/index.crates.io-1949cf8c6b5b557f

setup() {
  new_repo
  CARGO_HOME="$(mktemp -d)"
  EXTRA_ENV=(LICENSING_CACHE=0 "CARGO_HOME=$CARGO_HOME")
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT Apache-2.0)
LICENSING_DENY=(GPL-3.0-only)
LICENSING_ALLOW_EXPRESSIONS=("Apache-2.0 WITH LLVM-exception")
LICENSING_SELF_NAMES=("root-crate")
LICENSING_COPYRIGHT="2026 Test"
LICENSING_LICENSE=MIT
LICENSING_DOC_LICENSE=MIT
'
  put Cargo.toml '[package]
name = "root-crate"
version = "0.1.0"

[dependencies]
llvm-crate = "1"
'
  put Cargo.lock 'version = 4

[[package]]
name = "llvm-crate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000001"

[[package]]
name = "root-crate"
version = "0.1.0"
dependencies = [
 "llvm-crate",
]
'
  mkdir -p "$CARGO_HOME/$INDEX/llvm-crate-1.0.0"
  printf '[package]\nname = "llvm-crate"\nversion = "1.0.0"\nlicense = "Apache-2.0 WITH LLVM-exception"\n' \
    > "$CARGO_HOME/$INDEX/llvm-crate-1.0.0/Cargo.toml"
  put LICENSES/MIT.txt 'MIT License
'
  git -C "$ROOT" add -A
  licensing init
}

teardown() {
  rm -rf "$CARGO_HOME" "$ROOT" "$CACHE_DIR"
}

@test "download asks for the licence and the exception text, not for a text by hand" {
  licensing download --dry-run
  [[ "$output" == *"would fetch LICENSES/Apache-2.0.txt"* ]] || false
  [[ "$output" == *"would fetch LICENSES/LLVM-exception.txt"* ]] || false
  [[ "$output" != *"by hand"* ]] || false
}

@test "download --fix keeps both texts and claims the expression whole for the notice file" {
  put LICENSES/Apache-2.0.txt 'Apache License
'
  put LICENSES/LLVM-exception.txt 'LLVM Exceptions to the Apache 2.0 License
'
  licensing download --fix
  [ "$status" -eq 0 ]
  [ -f "$ROOT/LICENSES/Apache-2.0.txt" ]
  [ -f "$ROOT/LICENSES/LLVM-exception.txt" ]
  grep -qxF 'SPDX-License-Identifier = "Apache-2.0 WITH LLVM-exception"' "$ROOT/REUSE.toml"
  git -C "$ROOT" add -A
  licensing check --mode full
  [ "$status" -eq 0 ]
}
