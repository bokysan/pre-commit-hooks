#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# Committed third-party code is covered in REUSE.toml by one entry per vendor
# root, not one per package: the real licences are checked from the syft scan
# and listed in the SBOM, and REUSE.toml stays the same whatever syft finds.

# shellcheck disable=SC2034,SC2153 # EXTRA_ENV is read, and ROOT set, by helpers.bash, which `load` sources.
load helpers

setup() {
  new_repo
  EXTRA_ENV=(LICENSING_CACHE=0)
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT)
LICENSING_DENY=(GPL-3.0-only)
LICENSING_COPYRIGHT="2026 Test"
LICENSING_LICENSE=MIT
LICENSING_DOC_LICENSE=MIT
'
  put vendor/github.com/acme/lib/lib.go 'package lib
'
  put vendor/example.org/x/x.go 'package x
'
  # The licence texts the tree uses are already here, so download fetches nothing.
  put LICENSES/MIT.txt 'MIT License
'
  git -C "$ROOT" add -A
  licensing init
}

@test "download covers a tracked vendor root with one entry and writes its marker text" {
  licensing download
  [ "$(grep -c '^path = "vendor/\*\*"$' "$ROOT/REUSE.toml")" -eq 1 ]
  grep -q '^SPDX-License-Identifier = "LicenseRef-vendored-packages"$' "$ROOT/REUSE.toml"
  run grep -c '^path = "vendor/[^*]' "$ROOT/REUSE.toml"
  [ "$output" = "0" ]
  [ -s "$ROOT/LICENSES/LicenseRef-vendored-packages.txt" ]
}

@test "a vendor root git does not track gets no entry" {
  git -C "$ROOT" rm -rq --cached vendor
  licensing download
  run grep -c '^path = "vendor/' "$ROOT/REUSE.toml"
  [ "$output" = "0" ]
}

@test "download never overwrites an existing text for the marker" {
  put LICENSES/LicenseRef-vendored-packages.txt 'our own wording
'
  licensing download
  [ "$(cat "$ROOT/LICENSES/LicenseRef-vendored-packages.txt")" = "our own wording" ]
}

@test "download --dry-run writes neither REUSE.toml nor LICENSES" {
  before="$(cat "$ROOT/REUSE.toml")"
  licensing download --dry-run
  [ "$(cat "$ROOT/REUSE.toml")" = "$before" ]
  [ "$(grep -c 'would update REUSE.toml' <<<"$output")" -eq 1 ]
  [ ! -e "$ROOT/LICENSES/LicenseRef-vendored-packages.txt" ]
}

@test "fix is not a command any more" {
  licensing fix
  [ "$status" -eq 2 ]
  [[ "$output" == *"unknown command: fix"* ]]
}

@test "every committed vendor directory gets its own entry: Go, Rust, PHP, Ruby, iOS" {
  put Pods/Alamofire/Source/Session.swift 'import Foundation
'
  put Carthage/Checkouts/Lib/Lib.swift 'import Foundation
'
  put third_party/zlib/zlib.h '/* zlib */
'
  git -C "$ROOT" add -A
  licensing download
  for root in vendor Pods Carthage third_party; do
    grep -q "^path = \"${root}/\*\*\"$" "$ROOT/REUSE.toml" || { echo "no entry for ${root}/"; return 1; }
  done
}
