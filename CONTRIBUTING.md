<!--
SPDX-FileCopyrightText: 2026 Bojan Čekrlić
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing

## Gates

`pre-commit run --all-files` runs everything CI runs: whitespace and YAML hygiene, `shellcheck --severity=style`, `actionlint`, the version check, the documentation check (`scripts/check-docs.sh`), and this repository's own `licensing` hook. `bats tests` runs the behaviour tests (pre-push stage and CI). The commit-msg stage enforces Conventional Commits: `<type>[(scope)][!]: <description>` with type one of `feat fix perf refactor test docs build ci chore style revert`.

## Tests

`tests/*.bats` build a throwaway git repository per test and run `licensing.sh` inside it, the way the hook does. A fix to `licensing.sh` lands with a test that fails without it. End every `[[ ]]` assertion with `|| false`: bash 3.2 (macOS) fails a test on a false `[[ ]]` only when it is the last line, and a hook checks for it. Never raise a timeout or loosen an assertion to make a test pass; a flaky test is a bug in the script.

## Versioning and releases

The git tag is the version; `licensing.sh` has no version number of its own, and `--version` prints the tag of the
checkout it runs from.

1. Set every `rev:` in README.md to the new `vX.Y.Z`. `scripts/check-version.sh` checks that they agree.
2. Commit, tag `vX.Y.Z`, and push the commit and the tag. CI checks that the tag matches the README, and publishes the
   GitHub release.

Semver: a new knob or command is a minor; a changed default verdict or policy-file contract is a major; a fix is a patch. The scan cache key includes a checksum of `licensing.sh`, so any change to it invalidates every consumer's cache once.
