<!--
SPDX-FileCopyrightText: 2026 Bojan Čekrlić
SPDX-License-Identifier: CC-BY-4.0
-->

# Contributing

## Gates

`pre-commit run --all-files` runs everything CI runs: whitespace and YAML hygiene, `shellcheck --severity=style`, `actionlint`, the version check, and this repository's own `licensing` hook. `bats tests` runs the behaviour tests (pre-push stage and CI). The commit-msg stage enforces Conventional Commits: `<type>[(scope)][!]: <description>` with type one of `feat fix perf refactor test docs build ci chore style revert`.

## Tests

`tests/*.bats` build a throwaway git repository per test and run `licensing.sh` inside it, the way the hook does. A fix to `licensing.sh` lands with a test that fails without it. Never raise a timeout or loosen an assertion to make a test pass; a flaky test is a bug in the script.

## Versioning and releases

The repository version is `licensing.sh`'s version.

1. Set `LICENSING_SH_VERSION="X.Y.Z"` in `licensing.sh` and update the `rev: vX.Y.Z` in its integration notes and in the README.
2. `scripts/check-version.sh` must pass.
3. Commit, then tag `vX.Y.Z` and push the tag.

Semver: a new knob or command is a minor; a changed default verdict or policy-file contract is a major; a fix is a patch. The scan cache key includes the script version and a checksum of the file itself, so a release invalidates every consumer's cache once.

## Mirror

Forgejo is the source of truth. The GitHub copy is a push mirror (Forgejo: Settings → Repository → Mirror settings → Push mirror, target `https://github.com/bokysan/pre-commit-hooks.git`, with a GitHub token that may push). **The mirror is not configured until the maintainer says so**, and nothing in this repository pushes to GitHub by itself.
