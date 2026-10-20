#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# The repository's tag is the version; nothing in licensing.sh repeats it. What
# can go stale is the README, which tells users which rev to pin: every `rev:`
# and `--ref` it shows must name the same vX.Y.Z, and on a tag (argument, or the
# exact tag at HEAD) that version must be the tag.
set -euo pipefail
cd "$(dirname "$0")/.."

versions="$(grep -oE '(rev: |--ref )v[0-9]+\.[0-9]+\.[0-9]+' README.md | sed -E 's/^(rev: |--ref )//' | sort -u)"
if [[ -z "$versions" ]]; then
    echo "FAIL: README.md shows no 'rev: vX.Y.Z' to pin."
    exit 1
fi
if [[ "$(wc -l <<<"$versions" | tr -d ' ')" != 1 ]]; then
    echo "FAIL: README.md shows more than one version to pin:"
    sed 's/^/  /' <<<"$versions"
    exit 1
fi

tag="${1:-$(git describe --tags --exact-match 2>/dev/null || true)}"
if [[ -n "$tag" && "$tag" != "$versions" ]]; then
    echo "FAIL: tag '${tag}' but README.md tells users to pin '${versions}'."
    exit 1
fi
echo "ok: README.md pins ${versions}${tag:+ (tag ${tag})}"
