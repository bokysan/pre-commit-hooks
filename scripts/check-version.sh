#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# The repository version IS licensing.sh's version: tag vX.Y.Z carries
# LICENSING_SH_VERSION="X.Y.Z". On a tag (argument, or the exact tag at HEAD) the two
# must be equal; with no tag the version must still be a bare X.Y.Z.
set -euo pipefail
cd "$(dirname "$0")/.."

version="$(sed -n 's/^LICENSING_SH_VERSION="\(.*\)"$/\1/p' licensing.sh)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "FAIL: LICENSING_SH_VERSION in licensing.sh is '${version}', not X.Y.Z."
    exit 1
fi

tag="${1:-$(git describe --tags --exact-match 2>/dev/null || true)}"
if [[ -n "$tag" && "$tag" != "v${version}" ]]; then
    echo "FAIL: tag '${tag}' does not match LICENSING_SH_VERSION '${version}' (expected v${version})."
    exit 1
fi

# The example in the integration notes must name a real version, not a stale one.
if ! grep -q "rev: v${version} " licensing.sh; then
    echo "FAIL: licensing.sh's integration notes show a 'rev:' other than v${version}."
    exit 1
fi
echo "ok: version ${version}${tag:+ (tag ${tag})}"
