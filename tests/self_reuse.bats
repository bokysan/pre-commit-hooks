#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# reuse reads an SPDX licence tag wherever it appears in a file, and honours
# REUSE-IgnoreStart/End per 64 KiB chunk only: a tag near a chunk boundary is
# read even inside the markers, and then licensing.sh fails its own lint
# depending on where unrelated edits move the boundaries. So the script's code
# never spells the tag out; its header is the only place it appears.

@test "licensing.sh spells the SPDX licence tag only in its own header" {
  run grep -n 'SPDX-License-Identifier:' "${BATS_TEST_DIRNAME}/../licensing.sh"
  [ "$output" = "3:# SPDX-License-Identifier: MPL-2.0" ]
}
