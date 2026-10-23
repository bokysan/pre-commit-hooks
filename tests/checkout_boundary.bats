#!/usr/bin/env bats
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# The install preflight stops at another checkout. A directory carrying its own
# `.git` (a clone: a directory; a git worktree: a FILE holding a gitdir: pointer)
# is ANOTHER CHECKOUT wherever it sits, and its manifests are not this commit's.
# Walking into one made an agent worktree under `.claude/worktrees/<id>/` fail
# every commit with exit 2.
#
# A nested go.mod or build file is deliberately NOT a boundary: the script is
# ecosystem-generic and gates every module in the tree on purpose.
#
# Four Gradle manifests, none installed:
#   app/                             this checkout            MUST be reported
#   sub/deep/                        this checkout, deeper    MUST be reported
#   .claude/worktrees/probe/mobile/  agent worktree, .git file   MUST NOT be
#   nested-checkout/mobile/          nested checkout              MUST NOT be
# The two that must be reported are the positive control: a boundary drawn too
# wide reports nothing and would pass a test that only looked for absences.

# shellcheck disable=SC2034 # EXTRA_ENV is read by licensing() in helpers.bash, which `load` sources.
load helpers

GRADLE='dependencies { implementation("androidx.annotation:annotation:1.9.1") }
'

setup() {
  new_repo
  EXTRA_ENV=(LICENSING_CACHE=0)
  put .licensing.conf 'LICENSING_SCAN_TARGET="dir:."
LICENSING_ALLOW=(MIT Apache-2.0)
LICENSING_DENY=(GPL-3.0-only)
'
  put app/build.gradle.kts "$GRADLE"
  put sub/deep/build.gradle.kts "$GRADLE"
  put .claude/worktrees/probe/mobile/build.gradle.kts "$GRADLE"
  put nested-checkout/mobile/build.gradle.kts "$GRADLE"
  put .claude/worktrees/probe/.git "gitdir: /nowhere/.git/worktrees/probe
"
  put nested-checkout/.git "gitdir: /nowhere/.git/worktrees/nested-checkout
"
}

@test "the preflight reports this checkout's manifests and stops at nested checkouts" {
  licensing check --only deps --mode full
  [ "$status" -eq 2 ]
  [[ "$output" == *"app/build.gradle.kts"* ]] || false
  [[ "$output" == *"sub/deep/build.gradle.kts"* ]] || false
  [[ "$output" == *"in 2 location(s)"* ]] || false
  [[ "$output" != *".claude/worktrees/probe"* ]] || false
  [[ "$output" != *"nested-checkout"* ]] || false
}
