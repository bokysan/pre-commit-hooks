# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# Shared fixtures for the bats suites. Every test builds its own throwaway git
# repository and runs licensing.sh inside it, the way the pre-commit hook does.

LICENSING="${BATS_TEST_DIRNAME}/../licensing.sh"

# A fresh, host-independent git repository. The host's GIT_* variables are
# stripped: run from a pre-commit hook inside a worktree they would point the
# fixture's `git init` at the host repository and rewrite its config.
new_repo() {
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR GIT_PREFIX
  ROOT="$(cd "$(mktemp -d)" && pwd -P)"   # -P: macOS /var is a symlink to /private/var
  git -C "$ROOT" init -q .
  CACHE_DIR="$ROOT.cache"
}

# put <path> <body>: write a file, creating its directory.
put() {
  mkdir -p "$(dirname "$ROOT/$1")"
  printf '%s' "$2" > "$ROOT/$1"
}

# licensing <args...>: run the script in $ROOT; sets $status and $output (bats `run`).
# CI is cleared so --mode auto means the local mode, and the cache lives outside
# the tree (an untracked file inside it would fail `reuse lint`).
licensing() {
  run env -C "$ROOT" CI= LICENSING_CACHE_DIR="$CACHE_DIR" "${EXTRA_ENV[@]}" bash "$LICENSING" "$@"
}
EXTRA_ENV=()

teardown() {
  [[ -n "${ROOT:-}" ]] && rm -rf "$ROOT" "$CACHE_DIR"
}
