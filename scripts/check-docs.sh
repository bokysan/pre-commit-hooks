#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# README.md is the manual for licensing.sh. This gate keeps the two in step, in
# both directions, from what the script itself declares:
#
#   settings   every LICENSING_* setting the script assigns or reads has an entry
#              (#### `LICENSING_X`), and every entry names one that exists
#   defaults   every assignment in the ```bash block after "Default:" or "Defaults:"
#              in an entry is the script's own default, once comments are dropped
#              and whitespace is collapsed; a default over 200 characters may be
#              shown as (…)
#   env        every other environment variable the script reads is named
#   commands   every command in LICENSING_COMMANDS has a row, and --help lists it
#   options    every option the argument parsers accept has a row, and --help
#              lists it; every option row names one that exists
#   hooks      every hook id in .pre-commit-hooks.yaml has a row, and every hook
#              row names one that exists
#   hook entries  every command has a hook whose entry runs it, and every hook
#              entry runs licensing.sh with a command and options it accepts
#   files      every file or directory name a setting defaults to is named
#   labels     every setting entry opens with *Required.* or *Recommended.* (or the
#              _Required._ spelling a Markdown formatter writes) under
#              "Settings to set", and with *Optional.* under "Settings the defaults
#              cover"
#   anchors    every in-page link (#anchor) points at a heading that exists
#
# Usage: scripts/check-docs.sh [script] [readme] [hooks-manifest]
set -euo pipefail
cd "$(dirname "$0")/.."

SCRIPT="${1:-licensing.sh}"
README="${2:-README.md}"
HOOKS="${3:-.pre-commit-hooks.yaml}"

# Settings that are not for users, each with the reason. A name listed here that
# the script no longer has is itself a failure, so this list cannot go stale.
INTERNAL=(
  "LICENSING_COMMANDS|the command list --completion and the parser read"
  "LICENSING_LINT_CATEGORIES|the messages for reuse lint's report categories"
  "LICENSING_MEMO_MAX|an in-process memo size, invisible in any result"
  "LICENSING_PORCELAIN_VERSIONS|the --porcelain formats this version speaks"
  "LICENSING_REQUIRED_KEYS|the settings the policy file must define"
  "LICENSING_SYFT_STAMP|the prefix of the syft line in REUSE.toml"
  "LICENSING_VENDOR_LICENCE|the fixed id REUSE.toml gives committed third-party code"
)
# Environment variables that need no mention: every shell has them.
ENV_UNDOCUMENTED=" HOME PATH TMPDIR "

WORK="$(mktemp -d)"
trap '[[ -n "${KEEP_WORK:-}" ]] || rm -rf "$WORK"' EXIT
mkdir -p "$WORK/script" "$WORK/readme"

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

is_internal() {
  local e; for e in "${INTERNAL[@]}"; do [[ "${e%%|*}" == "$1" ]] && return 0; done
  return 1
}

# --- what the script declares ---------------------------------------------

# Assigned at the top level (the defaults a policy file overrides), or read from
# the environment with a default.
script_settings="$( { grep -oE '^LICENSING_[A-Z0-9_]+=' "$SCRIPT" | tr -d =
                      grep -oE '\$\{LICENSING_[A-Z0-9_]+:-' "$SCRIPT" | sed 's/^\${//; s/:-$//'
                    } | sort -u)"

# Read as ${NAME:-...} but never assigned anywhere in the script: that is an
# input from the environment.
script_env="$(grep -oE '\$\{[A-Z][A-Za-z0-9_]*:[-+]' "$SCRIPT" | sed 's/^\${//; s/:[-+]$//' \
  | grep -v '^LICENSING_' | sort -u | while read -r v; do
      # One awk, no pipe: under pipefail, `grep -v | grep -q` fails when grep -q
      # stops reading early, which would report a found assignment as missing.
      awk -v re="(^|[[:space:];(])(local |export )?${v}=" '!/^[[:space:]]*#/ && $0 ~ re { found = 1; exit } END { exit !found }' "$SCRIPT" || echo "$v"
    done)"

# The commands, from the one line the parser and --completion share.
script_commands="$(sed -n 's/^LICENSING_COMMANDS="\(.*\)"$/\1/p' "$SCRIPT" | tr ' ' '\n' | sed '/^$/d')"

# Options: every case pattern that starts with "-" in the two argument parsers
# (the first-argument case and the option loop), split on "|", "=*" dropped.
script_options="$(awk '
    /^case "\$\{1:-\}" in$/ { inparser = 1; next }
    /^while \[\[ \$# -gt 0 \]\]; do$/ { inparser = 1; next }
    inparser && /^(esac|done)$/ { inparser = 0; next }
    inparser && /^ +-[-A-Za-z]/ {
      pat = $0; sub(/^ +/, "", pat); sub(/\).*$/, "", pat)
      n = split(pat, alts, "|")
      for (i = 1; i <= n; i++) { a = alts[i]; sub(/=\*$/, "", a); if (a ~ /^-/ && a != "-*") print a }
    }' "$SCRIPT" | sort -u)"

# Every top-level LICENSING_* assignment in a file, whole: a multi-line array
# runs until its parentheses balance (quote-aware). Comments are dropped, whole
# lines and trailing ones alike. Heredoc bodies are skipped, since `init` writes
# a policy template that assigns the same names. One file per setting, in $1.
assignments() { # assignments <out dir> <file>
  awk -v out="$1" '
    # Scan a line for parentheses outside quotes; return where a comment starts, or 0.
    function scan(line,   i, c) {
      for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (esc) { esc = 0; continue }
        if (c == "\\" && !sq) { esc = 1; continue }
        if (sq) { if (c == "\047") sq = 0; continue }
        if (dq) { if (c == "\"") dq = 0; continue }
        if (c == "\047") { sq = 1; continue }
        if (c == "\"") { dq = 1; continue }
        if (c == "#" && (i == 1 || substr(line, i - 1, 1) ~ /[ \t]/)) return i
        if (c == "(") depth++
        if (c == ")") depth--
      }
      return 0
    }
    function clean(line,   cut) {
      cut = scan(line)
      if (cut) { line = substr(line, 1, cut - 1); sub(/[ \t]+$/, "", line) }
      return line
    }
    heredoc != "" { if ($0 == heredoc) heredoc = ""; next }
    !inarr && match($0, /<<-?\047?[A-Z_]+\047?$/) {
      heredoc = substr($0, RSTART, RLENGTH); gsub(/[<\047-]/, "", heredoc)
    }
    !inarr && /^LICENSING_[A-Z0-9_]+=/ {
      name = $0; sub(/=.*/, "", name)
      depth = 0; sq = dq = esc = 0; buf = clean($0)
      if (depth > 0) { inarr = 1; next }
      print buf > (out "/" name); close(out "/" name); next
    }
    inarr {
      if ($0 ~ /^[ \t]*#/) next
      line = clean($0); if (line ~ /[^ \t]/) buf = buf "\n" line
      if (depth <= 0) { inarr = 0; print buf > (out "/" name); close(out "/" name) }
    }' "$2"
}

assignments "$WORK/script" "$SCRIPT"

# A default that reads the environment first, NAME="${NAME:-X}", is shown as
# NAME="X": the environment is described in prose, the default is X.
for f in "$WORK"/script/*; do
  n="${f##*/}"
  sed -E "s/^${n}=\"\\\$\\{${n}:-(.*)\\}\"\$/${n}=\"\\1\"/" "$f" > "$f.h" && mv "$f.h" "$f"
done

# In the README, every ```bash block that follows a "Default:" or "Defaults:"
# line, or a "<details><summary>Default" line, inside a setting entry. Example
# blocks elsewhere in an entry are not compared. "Default: none." marks every
# setting the entry names as having no default.
awk -v blocks="$WORK/blocks.sh" -v out="$WORK/readme" '
  armed && !inblock && !fence && $0 == "```bash" { inblock = 1; next }
  inblock && $0 == "```" { inblock = 0; armed = 0; next }
  inblock { print > blocks; next }
  # Any other fenced block: skipped whole, so a "#" comment in it is not
  # mistaken for a heading.
  /^```/ { fence = !fence; next }
  fence { next }
  !inblock && /^#+ / {
    cur = ""; armed = 0
    if ($0 ~ /^####? `LICENSING_/) { cur = $0; gsub(/^####? `|`$/, "", cur); gsub(/`(, | and )`/, " ", cur) }
    next
  }
  cur != "" && $0 == "Default: none." { n = split(cur, each, " "); for (i = 1; i <= n; i++) { printf "" > (out "/" each[i] ".none"); close(out "/" each[i] ".none") }; next }
  cur != "" && ($0 == "Default:" || $0 == "Defaults:" || $0 ~ /^<details><summary>Default/) { armed = 1; next }
' "$README"
[[ -f "$WORK/blocks.sh" ]] && assignments "$WORK/readme" "$WORK/blocks.sh"

# Whitespace collapsed: the form two assignments are compared in.
normal() { tr '\n\t' '  ' < "$1" | tr -s ' ' | sed 's/^ //; s/ $//'; }

# A default too long to be worth reading may be shown as NAME=(…) or NAME="…".
ELIDE_OVER=200

hook_ids="$(sed -n 's/^- id: *//p' "$HOOKS" | sort -u)"

# File and directory names a setting defaults to: a single quoted word with an
# extension, or an all-capitals directory name.
default_files="$(sed -nE 's/^LICENSING_[A-Z0-9_]+="([.A-Za-z0-9_-]+\.[a-z]+|[A-Z][A-Z]+)"$/\1/p' "$SCRIPT" | sort -u)"
conf_default="$(sed -nE 's/^CONF="\$\{LICENSING_CONF:-\$\{REPO_ROOT\}\/([^}"]+)\}"$/\1/p' "$SCRIPT")"
[[ -n "$conf_default" ]] || fail "cannot find the policy file's default name (the CONF= line) in ${SCRIPT}"
default_files="$(printf '%s\n%s\n' "$default_files" "$conf_default" | sed '/^$/d' | sort -u)"

help_text="$(bash "$SCRIPT" --help 2>&1 || true)"

# --- what the README documents ----------------------------------------------

# The first cell of every table row, when it is one backticked word, and every
# heading that is one backticked word.
# shellcheck disable=SC2016 # the backticks are Markdown, matched literally.
readme_rows="$(sed -nE 's/^\| *`([^`]+)` *\|.*/\1/p; s/^#+ `([^`]+)`$/\1/p' "$README" | sort -u)"
# shellcheck disable=SC2016 # as above.
readme_entries="$(grep -E '^####? `LICENSING_[A-Z0-9_]+`((, | and )`LICENSING_[A-Z0-9_]+`)*$' "$README" \
  | grep -oE 'LICENSING_[A-Z0-9_]+' | sort -u)"

has_row() { grep -qxF -- "$1" <<<"$readme_rows"; }
mentions() { grep -qF -- "\`$1\`" "$README"; }

# --- forwards: declared -> documented --------------------------------------

while read -r v; do
  [[ -z "$v" ]] && continue
  is_internal "$v" && continue
  if ! grep -qxF -- "$v" <<<"$readme_entries"; then
    fail "setting ${v} has no entry in ${README} (### or #### \`${v}\`), or add it to INTERNAL in $0 with the reason"
    continue
  fi
  [[ -f "$WORK/script/$v" ]] || continue          # read from the environment only: no default to show
  want="$(normal "$WORK/script/$v")"
  if [[ "$want" == "${v}=\"\"" || "$want" == "${v}=()" ]]; then
    [[ -f "$WORK/readme/$v.none" || ( -f "$WORK/readme/$v" && "$(normal "$WORK/readme/$v")" == "$want" ) ]] \
      || fail "${v} has no default; its entry in ${README} must say \"Default: none.\" or show ${want}"
    continue
  fi
  if [[ ! -f "$WORK/readme/$v" ]]; then
    fail "the ${v} entry in ${README} does not show its default in a \`\`\`bash block after \"Default:\" or \"Defaults:\". The script has:"
    sed 's/^/    /' "$WORK/script/$v"
    continue
  fi
  got="$(normal "$WORK/readme/$v")"
  if [[ "$got" == "${v}=(…)" || "$got" == "${v}=\"…\"" ]]; then
    (( ${#want} > ELIDE_OVER )) || fail "${README} shortens the default of ${v} to (…), but it is only ${#want} characters: show it"
  elif [[ "$got" != "$want" ]]; then
    fail "the default shown for ${v} in ${README} is not the script's. The script has:"
    sed 's/^/    /' "$WORK/script/$v"
  fi
done <<<"$script_settings"

while read -r v; do
  [[ -z "$v" || "$ENV_UNDOCUMENTED" == *" $v "* ]] && continue
  mentions "$v" || fail "environment variable ${v} is read by ${SCRIPT} and not named in ${README}"
done <<<"$script_env"

while read -r c; do
  [[ -z "$c" ]] && continue
  has_row "$c" || fail "command ${c} has no row in ${README}"
  grep -qE "^  ${c}( |$)" <<<"$help_text" || fail "command ${c} is not listed by '${SCRIPT} --help'"
done <<<"$script_commands"

while read -r o; do
  [[ -z "$o" ]] && continue
  has_row "$o" || fail "option ${o} has no row in ${README}"
  grep -qE -- "(^| |,)${o}([ =,[]|$)" <<<"$help_text" || fail "option ${o} is not listed by '${SCRIPT} --help'"
done <<<"$script_options"

while read -r h; do
  [[ -z "$h" ]] && continue
  has_row "$h" || fail "hook ${h} in ${HOOKS} has no row in ${README}"
done <<<"$hook_ids"

while read -r f; do
  [[ -z "$f" ]] && continue
  mentions "$f" || fail "file ${f} (a setting's default) is not named in ${README}"
done <<<"$default_files"

for e in "${INTERNAL[@]}"; do
  grep -qxF -- "${e%%|*}" <<<"$script_settings" || fail "INTERNAL lists ${e%%|*}, which ${SCRIPT} no longer has"
done

# Hooks against commands: "<id>\t<entry>" for every hook in the manifest.
hook_entries="$(awk '
  /^- id: / { id = $3 }
  /^  entry: / { e = $0; sub(/^  entry: */, "", e); print id "\t" e }
' "$HOOKS")"
while read -r c; do
  [[ -z "$c" ]] && continue
  awk -F'\t' -v c="$c" '$2 == "licensing.sh " c || index($2, "licensing.sh " c " ") == 1 { found = 1 } END { exit !found }' \
    <<<"$hook_entries" || fail "command ${c} has no hook in ${HOOKS} whose entry runs 'licensing.sh ${c}'"
done <<<"$script_commands"
while IFS=$'\t' read -r id entry; do
  [[ -z "$id" ]] && continue
  read -r -a words <<<"$entry"
  if [[ "${words[0]:-}" != licensing.sh ]]; then
    fail "hook ${id} runs '${words[0]:-nothing}', not licensing.sh"; continue
  fi
  for ((i = 1; i < ${#words[@]}; i++)); do
    w="${words[$i]}"
    if (( i == 1 )) && [[ "$w" != -* ]]; then
      grep -qxF -- "$w" <<<"$script_commands" || fail "hook ${id} runs command '${w}', which ${SCRIPT} does not have"
    elif [[ "$w" == -* ]]; then
      grep -qxF -- "${w%%=*}" <<<"$script_options" || fail "hook ${id} passes option '${w}', which ${SCRIPT} does not accept"
    fi
  done
done <<<"$hook_entries"

# The label each setting entry opens with, against the group it sits in.
while IFS=$'\t' read -r name group label; do
  case "$group:$label" in
    set:Required|set:Recommended|keep:Optional) ;;
    set:*)  fail "${name} is under \"Settings to set\" and does not open with *Required.* or *Recommended.* (found: ${label:-nothing})" ;;
    keep:*) fail "${name} is under \"Settings the defaults cover\" and does not open with *Optional.* (found: ${label:-nothing})" ;;
    *)      fail "${name} is outside both settings groups" ;;
  esac
done < <(awk '
  /^```/ { fence = !fence; next }
  fence { next }
  /^## / { group = ""; if ($0 ~ /^## Settings to set/) group = "set"; if ($0 ~ /^## Settings the defaults cover/) group = "keep" }
  /^####? `LICENSING_[A-Z0-9_]+`((, | and )`LICENSING_[A-Z0-9_]+`)*$/ { names = $0; gsub(/^####? `|`$/, "", names); gsub(/`(, | and )`/, " ", names); want = 1; next }
  want && NF {
    label = ""; if (match($0, /^[*_][A-Za-z]+\.[*_]/)) label = substr($0, 2, RLENGTH - 3)   # *X.* or _X._, the same emphasis
    n = split(names, each, " "); for (i = 1; i <= n; i++) print each[i] "\t" group "\t" label
    want = 0
  }
' "$README")

# GitHub's heading anchors: lower case, punctuation other than "-" and "_"
# dropped, spaces turned into "-". Fenced code is skipped, where "#" is a comment.
anchors="$(awk '/^```/ { fence = !fence; next } !fence && /^#+ / { sub(/^#+ /, ""); print }' "$README" \
  | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9 _-]//g; s/ /-/g' | sort -u)"
while read -r a; do
  [[ -z "$a" ]] && continue
  grep -qxF -- "$a" <<<"$anchors" || fail "${README} links to #${a}, and no heading has that anchor"
done < <(grep -oE '\]\(#[^)]+\)' "$README" | sed -E 's/^\]\(#//; s/\)$//' | sort -u)

# --- backwards: documented -> declared -------------------------------------

while read -r r; do
  [[ -z "$r" ]] && continue
  case "$r" in
    LICENSING_*) grep -qxF -- "$r" <<<"$script_settings" || fail "${README} documents ${r}, which ${SCRIPT} does not have" ;;
    -*)          grep -qxF -- "$r" <<<"$script_options"  || fail "${README} documents option ${r}, which ${SCRIPT} does not accept" ;;
    licensing*)  grep -qxF -- "$r" <<<"$hook_ids"        || fail "${README} documents hook ${r}, which ${HOOKS} does not define" ;;
  esac
done <<<"$readme_rows"

if (( failures > 0 )); then
  echo
  echo "${failures} documentation gap(s) between ${SCRIPT} and ${README}."
  exit 1
fi
echo "ok: ${README} documents every setting, option, command, hook and default file of ${SCRIPT}"
