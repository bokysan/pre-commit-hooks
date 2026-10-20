#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Bojan Čekrlić
# SPDX-License-Identifier: MPL-2.0
#
# licensing.sh — one check for a project's licensing: every third-party
# dependency carries a licence the policy allows, REUSE.toml matches the same
# scan, and every file carries SPDX copyright and licence information.
#
# The manual is README.md in https://github.com/bokysan/pre-commit-hooks: why
# this exists, the commands, every LICENSING_* setting, and the files it reads
# and writes. This comment is what `licensing.sh --help` prints.
#
# Usage: licensing.sh [command] [options]
#
# Commands (default: check)
#   check      run the dependency gate, the REUSE.toml drift check and reuse lint
#   download   update LICENSES/ and the generated part of REUSE.toml (--fix: also
#              remove unused licence texts)
#   sbom       write an SPDX 2.3 JSON SBOM (default sbom.spdx.json)
#   init       write a starter .licensing.conf, REUSE.toml and .license-exceptions.txt
#
# Options
#   --mode auto|full|delta    auto = full under CI, else LICENSING_LOCAL_MODE
#   --only deps,toml,lint     run only these parts of check
#   -o, --output FILE         sbom: where to write
#   --all | --fix             download: fetch missing | fetch missing and remove unused
#   --dry-run                 download: print what would change, write nothing
#   --auto-install            run the install command for uninstalled dependencies
#   --skip-install-check      scan the tree as it is, without the install preflight
#   --no-cache                scan even when a cached scan matches
#   --jobs N|auto             syft processes to run at once
#   --obligations             after check: the duty x licence matrix
#   --components              after check: each licence's duties and components
#   --porcelain[=v1]          tab-separated records on stdout, for scripts
#   --color auto|on|off       colour in the findings table
#   --progress auto|on|off    terminal progress bar (OSC 9;4)
#   --progress-test           show what this terminal does with the progress bar
#   --completion bash|zsh|fish  print a shell completion script
#   -v, --verbose             progress, timings and what was skipped
#   -V, --version             print the version
#   -h, --help                print this text
#
# Exit codes
#   0  passed
#   1  policy violation: a denied or unreviewed licence, REUSE.toml drift, a
#      file without SPDX information, or a licence text that could not be fetched
#   2  usage error, missing policy file, uninstalled dependencies, or a missing
#      tool (syft or reuse, through neither mise nor PATH)
set -euo pipefail

# ---------------------------------------------------------------------------
# defaults — every one of these is overridable from .licensing.conf
# ---------------------------------------------------------------------------

# What syft scans. "dir:." catalogues every ecosystem present in the tree; use
# "file:go.mod" (or any single manifest) to restrict it.
LICENSING_SCAN_TARGET="dir:."

# Identity used when `init` seeds REUSE.toml. LICENSING_COPYRIGHT is the whole
# SPDX-FileCopyrightText value, so a company can own the copyright and keep a
# range of years: "2019-2026 ACME Inc." — empty falls back to the current year
# plus `git config user.name`, which is an individual and usually wrong for a
# corporate repository. The two licence ids are this project's OWN outbound
# licences (code and documentation), not the dependency policy below. All three
# may also be set in the environment for a one-shot `init`, where they win over
# the config file.
LICENSING_COPYRIGHT="${LICENSING_COPYRIGHT:-}"
LICENSING_LICENSE="${LICENSING_LICENSE:-}"
LICENSING_DOC_LICENSE="${LICENSING_DOC_LICENSE:-}"

# Keys that carry POLICY rather than mechanism. They have no defaults here on
# purpose — the config must set them or the run stops. Everything else in this
# block is mechanism and keeps a working default.
LICENSING_REQUIRED_KEYS="LICENSING_ALLOW LICENSING_DENY"

# Declared licence text is not an SPDX id. A Maven POM says "Apache License,
# Version 2.0", npm packages say "MIT License", and neither matches an
# allow-list or a deny-list entry — the first would fail review though it is
# fine, the second would escape a deny-list it belongs on. Each entry is
# <lowercased glob>|<SPDX id>, tried in order against the lowercased value.
# A bare "BSD" is mapped to BSD-3-Clause, the overwhelmingly common meaning;
# override the entry if your policy needs to tell the variants apart.
LICENSING_LICENSE_ALIASES=(
  "the apache software license*|Apache-2.0"
  "apache license*2*|Apache-2.0"
  "apache*2.0*|Apache-2.0"
  "apache software license*|Apache-2.0"
  "mit license*|MIT"
  "the mit license*|MIT"
  "bsd*3*clause*|BSD-3-Clause"
  "bsd license*|BSD-3-Clause"
  "*3-clause bsd*|BSD-3-Clause"
  "*2-clause bsd*|BSD-2-Clause"
  "lgpl|LGPL-2.1-only"
  "gnu lgpl*|LGPL-2.1-only"
  "new bsd*|BSD-3-Clause"
  "bsd|BSD-3-Clause"
  "psfl|PSF-2.0"
  "psf|PSF-2.0"
  "python software foundation*|PSF-2.0"
  "new bsd license*|BSD-3-Clause"
  "bsd*2*clause*|BSD-2-Clause"
  "simplified bsd*|BSD-2-Clause"
  "the bsd license*|BSD-3-Clause"
  "isc license*|ISC"
  "the unlicense*|Unlicense"
  "public domain*|LicenseRef-public-domain"
  "*public domain*|LicenseRef-public-domain"
  "unlicensed|LicenseRef-unlicensed"
  # MPL arrives written four ways: "MPL-2.0", "MPL 2.0", "Mozilla Public
  # License 2.0", and — in a package nobody has touched since 2011 — the bare
  # name with no version at all. The three that carry a version are mapped
  # here. The bare one deliberately is NOT: 1.1 and 2.0 are different licences,
  # a wrong id is worse than no id, and the packages that write it that way
  # ship the licence TEXT, which fill_licence_gaps reads and which settles it
  # for real.
  "mozilla public license*1.1*|MPL-1.1"
  "mozilla public license*2*|MPL-2.0"
  "mpl*1.1*|MPL-1.1"
  "mpl*2*|MPL-2.0"
  "eclipse public license*2*|EPL-2.0"
  "eclipse public license*1*|EPL-1.0"
  "common development and distribution license*1.1*|CDDL-1.1"
  "common development and distribution license*|CDDL-1.0"
  # "or later" first: the generic patterns below would answer -only, which is
  # a different licence and, for an allow list that takes GPL-3.0-or-later,
  # the wrong answer. Trove classifiers spell it out this way.
  "gnu general public license v3 or later*|GPL-3.0-or-later"
  "gnu general public license v2 or later*|GPL-2.0-or-later"
  "gnu lesser general public license v3 or later*|LGPL-3.0-or-later"
  "gnu lesser general public license v2 or later*|LGPL-2.1-or-later"
  "gnu affero general public license v3 or later*|AGPL-3.0-or-later"
  "gnu general public license*3*|GPL-3.0-only"
  "gnu general public license*2*|GPL-2.0-only"
  "gnu affero general public license*|AGPL-3.0-only"
  "gnu lesser general public license*3*|LGPL-3.0-only"
  "gnu lesser general public license*2.1*|LGPL-2.1-only"
  "gnu lesser general public license*|LGPL-2.1-only"
  "lgpl*3*|LGPL-3.0-only"
  "lgpl*2.1*|LGPL-2.1-only"
  "gpl*3*|GPL-3.0-only"
  "gpl*2*|GPL-2.0-only"
  # The rest of the OSI trove classifiers that turn up in a Python tree.
  "zlib/libpng license*|Zlib"
  "zlib license*|Zlib"
  "boost software license*|BSL-1.0"
  "academic free license*2*|AFL-2.1"
  "academic free license*|AFL-3.0"
  "artistic license*2*|Artistic-2.0"
  "artistic license*|Artistic-1.0"
  "zope public license*|ZPL-2.1"
  "historical permission notice and disclaimer*|HPND"
  "universal permissive license*|UPL-1.0"
  "mit no attribution*|MIT-0"
  "cc0*|CC0-1.0"
  "creative commons zero*|CC0-1.0"
  # Fonts, data and documentation: the licences that arrive with an asset
  # rather than with a package, and whose names almost never appear as an
  # SPDX id in the metadata that carries them.
  "sil open font license*|OFL-1.1"
  "*open font license*1.1*|OFL-1.1"
  "ofl*1.1*|OFL-1.1"
  "open data commons public domain dedication*|PDDL-1.0"
  "pddl*|PDDL-1.0"
  "open government licen[cs]e*3*|OGL-UK-3.0"
  "ogl-uk-3*|OGL-UK-3.0"
  "creative commons attribution no derivatives*|CC-BY-ND-4.0"
  "creative commons attribution-noderiv*|CC-BY-ND-4.0"
  "cc-by-nd*|CC-BY-ND-4.0"
  "creative commons attribution 3*|CC-BY-3.0"
  "cc-by-3.0*|CC-BY-3.0"
  "creative commons attribution share alike*|CC-BY-SA-4.0"
  "creative commons attribution*|CC-BY-4.0"
  "blue oak model license*|BlueOak-1.0.0"
  "functional source license*mit*|FSL-1.1-MIT"
  "unicode*data files*|Unicode-DFS-2016"
  # A URL where an id was wanted. npm's older "licenses": [{type, url}] form, a
  # Maven POM's <license><url>, and a bare link in a Python License: field all
  # arrive this way, and the link IS the answer — refusing the package for
  # review because the author linked the licence instead of naming it helps
  # nobody. A link cannot say -only or -or-later, so the GNU ones are read as
  # -only: the narrower grant, which is the safe direction to be wrong in.
  "*opensource.org/licenses/mit*|MIT"
  "*opensource.org/licenses/isc*|ISC"
  "*opensource.org/licenses/bsd-3*|BSD-3-Clause"
  "*opensource.org/licenses/bsd-2*|BSD-2-Clause"
  "*opensource.org/licenses/apache*|Apache-2.0"
  "*apache.org/licenses/license-2.0*|Apache-2.0"
  "*mozilla.org/mpl/1.1*|MPL-1.1"
  "*mozilla.org/mpl/2.0*|MPL-2.0"
  "*gnu.org/licenses/agpl*|AGPL-3.0-only"
  "*gnu.org/licenses/lgpl-2.1*|LGPL-2.1-only"
  "*gnu.org/licenses/lgpl*|LGPL-3.0-only"
  "*gnu.org/licenses/old-licenses/gpl-2*|GPL-2.0-only"
  "*gnu.org/licenses/gpl-2*|GPL-2.0-only"
  "*gnu.org/licenses/gpl*|GPL-3.0-only"
  "*creativecommons.org/publicdomain/zero*|CC0-1.0"
  "*nationalarchives.gov.uk/doc/open-government-licence/version/3*|OGL-UK-3.0"
  "*creativecommons.org/licenses/by-nd/4*|CC-BY-ND-4.0"
  "*creativecommons.org/licenses/by-sa/4*|CC-BY-SA-4.0"
  "*creativecommons.org/licenses/by/4*|CC-BY-4.0"
  "*creativecommons.org/licenses/by/3*|CC-BY-3.0"
  "*unlicense.org*|Unlicense"
  "*wtfpl*|WTFPL"
  "*eclipse.org/legal/epl-2*|EPL-2.0"
  "*eclipse.org/legal/epl-v10*|EPL-1.0"
  "*scripts.sil.org/ofl*|OFL-1.1"
)

# Aliases of LAST RESORT: a licence NAME that does not say which version, where
# guessing is better than nothing but worse than reading. Same
# <lowercased glob>|<SPDX id> form as the table above, and consulted only after
# it — and, crucially, they do not count as "this text names a licence", so a
# package that ships its licence TEXT is identified from the text and only a
# package that ships nothing falls back to the guess here.
#
# "Mozilla Public License" with no version is read as 1.1: a package that
# writes it that way predates 2.0, which has said "2.0" in its own name since
# 2012. Add your own for whatever your ecosystem is vague about.
LICENSING_LICENSE_ALIASES_LAST=(
  "mozilla public license*|MPL-1.1"
  "mpl|MPL-1.1"
)

# The DUTIES a licence can put you under, in roughly increasing order of what
# they cost you — the row order of the `--obligations` matrix. Each entry is
# <code>|<what it obliges you to do>.
#
# Keep the text ASCII: it is a table CELL, and columns are aligned by counting
# characters. An em dash is one column wide and three bytes long, and an awk
# that counts bytes short-pads the row and shifts every column after it.
# (obligations_matrix corrects for UTF-8 regardless, but a cell that needs the
# correction is a cell that will surprise somebody.)
#
# A fixed vocabulary, deliberately: prose written per licence cannot be
# compared across licences, and comparing them is the whole point of the
# matrix. "reproduce the licence text" and "reproduce the copyright notice and
# the licence text with the distribution" are one duty, not two.
LICENSING_DUTIES=(
  "notice|reproduce the copyright notice and the licence text"
  "no-endorse|do not use the authors' names to endorse your product"
  "notice-file|pass on the contents of the NOTICE file"
  "state-changes|state in each modified file that you changed it"
  "mark-changes|mark altered versions as altered"
  "credit|credit the author and link the licence"
  "no-derivatives|share it verbatim: do not distribute a modified version"
  "no-compete|do not use it in anything that competes with the licensor"
  "rename|a modified version must drop the original's reserved name"
  "no-sell-alone|do not sell the licensed files on their own"
  "source-modified|offer the source of the licensed files you modified"
  "same-licence|your changes to those files stay under this licence"
  "relink|leave the user able to relink against their own build"
  "install-info|installation information for consumer devices"
  "source-all|offer complete source for the whole work you link into"
  "network-source|offer that source to users of a network service too"
  "patent-retaliation|your patent grant ends if you sue over the work"
  "verify|the claim is the author's word, so check it before relying on it"
  "permission|no licence was granted: ask the author before shipping"
)

# Which of those duties each licence triggers, and the nuance that does not
# fit in a shared row. Each entry is <SPDX id>|<duty codes, space separated>|
# <note, optional>. A licence with NO codes asks nothing of you; a licence
# with no ENTRY is reported as unanswered rather than as free — the difference
# matters, and only one of the two is safe to ignore.
#
# Sorted by SPDX id, LC_ALL=C order — keep it that way, so a new one has an
# obvious place and a missing one is obvious by its absence.
#
# This is a checklist, not legal advice, and it is deliberately about the
# common case: distributing a binary or a service built on these components.
# Static linking, embedded firmware and patent portfolios all change the
# answer, and none of them are things a script can see.
LICENSING_OBLIGATIONS=(
  "0BSD||"
  "AFL-2.1|notice mark-changes patent-retaliation|"
  "AFL-3.0|notice mark-changes patent-retaliation|a modified source must carry a notice saying you modified it"
  "AGPL-3.0-only|notice source-all same-licence network-source install-info patent-retaliation|"
  "AGPL-3.0-or-later|notice source-all same-licence network-source install-info patent-retaliation|"
  "Apache-2.0|notice notice-file state-changes patent-retaliation|"
  "Artistic-1.0|notice mark-changes|say how a modified version differs from the standard one"
  "Artistic-2.0|notice mark-changes|say how a modified version differs from the standard one"
  "BSD-2-Clause|notice|the notice goes in the documentation of a binary distribution"
  "BSD-3-Clause|notice no-endorse|"
  "BSD-4-Clause|notice no-endorse|every advertisement of a feature must credit the authors — the clause that made this licence GPL-incompatible"
  "BSL-1.0|notice|SOURCE distributions only; a binary-only one requires nothing"
  "BlueOak-1.0.0|notice patent-retaliation|a LINK to the licence text satisfies the notice, which no other licence here allows"
  "CC-BY-3.0|credit mark-changes|termination is permanent: 4.0's automatic reinstatement within 30 days does not exist here"
  "CC-BY-4.0|credit mark-changes|"
  "CC-BY-ND-4.0|credit mark-changes no-derivatives|a modified version may be made, and may not be SHARED — this is the one CC licence a fork cannot ship"
  "CC-BY-SA-4.0|credit mark-changes same-licence|the whole adaptation, not only the files you touched"
  "CC0-1.0||"
  "CDDL-1.0|notice source-modified same-licence|per FILE: the rest of a larger work may be closed"
  "CDDL-1.1|notice source-modified same-licence|per FILE: the rest of a larger work may be closed"
  "Commercial|permission|not an SPDX id and not a public licence — it is what a package manager says when the terms live in a contract. Nothing in the tree states them: find the agreement signed with that vendor and read it, and record the outcome in the exceptions file"
  "EPL-1.0|notice source-modified same-licence|per FILE; a commercial distributor also indemnifies the contributors"
  "EPL-2.0|notice source-modified same-licence|per FILE; a commercial distributor also indemnifies the contributors"
  "FSL-1.1-MIT|notice no-compete|not open source: every version turns MIT two years after its own release, and until then it may not go into anything competing with the licensor"
  "GPL-2.0-only|notice source-all same-licence|"
  "GPL-2.0-or-later|notice source-all same-licence|"
  "GPL-3.0-only|notice source-all same-licence install-info patent-retaliation|"
  "GPL-3.0-or-later|notice source-all same-licence install-info patent-retaliation|"
  "HPND|notice|"
  "ISC|notice|"
  "LGPL-2.1-only|notice source-modified relink|link dynamically, or hand over your object files"
  "LGPL-2.1-or-later|notice source-modified relink|link dynamically, or hand over your object files"
  "LGPL-3.0-only|notice source-modified relink install-info|link dynamically, or hand over your object files"
  "LGPL-3.0-or-later|notice source-modified relink install-info|link dynamically, or hand over your object files"
  "LicenseRef-public-domain|verify|"
  "LicenseRef-unlicensed|permission|a manifest that says \"unlicensed\" usually means the author never thought about it"
  "MIT|notice|"
  "MIT-0||attribution is explicitly waived"
  "MIT-CMU|notice no-endorse|the notice goes in the DOCUMENTATION as well as in the copies"
  "MPL-1.1|notice source-modified same-licence|per FILE: the rest of a larger work may be closed"
  "MPL-2.0|notice source-modified same-licence|per FILE: the rest of a larger work may be closed"
  "LicenseRef-NOT-INSTALLED-HERE|verify|NOT a licence: this machine never unpacked these, so nothing on disk says what they are. Almost always a platform-specific optional package the package manager skipped — a Windows or Linux binding on a Mac. No install produces one; the same run on that platform reads them. Nothing to do here unless one is a package you DO ship on this platform"
  "NOASSERTION|permission|NOT a licence: the package is on disk and still states nothing — no metadata field, no LICENSE file, nothing the scan could read. Look each one up and record what you find in .license-exceptions.txt as <name> = <SPDX id>, or map it in LICENSING_LICENSE_ALIASES if it turns out to declare its licence in a shape syft does not recognise"
  "OFL-1.1|notice same-licence rename no-sell-alone|bundling the font with software is a sale the licence allows; selling the font itself is not"
  "OGL-UK-3.0|credit no-endorse|UK public-sector information: acknowledge the source with the attribution statement the Information Provider specifies — 'Contains public sector information licensed under the Open Government Licence v3.0' when it names none — and link the licence. A breach ENDS the grant automatically, and with it every other OGL grant from that licensor. Non-endorsement is wider than the BSD clause: your use must not suggest official status. Personal data, logos, crests, the Royal Arms and third-party rights are carved OUT of the grant, so a dataset under it can still carry material nothing licenses to you"
  "PDDL-1.0||a dedication for the DATABASE: its contents may still carry a licence of their own"
  "PSF-2.0|notice state-changes|"
  "Python-2.0|notice state-changes|"
  "TCL|notice|BSD-shaped terms"
  "UPL-1.0|notice patent-retaliation|"
  "Unicode-DFS-2016|notice no-endorse|the notice travels with the DATA FILES and their documentation, not only with code"
  "Unlicense||"
  "WTFPL||"
  "X11|notice no-endorse|"
  "ZPL-2.1|notice no-endorse|"
  "Zlib|notice mark-changes|the notice is required in the SOURCE; a binary needs nothing"
)

# Whole SPDX EXPRESSIONS the policy decides on as a unit. LICENSING_ALLOW and
# LICENSING_DENY are space-separated strings, so an expression with a space in
# it — every "WITH" and every "AND" — physically cannot go on either, and
# without these there was no way to state a verdict about one.
#
# The case that needs it is the SPDX EXCEPTION. An exception modifies the
# licence it is attached to, and usually loosens it: "GPL-2.0-only WITH
# Classpath-exception-2.0" is the licence that lets you link against
# OpenJDK without your own code becoming GPL, and it is an ordinary thing for
# an organisation to accept while refusing plain GPL-2.0-only. The base id is
# what a bare WITH expression is judged on — deliberately, because that is the
# conservative reading and the exception is the part a policy has to opt into
# — so refusing GPL means refusing it with the exception too, until it is
# named here.
#
# Arrays, one whole expression per element, matched against the NORMALISED
# expression (the form the findings table prints):
#
#   LICENSING_ALLOW_EXPRESSIONS=("GPL-2.0-only WITH Classpath-exception-2.0"
#                                "BSD-3-Clause AND TCL")
#   LICENSING_DENY_EXPRESSIONS=("MIT AND Commons-Clause")
#
# DENY beats ALLOW here as everywhere, and both beat the per-id lists: an
# expression named here is answered as a whole and its leaves are not consulted.
# shellcheck disable=SC2034 # read through their NAME, not their value: expr_listed takes the
# variable name as a string and expands it indirectly, so ShellCheck sees the default
# assignment and none of the reads. .licensing.conf overrides both.
LICENSING_ALLOW_EXPRESSIONS=()
# shellcheck disable=SC2034 # read through its NAME by expr_listed, as above.
LICENSING_DENY_EXPRESSIONS=()

# `component  # reason` lines exempt from the REVIEW failure (never from DENY).
LICENSING_EXCEPTIONS=".license-exceptions.txt"

# Catalogers ADDED to syft's directory defaults. syft's default set for a
# directory scan reads lockfiles but skips declared-only manifests that it
# treats as image-only (a bare package.json, an installed site-packages tree),
# so a node_modules/ or a vendored virtualenv would go ungated without these.
LICENSING_ADD_CATALOGERS=("javascript-package-cataloger" "python-installed-package-cataloger")

# Environment handed to syft. Licence resolution is per-ecosystem and mostly
# off by default: Go reads the module cache and upstream, Java resolves POMs
# from ~/.m2 and Maven Central (a POM often declares its licence only in a
# parent POM, so without this every Java component comes back with no licence).
# Add a line per ecosystem you need; each is NAME=value.
#
# SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES is not about licences but about
# WHICH PACKAGES EXIST. syft's javascript catalogers drop development-scoped
# dependencies by default, and they do it only when a package.json sits beside
# the lockfile — so on one yarn monorepo `syft scan file:yarn.lock` catalogued
# 6729 packages and `syft scan dir:.` catalogued about 4950, silently, with the
# missing 1768 never appearing anywhere in the run. Worse, the pruning was not
# deterministic there: three identical scans returned 4872, 4911 and 4966
# components, so which dependencies the gate looked at depended on the run.
#
# A dev dependency is still a dependency for licensing purposes. It is on the
# build machine, it goes into the builder stage of a Docker image, its
# behaviour ends up in the artefact, and a copyleft build tool is exactly the
# thing this script exists to catch. Off by default in syft, on here.
LICENSING_SYFT_ENV=(
  "SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true"
  "SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true"
  "SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY=true"
  "SYFT_JAVA_USE_NETWORK=true"
  "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true"
)

# Set to replace syft's cataloger selection outright (e.g. "all", or a
# comma-separated list). Empty = defaults + LICENSING_ADD_CATALOGERS.
LICENSING_CATALOGERS=""

# Manifests re-scanned in isolation (copied alone into a scratch directory)
# and merged over the tree scan. Cataloguing a manifest that sits inside a big
# tree lets syft attribute licences it found elsewhere in that tree to every
# component in the manifest — this project's own MPL-2.0 landed on all 130 Go
# modules that way, which is harmless for the allow-list but wrong in
# REUSE.toml. A manifest alone in a scratch directory has nothing to borrow
# from, so its result is the reference.
LICENSING_ISOLATED_MANIFESTS=("go.mod")

# Package caches OUTSIDE the repository, scanned only to fill in licences for
# components the project scan already found — they never add components of
# their own. Some ecosystems keep no copy of a dependency inside the project:
# a Dart package lives in ~/.pub-cache, so the lockfile names it and nothing on
# the project side carries a licence. Entries that do not exist are skipped
# silently.
#
# Not the Cargo registry. syft reads a crate only from a Cargo.lock, never from
# its Cargo.toml, so scanning ~/.cargo/registry/src read the Cargo.lock that
# hundreds of crates ship for their own builds: no licence for anything, and
# every one of those lockfiles added to the evidence of every crate it names —
# a hundred paths per crate, minutes of string handling on bash 3.2. Rust
# licences come from LICENSING_CARGO_REGISTRY_SRC instead.
LICENSING_AUX_SCAN_TARGETS=(
  "dir:${HOME}/.pub-cache/hosted"
)

# Where cargo unpacks the crates it downloads, one <name>-<version> directory
# per crate under one directory per registry index. A Rust dependency's licence
# is in that crate's own Cargo.toml (`license`, or `license-file`); the
# Cargo.lock syft catalogues it from carries none. A crate cargo never unpacked
# on this machine (a Windows-only dependency on a Mac) has nothing there and
# stays "named only in a lockfile", as before.
LICENSING_CARGO_REGISTRY_SRC="${CARGO_HOME:-${HOME}/.cargo}/registry/src"

# Extra syft --exclude globs, on top of everything git ignores.
LICENSING_EXCLUDE=()

# Always excluded: a dependency manifest INSIDE an installed package tree. It
# belongs to that package, not to this project — @nomicfoundation/solidity-
# analyzer ships the Cargo.lock of its own Rust build, @vue/vue-loader-v15 a
# pnpm-lock.yaml of its dev tree. Nothing there is installed, so every entry
# comes back with no licence and fails review, and none of it is a dependency
# of yours: the package itself is catalogued from its package.json and gated.
# The two lists are crossed: <root>/**/<manifest> for every combination.
LICENSING_NESTED_ROOTS=("node_modules" "vendor" "site-packages" "Pods" ".build" ".dart_tool")
LICENSING_NESTED_MANIFESTS=(
  "pnpm-lock.yaml" "yarn.lock" "package-lock.json" "npm-shrinkwrap.json"
  "Cargo.lock" "Cargo.toml"
  "go.mod" "go.sum"
  "Gemfile.lock" "composer.lock"
  "poetry.lock" "Pipfile.lock" "uv.lock" "requirements*.txt" "pyproject.toml"
  "pom.xml" "build.gradle" "build.gradle.kts" "gradle.lockfile"
  "pubspec.lock" "pubspec.yaml" "Podfile.lock" "Package.resolved"
)

# Exclude whatever .gitignore ignores (build output, caches, worktrees). Those
# are not shipped and their manifests are not ours.
LICENSING_EXCLUDE_GITIGNORED=1

# ... except these, which are gitignored in most repositories and are exactly
# where the licence text lives. A lockfile records versions, not licences —
# yarn.lock carries none at all — so a tree whose dependencies are not
# installed yields components with no licence and every one of them fails
# review. Any ignored path with one of these as a path component is scanned.
LICENSING_INCLUDE_GITIGNORED=("node_modules" "vendor" "site-packages" ".venv" "venv"
                              "Pods" ".build" "SourcePackages" "Carthage")

# Preflight: a dependency manifest whose packages are NOT installed. syft can
# only read licences from packages on disk, so scanning an uninstalled tree
# reports every component as "none detected" — thousands of false verdicts. The
# run stops before the scan and names the command to fix it; --auto-install
# runs that command instead.
#
# Maven is deliberately absent: syft reads pom.xml directly and resolves
# licences from ~/.m2 or Maven Central (see LICENSING_SYFT_ENV), so a Maven
# project needs no install step. Gradle is present because syft can only see
# Gradle dependencies through a gradle.lockfile or built jars — without one it
# reports NO components at all, which would pass the gate by seeing nothing.
#
# One entry per ecosystem, four pipe-separated fields:
#   <label>|<manifest glob>|<install paths, colon-separated>|<install command>
# Install paths accept %GOMODCACHE% (`go env GOMODCACHE`), %POETRYENV%
# (`poetry env info --path`) and %PUBCACHE% (~/.pub-cache), because those
# package directories live outside the repository. %CARGOCRATES% is stricter: it
# holds only when EVERY registry crate in that Cargo.lock is unpacked under
# LICENSING_CARGO_REGISTRY_SRC, where the crate licences are read. A registry
# that merely exists proves nothing: any machine that ever built Rust has one.
#
# The command field may list ALTERNATIVES separated by ` || `, and the first
# one whose tool is actually available wins. A leading NAME=value is allowed
# (PIPENV_VENV_IN_PROJECT=1 keeps the virtualenv inside the workspace, where
# the scan can see it), and `uv tool run <installer>` is a useful last
# alternative: uv fetches the installer on the fly, so a machine with only uv
# still installs a poetry or pipenv workspace without anything global — that is how a Python workspace
# gets `uv sync` on a machine with uv and `poetry install` on one without,
# with no configuration. %MANIFEST% expands to the matched file name. An empty
# command, or one whose tools are all missing, means the location is left to
# you; --auto-install still handles every other location and reports only
# those, naming the tools that would have worked.
LICENSING_INSTALL_CHECKS=(
  "npm (pnpm)|pnpm-lock.yaml|node_modules|pnpm install --frozen-lockfile"
  "npm (yarn)|yarn.lock|node_modules|yarn install"
  "npm|package-lock.json|node_modules|npm ci"
  "go|go.mod|vendor:%GOMODCACHE%|go mod download"
  "python (uv)|uv.lock|.venv:venv|uv sync"
  "python (poetry)|poetry.lock|.venv:venv:%POETRYENV%|poetry install || uv tool run poetry install"
  "python (pipenv)|Pipfile.lock|.venv:venv|PIPENV_VENV_IN_PROJECT=1 pipenv install --dev || PIPENV_VENV_IN_PROJECT=1 uv tool run pipenv install --dev"
  "python|requirements*.txt|.venv:venv:*/site-packages|uv venv && uv pip install -r %MANIFEST% || python3 -m venv .venv && .venv/bin/pip install -r %MANIFEST%"
  "python (pyproject)|pyproject.toml|.venv:venv:%POETRYENV%|uv sync || poetry install || uv tool run poetry install"
  "dart|pubspec.lock|.dart_tool:%PUBCACHE%|dart pub get || flutter pub get"
  "rust|Cargo.lock|%CARGOCRATES%|cargo fetch"
  "ios (cocoapods)|Podfile.lock|Pods|pod install"
  "ios (swiftpm)|Package.resolved|.build/checkouts:SourcePackages|swift package resolve"
  "java (gradle)|build.gradle.kts|gradle.lockfile:gradle/dependency-locks:build/libs|./gradlew dependencies --write-locks || gradle dependencies --write-locks"
  "java (gradle)|build.gradle|gradle.lockfile:gradle/dependency-locks:build/libs|./gradlew dependencies --write-locks || gradle dependencies --write-locks"
  "ruby|Gemfile.lock|vendor/bundle:.bundle|bundle install --path vendor/bundle"
  "php|composer.lock|vendor|composer install"
)

# Directories the preflight ignores (prefix match, repo-relative). For a
# workspace you deliberately do not gate — a sample app, a fixture project.
# Whatever lives there is then NOT licence-checked, so write down why.
LICENSING_INSTALL_CHECK_SKIP=()

# How many syft processes to run over the tree at once. A single syft indexes
# the filesystem sequentially, and on a large tree that dominates: measured on
# a 72,000-file npm-shaped tree, one process took 18.3s and six took 5.3s for
# identical output. The walk itself is not the cost (find(1) does it in 0.11s),
# so a faster directory walker would buy nothing — more processes is the lever.
#   auto  one worker per top-level directory, capped at the CPU count (default)
#   1     one scan of the whole tree
#   N     the same as auto, capped at N
# Only applies to a dir: scan target with at least two top-level directories.
# Verified to produce byte-identical component sets to a single scan; worker
# output has its paths re-prefixed, since syft reports them relative to ITS
# own root.
LICENSING_SCAN_JOBS=auto

# What makes "auto" decide a tree is big enough to split: ONE test, a handful
# of directory reads, never a walk. Count the entries in each package
# directory at the root and one level down (a monorepo keeps them per
# workspace) — 200 packages is where more processes start paying for
# themselves. An earlier version counted files with find(1), which is exactly
# the wrong thing to do on the trees that need splitting most; another counted
# top-level directories, which said "split" for a 13,000-file repository that
# happens to have 21 of them and lost a second every run.
LICENSING_SCAN_HEAVY_DIRS=("node_modules" "vendor" ".venv" "venv" "Pods" "target" "build")
LICENSING_SCAN_HEAVY_MIN_ENTRIES=200

# Directories that must NOT be split off into their own worker. Some catalogers
# key off the path itself: syft recognises a GitHub Actions workflow because it
# sits at .github/workflows/*.yml, and a worker rooted at .github sees only
# /workflows/*.yml — so splitting it silently dropped every action from the
# inventory. These stay in the root pass, where their path is intact.
LICENSING_SCAN_NOSPLIT=(".github" ".forgejo" ".gitlab" ".circleci" ".azuredevops" ".gitea")

# Re-use the previous scan when nothing it reads has changed. A full scan of a
# big tree is minutes, and most runs scan a tree that is byte-for-byte what it
# was a minute ago: the second `check` after fixing one thing, a pre-commit
# hook on the next commit, `download` straight after `check`.
#
# The key covers everything the result depends on: this script's version and
# checksum, syft's version, the whole scan configuration, the CONTENT of every
# dependency manifest and lockfile in the tree, the timestamp and entry count
# of every package directory and of the packages inside it, and the same
# timestamp and entry count for every package cache OUTSIDE the tree that the
# scan reads to fill licence gaps — a poetry virtualenv in ~/Library/Caches,
# the Cargo registry, ~/.pub-cache. Those last ones used to be in the key by
# PATH only, which meant a `poetry install` could put five hundred licences on
# disk without moving the key, and the inventory taken before it — the one
# where every one of those components is blank — went on being served. On the
# tree this was found on it hid ten deny-listed GPL/LGPL components, all of
# them first-party dependencies of a Python service in the same repository.
#
# What the key still CANNOT see is a change no manifest records — a file edited
# by hand inside node_modules, a LICENSE deleted from a site-packages tree.
# --no-cache scans regardless and is the answer whenever a result looks stale.
#
# Entries live outside the repository deliberately: an untracked file inside it
# is a file `reuse lint` fails on. LICENSING_IGNORE_PATHS is applied AFTER the
# cache is read, so changing it costs nothing and never needs a re-scan.
#
# The environment wins over this default (LICENSING_CACHE=0 for one run, as
# the tests do); .licensing.conf, sourced later, wins over both.
LICENSING_CACHE="${LICENSING_CACHE:-1}"
LICENSING_CACHE_DIR="${LICENSING_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/licensing.sh}"
LICENSING_CACHE_MAX_AGE_DAYS=30

# Evidence paths that are not a dependency of yours, as shell globs matched
# against the repo-relative path (`*` crosses `/`, so "*/fixtures/*" is enough;
# no "**" needed). A component is dropped only when EVERY path it was
# catalogued from matches — one real location keeps it.
#
# This is the post-scan escape hatch, and it is the one to reach for when
# something in an installed tree is not really a dependency: a vendored binary
# a package ships (node_modules/clipboardy/fallbacks/windows/*.exe), a demo
# application, a fixture nobody thought to name a fixture. Unlike
# LICENSING_EXCLUDE it costs no re-scan, because it is applied to the scan
# rather than to syft.
LICENSING_IGNORE_PATHS=()

# Inside a package directory, an installed npm package lives at
# <root>/node_modules/<name>/package.json or
# <root>/node_modules/@scope/<name>/package.json, and nowhere else. A
# package.json further down belongs to the package that SHIPS it and was never
# installed as a dependency: a test fixture (pino/test/fixtures/transport), a
# fixture's own node_modules (license-checker/test/node_modules/zone.js/mix), a
# scaffolding template (hardhat/templates/hardhat-3/03-minimal), an example app
# (style-dictionary/examples/…), a bundled copy (next/dist/compiled/tar).
#
# Every one of them fails review for a licence its parent package already
# declares, and the parent is gated in its own right. 1 = drop them, 0 = gate
# them like anything else. npm only: the rule is npm's own layout, and no other
# ecosystem's is this predictable.
LICENSING_SKIP_VENDORED_SUBPATHS=1

# How many failing components to print before summarising. 0 — the default —
# prints every one, and every one is the right number: these are the components
# a person now has to make a decision about, and a report that shows fifteen of
# them and hides the rest is a report that has to be run again with different
# settings before it can be acted on. A wall of findings is what a wall of
# findings looks like; scrolling is not the problem the truncation solved.
#
# Set a positive number if you would rather see the first N of a very long
# list. Nothing else caps it: --verbose says how much a run explains ITSELF —
# progress, timings, what it skipped — and never how much of the ANSWER it is
# willing to show.
LICENSING_MAX_FINDINGS=0

# 1 = run the preflight, 0 = scan whatever is on disk and take the verdicts.
LICENSING_INSTALL_CHECK=1

# 1 = run the install command instead of stopping (also --auto-install). Off by
# default: a gate should not mutate the tree it is gating without being asked.
# Read from the environment too, so a CI job can turn it on for its own runs
# without .licensing.conf turning it on for every developer.
LICENSING_AUTO_INSTALL="${LICENSING_AUTO_INSTALL:-0}"

# Components that ARE this project rather than a dependency of it: the Go main
# module, the root npm package, every workspace of a monorepo, anything
# published under your own scope. Gating the product against its own outbound
# licence is a false positive.
#
# WHAT IS MATCHED: the component's NAME on its own — the second field of every
# row in the scan, exactly as the ecosystem spells it and exactly as the
# findings table prints it before the "@". Not the version, not the type, not
# the path it was catalogued from. So for a row that reports as
#
#     acme@1.2.3 (npm)                  the name is  acme
#     @acme/ui-icons@0.0.1 (npm)        the name is  @acme/ui-icons
#     acme-backend@0.1.0 (python)       the name is  acme-backend
#     github.com/acme/tool (go-module)  the name is  github.com/acme/tool
#
# and the entry to add for the first of those is the bare word "acme".
#
# ACROSS ECOSYSTEMS: yes — one list, matched against every component whatever
# its type. That also means a pattern is as wide as its shape: "@acme/*"
# matches npm scoped packages and nothing else only because no other ecosystem
# spells names that way, while a bare "acme" would match an npm package, a
# PyPI package and a crate of that name alike. Type is not part of the test.
#
# GLOBS: bash pattern matching (the [[ $name == $pattern ]] kind), so "*"
# matches any run of characters INCLUDING "/", "?" matches one, and [abc]
# works. Anchored at both ends: the whole name must match, so "acme" does not
# cover "acme-web" and "acme*" does. Quote anything with a glob character in
# it — LICENSING_SELF_NAMES=("@acme/*") — or the shell expands it against the
# working directory before the array is built.
#
#     LICENSING_SELF_NAMES=("@acme/*" acme "acme-*" "github.com/acme/*")
#
# A component matched here leaves the gate entirely: no verdict, no obligation,
# no REUSE.toml annotation. The count is reported at the end of a passing run,
# so a pattern that is too wide shows up as a number that is too big. Prefer a
# scope or a prefix to a bare wildcard; "*" here disables the gate.
# shellcheck disable=SC2034 # read by name_matches through its NAME, as above.
LICENSING_SELF_NAMES=()

# What to do with a component that ONLY a lockfile mentions — nothing on disk
# corresponds to it. Almost always a platform-specific optional package the
# package manager skipped for this OS or CPU: @img/sharp-linux-x64 on a Mac,
# @libsql/win32-x64-msvc anywhere but Windows. No licence exists locally and
# no install will produce one, but the same run on Linux WILL check them.
#   exempt  count them, name them in the summary, do not fail (default)
#   review  gate them like anything else
# A deny-listed licence still fails either way.
LICENSING_LOCKFILE_ONLY="exempt"

# Evidence that is only a lockfile, never an installed package.
LICENSING_LOCKFILE_NAMES="yarn.lock package-lock.json pnpm-lock.yaml npm-shrinkwrap.json poetry.lock uv.lock Pipfile.lock Cargo.lock Gemfile.lock composer.lock gradle.lockfile pubspec.lock Podfile.lock Package.resolved"

# Evidence that names OTHER packages rather than the one it sits beside. This
# governs the licence-TEXT fallback and nothing else, and it exists because
# that fallback was inventing licences at scale.
#
# The fallback works by looking for a LICENSE file in the directory a
# component was catalogued from. Beside an installed package — a dist-info, a
# node_modules/<pkg>/package.json — that file is the package's own and is the
# best evidence there is. Beside a LOCKFILE it belongs to whoever wrote the
# lockfile, and handing it to the packages listed inside was worth 2052 wrong
# licences on one monorepo: every gem in lunr-languages' Gemfile.lock came back
# MIT because lunr-languages is MIT, and @ampproject/remapping came back
# BSD-3-Clause (it is Apache-2.0) because it appears in protobufjs's
# package-lock.json and protobufjs is BSD-3-Clause.
#
# A wrong licence is worse than none: no licence fails review and gets looked
# at, while a wrong permissive one passes the gate and is never seen again.
# Globs, matched against the file name. An ARRAY with the glob-bearing entries
# quoted, not a string: `for pat in $STRING` lets the shell pathname-expand
# "requirements*.txt" against the working directory first, so in a repository
# that happens to HAVE a requirements.txt at its root the pattern would quietly
# turn into that one file name and stop matching everything else.
# shellcheck disable=SC2206 # LICENSING_LOCKFILE_NAMES is a space-separated STRING (one place
# to write the list, and `in_list " $LICENSING_LOCKFILE_NAMES "` reads it as one), so
# splitting it into elements here is the conversion, not an accident.
LICENSING_FOREIGN_MANIFESTS=(${LICENSING_LOCKFILE_NAMES} "requirements*.txt"
                             go.mod go.sum pom.xml Gemfile Pipfile Podfile pubspec.yaml)

# Component types dropped from the gate entirely.
LICENSING_IGNORE_TYPES=()

# Drop npm components whose name is a path inside another package — a
# sub-directory package.json used for module resolution, never a dependency.
LICENSING_SKIP_NESTED_SUBPACKAGES=1

# Component types where "syft found no licence" is reported but not fatal —
# for ecosystems whose manifests carry no licence metadata at all. A deny-listed
# licence on these types still fails.
LICENSING_REVIEW_EXEMPT_TYPES=("github-action" "github-action-workflow")

# Resolve a GitHub Action's licence from the repository that publishes it.
# `uses: actions/checkout@v4` names a repository and nothing else — there is no
# manifest, no lockfile and no installed copy, so syft has nowhere to read a
# licence from and every action in the tree comes back blank. GitHub answers
# the question directly (/repos/<owner>/<repo>/license), which is the same
# trade this script already makes for Go and Maven: one network call to turn an
# unknown into an answer.
#
# The answer is cached on disk and never expires: a repository's licence is not
# something that changes under you, and a cache entry is what keeps a
# 24-action tree at zero calls per run after the first. A repository with no
# LICENSE file caches as "no answer" too, so it is asked once and not once a
# run. GITHUB_TOKEN or GH_TOKEN is used when set — unauthenticated GitHub
# allows 60 calls an hour, which one cold run on a large tree can exhaust.
#
# 0 = never call out; those components stay unlicensed and, being
# review-exempt by type, still do not fail the gate.
LICENSING_GITHUB_LICENCES=1
LICENSING_GITHUB_API="https://api.github.com"

# Directories holding third-party source that is COMMITTED to this repository:
# vendor/ (go mod vendor, cargo vendor, Composer, Bundler's vendor/bundle),
# node_modules, third_party/, and CocoaPods' and Carthage's checkouts. Each one
# git tracks gets one REUSE annotation for all of it. A root git does not track
# (node_modules in nearly every repository) gets none: REUSE only looks at
# tracked files.
LICENSING_VENDOR_ROOTS=("vendor" "node_modules" "third_party" "Pods" "Carthage")

# Path globs that make a commit "dependency-affecting" in delta mode.
LICENSING_TRIGGER_PATHS=(
  "go.mod" "go.sum" "vendor/*"
  "package.json" "package-lock.json" "yarn.lock" "pnpm-lock.yaml" "node_modules/*"
  "requirements*.txt" "pyproject.toml" "poetry.lock" "Pipfile.lock" "setup.py" "uv.lock"
  "pubspec.yaml" "pubspec.lock" "gradle.lockfile"
  "Cargo.toml" "Cargo.lock"
  "Gemfile" "Gemfile.lock" "composer.json" "composer.lock"
  "pom.xml" "build.gradle" "build.gradle.kts" "gradle/*"
  "Package.swift" "Package.resolved" "Podfile" "Podfile.lock"
  ".github/workflows/*" ".forgejo/workflows/*"
)

# How syft and reuse are invoked:
#   auto  use `mise exec -- <tool>` when mise provides the tool, else PATH
#   mise  require mise to provide it (fail otherwise) — strictest pinning
#   path  ignore mise, use whatever is on PATH
LICENSING_TOOL_RUNNER="auto"

# The REUSE half is part of the gate, not an add-on: 1 (required, the default)
# runs `reuse lint` and fails when the tool is missing. 0 exists only as an
# onboarding escape hatch while a repository is still adding SPDX headers, and
# says so loudly on every run — it is not a supported steady state.
LICENSING_REUSE="1"
LICENSING_REUSE_TOML="REUSE.toml"

# REUSE.toml is half hand-written, half generated. Everything ABOVE this marker
# line is yours — first-party globs, in-tree third-party code — and is copied
# through untouched; everything below is one annotation per vendored component,
# rewritten by `licensing.sh download` from the same scan the licence gate uses. A
# REUSE.toml without the marker is treated as fully hand-maintained and is only
# linted, never rewritten.
LICENSING_REUSE_MARKER="# --- generated by licensing.sh: vendored components (do not edit below) ---"

# Where the licence TEXTS live — REUSE's directory, one <SPDX-id>.txt per
# licence the tree uses. `download` fills it and, with --fix, prunes it.
LICENSING_LICENSES_DIR="LICENSES"

# Which halves of this script decide that a licence text belongs in there,
# space separated: "reuse" (ids in inline headers and in REUSE.toml) and
# "syft" (ids the component scan found). Both by default, which is right for a
# repository that VENDORS its dependencies — their texts ship, so their texts
# belong in the tree. Drop "syft" in a repository that does not vendor:
# `reuse lint` fails on a licence text nothing in the tree references, and a
# dependency downloaded at build time is nothing in the tree.
LICENSING_LICENSE_SOURCES="reuse syft"

# The file that JUSTIFIES those dependency licence texts, when "syft" is one
# of the sources above. `reuse lint` fails on a licence text nothing in the
# tree references, and a dependency's text is exactly that: node_modules is
# gitignored in nearly every repository, so the twenty-six texts fetched for
# components come back as "unused licenses" and the gate fails on the texts it
# was asked to fetch.
#
# REUSE has no allow-list for this — the only way to tell it a text is in use
# is for a file to say so. Name a file here (a NOTICE, a THIRD-PARTY-LICENSES
# document — whatever your product actually ships to satisfy the "reproduce the
# notice" duty), and the generated section of REUSE.toml gets one annotation
# claiming every dependency licence for it:
#
#   [[annotations]]
#   path = "THIRD-PARTY-LICENSES.md"
#   precedence = "aggregate"
#   SPDX-License-Identifier = "Apache-2.0 AND BSD-3-Clause AND ISC AND ..."
#
# "aggregate" adds those ids to whatever the file declares for ITSELF, so the
# file keeps its own header and licence. The file must EXIST — REUSE silently
# ignores an annotation whose path is not there — and it needs copyright
# information of its own, from its inline header or from LICENSING_COPYRIGHT.
#
# The expression names the licences the component scan found that ALSO have a
# text in LICENSES/, and nothing else. Both halves of that matter: a text
# nothing found any more stays out, so `reuse lint` still calls it unused and
# `download --fix` still removes it; and a licence found with no text on disk
# stays out too, so a free-text id syft could not map never becomes a "bad
# license" in REUSE.toml.
#
# `download` WRITES the file when one is needed and there is none — it cannot be
# empty, and it cannot be in LICENSES/: reuse reads everything in that
# directory as a licence TEXT, so a notice file there comes back as
# "Bad licenses: THIRD-PARTY-LICENSES" and justifies nothing. The generated
# file is a seed, never rewritten afterwards: what it says is stable, and the
# list that changes with your dependencies lives in the REUSE.toml annotation,
# where the drift check watches it.
#
# NEEDED is the operative word. The expression names only what NOTHING ELSE in
# the tree accounts for: a licence claimed by an annotation above the marker,
# by a tracked file's own SPDX header, by one of the vendored-component blocks
# below the marker, or by this project's outbound licence is a licence REUSE
# already calls used. A repository that vendors its dependencies therefore
# gets no notice file and no annotation at all, because it never had the
# problem.
#
# ORDER: the annotation is a reference like any other, so a text that a REMOVED
# dependency left behind looks used until REUSE.toml is regenerated. `download`
# therefore regenerates it before it removes texts, and again after it fetches.
#
# Empty = never annotate and never write anything, for a repository that would
# rather not keep the texts at all: LICENSING_LICENSE_SOURCES="reuse" and
# `download --fix` then drop them instead of justifying them.
LICENSING_NOTICE_FILE="THIRD-PARTY-LICENSES.md"

# Terminal progress via OSC 9;4 — the escape sequence Windows Terminal,
# ConEmu, WezTerm and Ghostty turn into a taskbar/tab progress bar, and the
# one mise uses. Unknown terminals would print the raw bytes, so this is an
# allow-list, not a guess.
#   auto  on when stderr is a terminal that is known to support it (default)
#   on    always emit, whatever the terminal claims
#   off   never
LICENSING_PROGRESS="${LICENSING_PROGRESS:-auto}"

# Mode used by `--mode auto` outside CI. Set to "delta" to trade coverage for
# a couple of seconds per commit.
LICENSING_LOCAL_MODE="full"

# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------
ME="$(basename "$0")"
# The SPDX licence tag, put together from two pieces. reuse reads the literal tag
# wherever it appears and honours REUSE-IgnoreStart/End only per 64 KiB chunk, so
# a tag spelled out in this script's code could be read as a statement about
# the script itself whenever an edit moves a chunk boundary next to it.
SPDX_ID_TAG="SPDX-License-""Identifier:"
SELF="$0"                 # how the caller invoked us, for copy-pasteable hints

# The command a person should type to run `licensing.sh <args>`. Run as a
# pre-commit hook (pre-commit sets PRE_COMMIT=1) the script lives in pre-commit's
# cache under a hashed directory, so "$0 download" would name a path nobody can type
# twice; the hook that runs the same command is the answer instead.
how() { # how <licensing.sh args...> -> a command line
  if [[ "${PRE_COMMIT:-}" != 1 ]]; then echo "${SELF} $*"; return 0; fi
  case "$*" in
    check|check\ *) echo "pre-commit run licensing --all-files" ;;
    init)          echo "pre-commit run licensing-init --hook-stage manual" ;;
    "download --fix") echo "pre-commit run licensing-download --hook-stage manual" ;;
    sbom)          echo "pre-commit run licensing-sbom --hook-stage manual" ;;
    *)             echo "pre-commit run licensing-cli --hook-stage manual (with args: [${*// /, }])" ;;
  esac
}
# Where this file actually IS, resolved before the cd below, so the cache key
# can include the script's own bytes. A version number is a promise somebody
# has to remember to keep; the file's checksum is not, and an edited script
# that reused a cache written by the previous edit would be a bug nobody could
# see.
case "$0" in
  /*) SELF_PATH="$0" ;;
  *)  SELF_PATH="$PWD/$0" ;;
esac
[[ -r "$SELF_PATH" ]] || SELF_PATH=""

# The version is the tag of the git checkout this file is in; no number is
# written into the script. pre-commit runs a hook from a clone of the hooks
# repository that holds no tags (it fetches the pinned rev alone), but records
# the tag it fetched in FETCH_HEAD. Failing both, the commit; outside any git
# checkout, "unknown".
script_version() {
  local d head fh tag
  d="$(dirname "${SELF_PATH:-$0}")"
  tag="$(git -C "$d" describe --tags --exact-match 2>/dev/null)" && { echo "$tag"; return 0; }
  head="$(git -C "$d" rev-parse HEAD 2>/dev/null)" || { echo unknown; return 0; }
  fh="$(git -C "$d" rev-parse --git-path FETCH_HEAD 2>/dev/null)"
  case "$fh" in /*) ;; *) fh="$d/$fh" ;; esac
  if [[ -f "$fh" ]]; then
    tag="$(awk -v h="$head" '$1 == h && match($0, /tag \047[^\047]+\047/) { print substr($0, RSTART + 5, RLENGTH - 6); exit }' "$fh")"
    [[ -n "$tag" ]] && { echo "$tag"; return 0; }
  fi
  git -C "$d" rev-parse --short HEAD
}
die()  { echo "$ME: $*" >&2; exit 2; }
fail() { echo "$ME: $*" >&2; exit 1; }

# --- where the human-readable output goes ------------------------------------
# STDOUT, through fd 3. What --components, --obligations and the findings table
# print is the answer somebody asked this script for, and an answer belongs
# where `> report.txt` and `| tee` can take it. It used to go to stderr — all
# of it, under one blanket rule whose stated reason (see gen_toml below) covers
# only progress lines and was never meant to swallow the report.
#
# Why an extra descriptor rather than plain stdout:
#
#   1. gen_toml and its kind redirect stdout into a FILE. A note written while
#      that redirection is in force would land inside the generated REUSE.toml.
#      fd 3 is duplicated from stdout ONCE, here, before any of that, so it
#      still points at the real stdout and cannot be captured by accident.
#   2. --porcelain owns stdout for its records, and the promise there is that
#      `check --porcelain > licences.tsv` is the whole report and nothing else.
#      In that mode fd 3 is pointed at stderr instead, so the two never mix.
#
# What deliberately does NOT go here: die/fail and the exit-2 guidance blocks
# (an error is not the report anybody asked for), and the liveness signals —
# tnote and the OSC progress bar — which are the "is this thing still running"
# channel for a person watching a terminal, not content. Both stay on stderr.
exec 3>&1

note() { echo "$ME: $*" >&3; }
# --verbose output is DIAGNOSTICS — a line per scan worker, a line per skipped
# component, the timings — and diagnostics are not the report. They go to
# stderr, so `check --components --verbose | tee licensing.log` puts the
# report in the file and the running commentary on the terminal, which is the
# only arrangement in which both are readable.
vnote() { [[ -n "${LICENSING_VERBOSE:-}" ]] && echo "$ME:   $*" >&2; return 0; }
# A run that found nothing wrong says nothing: silence IS the pass, and a hook
# that prints eight lines per commit is eight lines nobody reads. snote carries
# the confirmations and the counts — real information, but only when asked for,
# and stderr for the same reason vnote is.
snote() { [[ -n "${LICENSING_VERBOSE:-}" ]] && echo "$ME: $*" >&2; return 0; }
# Progress for something slow, on a terminal only: a person waiting on a scan
# needs to know it started, and a pipe being read by a script does not. Under
# --porcelain there is no person at all — the terminal it was started from is
# not the thing reading the output — so these go away entirely and stderr
# carries only what went wrong.
#
# Stderr, and gated on stderr being a terminal, unlike everything else here:
# this is liveness, the same channel as the progress bar. A person who runs
# `check --components > report.txt` still wants to be told the scan will take
# minutes, and does not want that line inside report.txt.
tnote() {
  [[ "${PORCELAIN:-0}" == 1 && -z "${LICENSING_VERBOSE:-}" ]] && return 0
  [[ -n "${LICENSING_VERBOSE:-}" || -t 2 ]] && echo "$ME: $*" >&2
  return 0
}
# Elapsed seconds since $1 (a snapshot of $SECONDS).
since() { echo "$(( SECONDS - $1 ))s"; }
# syft is quiet unless asked: its progress output is the answer to "is this
# thing doing anything?" on a tree big enough to take minutes.
syft_quiet() { [[ -n "${LICENSING_VERBOSE:-}" ]] && echo "" || echo "-q"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- colour ------------------------------------------------------------------
# A finding is read by a human staring at a wall of paths, so status and
# licence carry colour when the human-output stream (fd 3, normally stdout) is
# a terminal — asking about stderr instead is what used to write escape
# sequences into `check --components > report.txt`. NO_COLOR wins, a dumb TERM
# wins, and LICENSING_COLOR=on|off|auto settles it either way.
LICENSING_COLOR="${LICENSING_COLOR:-auto}"
C_RESET=""; C_DENY=""; C_REVIEW=""; C_LIC=""; C_NAME=""; C_PATH=""; C_HEAD=""
COLOR_READY=0
color_init() {
  [[ "$COLOR_READY" == 1 ]] && return 0
  COLOR_READY=1
  local on=0
  case "$LICENSING_COLOR" in
    on)  on=1 ;;
    off) on=0 ;;
    *)   if [[ -t 3 && -z "${NO_COLOR:-}" ]]; then
           case "${TERM:-}" in dumb|"") ;; *) on=1 ;; esac
         fi ;;
  esac
  [[ "$on" == 1 ]] || return 0
  C_RESET=$'\033[0m'
  C_DENY=$'\033[1;97;41m'      # white on red — this one stops the build
  C_REVIEW=$'\033[1;30;43m'    # black on yellow — this one wants a decision
  C_LIC=$'\033[36m'; C_NAME=$'\033[1m'; C_PATH=$'\033[2m'; C_HEAD=$'\033[1;4m'
  return 0
}

# How wide the table may be. A finding column that runs off the edge is worse
# than one that says "...".
#
# Measured on stderr, not on the stream the table is written to: a report
# redirected to a file was still typed by somebody at a terminal, and laying it
# out for the width they can actually see beats falling back to 80 columns.
term_cols() {
  local c=""
  [[ -t 2 ]] && c="$(tput cols 2>/dev/null || true)"
  case "$c" in ''|*[!0-9]*) c=120 ;; esac
  [[ "$c" -lt 60 ]] && c=60
  echo "$c"
}

# STATUS | LICENCE | COMPONENT | PATH, aligned, from tab-separated records.
# Padding is computed on the plain text and the colour wrapped around it
# afterwards, because an escape sequence counts as width to printf and as
# nothing to the eye.
# ONE table for every finding, sorted by status, then licence, then name:
# DENY sorts before REVIEW, which is both alphabetical and the order you want
# to read them in, and rows that share a licence are rows you decide about
# together.
#
# Padding is computed on the plain text and the colour wrapped around it
# afterwards, because an escape sequence counts as width to printf and as
# nothing to the eye.
render_findings() { # render_findings <tsv file> [max REVIEW rows]
  local f="$1" max="${2:-0}"
  [[ -s "$f" ]] || return 0
  color_init
  # LC_ALL=C for awk too: dw() below counts bytes, and GNU awk in a UTF-8 locale
  # rejects the byte range it uses ("Invalid collation character").
  LC_ALL=C sort -t"$(printf '\t')" -k1,1 -k2,2 -k3,3 "$f" \
    | LC_ALL=C awk -F'\t' -v max="$max" -v conf="${CONF##*/}" \
      -v cD="$C_DENY" -v cR="$C_REVIEW" -v cL="$C_LIC" -v cN="$C_NAME" \
      -v cP="$C_PATH" -v cH="$C_HEAD" -v cZ="$C_RESET" '
    function dw(s,   t, n) { t = s; n = gsub(/[\200-\277]/, "", t); return length(s) - n }
    function sp(n,   o) { o = ""; while (n-- > 0) o = o " "; return o }
    function pad(s, w,   d) { d = w - dw(s); if (d < 0) d = 0; return s sp(d) }
    { rows[++n] = $0
      if (dw($2) > wl) wl = dw($2)
      if (dw($3) > wc) wc = dw($3) }
    END {
      if (n == 0) exit
      if (wl < 7) wl = 7
      if (wc < 9) wc = 9
      # Nothing is truncated. Every column here is something you have to act
      # on — you cannot decide about a licence you can only see half of, and
      # you cannot open a path that ends in "...". A row wider than the
      # terminal wraps, which is ugly and complete; the alternative was
      # tidy and useless.
      #
      # The status sits in a field of 8 so that the colour, which is a
      # background, has a space either side of the word and reads as a label
      # rather than as ink that ran into the text.
      printf "  %s%s %s %s %s%s\n", cH, pad(" STATUS", 8), pad("LICENCE", wl), pad("COMPONENT", wc), "PATH", cZ
      hidden = 0
      for (i = 1; i <= n; i++) {
        split(rows[i], f, "\t")
        # The cap is on REVIEW only: a deny-listed component fails the build,
        # and hiding one of those behind "and N more" would be hiding the
        # reason the build failed.
        if (f[1] != "DENY") {
          shown_review++
          if (max > 0 && shown_review > max) { hidden++; continue }
        }
        c = (f[1] == "DENY") ? cD : cR
        printf "  %s %s %s%s %s%s%s %s%s%s %s%s%s\n", \
          c, f[1], cZ, sp(8 - dw(f[1]) - 2), \
          cL, pad(f[2], wl), cZ, cN, pad(f[3], wc), cZ, cP, f[4], cZ
      }
      # Names the setting that hid them, which is the only thing that can:
      # this said "--verbose lists every one" and --verbose never did.
      if (hidden > 0) printf "  %s... and %d more to review (LICENSING_MAX_FINDINGS=0 in %s prints every one)%s\n", cP, hidden, conf, cZ
    }
  ' >&3
}

# --- terminal progress (OSC 9;4) --------------------------------------------
# Steps are planned as the run learns its own shape: the scan is one step, or
# one per worker plus one when it splits, and each phase asked for by --only
# adds its own. The denominator may grow mid-run; the percentage simply
# re-scales, which is what a caller watching a bar actually wants.
PROGRESS_ON=0; PROGRESS_DONE=0; PROGRESS_TOTAL=0
# A worker is a subshell and cannot touch the parent's counter, so the count
# of finished workers lives in a file they all append to. A short append is
# atomic, and two workers computing the same percentage costs nothing.
PROGRESS_DONE_FILE=""; PROGRESS_BASE=0

progress_supported() {
  case "$LICENSING_PROGRESS" in
    off) return 1 ;;
    on)  return 0 ;;
  esac
  [[ -t 2 ]] || return 1
  [[ -n "${CI:-}" ]] && return 1
  case "${TERM:-}" in dumb|"") return 1 ;; esac
  # Terminals known to RENDER OSC 9;4 rather than print it. Anything absent
  # gets nothing until you run --progress-test and decide for yourself.
  #
  # iTerm2 is here on an eyewitness report of a bar appearing, not on my
  # reading of the docs — older builds treated the whole OSC 9 family as a
  # notification request, so a version that predates progress support will pop
  # a notification per update instead of drawing anything. If that happens,
  # LICENSING_PROGRESS="off" in .licensing.conf, and --progress-test shows
  # which behaviour this build has.
  [[ -n "${WT_SESSION:-}" || -n "${ConEmuANSI:-}" ]] && return 0   # Windows Terminal, ConEmu/Cmder
  case "${TERM_PROGRAM:-}" in WezTerm|ghostty|mintty|iTerm.app|vscode) return 0 ;; esac
  return 1
}

# Show what this terminal actually does with the sequence. The only honest
# test is your own eyes: a supporting terminal draws a bar in its tab or
# taskbar, one that does not prints the escape bytes as text.
progress_test() {
  local p
  echo "Emitting OSC 9;4 progress for ~3 seconds."
  echo
  echo "  A supporting terminal draws a bar in its TAB or TASKBAR button —"
  echo "  nothing appears in the text area. It should ramp, turn red, then clear."
  echo "  An unsupporting terminal prints stray text like ]9;4;1;40 below,"
  echo "  and an older iTerm2 pops a notification per step instead."
  echo
  PROGRESS_ON=1
  for p in 0 20 40 60 80 100; do progress_emit 1 "$p"; sleep 0.3; done
  progress_emit 2 100; sleep 0.8
  progress_emit 0 0
  PROGRESS_ON=0
  echo
  if progress_supported; then
    echo "This terminal is on the built-in allow-list (${TERM_PROGRAM:-${WT_SESSION:+Windows Terminal}${ConEmuANSI:+ConEmu}}) — progress is already on."
  else
    echo "This terminal is NOT on the allow-list, so \"auto\" stays silent here."
    echo "If a bar appeared above, turn it on in ${CONF##*/}:"
    echo
    echo "    LICENSING_PROGRESS=\"on\""
  fi
}

progress_emit() { # progress_emit <state> <percent>
  [[ "$PROGRESS_ON" == 1 ]] || return 0
  printf '\033]9;4;%s;%s\007' "$1" "$2" >&2
}

progress_init() { progress_supported && PROGRESS_ON=1; progress_emit 3 0; return 0; }
progress_plan() { PROGRESS_TOTAL=$(( PROGRESS_TOTAL + $1 )); return 0; }
progress_step() { # progress_step [count]
  PROGRESS_DONE=$(( PROGRESS_DONE + ${1:-1} ))
  [[ "$PROGRESS_TOTAL" -le 0 ]] && return 0
  local pct=$(( PROGRESS_DONE * 100 / PROGRESS_TOTAL ))
  [[ "$pct" -gt 100 ]] && pct=100
  progress_emit 1 "$pct"
  return 0
}
# Idempotent: main ends the bar explicitly, and the EXIT trap ends it again
# for the paths that die early (a missing tool, a failed worker).
# Called from inside a worker subshell when its syft finishes.
progress_worker_done() {
  [[ "$PROGRESS_ON" == 1 && -n "$PROGRESS_DONE_FILE" ]] || return 0
  echo x >> "$PROGRESS_DONE_FILE"
  local n pct
  n="$(wc -l < "$PROGRESS_DONE_FILE" 2>/dev/null | tr -d ' ')"
  [[ -z "$n" || "$PROGRESS_TOTAL" -le 0 ]] && return 0
  pct=$(( (PROGRESS_BASE + n) * 100 / PROGRESS_TOTAL ))
  [[ "$pct" -gt 100 ]] && pct=100
  progress_emit 1 "$pct"
  return 0
}

progress_end() { # progress_end <exit code>
  [[ "$PROGRESS_ON" == 1 ]] || return 0
  if [[ "${1:-0}" == 0 ]]; then progress_emit 1 100; else progress_emit 2 100; fi
  progress_emit 0 0
  PROGRESS_ON=0
  return 0
}

# Resolve a tool to the command words that run it, mise first so the pinned
# version wins over whatever a developer happens to have on PATH. Prints the
# words; returns 1 when the tool cannot be found at all.
resolve_tool() { # resolve_tool <tool> [dir]
  local n="$1" d="${2:-.}"
  if [[ "$LICENSING_TOOL_RUNNER" != path ]] && have mise && (cd "$d" && mise which "$n" >/dev/null 2>&1); then
    echo "mise exec -- $n"; return 0
  fi
  [[ "$LICENSING_TOOL_RUNNER" == mise ]] && return 1
  have "$n" && { echo "$n"; return 0; }
  return 1
}

# Does a mise config apply in this directory? `mise exec` then activates the
# repository's whole pinned toolchain — python, node, ruby — for the command,
# not just tools mise itself installed. An installer that shells out to python
# needs that: pipenv looks for the Python the Pipfile asks for, and finds it
# only when mise has put it on PATH.
mise_applies() { # mise_applies <dir>
  [[ "$LICENSING_TOOL_RUNNER" == path ]] && return 1
  have mise || return 1
  (cd "$1" && mise ls --current 2>/dev/null | grep -q .)
}

missing_tool() {
  die "$1 not found, neither through mise nor on PATH. Pin it in mise.toml ([tools] ${2}) and run 'mise install', or install ${1} and put it on PATH."
}

# Set by need_syft / need_reuse, used as "${SYFT[@]}" / "${REUSE[@]}".
SYFT=(); REUSE=(); SYFT_OK=0; REUSE_OK=""
need_syft() {
  [[ "$SYFT_OK" == 1 ]] && return 0
  local c; c="$(resolve_tool syft)" || missing_tool syft 'syft = "1.51.0"'
  # shellcheck disable=SC2206 # resolve_tool returns a COMMAND LINE ("mise exec -- syft"), and
  # the split is what turns it into argv.
  SYFT=($c); SYFT_OK=1
}
need_reuse() {
  [[ -n "$REUSE_OK" ]] && return "$REUSE_OK"
  local c
  # shellcheck disable=SC2206 # a command line split into argv, as in need_syft above.
  if c="$(resolve_tool reuse)"; then REUSE=($c); REUSE_OK=0; else REUSE_OK=1; fi
  return "$REUSE_OK"
}

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a git repository"
cd "$REPO_ROOT"

CONF="${LICENSING_CONF:-${REPO_ROOT}/.licensing.conf}"

TMPDIR_RUN="$(mktemp -d)"
# shellcheck disable=SC2329 # invoked by the `trap cleanup EXIT` on the next line.
cleanup() { progress_end "$?"; rm -rf "$TMPDIR_RUN"; }
trap cleanup EXIT
SCAN="${TMPDIR_RUN}/scan.txt"
SCANNED=0
# Package directories outside the repository that the preflight verified as
# populated; scan_now reads them so their licences reach the gate.
EXTERNAL_LOCATIONS="${TMPDIR_RUN}/external"; : > "$EXTERNAL_LOCATIONS"
# Set by licence_file_for / where_from_paths, which return through a variable
# rather than through $( ) — a fork per component is minutes on a monorepo.
LICFILE_OUT=""; WHERE_OUT=""; WHERE_ONE=""

# The comment block at the top of this file is the --help text: print it
# verbatim, minus the shebang and the SPDX header. The manual is README.md.
usage() {
  awk 'NR<=3 {next} /^#/ {sub(/^# ?/,""); print; next} {exit}' "$0"
  exit "${1:-0}"
}

# The commands, options and option VALUES, in one place, so --completion and
# the parser cannot drift apart: everything below is read from here.
LICENSING_COMMANDS="check download sbom init"

# The long options, read out of the parser below rather than listed here: a
# second list is a second thing to forget, and the one that goes stale is
# always the one nobody runs.
# Every option the parser accepts, read out of the parser itself. The case
# PATTERN is what is read — the part before the ")" — split on "|", so the
# short form of an option comes out beside its long one (-v with --verbose)
# instead of being dropped: a grep for "--" over the whole line found the long
# options and nothing else, and also whatever happened to look like one inside
# the case body. "--mode=*" and "--mode" are the same option and appear once.
completion_flags() {
  awk '/^while \[\[ \$# -gt 0 \]\]; do$/ { inparser = 1; next }
       inparser && /^done$/ { exit }
       inparser && /^    -/ {
         pat = $0; sub(/\).*$/, "", pat)
         n = split(pat, alts, "|")
         for (i = 1; i <= n; i++) {
           a = alts[i]
           gsub(/^[ \t]+|[ \t]+$/, "", a)
           sub(/=\*$/, "", a)
           if (a ~ /^--?[A-Za-z][A-Za-z0-9-]*$/) print a
         }
       }' "$SELF" \
    | LC_ALL=C sort -u | tr '\n' ' '
}
LICENSING_VALUES_mode="full delta auto"
LICENSING_VALUES_only="deps toml lint deps,toml deps,lint toml,lint deps,toml,lint"
LICENSING_VALUES_color="auto on off"
LICENSING_VALUES_progress="auto on off"
LICENSING_VALUES_completion="bash zsh fish"

# A completion script for the shell named, on stdout, for eval or for a file.
# Generated rather than shipped alongside: a separate file is a second thing to
# keep in step with the parser, and this script is copied between repositories
# on its own.
completion_script() { # completion_script <bash|zsh|fish>
  # Both the name it was invoked as and its stem, so completion fires whether
  # it is on PATH as licensing.sh or symlinked as licensing.
  local names="$ME" LICENSING_FLAGS
  [[ "${ME%.sh}" != "$ME" ]] && names="$names ${ME%.sh}"
  LICENSING_FLAGS="$(completion_flags)"
  LICENSING_FLAGS="${LICENSING_FLAGS% }"
  case "$1" in
    bash)
      cat <<BASHEOF
# ${ME} completion for bash — source it, or put it in a bash-completion dir.
_licensing_sh() {
  local cur prev
  cur="\${COMP_WORDS[COMP_CWORD]}"
  prev="\${COMP_WORDS[COMP_CWORD-1]}"
  case "\$prev" in
    --mode)       COMPREPLY=( \$(compgen -W "${LICENSING_VALUES_mode}" -- "\$cur") ); return ;;
    --only)       COMPREPLY=( \$(compgen -W "${LICENSING_VALUES_only}" -- "\$cur") ); return ;;
    --color)      COMPREPLY=( \$(compgen -W "${LICENSING_VALUES_color}" -- "\$cur") ); return ;;
    --progress)   COMPREPLY=( \$(compgen -W "${LICENSING_VALUES_progress}" -- "\$cur") ); return ;;
    --completion) COMPREPLY=( \$(compgen -W "${LICENSING_VALUES_completion}" -- "\$cur") ); return ;;
    -o|--output)  COMPREPLY=( \$(compgen -f -- "\$cur") ); return ;;
    --jobs)       return ;;
  esac
  case "\$cur" in
    -*) COMPREPLY=( \$(compgen -W "${LICENSING_FLAGS}" -- "\$cur") ); return ;;
  esac
  if [[ \$COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( \$(compgen -W "${LICENSING_COMMANDS}" -- "\$cur") )
  fi
}
complete -F _licensing_sh ${names}
BASHEOF
      ;;
    zsh)
      cat <<ZSHEOF
#compdef ${names}
# ${ME} completion for zsh — put it in a directory on \$fpath as _${ME%.sh}.
_licensing_sh() {
  _arguments -s \\
    '1:command:(${LICENSING_COMMANDS})' \\
    '--mode[which components are gated]:mode:(${LICENSING_VALUES_mode})' \\
    '--only[which halves run]:halves:(${LICENSING_VALUES_only})' \\
    '--color[coloured findings table]:when:(${LICENSING_VALUES_color})' \\
    '--progress[OSC 9;4 progress bar]:when:(${LICENSING_VALUES_progress})' \\
    '--completion[print a completion script]:shell:(${LICENSING_VALUES_completion})' \\
    '(-o --output)'{-o,--output}'[write the SBOM here]:file:_files' \\
    '--jobs[parallel syft workers]:count:' \\
    '--auto-install[install dependencies before scanning]' \\
    '--skip-install-check[scan whatever is on disk]' \\
    '--no-cache[scan again instead of re-using the last scan]' \\
    '--all[download every licence text the tree is missing]' \\
    '--fix[download the missing texts and remove the unused ones]' \\
    '--dry-run[say what download would change, change nothing]' \\
    '--porcelain[machine-readable records on stdout]' \\
    '--obligations[what the licences found ask of you]' \\
    '--components[obligations, with the packages under each]' \\
    '--progress-test[show what this terminal does with a progress bar]' \\
    '(-v --verbose)'{-v,--verbose}'[say what it is doing]' \\
    '(-h --help)'{-h,--help}'[the manual]' \\
    '(-V --version)'{-V,--version}'[version and date]'
}
_licensing_sh "\$@"
ZSHEOF
      ;;
    fish)
      local c n
      echo "# ${ME} completion for fish — put it in ~/.config/fish/completions/${ME%.sh}.fish"
      for n in $names; do
        echo "complete -c ${n} -f"
        for c in $LICENSING_COMMANDS; do
          echo "complete -c ${n} -n __fish_use_subcommand -a ${c}"
        done
      done
      local ME_SAVE="$ME"
      for ME in $names; do
      cat <<FISHEOF
complete -c ${ME} -l mode -x -a '${LICENSING_VALUES_mode}' -d 'which components are gated'
complete -c ${ME} -l only -x -a '${LICENSING_VALUES_only}' -d 'which halves run'
complete -c ${ME} -l color -x -a '${LICENSING_VALUES_color}' -d 'coloured findings table'
complete -c ${ME} -l progress -x -a '${LICENSING_VALUES_progress}' -d 'OSC 9;4 progress bar'
complete -c ${ME} -l completion -x -a '${LICENSING_VALUES_completion}' -d 'print a completion script'
complete -c ${ME} -s o -l output -r -d 'write the SBOM here'
complete -c ${ME} -l jobs -x -d 'parallel syft workers'
complete -c ${ME} -l auto-install -d 'install dependencies before scanning'
complete -c ${ME} -l skip-install-check -d 'scan whatever is on disk'
complete -c ${ME} -l no-cache -d 'scan again instead of re-using the last scan'
complete -c ${ME} -l all -d 'download every licence text the tree is missing'
complete -c ${ME} -l fix -d 'download the missing texts and remove the unused ones'
complete -c ${ME} -l dry-run -d 'say what download would change, change nothing'
complete -c ${ME} -l porcelain -d 'machine-readable records on stdout'
complete -c ${ME} -l obligations -d 'what the licences found ask of you'
complete -c ${ME} -l components -d 'obligations, with the packages under each'
complete -c ${ME} -l progress-test -d 'show what this terminal does with a progress bar'
complete -c ${ME} -s v -l verbose -d 'say what it is doing'
complete -c ${ME} -s h -l help -d 'the manual'
complete -c ${ME} -s V -l version -d 'version and date'
FISHEOF
      done
      ME="$ME_SAVE"
      ;;
    *) die "unknown shell for --completion: $1 (${LICENSING_VALUES_completion})" ;;
  esac
}

# A declared value that names no licence. "Dual License" says there are two
# and then names neither; "UNKNOWN" is what setuptools writes when the author
# wrote nothing. Treated as absent, so the classifiers beside it get their
# turn — python-dateutil says "Dual License" and then classifies itself
# Apache-2.0 and BSD, which is the answer.
LICENSING_PLACEHOLDER_LICENCES="dual license|dual licence|dual|unknown|none|n/a|na|see license|see licence|see license file|license|licence|licensed|free|freeware|copyright|osi approved|other/proprietary license"

# Not one fork. `echo | tr | tr` is three processes, and this runs once per
# licence of every component in the tree — on a monorepo that is tens of
# thousands of processes, which is minutes of nothing happening.
placeholder_lic() { # placeholder_lic <value>
  local v="$1" hit=1 had=0
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  [[ -z "$v" ]] && return 0
  while [[ "$v" == *"  "* ]]; do v="${v//  / }"; done
  shopt -q nocasematch && had=1
  shopt -s nocasematch
  case "|${LICENSING_PLACEHOLDER_LICENCES}|" in *"|${v}|"*) hit=0 ;; esac
  [[ "$had" == 0 ]] && shopt -u nocasematch
  return "$hit"
}

# Declared text -> SPDX id, or the value unchanged when nothing matches. This
# is a LEAF mapping: hand it one licence, never an expression. The alias
# patterns are globs, and "GPL-2.0-only OR LGPL-2.1-or-later" matches "gpl*2*"
# as happily as a bare GPLv2 does — which would collapse a dual licence into
# the copyleft half of itself. normalize_expr splits first, for that reason.
normalize_lic() {
  local v="$1" lower entry pat id
  # An id the policy already names is the answer, not a candidate for the
  # alias globs: "LGPL-2.1-or-later" is a valid SPDX id, and "lgpl*2.1*" would
  # otherwise rewrite it to the -only variant the policy did not choose.
  in_list "$v" " $LICENSING_ALLOW $LICENSING_DENY " && { echo "$v"; return; }
  # "A WITH B" is ONE leaf carrying a modifier, and every alias pattern below
  # is matched against the whole string: "gpl*2*" matches "GPL-2.0-only WITH
  # Classpath-exception-2.0" and answers "GPL-2.0-only", throwing the exception
  # away right here — before id_verdict can look the pair up in
  # LICENSING_ALLOW_EXPRESSIONS, which is the one place entitled to decide
  # about it. Normalise the base licence, keep the exception attached to it.
  #
  # Load-bearing, not tidiness: without these four lines the expression lists
  # cannot answer for a WITH at all, which is the case they exist for.
  case "$v" in
    *" WITH "*) echo "$(normalize_lic "${v%% WITH *}") WITH ${v#* WITH }"; return ;;
  esac
  # "GPL-3.0-or-later" is already an unambiguous SPDX id, and the fuzzy
  # patterns below would answer "GPL-3.0-only", which is a different licence
  # and a different verdict. Only the SUFFIXED forms are protected: a bare
  # "LGPL-3.0" is a deprecated id and does want mapping.
  case "$v" in
    *[[:space:]]*) ;;
    *-only|*-or-later) echo "$v"; return ;;
  esac
  # A whole Python trove classifier where an id was wanted: "License :: OSI
  # Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)". The
  # licence is the LAST segment; everything before it is Python's taxonomy,
  # and left in place it matches no alias and no list.
  case "$v" in
    [Ll]icen[sc]e" :: "*) v="${v##* :: }" ;;
  esac
  lower="$(echo "$v" | tr '[:upper:]' '[:lower:]' | tr -s ' ')"
  lower="${lower# }"; lower="${lower% }"
  for entry in ${LICENSING_LICENSE_ALIASES[@]+"${LICENSING_LICENSE_ALIASES[@]}"} \
               ${LICENSING_LICENSE_ALIASES_LAST[@]+"${LICENSING_LICENSE_ALIASES_LAST[@]}"}; do
    pat="${entry%%|*}"; id="${entry#*|}"
    # shellcheck disable=SC2053
    [[ "$lower" == $pat ]] && { echo "$id"; return; }
  done
  echo "$v"
}

# Is this text a licence this tool can name? True when an alias claims it,
# when the policy lists it, or when it is shaped like a bare SPDX id. It is
# the test that tells free-text alternatives apart from a licence whose own
# NAME contains the word "or".
known_leaf() { # known_leaf <text>
  local t="$1" id
  t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
  [[ -z "$t" ]] && return 1
  id="$(normalize_lic "$t")"
  [[ "$id" != "$t" ]] && return 0
  [[ "$(id_verdict "$id")" != unknown ]] && return 0
  case "$id" in *[[:space:]]*) return 1 ;; esac
  case "$id" in [A-Za-z]*) ;; *) return 1 ;; esac
  case "$id" in *[!A-Za-z0-9.+-]*) return 1 ;; esac
  return 0
}

# The same question known_leaf answers, asked without forking. known_leaf goes
# through normalize_lic, and normalize_lic is called as $( ) — a fork. This one
# runs for every licence of every component in the tree, where a fork per call
# is minutes of nothing happening on a monorepo, so the alias globs are matched
# in the shell instead (case-insensitively, since they are written lowercase).
# It is used only to decide whether reading a file off disk is WORTH it, so a
# conservative answer costs a file read and never a wrong verdict.
nameable_lic() { # nameable_lic <one licence value>
  # Remembered (see memo_expr): the answer depends on the string and the
  # policy alone, and the alias loop below is ~70 glob matches per call.
  local known=0
  if memo_get "nameable:$1"; then return "$MEMO_OUT"; fi
  nameable_lic_uncached "$1" || known=$?
  memo_put "nameable:$1" "$known"
  return "$known"
}
nameable_lic_uncached() { # nameable_lic_uncached <one licence value>
  local v="$1" entry pat had=0 rc=1
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
  [[ -z "$v" ]] && return 1
  while [[ "$v" == *"  "* ]]; do v="${v//  / }"; done
  # A whole Python trove classifier where an id was wanted: "License :: OSI
  # Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)". The
  # licence is the LAST segment; everything before it is Python's taxonomy,
  # and left in place it matches no alias and no list.
  case "$v" in
    [Ll]icen[sc]e" :: "*) v="${v##* :: }" ;;
  esac
  # A bare SPDX-shaped id names a licence whether or not this policy knows it:
  # "Commercial" and "FSL-1.1-MIT" are answers, not gaps, and a LICENSE file
  # must not be allowed to overrule one.
  case "$v" in
    *[!A-Za-z0-9.+-]*) ;;
    [A-Za-z0-9]*) return 0 ;;
  esac
  in_list "$v" " $LICENSING_ALLOW $LICENSING_DENY " && return 0
  shopt -q nocasematch && had=1
  shopt -s nocasematch
  for entry in ${LICENSING_LICENSE_ALIASES[@]+"${LICENSING_LICENSE_ALIASES[@]}"}; do
    pat="${entry%%|*}"
    # shellcheck disable=SC2053
    [[ "$v" == $pat ]] && { rc=0; break; }
  done
  [[ "$had" == 0 ]] && shopt -u nocasematch
  return "$rc"
}

# True when NOTHING in this value names a licence — not an id, not an alias,
# not one side of a choice. What is left is free text somebody typed: "Mozilla
# Public License" with no version, "SEE LICENSE IN FEEL-FREE.md", a bare URL
# nobody mapped, "???????". The licence TEXT the package ships is a better
# witness than any of those, and fill_licence_gaps goes and reads it.
#
# One nameable side is enough to leave the value alone: "MIT OR SEE LICENSE IN
# FEEL-FREE.md" is already an answer, and replacing it with whatever a file
# says would throw the MIT half away.
unmappable_lic() { # unmappable_lic <one licence value>
  local v="$1" part
  nameable_lic "$v" && return 1
  v="${v//(/ }"; v="${v//)/ }"
  # A URL is not a path with alternatives in it: splitting one on "/" turns
  # "example.com" into something that looks like a bare id and answers yes.
  case "$v" in *://*) ;; *) v="${v//\//$'\n'}" ;; esac
  v="${v// OR /$'\n'}"; v="${v// AND /$'\n'}"
  v="${v// or /$'\n'}"; v="${v// and /$'\n'}"
  v="${v//, /$'\n'}"
  while IFS= read -r part; do
    [[ -z "${part//[[:space:]]/}" ]] && continue
    nameable_lic "$part" && return 1
  done <<EOF
${v}
EOF
  return 0
}

# True when splitting on <sep> yields nothing but licences we can name, and at
# least two of them. This is what keeps "Apache 2.0 or BSD" (two licences, a
# choice) apart from "GNU Lesser General Public License v2 or later" (one
# licence, whose name happens to contain the word).
soft_split_ok() { # soft_split_ok <value> <separator>
  local rest="$1" sep="$2" part n=0
  [[ "$rest" == *"$sep"* ]] || return 1
  while [[ -n "$rest" ]]; do
    if [[ "$rest" == *"$sep"* ]]; then part="${rest%%"$sep"*}"; rest="${rest#*"$sep"}"
    else part="$rest"; rest=""; fi
    known_leaf "$part" || return 1
    n=$((n+1))
  done
  [[ "$n" -ge 2 ]]
}

# Brackets, taken seriously. Everything below splits an SPDX expression on its
# operators, and doing that without counting brackets reads "MIT AND (A OR B)"
# as "(MIT AND A) OR B" — a different grant, and for a gate the more permissive
# one. Two helpers, both returning through a global, because bash cannot return
# an array and a $( ) inside a function that recurses is a fork per level.

# "(MIT OR Apache-2.0)" -> "MIT OR Apache-2.0". "(A) AND (B)" is left alone:
# the FIRST bracket has to be the one the LAST bracket closes.
EXPR_STRIPPED=""
strip_outer_parens() { # strip_outer_parens <expression>
  local e="$1" i n depth ch
  while :; do
    e="${e#"${e%%[![:space:]]*}"}"; e="${e%"${e##*[![:space:]]}"}"
    [[ "$e" == \(*\) ]] || break
    n=${#e}; depth=0; i=0
    while [[ $i -lt $n ]]; do
      ch="${e:$i:1}"
      case "$ch" in "(") depth=$((depth+1)) ;; ")") depth=$((depth-1)) ;; esac
      [[ $depth -eq 0 ]] && break
      i=$((i+1))
    done
    [[ $i -eq $(( n - 1 )) ]] || break     # the opening bracket closed early
    e="${e:1:$(( n - 2 ))}"
  done
  EXPR_STRIPPED="$e"
}

# Split on <op> at bracket depth zero, and nowhere else. Parts land in
# EXPR_PARTS; returns 1 when the operator does not occur at depth zero, so the
# caller can move on to the next one.
EXPR_PARTS=()
expr_split() { # expr_split <expression> <operator>
  local e="$1" op="$2" i=0 depth=0 n=${#1} m=${#2} ch part="" found=1
  EXPR_PARTS=()
  while [[ $i -lt $n ]]; do
    ch="${e:$i:1}"
    case "$ch" in "(") depth=$((depth+1)) ;; ")") depth=$((depth-1)) ;; esac
    if [[ $depth -eq 0 && "${e:$i:$m}" == "$op" ]]; then
      EXPR_PARTS+=("$part"); part=""; i=$(( i + m )); found=0; continue
    fi
    part="${part}${ch}"; i=$(( i + 1 ))
  done
  EXPR_PARTS+=("$part")
  return "$found"
}

# One expression with every leaf mapped through the alias table and every
# operator canonicalised to SPDX " OR " / " AND ". Free-text alternatives are
# recognised too — "GPL 2.0/LGPL 2.1", "Apache 2.0 or BSD", "MIT, Apache-2.0"
# are all a CHOICE, and a choice is allowed when either side is (expr_verdict
# says so). They are only split when soft_split_ok agrees.
normalize_expr() { # normalize_expr <expression>
  local e="$1" part rest joined="" op sep
  e="${e#"${e%%[![:space:]]*}"}"; e="${e%"${e##*[![:space:]]}"}"
  [[ -z "$e" ]] && return 0

  # A wholly parenthesised expression means exactly what it means without the
  # brackets, and "(MIT OR Apache-2.0)" is not a form anyone can paste onto an
  # allow list, so they come off. Brackets that GROUP — "MIT AND (A OR B)", or
  # anything with a bracket inside — are left exactly as they are.
  strip_outer_parens "$e"
  if [[ "$EXPR_STRIPPED" != "$e" ]]; then
    normalize_expr "$EXPR_STRIPPED"; return
  fi

  for op in " OR " " AND "; do
    if expr_split "$e" "$op"; then
      local parts=(${EXPR_PARTS[@]+"${EXPR_PARTS[@]}"})   # the recursion clobbers it
      local sub
      for part in ${parts[@]+"${parts[@]}"}; do
        sub="$(normalize_expr "$part")"
        # A part that still holds an operator holds a DIFFERENT one — this
        # split took every top-level occurrence of ours — so it needs its
        # brackets back. Without them "MIT AND (A OR B)" comes out as
        # "MIT AND A OR B", which is a different grant.
        case "$sub" in *" OR "*|*" AND "*) sub="(${sub})" ;; esac
        joined="${joined:+${joined}${op}}${sub}"
      done
      echo "$joined"; return
    fi
  done

  # A comma is the one separator that does not say which it means. "MIT,
  # Apache-2.0" is a choice; "BSD-3-Clause, TCL" is a package under both. Read
  # it as a choice only while nothing in the list is deny-listed — where it
  # matters, the conservative reading is the one that binds you to every part.
  for sep in " or " " Or " "/" ", "; do
    soft_split_ok "$e" "$sep" || continue
    local glue=" OR "
    if [[ "$sep" == ", " ]]; then
      rest="$e"
      while [[ -n "$rest" ]]; do
        if [[ "$rest" == *"$sep"* ]]; then part="${rest%%"$sep"*}"; rest="${rest#*"$sep"}"
        else part="$rest"; rest=""; fi
        [[ "$(expr_verdict "$(normalize_expr "$part")")" == deny ]] && { glue=" AND "; break; }
      done
    fi
    rest="$e"
    while [[ -n "$rest" ]]; do
      if [[ "$rest" == *"$sep"* ]]; then part="${rest%%"$sep"*}"; rest="${rest#*"$sep"}"
      else part="$rest"; rest=""; fi
      part="${part#"${part%%[![:space:]]*}"}"; part="${part%"${part##*[![:space:]]}"}"
      # Recurse, never normalize_lic: a part can hold a separator of its own
      # ("GPL 2.0/LGPL 2.1 or MIT" splits twice), and mapping it whole would
      # glob-match the first alias and drop the rest.
      joined="${joined:+${joined}${glue}}$(normalize_expr "$part")"
    done
    echo "$joined"; return
  done

  normalize_lic "$e"
}

# LICENSING_ALLOW and LICENSING_DENY are ARRAYS, one SPDX id per element:
#
#   LICENSING_ALLOW=(
#     MIT
#     Apache-2.0
#     ISC
#   )
#
# A policy list reaches a few hundred characters as one string, which is a line
# nobody can read in a review and one that every branch touching it conflicts
# on. One id per line diffs, reviews and merges a line at a time.
#
# A string is refused rather than accepted quietly. It would still work — the
# rest of this script wants the ids space-separated and that is what an array
# is flattened into here — but two spellings of a policy is one more thing to
# know before you can read one, and the conversion is mechanical.
#
# An element with a space in it is refused too: these lists hold single ids,
# and flattening "BSD-3-Clause AND TCL" would silently turn one expression into
# three meaningless tokens, one of which is the word AND. That belongs in
# LICENSING_ALLOW_EXPRESSIONS.
normalize_policy_list() { # normalize_policy_list <variable name>
  local k="$1" decl one
  decl="$(declare -p "$k" 2>/dev/null)" || return 0
  case "$decl" in
    "declare -a"*|"typeset -a"*) ;;
    *)
      eval "local _cur=\"\${${k}}\""
      # shellcheck disable=SC2154,SC2086 # _cur is created by the eval on the line above, and
      # the split is what puts one id per line in the message below.
      die "${CONF##*/} sets ${k} to a string. It is an array, one SPDX id per element:

  ${k}=(
$(printf '%s\n' ${_cur} | sed 's/^/    /')
  )

An empty policy — nothing pre-approved, every component reported — is ${k}=()."
      ;;
  esac
  eval "local _items=(\${${k}[@]+\"\${${k}[@]}\"})"
  # shellcheck disable=SC2154 # _items is created by the eval on the line above.
  for one in ${_items[@]+"${_items[@]}"}; do
    case "$one" in
      *[[:space:]]*)
        die "${CONF##*/} has \"${one}\" in ${k}. That is an expression, not an id, and this list holds single SPDX ids — it would be read as several, one of them an operator. Put it in ${k}_EXPRESSIONS instead:

  ${k}_EXPRESSIONS=(\"${one}\")" ;;
    esac
  done
  eval "${k}=\"\${_items[*]-}\""
  return 0
}

# Is this whole expression named in one of the expression lists? Exact match
# after trimming, on the normalised form.
expr_listed() { # expr_listed <expression> <array variable name>
  local e="$1" one
  eval "local _items=(\${${2}[@]+\"\${${2}[@]}\"})"
  for one in ${_items[@]+"${_items[@]}"}; do
    [[ "$e" == "$one" ]] && return 0
  done
  return 1
}

# Verdict for one SPDX id: allow | deny | unknown.
id_verdict() {
  local l; l="$(normalize_lic "$1")"
  # A whole expression the policy has answered for — "GPL-2.0-only WITH
  # Classpath-exception-2.0" — is answered as it stands, before the exception
  # is dropped and the base id decides.
  expr_listed "$l" LICENSING_DENY_EXPRESSIONS  && { echo deny; return; }
  expr_listed "$l" LICENSING_ALLOW_EXPRESSIONS && { echo allow; return; }
  # "Apache-2.0 WITH LLVM-exception" — the exception widens permission, so the
  # base id is what is judged when the pair has not been named above.
  case "$l" in *" WITH "*) l="${l%% WITH *}" ;; esac
  in_list "$l" " $LICENSING_DENY " && { echo deny; return; }
  in_list "$l" " $LICENSING_ALLOW " && { echo allow; return; }
  echo unknown
}

# normalize_expr and expr_verdict are pure functions of a licence string, and
# a run asks them about the same few dozen strings once per component: 650
# Rust crates are 650 times "MIT OR Apache-2.0". Each call is a $( ) fork plus
# a character-by-character parse, so they are remembered here, in the calling
# shell — a $( ) cannot remember anything — and a repeat costs an array scan
# instead. Two parallel arrays, not an associative one: bash 3.2 has none.
# Capped, so a tree with thousands of distinct free-text licences does not
# turn every lookup into a long scan; past the cap it simply computes.
MEMO_KEYS=(); MEMO_VALS=(); MEMO_OUT=""
LICENSING_MEMO_MAX=500
memo_get() { # memo_get <key> -> MEMO_OUT; 1 when not remembered
  local i=0 n=${#MEMO_KEYS[@]}
  while [[ $i -lt $n ]]; do
    if [[ "${MEMO_KEYS[$i]}" == "$1" ]]; then MEMO_OUT="${MEMO_VALS[$i]}"; return 0; fi
    i=$((i + 1))
  done
  return 1
}
memo_put() { # memo_put <key> <value>
  [[ ${#MEMO_KEYS[@]} -lt $LICENSING_MEMO_MAX ]] || return 0
  MEMO_KEYS+=("$1"); MEMO_VALS+=("$2")
}
memo_expr() { # memo_expr <norm|verdict> <expression> -> MEMO_OUT
  memo_get "${1}:${2}" && return 0
  case "$1" in
    norm)    MEMO_OUT="$(normalize_expr "$2")" ;;
    verdict) MEMO_OUT="$(expr_verdict "$2")" ;;
  esac
  memo_put "${1}:${2}" "$MEMO_OUT"
}

# Verdict for a whole SPDX expression: "(MIT OR GPL-3.0-or-later)" is a CHOICE,
# so it is allowed when either side is — picking MIT is a real option and
# refusing the package because GPL appears in the expression is wrong. "A AND
# B" binds you to both, so every operand must pass.
expr_verdict() {
  local e part v seen_deny=0 seen_unknown=0 seen_allow=0
  strip_outer_parens "$1"; e="$EXPR_STRIPPED"

  # The whole expression first: "BSD-3-Clause AND TCL" can be decided as one
  # thing, and deciding it that way is different from deciding its parts.
  expr_listed "$e" LICENSING_DENY_EXPRESSIONS  && { echo deny; return; }
  expr_listed "$e" LICENSING_ALLOW_EXPRESSIONS && { echo allow; return; }

  if expr_split "$e" " OR "; then
    local parts=(${EXPR_PARTS[@]+"${EXPR_PARTS[@]}"})
    for part in ${parts[@]+"${parts[@]}"}; do
      v="$(expr_verdict "$part")"
      case "$v" in allow) seen_allow=1 ;; deny) seen_deny=1 ;; *) seen_unknown=1 ;; esac
    done
    [[ $seen_allow == 1 ]] && { echo allow; return; }
    [[ $seen_unknown == 1 ]] && { echo unknown; return; }
    echo deny; return
  fi

  if expr_split "$e" " AND "; then
    local parts=(${EXPR_PARTS[@]+"${EXPR_PARTS[@]}"})
    for part in ${parts[@]+"${parts[@]}"}; do
      v="$(expr_verdict "$part")"
      case "$v" in deny) seen_deny=1 ;; unknown) seen_unknown=1 ;; esac
    done
    [[ $seen_deny == 1 ]] && { echo deny; return; }
    [[ $seen_unknown == 1 ]] && { echo unknown; return; }
    echo allow; return
  fi

  id_verdict "$e"
}

# The individual ids inside an expression that the policy does not cover, one
# per line. Reporting the whole expression would be useless — "(MIT OR
# Commercial)" is not something anyone can paste into an allow list, and
# splitting it on spaces turns it into rubble.
unknown_leaves() { # unknown_leaves <expression>
  local e="$1" part rest
  e="${e//(/ }"; e="${e//)/ }"
  e="${e// OR /$'\n'}"; e="${e// AND /$'\n'}"
  while IFS= read -r part; do
    part="${part#"${part%%[![:space:]]*}"}"; part="${part%"${part##*[![:space:]]}"}"
    [[ -z "$part" || "$part" == sha256:* ]] && continue
    case "$part" in *" WITH "*) part="${part%% WITH *}" ;; esac
    [[ "$(id_verdict "$part")" == unknown ]] && normalize_lic "$part"
  done <<EOF
${e}
EOF
}

# The individual ids inside an expression that the policy REFUSES. Same
# reasoning as unknown_leaves: "GPL-2.0-only OR LGPL-2.1-or-later" split on
# spaces yields the word "OR", which is not a licence and helps nobody.
deny_leaves() { # deny_leaves <expression or comma-joined list of them>
  local e="$1" part
  e="${e//(/ }"; e="${e//)/ }"
  e="${e//, /$'\n'}"
  e="${e// OR /$'\n'}"; e="${e// AND /$'\n'}"
  while IFS= read -r part; do
    part="${part#"${part%%[![:space:]]*}"}"; part="${part%"${part##*[![:space:]]}"}"
    [[ -z "$part" || "$part" == sha256:* ]] && continue
    case "$part" in *" WITH "*) part="${part%% WITH *}" ;; esac
    [[ "$(id_verdict "$part")" == deny ]] && normalize_lic "$part"
  done <<EOF
${e}
EOF
}

# Does a component name match any entry (plain or glob) of the named array?
name_matches() { # name_matches <name> <array variable name>
  local n="$1" arrname="$2" pat
  eval "local _items=(\${${arrname}[@]+\"\${${arrname}[@]}\"})"
  for pat in ${_items[@]+"${_items[@]}"}; do
    # shellcheck disable=SC2053
    [[ "$n" == $pat ]] && return 0
  done
  return 1
}

# True when every evidence path for an npm component sits BELOW that package's
# own directory — i.e. all of them are sub-path package.json shims.
nested_manifest_only() { # nested_manifest_only <name> <comma-separated paths>
  local name="$1" paths_csv="$2" p tail
  local IFS=','
  for p in $paths_csv; do
    [[ -z "$p" ]] && continue
    unset IFS
    case "$p" in
      */"${name}"/package.json|"/${name}/package.json") return 1 ;;   # the package itself
      */"${name}"/*) tail="${p##*/"${name}"/}"
    case "$tail" in package.json) return 1 ;; esac ;;
      *) return 1 ;;
    esac
    IFS=','
  done
  return 0
}

# True when every piece of evidence for a component is a lockfile — the
# package manager wrote its name down but never put it on disk.
lockfile_only() { # lockfile_only <comma-separated paths>
  local paths_csv="$1" p base
  [[ -z "$paths_csv" ]] && return 1
  local IFS=','
  for p in $paths_csv; do
    [[ -z "$p" ]] && continue
    base="${p##*/}"
    unset IFS
    in_list "$base" " $LICENSING_LOCKFILE_NAMES " || return 1
    IFS=','
  done
  return 0
}

# "where was this found", without forking: a component-sized loop that shells
# out three times per line costs more than the whole scan on a big tree.
# Sets WHERE_OUT rather than printing, because $( ) is itself a fork.
where_from_paths() { # where_from_paths <comma-separated paths>
  local paths_csv="$1" n=0 p1 rest p2
  # Count the commas by stepping from one to the next. `${paths_csv//[^,]/}`
  # said the same in one expansion, but bash 3.2 (macOS) matches a negated
  # bracket per character under a UTF-8 locale: 23 s for one 6 KB list.
  rest="$paths_csv"
  while [[ "$rest" == *,* ]]; do rest="${rest#*,}"; n=$((n + 1)); done
  [[ -z "$paths_csv" || "$n" == 0 ]] && { WHERE_OUT="unknown"; WHERE_ONE="unknown"; return; }
  p1="${paths_csv%%,*}"; p1="${p1#/}"
  WHERE_ONE="$p1"
  [[ "$n" -gt 1 ]] && WHERE_ONE="${p1} (+$(( n - 1 )))"
  if [[ "$n" -gt 1 ]]; then
    rest="${paths_csv#*,}"; p2="${rest%%,*}"; p2="${p2#/}"
    WHERE_OUT="${p1}, ${p2}"
    [[ "$n" -gt 2 ]] && WHERE_OUT="${WHERE_OUT}, +$(( n - 2 )) more"
  else
    WHERE_OUT="$p1"
  fi
}

in_list() { # in_list <needle> <space-separated haystack>
  case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# ---------------------------------------------------------------------------
# scan — the single syft invocation both halves consume
# ---------------------------------------------------------------------------
# Build the shared syft argument list (exclusions + cataloger selection) into
# the array named by $1.
syft_args() {
  local args=() p sel=""
  if [[ "$LICENSING_EXCLUDE_GITIGNORED" == 1 ]]; then
    local keep comp
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      p="${p%/}"
      keep=0
      for comp in ${LICENSING_INCLUDE_GITIGNORED[@]+"${LICENSING_INCLUDE_GITIGNORED[@]}"}; do
        case "/${p}/" in */"${comp}"/*) keep=1; break ;; esac
      done
      [[ "$keep" == 1 ]] && continue
      args+=(--exclude "./${p}" --exclude "./${p}/**")
    done < <(git ls-files --others --ignored --exclude-standard --directory)
  fi
  args+=(--exclude './.git/**')
  for p in ${LICENSING_EXCLUDE[@]+"${LICENSING_EXCLUDE[@]}"}; do args+=(--exclude "$p"); done
  local nroot nman
  for nroot in ${LICENSING_NESTED_ROOTS[@]+"${LICENSING_NESTED_ROOTS[@]}"}; do
    for nman in ${LICENSING_NESTED_MANIFESTS[@]+"${LICENSING_NESTED_MANIFESTS[@]}"}; do
      args+=(--exclude "./**/${nroot}/**/${nman}")
    done
  done
  if [[ -n "$LICENSING_CATALOGERS" ]]; then
    args+=(--override-default-catalogers "$LICENSING_CATALOGERS")
  else
    for p in ${LICENSING_ADD_CATALOGERS[@]+"${LICENSING_ADD_CATALOGERS[@]}"}; do
      sel="${sel:+$sel,}+${p}"
    done
    [[ -n "$sel" ]] && args+=(--select-catalogers "$sel")
  fi
  eval "$1=(\"\${args[@]}\")"
}

# The worker count actually used: never more than the CPU count, never more
# than the number of top-level directories there are to split.
# Is this tree worth splitting? Two cheap looks at the root, no recursion:
# a populated package directory (node_modules and friends), or enough
# top-level directories to look like a monorepo.
tree_is_big() {
  local name d n total=0
  for name in ${LICENSING_SCAN_HEAVY_DIRS[@]+"${LICENSING_SCAN_HEAVY_DIRS[@]}"}; do
    for d in "$name" */"$name"; do
      [[ -d "$d" ]] || continue
      set -- "$d"/*
      n=$#
      [[ "$n" == 1 && ! -e "$1" ]] && n=0     # an unmatched glob is one word
      total=$(( total + n ))
      [[ "$total" -ge "$LICENSING_SCAN_HEAVY_MIN_ENTRIES" ]] && {
        vnote "splitting: ${total}+ packages installed under ${name}/"
        return 0
      }
    done
  done
  vnote "one scan: ${total} installed packages in the root and one level down, below ${LICENSING_SCAN_HEAVY_MIN_ENTRIES}"
  return 1
}

resolve_scan_jobs() {
  local want="$LICENSING_SCAN_JOBS" cpus
  case "$want" in
    ''|1|0) echo 1; return ;;
    auto)
      tree_is_big || { echo 1; return; }
      cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
      want="$cpus" ;;
    *[!0-9]*) note "warning: LICENSING_SCAN_JOBS=${want} is not a number — using 1"; echo 1; return ;;
  esac
  echo "$want"
}

# Top-level directories worth giving a worker: real directories, not .git, and
# not something .gitignore excludes (those are already out of the scan).
split_subdirs() { # split_subdirs <root>
  local root="$1" d base nos skip
  for d in "$root"/*/ "$root"/.[!.]*/; do
    [[ -d "$d" ]] || continue
    base="${d%/}"; base="${base##*/}"
    [[ "$base" == ".git" ]] && continue
    skip=0
    for nos in ${LICENSING_SCAN_NOSPLIT[@]+"${LICENSING_SCAN_NOSPLIT[@]}"}; do
      [[ "$base" == "$nos" ]] && { skip=1; break; }
    done
    [[ "$skip" == 1 ]] && continue
    echo "$base"
  done
}

# syft reports paths relative to ITS scan root, so a worker on dir:a returns
# /node_modules/x/package.json where the whole-tree scan returns
# /a/node_modules/x/package.json. Put the prefix back, or delta scoping and
# every "catalogued from" line silently point at the wrong place.
reprefix_paths() { # reprefix_paths <subdir>
  awk -F'|' -v pfx="$1" 'NF {
    n = split($4, ps, ","); out = ""
    for (i = 1; i <= n; i++) if (ps[i] != "") out = out "/" pfx ps[i] ","
    print $1 "|" $2 "|" $3 "|" out "|" $5
  }'
}

# An exclude written against the repository root has to be rewritten for a
# worker whose root is one directory down: ./vendor/**/yarn.lock means
# ./**/yarn.lock to the worker scanning dir:vendor.
worker_excludes() { # worker_excludes <subdir> <original args...>
  local sub="$1"; shift
  local out=() a val nroot nman onroot=0
  # Is this worker rooted ON a vendor directory? Then the repository-anchored
  # patterns naming THAT directory are dead weight here and are dropped below,
  # and one pattern per manifest replaces the lot.
  for nroot in ${LICENSING_NESTED_ROOTS[@]+"${LICENSING_NESTED_ROOTS[@]}"}; do
    [[ "$sub" == "$nroot" ]] && { onroot=1; break; }
  done
  while [[ $# -gt 0 ]]; do
    a="$1"
    if [[ "$a" == "--exclude" && $# -gt 1 ]]; then
      val="$2"; shift 2
      # "./**/node_modules/**/Cargo.lock" cannot match anything the worker
      # rooted at dir:node_modules sees — the segment it needs is the root
      # itself and is no longer in the path. syft matches every pattern
      # against every file, so carrying 23 patterns that can never fire is
      # pure cost on the largest directory in the tree.
      if [[ "$onroot" == 1 && "$val" == "./**/${sub}/**/"* ]]; then continue; fi
      out+=("--exclude" "$val")
      # A pattern anchored at the repository root has to be re-anchored at the
      # worker's root, and it needs its own --exclude: emitting the bare value
      # made syft see a second positional argument and die with "accepts at
      # most 1 arg(s)" — silently, because worker stderr went to /dev/null.
      case "$val" in
        "./${sub}/"*) out+=("--exclude" "./${val#./"${sub}"/}") ;;
      esac
    else
      out+=("$a"); shift
    fi
  done
  # A worker rooted ON a vendor directory cannot match the pattern that keeps
  # dependency manifests out of one. "./**/node_modules/**/Cargo.lock" needs a
  # node_modules segment in the path, and to the worker scanning dir:node_modules
  # the path is "/@nomicfoundation/solidity-analyzer/Cargo.lock" — there is no
  # such segment, so nothing matched and the whole rule quietly stopped
  # applying to the biggest vendor directory in the tree. That is where 93
  # Rust crates and 10 Ruby gems came from in a repository that has neither:
  # they are the build-time lockfiles of two npm packages, describing packages
  # nothing here installs. Inside a vendor root EVERYTHING is somebody else's
  # installed package, so the manifests are excluded at any depth.
  # One pattern per manifest, at any depth. "./**/x" matches a file at the
  # worker root as well as one below it — doublestar lets "**" stand for zero
  # segments — so the separate "./x" this used to also emit was a second
  # pattern per manifest for nothing, on the one worker that can least afford
  # it.
  if [[ "$onroot" == 1 ]]; then
    for nman in ${LICENSING_NESTED_MANIFESTS[@]+"${LICENSING_NESTED_MANIFESTS[@]}"}; do
      out+=("--exclude" "./**/${nman}")
    done
  fi
  printf '%s\n' ${out[@]+"${out[@]}"}
}

# The syft actually in use, asked once. Licence detection changes between
# releases, so this belongs in the cache key whether or not the policy pins a
# version.
SYFT_VERSION_SEEN=""
syft_version() {
  [[ -n "$SYFT_VERSION_SEEN" ]] && { echo "$SYFT_VERSION_SEEN"; return 0; }
  SYFT_VERSION_SEEN="$("${SYFT[@]}" version 2>/dev/null | awk '/^Version:/ {print $2; exit}')"
  [[ -z "$SYFT_VERSION_SEEN" ]] && SYFT_VERSION_SEEN="unknown"
  echo "$SYFT_VERSION_SEEN"
}

# REUSE.toml's generated section is written from a syft scan, and licence
# detection differs between syft releases. The syft that wrote it is recorded on
# the line after the marker, so the file itself says what it was made with and
# every machine reads the same answer. Any syft works: a different one is a
# reason to expect drift, never a failure, and the stamp is left out of the
# drift comparison.
LICENSING_SYFT_STAMP="# generated with syft "

toml_stamp() { # toml_stamp <file>: the syft version recorded in it, or nothing
  sed -n "s/^${LICENSING_SYFT_STAMP}//p" "$1" | head -1
}

without_stamp() { grep -v "^${LICENSING_SYFT_STAMP}" "$1" || true; }

warn_syft_changed() { # warn_syft_changed <REUSE.toml>
  local was now; was="$(toml_stamp "$1")"; now="$(syft_version)"
  [[ -z "$was" || "$now" == unknown || "$was" == "$now" ]] && return 0
  note "warning: syft ${now} is in use and ${1} was generated with ${was}. Licence detection differs between releases; if the check below reports drift, run '$(how download --fix)' to regenerate it with this syft."
}

# ---------------------------------------------------------------------------
# scan cache
# ---------------------------------------------------------------------------
# One number for a stream. A real hash when the machine has one, cksum (POSIX,
# everywhere) when it does not: this is a cache key, not a signature, and CRC
# plus length tells two dependency trees apart perfectly well.
digest() {
  if have shasum;         then shasum -a 256 | cut -d' ' -f1
  elif have sha256sum;    then sha256sum | cut -d' ' -f1
  else                         cksum | tr -d ' '
  fi
}

# What a scan reads through, as a stream to be hashed: every dependency
# manifest and lockfile under <dir> BY CONTENT — so a reformat that changes
# nothing is not mistaken for a change, and a bumped version is never missed —
# and every package directory beside one by timestamp and entry count, because
# hashing node_modules would cost more than the scan this is trying to avoid.
#
# The installed trees are PRUNED from the walk on purpose: what is inside them
# is described by the lockfile that put it there and by the directory's own
# mtime and entry count, and walking them here would spend the seconds this is
# meant to save.
cache_inputs() { # cache_inputs [dir]
  local dir="${1:-.}" entry glob names=() first=1 d dirs=() paths=() kids=() n base parent
  for entry in ${LICENSING_INSTALL_CHECKS[@]+"${LICENSING_INSTALL_CHECKS[@]}"}; do
    glob="${entry#*|}"; glob="${glob%%|*}"
    if [[ "$first" == 1 ]]; then names=(-name "$glob"); first=0
    else names+=(-o -name "$glob"); fi
  done
  # package.json is not in the install table (a bare one names no lockfile) and
  # is the manifest a workspace changes most often. .gitignore is here because
  # what it ignores is what the scan excludes: adding a directory to it changes
  # the inventory without touching a single manifest.
  if [[ "$first" == 1 ]]; then names=(-name package.json -o -name .gitignore)
  else names+=(-o -name package.json -o -name .gitignore); fi
  find "$dir" \( -name node_modules -o -name vendor -o -name site-packages -o -name .git \) -prune -o \
      -type f \( "${names[@]}" \) -print 2>/dev/null | LC_ALL=C sort | while IFS= read -r d; do
    cksum "$d" 2>/dev/null || echo "unreadable ${d}"
  done
  # A directory that IS a package tree — a worker keyed on node_modules, or on
  # vendor — prunes ITSELF out of the walk above, and no lockfile lives inside
  # one. What governs node_modules is the package-lock.json BESIDE it, so that
  # is what goes in the key: without this such a worker has nothing in its key
  # that a dependency change can move, and `npm install` of a GPL package would
  # be answered with the clean scan from before it.
  base="${dir%/}"; base="${base##*/}"
  if [[ -d "$dir" ]] && in_list "$base" " ${LICENSING_SCAN_HEAVY_DIRS[*]-} "; then
    parent="${dir%/*}"; [[ "$parent" == "$dir" ]] && parent="."
    find "$parent" -maxdepth 1 -type f \( "${names[@]}" \) -print 2>/dev/null \
      | LC_ALL=C sort | while IFS= read -r d; do
      cksum "$d" 2>/dev/null || echo "unreadable ${d}"
    done
    paths+=("$dir")
  fi
  # The package directories themselves, here and two levels down — deep enough
  # for a monorepo's per-workspace node_modules and per-app virtualenv.
  for n in ${LICENSING_SCAN_HEAVY_DIRS[@]+"${LICENSING_SCAN_HEAVY_DIRS[@]}"}; do
    for d in "$dir/$n" "$dir"/*/"$n" "$dir"/*/*/"$n"; do
      [[ -d "$d" ]] || continue
      paths+=("$d")
    done
  done
  # And the packages inside each of them: a directory's own mtime moves when a
  # package is added to it or taken out, and does NOT move when one is replaced
  # in place, which is what a version bump does. One level, plus a second for
  # an @scope, is where a package manager puts a package and nowhere deeper.
  for d in ${paths[@]+"${paths[@]}"}; do
    set -- "$d"/*
    [[ $# == 1 && ! -e "$1" ]] && set --
    dirs+=("${d}=$#")
    kids+=("$@")
    set -- "$d"/@*/*
    [[ $# == 1 && ! -e "$1" ]] || kids+=("$@")
  done
  if [[ ${#dirs[@]} -gt 0 ]]; then
    printf '%s\n' "${dirs[@]}"
    # One ls for all of them, batched by xargs rather than passed at once: a
    # fork per package directory would not be free, and a monorepo's worth of
    # package paths in one argument list would not fit.
    printf '%s\n' "${paths[@]}" ${kids[@]+"${kids[@]}"} | xargs ls -ld 2>/dev/null
  fi
  return 0
}

# Every package location scanned to fill licence gaps, one syft target per
# line: the ones the policy names, plus the out-of-tree ones the preflight
# found (poetry keeps its virtualenv in ~/Library/Caches, so a Django
# dependency's dist-info is there and nowhere in the tree). Both the scan and
# the cache key read this, so neither can be looking at a different set.
aux_targets_list() {
  local t
  for t in ${LICENSING_AUX_SCAN_TARGETS[@]+"${LICENSING_AUX_SCAN_TARGETS[@]}"}; do
    [[ -n "$t" ]] && echo "$t"
  done
  [[ -s "$EXTERNAL_LOCATIONS" ]] && LC_ALL=C sort -u "$EXTERNAL_LOCATIONS"
  return 0
}

# What those locations HOLD, not merely where they are. The tree walk in
# cache_inputs stops at the repository, so without this the key carries the
# path of a virtualenv and nothing about its contents: `poetry install` could
# add, remove or upgrade every package in it and the cached inventory — the
# one that has no licence for any of them, because it was taken before the
# install — would still be served as current. That is the one kind of stale
# answer a licence gate must never give, because an inventory that lost
# licences passes by seeing less.
#
# Timestamp and entry count, the same cheap witness cache_inputs uses for
# node_modules, applied to the directory a package manager actually fills:
# the target itself, and site-packages under a virtualenv's lib/.
aux_cache_lines() {
  local t p d
  while IFS= read -r t; do
    [[ -n "$t" ]] || continue
    p="${t#*:}"
    if [[ ! -e "$p" ]]; then echo "aux=${t}|absent"; continue; fi
    for d in "$p" "$p"/lib/*/site-packages "$p"/lib/site-packages; do
      [[ -d "$d" ]] || continue
      set -- "$d"/*
      [[ $# == 1 && ! -e "$1" ]] && set --
      echo "aux=${d}|$#"
      ls -ld "$d" 2>/dev/null || :
    done
  done < <(aux_targets_list)
  return 0
}

# What the Cargo registry HOLDS, for the same reason: fill_licence_gaps reads
# crate licences from it during the scan, so they are cached with the scan.
# `cargo fetch` unpacking one more crate adds a directory to its index, which
# moves the entry count and the timestamp, so a crate that was lockfile-only
# in the cached answer is read once it is on disk.
cargo_cache_lines() {
  local d
  [[ -d "$LICENSING_CARGO_REGISTRY_SRC" ]] || { echo "cargo=absent"; return 0; }
  for d in "$LICENSING_CARGO_REGISTRY_SRC"/*; do
    [[ -d "$d" ]] || continue
    set -- "$d"/*
    [[ $# == 1 && ! -e "$1" ]] && set --
    echo "cargo=${d}|$#"
    ls -ld "$d" 2>/dev/null || :
  done
  return 0
}

# The configuration half of every key — everything that changes what a scan
# WOULD find, without looking at the tree at all. syft's version is in here
# because licence detection differs between releases: upgrading syft must
# invalidate every cached scan, or the upgrade would be invisible.
cache_config_lines() {
  echo "script=$(if [[ -n "$SELF_PATH" ]]; then cksum < "$SELF_PATH"; else echo "?"; fi) syft=$(syft_version)"
  echo "target=${LICENSING_SCAN_TARGET}"
  echo "catalogers=${LICENSING_CATALOGERS}|${LICENSING_ADD_CATALOGERS[*]-}"
  echo "syftenv=${LICENSING_SYFT_ENV[*]-}"
  echo "exclude=${LICENSING_EXCLUDE[*]-}"
  echo "nested=${LICENSING_NESTED_ROOTS[*]-}|${LICENSING_NESTED_MANIFESTS[*]-}"
  echo "gitignore=${LICENSING_EXCLUDE_GITIGNORED}|${LICENSING_INCLUDE_GITIGNORED[*]-}"
  echo "isolated=${LICENSING_ISOLATED_MANIFESTS[*]-}"
  echo "nosplit=${LICENSING_SCAN_NOSPLIT[*]-}"
  # The package caches read to fill licence gaps — the configured ones and the
  # ones the preflight found outside the repository — by WHAT THEY HOLD. Those
  # are scanned too, so a different answer there is a different scan.
  aux_cache_lines
  cargo_cache_lines
  return 0
}

# The whole merged inventory, keyed on the entire tree. This is the layer that
# makes `check` followed by `download`, or a second `check` after fixing one
# thing somewhere else, cost nothing at all.
cache_file() {
  [[ "$LICENSING_CACHE" == 1 ]] || return 1
  local k; k="$({ cache_config_lines; cache_inputs "${LICENSING_SCAN_TARGET#dir:}"; } 2>/dev/null | digest)"
  [[ -n "$k" ]] || return 1
  echo "${LICENSING_CACHE_DIR}/scan-${k}.rows"
}

# One worker's rows, keyed on ITS subtree. This is the layer that survives an
# edit: removing a GPL dependency changes the root lockfile and the root
# node_modules, and nothing at all about apps/ or backend/ — so those workers
# hand back what they found last time and only the tree that changed is
# scanned again.
worker_cache_file() { # worker_cache_file <root> <subdir>
  [[ "$LICENSING_CACHE" == 1 ]] || return 1
  local k; k="$({ cache_config_lines; echo "worker=${2}"; cache_inputs "${1}/${2}"; } 2>/dev/null | digest)"
  [[ -n "$k" ]] || return 1
  echo "${LICENSING_CACHE_DIR}/worker-${k}.rows"
}

# The pass over the files in the root itself, plus the directories that are
# deliberately never split off (a cataloger that keys off .github/workflows
# needs the path intact). Everything else is somebody's worker.
root_cache_file() { # root_cache_file <root> <subdir...>
  [[ "$LICENSING_CACHE" == 1 ]] || return 1
  local root="$1"; shift
  local k d
  k="$({ cache_config_lines
         echo "rootpass=$*"
         find "$root" -maxdepth 1 -type f -print 2>/dev/null | LC_ALL=C sort \
           | while IFS= read -r d; do cksum "$d" 2>/dev/null || echo "unreadable ${d}"; done
         for d in ${LICENSING_SCAN_NOSPLIT[@]+"${LICENSING_SCAN_NOSPLIT[@]}"}; do
           [[ -d "${root}/${d}" ]] || continue
           find "${root}/${d}" -type f -print 2>/dev/null | LC_ALL=C sort \
             | while IFS= read -r f; do cksum "$f" 2>/dev/null || echo "unreadable ${f}"; done
         done; } 2>/dev/null | digest)"
  [[ -n "$k" ]] || return 1
  echo "${LICENSING_CACHE_DIR}/root-${k}.rows"
}

# Hand back what is cached, and keep it from ageing out while it is in use.
#
# "empty-ok" is for a WORKER: a top-level directory with no components in it
# has an empty result, that result is correct, and without this it would be the
# one thing the cache could never remember. The whole inventory is held to the
# stricter test on purpose — an empty one passes every gate by seeing nothing,
# and that is not a state to hand back from a cache.
cache_take() { # cache_take <cache file> <destination> [empty-ok]
  if [[ "${3:-}" == empty-ok ]]; then
    [[ -n "$1" && -f "$1" ]] || return 1
  else
    [[ -n "$1" && -s "$1" ]] || return 1
  fi
  cp "$1" "$2" 2>/dev/null || return 1
  touch "$1" 2>/dev/null || :
  return 0
}

cache_put() { # cache_put <source> <cache file>
  [[ "$LICENSING_CACHE" == 1 && -n "$2" ]] || return 0
  mkdir -p "$LICENSING_CACHE_DIR" 2>/dev/null || return 0
  # shellcheck disable=SC2015 # not an if-then-else: the trailing rm is the cleanup for a
  # failure of EITHER the copy or the rename, which is exactly when it should run.
  cp "$1" "${2}.$$" 2>/dev/null && mv "${2}.$$" "$2" 2>/dev/null || rm -f "${2}.$$" 2>/dev/null
  return 0
}

# Age out what nobody has used. A key changes with every lockfile edit, so the
# directory would otherwise grow an entry per dependency bump, forever.
cache_prune() {
  [[ "$LICENSING_CACHE" == 1 && -d "$LICENSING_CACHE_DIR" ]] || return 0
  [[ "${LICENSING_CACHE_MAX_AGE_DAYS:-0}" -gt 0 ]] || return 0
  find "$LICENSING_CACHE_DIR" -type f -name '*.rows' -mtime "+${LICENSING_CACHE_MAX_AGE_DAYS}" \
    -exec rm -f {} + 2>/dev/null || :
  return 0
}

# Line format: type|name|version|comma-separated paths|space-separated licences
# shellcheck disable=SC2120 # "$@" is an extra-syft-argument passthrough. The one caller today
# passes none, which is not the same as the parameter being unused.
scan_now() {
  need_syft

  # The whole inventory, if nothing a scan reads has changed since last time.
  local scancache=""
  if scancache="$(cache_file)" && cache_take "$scancache" "$SCAN"; then
    SCANNED=1
    progress_step
    snote "scan: $(wc -l < "$SCAN" | tr -d ' ') component(s) from cache — nothing a scan reads has changed (--no-cache re-scans)"
    after_scan
    return 0
  fi

  local excludes=(); syft_args excludes

  local tmpl="${TMPDIR_RUN}/tmpl"
  # Licences are ';' separated, not space separated: a Maven POM declares free
  # text like "Apache License, Version 2.0", which spaces would shred into four
  # unrecognisable tokens.
  printf '{{range .artifacts}}{{.type}}|{{.name}}|{{.version}}|{{range .locations}}{{.path}},{{end}}|{{range .licenses}}{{.value}};{{end}}\n{{end}}' > "$tmpl"

  local raw="${TMPDIR_RUN}/raw.txt" t0=$SECONDS q
  q="$(syft_quiet)"
  vnote "excludes: $(( ${#excludes[@]} / 2 )), catalogers: ${LICENSING_CATALOGERS:-defaults + ${LICENSING_ADD_CATALOGERS[*]-}}"
  vnote "syft env: ${LICENSING_SYFT_ENV[*]-none}"
  local jobs; jobs="$(resolve_scan_jobs)"
  local subs=() root="${LICENSING_SCAN_TARGET#dir:}"
  if [[ "$jobs" -gt 1 && "$LICENSING_SCAN_TARGET" == dir:* ]]; then
    while IFS= read -r d; do [[ -n "$d" ]] && subs+=("$d"); done < <(split_subdirs "$root")
  fi

  if [[ ${#subs[@]} -lt 2 ]]; then
    # One scan: syft's own progress is the only sign of life there is.
    if [[ -n "${LICENSING_VERBOSE:-}" ]]; then
      tnote "scanning ${LICENSING_SCAN_TARGET} for components (syft progress below)"
    else
      tnote "scanning ${LICENSING_SCAN_TARGET} for components — minutes on a large tree with dependencies installed; --verbose shows progress"
    fi
    # shellcheck disable=SC2086 # $q is one optional flag, empty when not quiet — quoting it
    # would pass syft an empty argument instead of nothing.
    env ${LICENSING_SYFT_ENV[@]+"${LICENSING_SYFT_ENV[@]}"} \
      "${SYFT[@]}" scan "$LICENSING_SCAN_TARGET" "${excludes[@]}" "$@" -o template -t "$tmpl" $q \
      | awk 'NF' > "$raw"
  else
    # One worker per top-level directory, plus one pass for the files that sit
    # in the root itself, all merged as if a single scan had produced them.
    # A worker's syft prints a progress bar of its own; twenty of them
    # interleaved is noise, so each worker reports once, when it finishes.
    local sub i=0 wdir="${TMPDIR_RUN}/workers"; mkdir -p "$wdir"
    local rootex=() wex total="${#subs[@]}"
    tnote "scanning in parallel: ${total} top-level directories, ${jobs} at a time"
    # Every syft instance is a step of its own — the workers and the root pass
    # — so the bar moves as each one finishes rather than once per batch.
    progress_plan $(( total + 1 ))
    PROGRESS_DONE_FILE="${wdir}/progress"; : > "$PROGRESS_DONE_FILE"
    PROGRESS_BASE="$PROGRESS_DONE"
    local wcache cached=0
    [[ "$LICENSING_CACHE" == 1 ]] && mkdir -p "$LICENSING_CACHE_DIR" 2>/dev/null
    for sub in "${subs[@]}"; do
      rootex+=(--exclude "./${sub}/**" --exclude "./${sub}")
      # A subtree nothing has touched hands back what it found last time. The
      # rows are already re-prefixed, so a cached worker and a live one are
      # indistinguishable downstream.
      wcache="$(worker_cache_file "$root" "$sub" || true)"
      if cache_take "$wcache" "${wdir}/${i}.txt" empty-ok; then
        vnote "worker cached: ${sub} — $(wc -l < "${wdir}/${i}.txt" | tr -d ' ') rows, unchanged since the last scan"
        cached=$((cached + 1))
        progress_worker_done
        i=$((i + 1))
        continue
      fi
      wex=(); while IFS= read -r a; do wex+=("$a"); done < <(worker_excludes "$sub" "${excludes[@]}")
      (
        local wt0=$SECONDS
        if env ${LICENSING_SYFT_ENV[@]+"${LICENSING_SYFT_ENV[@]}"} \
             "${SYFT[@]}" scan "dir:${root}/${sub}" ${wex[@]+"${wex[@]}"} -o template -t "$tmpl" -q \
             2> "${wdir}/${i}.err" \
             | awk 'NF' | reprefix_paths "$sub" > "${wdir}/${i}.txt"; then
          vnote "worker done: ${sub} — $(wc -l < "${wdir}/${i}.txt" | tr -d ' ') rows in $(since $wt0)"
          cache_put "${wdir}/${i}.txt" "$wcache"
          progress_worker_done
        else
          echo "FAILED" > "${wdir}/${i}.failed"
        fi
      ) &
      i=$((i + 1))
      if [[ $(( i % jobs )) -eq 0 ]]; then wait; fi
    done
    local rcache; rcache="$(root_cache_file "$root" "${subs[@]}" || true)"
    if cache_take "$rcache" "${wdir}/root.txt" empty-ok; then
      vnote "worker cached: <root files> — $(wc -l < "${wdir}/root.txt" | tr -d ' ') rows, unchanged since the last scan"
      cached=$((cached + 1))
      progress_worker_done
    else
      (
        local wt0=$SECONDS
        if env ${LICENSING_SYFT_ENV[@]+"${LICENSING_SYFT_ENV[@]}"} \
             "${SYFT[@]}" scan "$LICENSING_SCAN_TARGET" "${excludes[@]}" "${rootex[@]}" \
             -o template -t "$tmpl" -q 2> "${wdir}/root.err" \
             | awk 'NF' > "${wdir}/root.txt"; then
          vnote "worker done: <root files> — $(wc -l < "${wdir}/root.txt" | tr -d ' ') rows in $(since $wt0)"
          cache_put "${wdir}/root.txt" "$rcache"
          progress_worker_done
        else
          echo "FAILED" > "${wdir}/root.failed"
        fi
      ) &
    fi
    wait
    [[ "$cached" -gt 0 ]] && snote "scan: ${cached} of $(( total + 1 )) trees were unchanged and came from cache"

    # A worker that died would silently shrink the inventory, and a smaller
    # inventory passes the gate. Never let that happen quietly.
    #
    # Counted with a glob rather than `ls ... | wc -l`: when no worker failed
    # the glob matches nothing, ls exits non-zero, pipefail hands that to the
    # assignment, and `set -e` killed the run right here — silently, with the
    # scan finished and nothing written. `check` never showed it because
    # gate_deps is called as `gate_deps || rc=1`, which suspends errexit for
    # everything underneath it; `sbom` is not, so they died on every
    # tree big enough to be scanned in parallel.
    local failed=0 wf
    for wf in "${wdir}"/*.failed; do [[ -e "$wf" ]] && failed=$((failed + 1)); done
    if [[ "$failed" -gt 0 ]]; then
      for f in "${wdir}"/*.err; do
        [[ -s "$f" ]] && { echo "--- ${f##*/} ---" >&2; head -5 "$f" >&2; }
      done
      fail "${failed} of $(( total + 1 )) scan workers failed — the component inventory would be incomplete. Re-run with --jobs 1 to scan in one pass."
    fi

    # Adopt what the workers counted, so later phases carry on from there.
    PROGRESS_DONE=$(( PROGRESS_BASE + $(wc -l < "$PROGRESS_DONE_FILE" | tr -d ' ') ))
    PROGRESS_DONE_FILE=""
    cat "${wdir}"/*.txt > "$raw" 2>/dev/null || : > "$raw"
    vnote "parallel scan: $(wc -l < "$raw" | tr -d ' ') rows from $(( total + 1 )) workers"
  fi
  vnote "tree scan: $(wc -l < "$raw" | tr -d ' ') rows in $(since $t0)"

  # Re-scan the configured manifests in isolation and let those licences win.
  local m iso="${TMPDIR_RUN}/iso" over="${TMPDIR_RUN}/over.txt"
  : > "$over"
  for m in ${LICENSING_ISOLATED_MANIFESTS[@]+"${LICENSING_ISOLATED_MANIFESTS[@]}"}; do
    [[ -f "$m" ]] || continue
    rm -rf "$iso"; mkdir -p "$iso"
    cp "$m" "${iso}/$(basename "$m")"
    vnote "re-scanning ${m} in isolation (reference licences)"
    progress_plan 1
    env ${LICENSING_SYFT_ENV[@]+"${LICENSING_SYFT_ENV[@]}"} \
      "${SYFT[@]}" scan "file:${iso}/$(basename "$m")" -o template -t "$tmpl" -q \
      | awk -F'|' -v path="/${m}" 'NF { printf "%s|%s|%s|%s,|%s\n", $1, $2, $3, path, $5 }' >> "$over"
    progress_step
  done

  if [[ -s "$over" ]]; then
    # Drop tree-scan lines for any component the isolated scan re-catalogued,
    # then splice the isolated lines in.
    awk -F'|' 'NR==FNR { key[$1"|"$2"|"$3]=1; next } !($1"|"$2"|"$3 in key)' "$over" "$raw" > "${raw}.keep"
    cat "$over" >> "${raw}.keep"
    mv "${raw}.keep" "$raw"
  fi
  # Fill licence gaps from the out-of-tree package caches, for components this
  # project already has. Never introduces a component: the cache holds every
  # package the machine ever downloaded, not this project's dependencies.
  local aux="${TMPDIR_RUN}/aux.txt" auxone="${TMPDIR_RUN}/aux.one" auxerr="${TMPDIR_RUN}/aux.err" t n auxrc
  : > "$aux"
  local aux_targets=()
  while IFS= read -r t; do [[ -n "$t" ]] && aux_targets+=("$t"); done < <(aux_targets_list)
  for t in ${aux_targets[@]+"${aux_targets[@]}"}; do
    case "$t" in dir:*|file:*) [[ -e "${t#*:}" ]] || { vnote "aux target absent, skipped: $t"; continue; } ;; esac
    tnote "reading ${t#*:} to fill licence gaps for components already found"
    progress_plan 1
    : > "$auxone"; : > "$auxerr"; auxrc=0
    # `|| auxrc=$?` and not a bare pipeline: with `set -e` and pipefail a syft
    # that fails here took the whole run down without a word, and the stderr
    # that would have said why went to /dev/null. A package cache is
    # best-effort by definition — the tree scan already stands on its own — so
    # a failure to read one is a loud warning, never the end of the run.
    env ${LICENSING_SYFT_ENV[@]+"${LICENSING_SYFT_ENV[@]}"} \
      "${SYFT[@]}" scan "$t" -o template -t "$tmpl" -q 2> "$auxerr" | awk 'NF' > "$auxone" || auxrc=$?
    n="$(wc -l < "$auxone" | tr -d ' ')"
    # Nothing read back is not the same as nothing there, and either way every
    # component this location would have identified stays blank — which is the
    # quietest way there is to lose a licence, and the reason it gets said out
    # loud rather than counted.
    if [[ "$auxrc" != 0 || "$n" == 0 ]]; then
      note "warning: reading ${t#*:} produced no components — every licence it would have supplied stays unread, and those components are reported as NOASSERTION"
      [[ -s "$auxerr" ]] && head -3 "$auxerr" >&3
    else
      vnote "aux: ${n} component(s) read from ${t#*:}"
      cat "$auxone" >> "$aux"
    fi
    progress_step
  done
  if [[ -s "$aux" ]]; then
    # Through a temporary file, not straight back into "$raw": awk is reading
    # that file, and appending to a file awk still has open is a race nobody
    # wants to debug the day it loses.
    awk -F'|' 'NR==FNR { seen[$1"|"$2"|"$3]=1; next } ($1"|"$2"|"$3) in seen' "$raw" "$aux" > "${aux}.keep"
    vnote "aux: $(wc -l < "${aux}.keep" | tr -d ' ') row(s) matched a component this project already has"
    cat "${aux}.keep" >> "$raw"
  fi

  # One line per component: union the evidence paths and the licences found at
  # each of them. A lockfile entry carrying no licence must not outvote the
  # installed package that carries one.
  LC_ALL=C sort -u "$raw" | awk -F'|' '
    {
      key = $1 "|" $2 "|" $3
      n = split($4, ps, ",")
      for (i = 1; i <= n; i++)
        if (ps[i] != "" && !((key SUBSEP ps[i]) in seenp)) { seenp[key, ps[i]] = 1; paths[key] = paths[key] ps[i] "," }
      m = split($5, ls, ";")
      for (i = 1; i <= m; i++)
        if (ls[i] != "" && !((key SUBSEP ls[i]) in seenl)) { seenl[key, ls[i]] = 1; lics[key] = lics[key] ls[i] ";" }
      if (!(key in ord)) { ord[key] = ++c; keys[c] = key }
    }
    END { for (i = 1; i <= c; i++) print keys[i] "|" paths[keys[i]] "|" lics[keys[i]] }
  ' > "$SCAN"
  SCANNED=1
  progress_step
  fill_licence_gaps
  # Cached BEFORE the ignore rules run: those are a policy decision about a
  # scan, not part of one, so changing them costs a re-read and never a
  # re-scan.
  cache_put "$SCAN" "$scancache"
  cache_prune
  snote "scan: $(wc -l < "$SCAN" | tr -d ' ') component(s) in $(since $t0)"
  after_scan
}

# What a fresh scan and a cache hit both have to do before either half of this
# script reads $SCAN.
after_scan() {
  prune_scan
  apply_reviewed_licences
  if [[ -n "${LICENSING_VERBOSE:-}" ]]; then
    awk -F'|' '{ n[$1]++ } END { for (t in n) printf "    %-16s %d\n", t, n[t] }' "$SCAN" | LC_ALL=C sort >&2
  fi
  [[ -n "${LICENSING_DEBUG_DIR:-}" ]] && cp "$SCAN" "${LICENSING_DEBUG_DIR}/scan.txt"
  [[ -s "$SCAN" ]] || note "warning: syft found no components in ${LICENSING_SCAN_TARGET}"
  return 0
}

# A licence a person found by reading, for a component the scan read nothing
# for: `<name> = <SPDX expression>  # reason` in the exceptions file.
#
# Applied to the inventory itself, after the scan and before either half reads
# it, so the gate, --obligations, --porcelain, the SBOM and the REUSE.toml
# annotations all see the same answer — rather than a component that is MIT to
# one consumer of the scan and NOASSERTION to the next.
#
# It fills a GAP and nothing else. A component the scan did read a licence for
# keeps the scan's answer, and the disagreement is said out loud: the file
# records what a person found where the tooling found nothing, not a way to
# overrule what the package itself declares. And the licence it fills in is
# gated like any other — normalised, then judged against ALLOW and DENY — so a
# reviewed licence on the deny list still fails.
#
# Applied after the cache, like the ignore rules: it is a policy decision about
# a scan, so editing the file costs a re-read and never a re-scan.
apply_reviewed_licences() {
  [[ -f "$LICENSING_EXCEPTIONS" ]] || return 0
  local reviewed="${TMPDIR_RUN}/reviewed.tsv"
  awk '{ sub(/#.*/, "") }
       (i = index($0, "=")) > 0 {
         name = substr($0, 1, i - 1); lic = substr($0, i + 1)
         gsub(/^[ \t]+|[ \t]+$/, "", name); gsub(/^[ \t]+|[ \t]+$/, "", lic)
         if (name != "" && lic != "") print name "\t" lic
       }' "$LICENSING_EXCEPTIONS" > "$reviewed"
  [[ -s "$reviewed" ]] || return 0

  local reviewed_scan="${TMPDIR_RUN}/scan.reviewed" reviewed_report="${TMPDIR_RUN}/reviewed.report"
  awk -F'|' -v OFS='|' -v report="$reviewed_report" '
    NR == FNR { split($0, r, "\t"); lic[r[1]] = r[2]; next }
    ($2 in lic) {
      if ($5 ~ /^[ \t;]*$/) { $5 = lic[$2] ";"; applied++ }
      else printf "%s\t%s\t%s\n", $2, lic[$2], $5 > report
    }
    { print }
    END { printf "%d\n", applied + 0 > (report ".count") }
  ' "$reviewed" "$SCAN" > "$reviewed_scan" && mv "$reviewed_scan" "$SCAN"

  local applied name want found
  applied="$(cat "${reviewed_report}.count" 2>/dev/null || echo 0)"
  [[ "$applied" -gt 0 ]] && vnote "exceptions: ${applied} component(s) given the licence a reviewer recorded in ${LICENSING_EXCEPTIONS}"
  if [[ -s "$reviewed_report" ]]; then
    while IFS=$'\t' read -r name want found; do
      note "warning: ${LICENSING_EXCEPTIONS} records ${want} for ${name}, but the scan read ${found%;} from the package itself — the scan's answer stands. Drop the licence from that line if the package is right, or tell its authors if it is not."
    done < "$reviewed_report"
  fi
  return 0
}

# True when every evidence path for this component matches an ignore glob. One
# real location keeps it: a package that is genuinely installed somewhere and
# also happens to appear in a fixture is still installed.
ignored_paths_only() { # ignored_paths_only <comma-separated paths>
  local paths_csv="$1" p pat hit
  [[ ${#LICENSING_IGNORE_PATHS[@]} -gt 0 ]] || return 1
  [[ -n "$paths_csv" ]] || return 1
  local plines="${paths_csv//,/$'\n'}"
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    p="${p#/}"
    hit=0
    for pat in "${LICENSING_IGNORE_PATHS[@]}"; do
      # shellcheck disable=SC2053
      [[ "$p" == $pat ]] && { hit=1; break; }
    done
    [[ "$hit" == 1 ]] || return 1
  done <<EOF
${plines}
EOF
  return 0
}

# True when this npm evidence path is where the package manager would have put
# an installed package: one segment after the last vendor root, or two when the
# first is a @scope. Anything deeper is a file the surrounding package ships.
installed_npm_path() { # installed_npm_path <path>
  local p="/${1#/}" root tail dir
  for root in ${LICENSING_NESTED_ROOTS[@]+"${LICENSING_NESTED_ROOTS[@]}"}; do
    case "$p" in */"${root}"/*) ;; *) continue ;; esac
    tail="${p##*/"${root}"/}"
    dir="${tail%/*}"
    [[ "$dir" == "$tail" ]] && return 1          # a loose file, not a package
    case "$dir" in
      @*/*/*) return 1 ;;
      @*/*)   return 0 ;;
      */*)    return 1 ;;
      *)      return 0 ;;
    esac
  done
  return 0                                        # not inside a vendor root
}

# True when EVERY package.json this npm component was catalogued from sits
# somewhere no package manager would have installed one.
vendored_subpath_only() { # vendored_subpath_only <comma-separated paths>
  local paths_csv="$1" p
  [[ -n "$paths_csv" ]] || return 1
  local plines="${paths_csv//,/$'\n'}"
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    installed_npm_path "$p" && return 1
  done <<EOF
${plines}
EOF
  return 0
}

# Take out of the inventory what is not a dependency of this project: the paths
# the policy has decided do not count, and the npm packages that were never
# installed as packages at all. Both are counted out loud, because an inventory
# that quietly got smaller is an inventory that quietly passed.
prune_scan() {
  local type name ver path lics n_ign=0 n_sub=0
  local tmp="${TMPDIR_RUN}/pruned.txt"
  [[ -s "$SCAN" ]] || return 0
  if [[ ${#LICENSING_IGNORE_PATHS[@]} -eq 0 && "$LICENSING_SKIP_VENDORED_SUBPATHS" != 1 ]]; then
    return 0
  fi
  while IFS='|' read -r type name ver path lics; do
    if ignored_paths_only "$path"; then
      n_ign=$((n_ign + 1))
      vnote "ignored by LICENSING_IGNORE_PATHS: ${type} ${name}@${ver}"
      continue
    fi
    if [[ "$LICENSING_SKIP_VENDORED_SUBPATHS" == 1 && "$type" == npm ]] && vendored_subpath_only "$path"; then
      n_sub=$((n_sub + 1))
      vnote "not an installed package, part of the one that ships it: ${name}@${ver} (${path%%,*})"
      continue
    fi
    printf '%s|%s|%s|%s|%s\n' "$type" "$name" "$ver" "$path" "$lics"
  done < "$SCAN" > "$tmp"
  mv "$tmp" "$SCAN"
  [[ "$n_ign" -gt 0 ]] && snote "scan: ${n_ign} component(s) ignored by LICENSING_IGNORE_PATHS"
  [[ "$n_sub" -gt 0 ]] && snote "scan: ${n_sub} npm component(s) dropped — a fixture, template or bundled copy inside another package, never installed as a dependency (LICENSING_SKIP_VENDORED_SUBPATHS=0 gates them; --verbose lists them)"
  return 0
}

# Files that hold a licence TEXT, looked for beside a component's evidence
# when its metadata will not say what the licence is. GLOBS, in order of
# preference, and the sub-directories a wheel puts them in: the shell expands
# a glob itself, where a list of twelve names meant thirty-six stat calls per
# component and this runs for every component whose metadata said nothing.
# Arrays with the globs quoted, for the same reason as
# LICENSING_FOREIGN_MANIFESTS above: unquoted in a `for`, "LICENSE.*" is
# expanded against the working directory before it is ever used as a pattern.
LICENSING_LICENCE_FILE_GLOBS=(LICENSE LICENCE COPYING "LICENSE.*" "LICENCE.*"
                              "COPYING.*" "LICEN[SC]E-*")
LICENSING_LICENCE_FILE_DIRS=(. licenses license_files)

# Which licence a text IS, from the phrases that only that licence contains.
# The package is installed, so its LICENSE file is right there — and a licence
# text is a far better witness than a metadata field somebody forgot to fill
# in. Only the first 400 lines are read: every phrase below appears in the
# opening of its licence, and a GPL text runs to 700.
#
# Fingerprints, not full-text comparison. It answers "which licence is this"
# for the ones people actually ship, and stays silent otherwise — a wrong id
# here would be worse than no id, because no id fails review and a wrong one
# does not.
licence_from_text() { # licence_from_text <file>
  [[ -f "$1" ]] || return 0
  # One process, not two: the line limit lives in the awk rather than in a
  # head(1) in front of it.
  awk 'FNR > 400 { exit }
    { l = tolower($0); t = t " " l
      if (l ~ /neither the name/) neither = 1
      if (l ~ /all advertising materials/) advert = 1
      if (l ~ /or \(at your option\) any later version/) later = 1
      if (l ~ /copyright notice/) notice = 1
    }
    END {
      gsub(/[ \t]+/, " ", t)
      if (t ~ /gnu affero general public license/) { print later ? "AGPL-3.0-or-later" : "AGPL-3.0-only"; exit }
      if (t ~ /gnu lesser general public license/) {
        if (t ~ /version 3/) { print later ? "LGPL-3.0-or-later" : "LGPL-3.0-only"; exit }
        print later ? "LGPL-2.1-or-later" : "LGPL-2.1-only"; exit
      }
      if (t ~ /gnu general public license/) {
        if (t ~ /version 3/) { print later ? "GPL-3.0-or-later" : "GPL-3.0-only"; exit }
        print later ? "GPL-2.0-or-later" : "GPL-2.0-only"; exit
      }
      if (t ~ /apache license/ && t ~ /version 2\.0/) { print "Apache-2.0"; exit }
      if (t ~ /mozilla public license/) {
        if (t ~ /version 1\.1/) { print "MPL-1.1"; exit }
        if (t ~ /version 2\.0/) { print "MPL-2.0"; exit }
      }
      if (t ~ /eclipse public license/ && t ~ /v ?2\.0/) { print "EPL-2.0"; exit }
      if (t ~ /eclipse public license/ && t ~ /v ?1\.0/) { print "EPL-1.0"; exit }
      if (t ~ /common development and distribution license/) { print (t ~ /1\.1/) ? "CDDL-1.1" : "CDDL-1.0"; exit }
      if (t ~ /boost software license/) { print "BSL-1.0"; exit }
      if (t ~ /python software foundation license/) { print "PSF-2.0"; exit }
      if (t ~ /cc0 1\.0 universal/) { print "CC0-1.0"; exit }
      if (t ~ /open government licence/ && t ~ /version 3|v3\.0/) { print "OGL-UK-3.0"; exit }
      if (t ~ /this is free and unencumbered software released into the public domain/) { print "Unlicense"; exit }
      if (t ~ /do what the fuck you want to public license/) { print "WTFPL"; exit }
      if (t ~ /altered source versions must be plainly marked as such/) { print "Zlib"; exit }
      if (t ~ /permission is hereby granted, free of charge, to any person obtaining a copy/) { print "MIT"; exit }
      if (t ~ /permission to use, copy, modify, and\/or distribute this software/) { print notice ? "ISC" : "0BSD"; exit }
      if (t ~ /redistribution and use in source and binary forms/) {
        if (advert) { print "BSD-4-Clause"; exit }
        print neither ? "BSD-3-Clause" : "BSD-2-Clause"; exit
      }
    }
  ' "$1"
}

# The licence file that belongs to a component, from its own evidence. Only
# the directory the evidence sits in is searched, plus the sub-directories a
# wheel puts licence files in — walking up would find the NEXT package's
# LICENSE and attribute it to this one. A Python RECORD is read as an index:
# it lists the licence file wherever the wheel put it, relative to the
# directory the .dist-info itself is in.
# owner/repo out of whatever shape the workflow wrote the action in:
# "actions/checkout@v4", "https://github.com/jdx/mise-action@v2" (some
# workflow systems name the host), "github/codeql-action/analyze@v2" (an action in a
# sub-directory — the licence belongs to the repository, not the folder).
github_action_repo() { # github_action_repo <component name> -> owner/repo
  local n="$1" owner rest repo
  n="${n#http://}"; n="${n#https://}"; n="${n#github.com/}"
  n="${n%%@*}"
  [[ "$n" == */* ]] || return 1
  owner="${n%%/*}"; rest="${n#*/}"; repo="${rest%%/*}"
  # A local action ("./.github/actions/build") belongs to this repository and
  # carries this repository's licence, which is not a dependency licence.
  case "$owner" in ""|.|..) return 1 ;; esac
  [[ -n "$repo" ]] || return 1
  printf '%s/%s\n' "$owner" "$repo"
}

# The SPDX id GitHub reports for a repository, or nothing. Never fatal: this is
# one more place to look, and a network that is not there just means the
# component stays unlicensed, exactly as it was before the call was tried.
github_licence() { # github_licence <owner/repo>
  local slug="$1" cf id tok auth=()
  [[ "$LICENSING_GITHUB_LICENCES" == 1 ]] || return 1
  cf="${LICENSING_CACHE_DIR}/gh-${slug//\//_}.lic"
  if [[ -f "$cf" ]]; then
    id="$(cat "$cf" 2>/dev/null || true)"
    [[ -n "$id" ]] || return 1          # a cached "no licence" is an answer too
    echo "$id"; return 0
  fi
  have curl || return 1
  tok="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
  [[ -n "$tok" ]] && auth=(-H "Authorization: Bearer ${tok}")
  id="$(curl -fsS --max-time 10 ${auth[@]+"${auth[@]}"} \
          -H 'Accept: application/vnd.github+json' \
          "${LICENSING_GITHUB_API}/repos/${slug}/license" 2>/dev/null \
        | tr ',' '\n' | sed -n 's/.*"spdx_id"[ ]*:[ ]*"\([^"]*\)".*/\1/p' | head -1)" || id=""
  case "$id" in NOASSERTION|null) id="" ;; esac
  mkdir -p "$LICENSING_CACHE_DIR" 2>/dev/null || :
  printf '%s' "$id" > "$cf" 2>/dev/null || :
  [[ -n "$id" ]] || return 1
  echo "$id"
}

# True when this file name names other packages rather than itself — see
# LICENSING_FOREIGN_MANIFESTS.
foreign_manifest() { # foreign_manifest <file name>
  local b="$1" pat
  for pat in ${LICENSING_FOREIGN_MANIFESTS[@]+"${LICENSING_FOREIGN_MANIFESTS[@]}"}; do
    # shellcheck disable=SC2053
    [[ "$b" == $pat ]] && return 0
  done
  return 1
}

licence_file_for() { # licence_file_for <comma-separated evidence paths>
  local paths_csv="$1" p d sub g rel cand lines
  LICFILE_OUT=""
  # One path per line rather than an IFS split: a path may contain a space,
  # and `IFS=` scoped to the read leaves the caller's IFS alone. The split has
  # to happen HERE — inside a here-document $'\n' is four literal characters.
  lines="${paths_csv//,/$'\n'}"
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    # A LICENSE beside a lockfile is the lockfile author's, not the listed
    # package's. Skip the path rather than the component: the same component
    # may also have been catalogued from its own installed copy, and that copy
    # is exactly the evidence this is looking for.
    foreign_manifest "${p##*/}" && continue
    d=".${p%/*}"
    case "${p##*/}" in
      RECORD)
        rel="$(awk -F, 'tolower($1) ~ /(^|\/)(license|licence|copying)[^\/]*$/ { print $1; exit }' ".${p}" 2>/dev/null)"
        if [[ -n "$rel" ]]; then
          cand="${d%/*}/${rel}"
          [[ -f "$cand" ]] && { LICFILE_OUT="$cand"; return 0; }
        fi
        ;;
    esac
    for sub in ${LICENSING_LICENCE_FILE_DIRS[@]+"${LICENSING_LICENCE_FILE_DIRS[@]}"}; do
      # A wheel's licences/ sub-directory usually is not there; testing once
      # beats expanding seven globs into it.
      [[ "$sub" == "." || -d "${d}/${sub}" ]] || continue
      for g in ${LICENSING_LICENCE_FILE_GLOBS[@]+"${LICENSING_LICENCE_FILE_GLOBS[@]}"}; do
        # Unquoted on purpose: the shell globs it. An unmatched glob stays
        # literal, and -f says no to that.
        for cand in "${d}/${sub}"/$g; do
          [[ -f "$cand" ]] && { LICFILE_OUT="$cand"; return 0; }
        done
      done
    done
  done <<EOF
${lines}
EOF
  return 1
}

# Where cargo unpacked a crate: sets CARGO_DIR and returns 0, or returns 1
# when this machine never unpacked it. A glob test, not a fork.
CARGO_DIR=""
cargo_crate_dir() { # cargo_crate_dir <name> <version>
  local d
  CARGO_DIR=""
  for d in "${LICENSING_CARGO_REGISTRY_SRC}"/*/"${1}-${2}"; do
    [[ -f "${d}/Cargo.toml" ]] && { CARGO_DIR="$d"; return 0; }
  done
  return 1
}

# Every unpacked crate's `license = "<SPDX expression>"` in ONE awk, merged into
# $SCAN in one more. Per crate that was a $( ) and an awk each, and forks are
# what macOS is slow at: 650 crates cost 7 s. The [package] table is the only
# one that counts — a dependency table can carry keys of its own. Crates that
# name a `license-file` or ship only a licence text are left blank here and
# read one at a time by cargo_dir_licence, which is rare enough to afford it.
# Sets CARGO_BATCH_COUNT.
CARGO_BATCH_COUNT=0
cargo_licences_batch() {
  local list="${TMPDIR_RUN}/cargo.list" map="${TMPDIR_RUN}/cargo.map" got="${TMPDIR_RUN}/cargo.got"
  local tmp="${TMPDIR_RUN}/cargo.scan" type name ver path lics line
  CARGO_BATCH_COUNT=0
  : > "$list"
  while IFS='|' read -r type name ver path lics; do
    [[ "$type" == rust-crate && -z "${lics//[[:space:];]/}" ]] || continue
    cargo_crate_dir "$name" "$ver" && printf '%s/Cargo.toml\0' "$CARGO_DIR" >> "$list"
  done < "$SCAN"
  [[ -s "$list" ]] || return 0
  # xargs, so a monorepo's worth of paths never exceeds the argument limit;
  # each line of the map names its file, so a split run changes nothing.
  # shellcheck disable=SC2016 # an awk program, not a shell string
  xargs -0 awk '
    FNR == 1 { pkg = 0; done = 0; d = FILENAME; sub(/\/Cargo\.toml$/, "", d); n = split(d, s, "/"); key = s[n] }
    done { next }
    /^[ \t]*\[/ { pkg = ($0 ~ /^[ \t]*\[package\][ \t]*$/); next }
    pkg && /^[ \t]*license[ \t]*=/ {
      v = $0; sub(/^[^=]*=[ \t]*"/, "", v); sub(/".*$/, "", v)
      if (v != "") print key "\t" v
      done = 1
    }
  ' < "$list" > "$map"
  [[ -s "$map" ]] || return 0
  awk -F'|' -v OFS='|' -v got="$got" '
    FILENAME == ARGV[1] { i = index($0, "\t"); k = substr($0, 1, i - 1); if (!(k in lic)) lic[k] = substr($0, i + 1); next }
    $1 == "rust-crate" && $5 ~ /^[ \t;]*$/ && (($2 "-" $3) in lic) {
      $5 = lic[$2 "-" $3] ";"
      print $2 "@" $3 " -> " lic[$2 "-" $3] > got
    }
    { print }
  ' "$map" "$SCAN" > "$tmp" && mv "$tmp" "$SCAN"
  [[ -s "$got" ]] || return 0
  while IFS= read -r line; do
    CARGO_BATCH_COUNT=$((CARGO_BATCH_COUNT + 1))
    vnote "licence read from the unpacked crate: rust-crate ${line}"
  done < "$got"
  return 0
}

# The licence of one unpacked crate that declares no `license`: the file its
# `license-file` names, or else the licence text it ships, read as text.
cargo_dir_licence() { # cargo_dir_licence <crate dir>
  local d="$1" file g cand
  file="$(awk '
    /^[ \t]*\[/ { pkg = ($0 ~ /^[ \t]*\[package\][ \t]*$/); next }
    pkg && /^[ \t]*license-file[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*"/, "", v); sub(/".*$/, "", v); print v; exit }
  ' "${d}/Cargo.toml")"
  if [[ -n "$file" ]]; then licence_from_text "${d}/${file}"; return 0; fi
  for g in ${LICENSING_LICENCE_FILE_GLOBS[@]+"${LICENSING_LICENCE_FILE_GLOBS[@]}"}; do
    # Unquoted on purpose: the shell globs it, as in licence_file_for.
    for cand in "${d}"/$g; do
      [[ -f "$cand" ]] && { licence_from_text "$cand"; return 0; }
    done
  done
  return 0
}

# syft reports no licence for a Python package that declares one only in a PEP
# 639 License-Expression or in a trove classifier — fastapi, colorama and
# exceptiongroup all do. The METADATA file is right there in the evidence, so
# read it: License-Expression first, then License:, then the classifiers.
#
# EVERY classifier, joined with OR. A package under two licences has two of
# them and a License: field that cannot hold both — python-dateutil writes
# "Dual License" there and classifies itself Apache-2.0 and BSD — so taking
# the last classifier alone throws away half the answer, and taking the
# License: text alone throws away all of it.
python_metadata_licence() { # python_metadata_licence <METADATA path>
  [[ -f "$1" ]] || return 0
  awk -v placeholders="|${LICENSING_PLACEHOLDER_LICENCES}|" '
    function is_placeholder(v,   t) {
      t = tolower(v)
      gsub(/^[ \t]+|[ \t]+$/, "", t)
      if (t == "") return 1
      if (length(t) > 60) return 1          # the licence TEXT, pasted into the field
      return index(placeholders, "|" t "|") > 0
    }
    /^License-Expression:/ { sub(/^License-Expression:[ \t]*/, ""); if ($0 != "") { print; exit } }
    /^License:/ { sub(/^License:[ \t]*/, ""); if (lic == "") lic = $0 }
    /^Classifier: License :: OSI Approved :: / {
      sub(/^Classifier: License :: OSI Approved :: /, "")
      if ($0 != "" && !($0 in seen)) { seen[$0] = 1; cls[++nc] = $0 }
    }
    /^Classifier: License :: / {
      if ($0 !~ /OSI Approved/) { sub(/^Classifier: License :: /, ""); if (other == "") other = $0 }
    }
    END {
      expr = ""
      for (i = 1; i <= nc; i++) expr = expr (expr == "" ? "" : " OR ") cls[i]
      usable = (lic != "" && !is_placeholder(lic))
      # A License: field that already spells out a choice beats the
      # classifiers; a single-token one loses to two classifiers, because one
      # token cannot say "either of these".
      if (usable && (nc < 2 || lic ~ / OR | AND | or |\/|,/)) { print lic; exit }
      if (expr != "") { print expr; exit }
      if (usable) { print lic; exit }
      if (other != "") { print other }
    }
  ' "$1" 2>/dev/null
}

# npm's own convention for a licence that has no SPDX id: "SEE LICENSE IN
# <file>", where the file sits in the package. It names the file outright, so
# this is the one case where the right file needs no guessing — and a file
# called MY-LICENSE.md or FEEL-FREE.md matches none of the LICENSE globs above,
# which is exactly why it gets its own step.
#
# Resolved LEAF BY LEAF, not value by value: "MIT OR SEE LICENSE IN
# FEEL-FREE.md" is a choice with one nameable side and one unnameable one, and
# only the second half has anything to do with a file.
#
# What the text identifies as wins. A bespoke text that identifies as nothing
# still gets a NAME — LicenseRef-<file> — because the file IS the licence, and
# "SEE LICENSE IN FEEL-FREE.md" is not something a policy can be written
# against while "LicenseRef-FEEL-FREE" is. Only a file that is not there is
# left as prose: there is nothing to point a LicenseRef at.
see_leaf_file() { # see_leaf_file <file name> <comma-separated paths>
  local name="$1" p cand
  local plines="${2//,/$'\n'}"
  LICFILE_OUT=""
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    cand=".${p%/*}/${name}"
    [[ -f "$cand" ]] && { LICFILE_OUT="$cand"; return 0; }
  done <<EOF
${plines}
EOF
  return 1
}

# <file name> -> LicenseRef-<something a policy can name>.
licenseref_for_file() { # licenseref_for_file <file name>
  local stem="${1##*/}"
  stem="${stem%.*}"
  stem="${stem//[!A-Za-z0-9.-]/-}"
  while [[ "$stem" == *--* ]]; do stem="${stem//--/-}"; done
  stem="${stem#-}"; stem="${stem%-}"
  [[ -z "$stem" ]] && stem="custom"
  echo "LicenseRef-${stem}"
}

# One expression with its "SEE LICENSE IN <file>" leaves replaced. Recursive
# over the operators for the same reason normalize_expr is: a leaf is what a
# file name belongs to, and the operators are not part of it.
resolve_see_expr() { # resolve_see_expr <expression> <comma-separated paths>
  local e="$1" op part rest joined="" name id
  for op in " OR " " AND "; do
    if [[ "$e" == *"$op"* ]]; then
      rest="$e"
      while [[ -n "$rest" ]]; do
        if [[ "$rest" == *"$op"* ]]; then part="${rest%%"$op"*}"; rest="${rest#*"$op"}"
        else part="$rest"; rest=""; fi
        joined="${joined:+${joined}${op}}$(resolve_see_expr "$part" "$2")"
      done
      echo "$joined"; return
    fi
  done
  if [[ "$e" =~ ^[[:space:]]*SEE[[:space:]]+LICEN[SC]E[[:space:]]+IN[[:space:]]+(.+)$ ]]; then
    name="${BASH_REMATCH[1]}"
    name="${name%"${name##*[![:space:]]}"}"
    if [[ -n "$name" ]] && see_leaf_file "$name" "$2"; then
      id="$(licence_from_text "$LICFILE_OUT")"
      [[ -z "$id" ]] && id="$(licenseref_for_file "$name")"
      echo "$id"; return
    fi
  fi
  echo "$e"
}

# The whole ;-separated list, with every such leaf resolved. Returns 1 and
# nothing at all when there was none, so the caller can skip the work.
resolve_see_licences() { # resolve_see_licences <;-separated licences> <paths>
  local lics="$1" one acc="" had=0 hit=1
  shopt -q nocasematch && had=1
  shopt -s nocasematch
  if [[ "$lics" == *"see licen"*" in "* ]]; then
    local llines="${lics//;/$'\n'}"
    while IFS= read -r one; do
      [[ -z "$one" ]] && continue
      acc="${acc}$(resolve_see_expr "$one" "$2");"
    done <<EOF
${llines}
EOF
    hit=0
  fi
  [[ "$had" == 0 ]] && shopt -u nocasematch
  [[ "$hit" == 0 ]] && echo "$acc"
  return "$hit"
}

# The full CHOICE a Python package declares, when syft reported one side of it.
#
# syft reads a single licence out of a dist-info, and a package that offers a
# choice declares it as several trove classifiers: pyphen is "GPL-2.0-or-later
# OR LGPL-2.1-or-later OR MPL-1.1", and syft answers with one of the three.
# Which one decides whether a package you may take under the MPL comes back
# deny-listed as GPL — a build stopped over a licence nobody is forcing on you.
#
# Deliberately one-directional and deliberately narrow: it only ever WIDENS,
# and only when the metadata names more licences than syft did AND every
# licence syft named is among them. Anything else means the two are talking
# about different things, and the narrower reading stays.
python_choice_widen() { # python_choice_widen <;-separated licences> <paths>
  local lics="$1" p meta expr one norm ok bases
  local plines="${2//,/$'\n'}" llines="${1//;/$'\n'}"
  while IFS= read -r p; do
    case "$p" in */METADATA) ;; *) continue ;; esac
    [[ -f ".${p}" ]] || continue
    meta="$(python_metadata_licence ".${p}")"
    case "$meta" in *" OR "*) ;; *) continue ;; esac
    expr="$(normalize_expr "$meta")"
    case "$expr" in *" OR "*) ;; *) continue ;; esac
    # The licences the metadata names, with the "or later" tail taken off:
    # syft answers with a deprecated bare id ("GPL-2.0") where the classifier
    # says "v2 or later", and those are the same licence with one of the two
    # being vaguer about the tail. The metadata is the precise one, which is
    # the whole reason for preferring it.
    bases=" "
    for one in ${expr//[()]/ }; do
      case "$one" in OR|AND|"") continue ;; esac
      one="${one%-only}"; one="${one%-or-later}"
      bases="${bases}${one} "
    done
    ok=1
    while IFS= read -r one; do
      [[ -z "$one" || "$one" == sha256:* ]] && continue
      norm="$(normalize_lic "$one")"
      norm="${norm%-only}"; norm="${norm%-or-later}"
      in_list "$norm" "$bases" || { ok=0; break; }
    done <<INNER
${llines}
INNER
    [[ "$ok" == 1 ]] && { echo "$expr"; return 0; }
  done <<EOF
${plines}
EOF
  return 1
}

# True when the licences syft found for a component say nothing USABLE: none at
# all, nothing but placeholders, or nothing but free text that names no licence
# this tool can recognise. What is on disk is then the better witness, and it is
# right there in the evidence paths.
#
# The free-text half is what tells "Mozilla Public License" (which version?)
# apart from "MPL-2.0", and it is why a package that declares its licence in
# prose still ends up with an id: nobody ships the wrong LICENSE file.
needs_fill() { # needs_fill <;-separated licences>
  local lics="$1" one
  [[ -z "${lics//[[:space:];]/}" ]] && return 0
  # A function-local IFS, restored by bash on return — the caller's may be
  # unset at this point, and reading an unset IFS is fatal under `set -u`.
  local IFS=';'
  for one in $lics; do
    [[ -z "$one" || "$one" == sha256:* ]] && continue
    placeholder_lic "$one" && continue
    unmappable_lic "$one" && continue
    return 1
  done
  return 0
}

# Fill empty (or placeholder-only) licence fields from what the installed
# package says about itself: Python dist-info metadata first, then the licence
# TEXT the package ships. A LICENSE file is the most reliable evidence there
# is — nobody ships the wrong one — and it is the only evidence at all for the
# many packages whose metadata licence field was left blank.
fill_licence_gaps() {
  local tmp="${TMPDIR_RUN}/filled.txt" type name ver path lics p found lfile plines seen_new
  local n_meta=0 n_text=0 n_named=0 n_wide=0 n_gh=0 n_cargo=0 slug n_todo t0=$SECONDS
  : > "$tmp"
  # Say so before starting. This pass reads files for every component syft
  # left blank, and on a monorepo that is thousands of them: without a line
  # here the run looks like it stopped.
  cargo_licences_batch
  n_cargo=$CARGO_BATCH_COUNT
  n_todo="$(awk -F'|' '$5 ~ /^[ \t;]*$/ { n++ } END { print n + 0 }' "$SCAN")"
  [[ "$n_todo" -gt 200 ]] && tnote "reading licence metadata and LICENSE files for ${n_todo} component(s) syft left blank"
  while IFS='|' read -r type name ver path lics; do
    # "SEE LICENSE IN <file>" names the file, so no glob has to find it — and
    # this runs whatever else the component declared, because the leaf is
    # unnameable even when the leaf beside it is not.
    # The same test resolve_see_licences starts with, made here first: almost
    # no component says "SEE LICENSE IN", and the $( ) was a fork for each one.
    if [[ "$lics" == *[Ss][Ee][Ee]" "[Ll][Ii][Cc][Ee][Nn]*" "[Ii][Nn]" "* ]] \
       && seen_new="$(resolve_see_licences "$lics" "$path")" && [[ "$seen_new" != "$lics" ]]; then
      n_named=$((n_named+1))
      vnote "licence read from the file the package named: ${type} ${name}@${ver} -> ${seen_new%;} (was ${lics%;})"
      lics="$seen_new"
    fi
    if needs_fill "$lics"; then
      found=""
      if [[ "$type" == python ]]; then
        plines="${path//,/$'\n'}"
        while IFS= read -r p; do
          case "$p" in
            */METADATA)
              found="$(python_metadata_licence ".${p}")"
              # Free text in the metadata is no better than free text from
              # syft: fall through to the licence TEXT, which names itself.
              [[ -n "$found" ]] && ! placeholder_lic "$found" && ! unmappable_lic "$found" && break
              found=""
              ;;
          esac
        done <<EOF
${plines}
EOF
        [[ -n "$found" ]] && n_meta=$((n_meta+1))
      fi
      # A crate's licence is in its Cargo.toml, which syft never reads; the
      # Cargo.lock it catalogued the crate from holds none.
      if [[ -z "$found" && "$type" == rust-crate ]] && cargo_crate_dir "$name" "$ver"; then
        found="$(cargo_dir_licence "$CARGO_DIR")"
        if [[ -n "$found" ]]; then
          n_cargo=$((n_cargo+1))
          vnote "licence read from the unpacked crate: ${type} ${name}@${ver} -> ${found}"
        fi
      fi
      if [[ -z "$found" ]]; then
        # Sets LICFILE_OUT rather than printing: $( ) is a fork, and this runs
        # once per blank component.
        licence_file_for "$path" || :
        lfile="$LICFILE_OUT"
        if [[ -n "$lfile" ]]; then
          found="$(licence_from_text "$lfile")"
          if [[ -n "$found" ]]; then
            n_text=$((n_text+1))
            vnote "licence read from text: ${type} ${name}@${ver} -> ${found} (${lfile#./})"
          fi
        fi
      fi
      # A GitHub Action has no manifest, no lockfile and no installed copy —
      # the workflow names a repository, and the repository is the only thing
      # that knows. Last, because it is the only fallback that leaves the
      # machine.
      if [[ -z "$found" && "$LICENSING_GITHUB_LICENCES" == 1 ]] \
         && in_list "$type" " github-action github-action-workflow "; then
        slug="$(github_action_repo "$name" || true)"
        if [[ -n "$slug" ]]; then
          found="$(github_licence "$slug" || true)"
          if [[ -n "$found" ]]; then
            n_gh=$((n_gh+1))
            vnote "licence read from the GitHub API: ${type} ${name} -> ${found} (${slug})"
          fi
        fi
      fi
      [[ -n "$found" ]] && lics="$(normalize_expr "$found");"
    elif [[ "$type" == python && "$lics" != *" OR "* && "$path" == */METADATA* ]]; then
      # syft named one licence where the package offers a choice of several.
      if found="$(python_choice_widen "$lics" "$path")"; then
        n_wide=$((n_wide+1))
        vnote "licence widened from the trove classifiers: ${type} ${name}@${ver} -> ${found} (syft read ${lics%;})"
        lics="${found};"
      fi
    fi
    printf '%s|%s|%s|%s|%s\n' "$type" "$name" "$ver" "$path" "$lics"
  done < "$SCAN" > "$tmp"
  mv "$tmp" "$SCAN"
  [[ $n_meta -gt 0 ]] && vnote "python: ${n_meta} licence(s) read from dist-info metadata syft left empty"
  [[ $n_named -gt 0 ]] && vnote "see-license-in: ${n_named} licence(s) identified from the file the package named"
  [[ $n_text -gt 0 ]] && vnote "licence text: ${n_text} licence(s) identified from a LICENSE file the package ships"
  [[ $n_gh -gt 0 ]] && vnote "github: ${n_gh} action licence(s) read from the GitHub API (cached in ${LICENSING_CACHE_DIR})"
  [[ $n_cargo -gt 0 ]] && vnote "cargo: ${n_cargo} crate licence(s) read from ${LICENSING_CARGO_REGISTRY_SRC}"
  [[ $n_wide -gt 0 ]] && note "deps: ${n_wide} Python component(s) declare a CHOICE of licences that syft reported as one — read from the trove classifiers instead (--verbose names them)"
  [[ "$n_todo" -gt 200 ]] && snote "licence gaps: ${n_meta} from metadata, ${n_cargo} from Cargo.toml, $(( n_named + n_text )) from a licence text, in $(since $t0)"
  return 0
}

# shellcheck disable=SC2119 # scan_now takes optional extra syft arguments; none here.
ensure_scan() { [[ "$SCANNED" == 1 ]] || { install_preflight; scan_now; }; }

# %GOMODCACHE% -> the real module cache; anything else stays as written.
resolve_install_path() {
  local p="$1" base="$2" gmc pv
  case "$p" in *%GOMODCACHE%*)
      gmc="$(have go && go env GOMODCACHE 2>/dev/null)"
      [[ -z "$gmc" ]] && { echo ""; return; }
      echo "$gmc"; return ;;
    *%PUBCACHE%*)
      [[ -d "${HOME}/.pub-cache/hosted" ]] && { echo "${HOME}/.pub-cache/hosted"; return; }
      echo ""; return ;;
    *%POETRYENV%*)
      pv="$(have poetry && (cd "$base" && poetry env info --path 2>/dev/null))"
      [[ -z "$pv" ]] && { echo ""; return; }
      echo "$pv"; return ;;
  esac
  case "$p" in /*) echo "$p" ;; *) echo "${base%/}/${p}" ;; esac
}

# Does at least one of a manifest's package locations exist and hold anything?
# A location is a directory (node_modules, .venv) or a file (gradle.lockfile):
# for Gradle, a lockfile IS the installed state as far as a scanner is
# concerned — without one, syft sees no Gradle dependency at all.
# Paths are colon-separated and relative to the manifest's own directory, so a
# workspace is judged by its own node_modules and not the repository root's.
any_populated() { # any_populated <manifest dir> <colon-separated paths>
  local base="$1" paths_csv="$2" p full
  local IFS=':'
  for p in $paths_csv; do
    [[ -z "$p" ]] && continue
    if [[ "$p" == %CARGOCRATES% ]]; then
      cargo_crates_unpacked "$base" && return 0
      continue
    fi
    full="$(resolve_install_path "$p" "$base")"
    [[ -z "$full" ]] && continue
    case "$full" in
      *"*"*) [[ -n "$(find "${full%%\**}" -path "$full" -print 2>/dev/null | head -1)" ]] && return 0 ;;
      *)     [[ -d "$full" && -n "$(ls -A "$full" 2>/dev/null)" ]] && return 0
             [[ -s "$full" ]] && return 0 ;;
    esac
  done
  return 1
}

# Is every registry crate a Cargo.lock names unpacked in the Cargo registry?
# Git and path dependencies are not registry crates and are not looked for.
cargo_crates_unpacked() { # cargo_crates_unpacked <manifest dir>
  local lock="${1%/}/Cargo.lock" name ver
  [[ -f "$lock" ]] || return 1
  while IFS=' ' read -r name ver; do
    [[ -n "$name" ]] || continue
    compgen -G "${LICENSING_CARGO_REGISTRY_SRC}/*/${name}-${ver}" >/dev/null || return 1
  done < <(awk '
    /^\[\[package\]\]/ { if (n != "" && reg) print n, v; n = v = ""; reg = 0; next }
    /^name = /    { n = $3; gsub(/"/, "", n) }
    /^version = / { v = $3; gsub(/"/, "", v) }
    /^source = "registry\+/ { reg = 1 }
    END { if (n != "" && reg) print n, v }
  ' "$lock")
  return 0
}

# Human-readable list of the package directories that were looked at.
display_paths() { # display_paths <manifest dir> <colon-separated paths>
  local base="$1" paths_csv="$2" p full acc=""
  local IFS=':'
  for p in $paths_csv; do
    [[ -z "$p" ]] && continue
    if [[ "$p" == %CARGOCRATES% ]]; then
      acc="${acc:+$acc, }${LICENSING_CARGO_REGISTRY_SRC} (some crates of Cargo.lock are not there)"
      continue
    fi
    full="$(resolve_install_path "$p" "$base")"
    if [[ -z "$full" ]]; then
      case "$p" in *%GOMODCACHE%*)  full="the Go module cache" ;;
                   *%PUBCACHE%*)    full="the pub cache (~/.pub-cache)" ;;
                   *%POETRYENV%*)   full="poetry's virtualenv" ;;
                   *)               full="$p" ;; esac
    fi
    acc="${acc:+$acc, }${full#./}"
  done
  echo "$acc"
}

# The tool a command actually runs, skipping leading NAME=value assignments
# (some installers need one to put the virtualenv inside the project).
cmd_tool() {
  local rest="$1" w
  while :; do
    w="${rest%% *}"
    case "$w" in
      *=*) [[ "$rest" == *" "* ]] || { echo ""; return; }; rest="${rest#* }" ;;
      *)   echo "$w"; return ;;
    esac
  done
}

# Choose among ` || `-separated alternatives: the first whose leading tool is
# available (mise first, then PATH). Prints the chosen command with %MANIFEST%
# expanded, or nothing when no alternative can run.
pick_install_cmd() { # pick_install_cmd <dir> <alternatives> <manifest name>
  local dir="$1" alts="$2" manifest="$3" one rest tool
  [[ -z "$alts" ]] && { echo ""; return; }
  rest="$alts"
  while [[ -n "$rest" ]]; do
    if [[ "$rest" == *" || "* ]]; then one="${rest%% || *}"; rest="${rest#* || }"
    else one="$rest"; rest=""; fi
    tool="$(cmd_tool "$one")"
    [[ -z "$tool" ]] && continue
    resolve_tool "$tool" "$dir" >/dev/null 2>&1 || continue
    echo "${one//\%MANIFEST\%/$manifest}"
    return
  done
  echo ""
}

# The tools an entry would have needed, for the "left to you" message.
install_cmd_tools() { # install_cmd_tools <alternatives>
  local rest="$1" one acc=""
  while [[ -n "$rest" ]]; do
    if [[ "$rest" == *" || "* ]]; then one="${rest%% || *}"; rest="${rest#* || }"
    else one="$rest"; rest=""; fi
    acc="${acc:+$acc or }$(cmd_tool "$one")"
  done
  echo "$acc"
}

# Run one install command in its own directory, through mise when mise
# provides the tool, so the pinned node/python/ruby is the one that installs.
run_install() { # run_install <dir> <command>
  local dir="$1" cmd="$2" first rest prefix="" run
  first="$(cmd_tool "$cmd")"
  # keep any leading NAME=value assignments in front of whatever runs the tool
  while [[ "$cmd" == *=* && "${cmd%% *}" == *=* ]]; do
    prefix="${prefix}${cmd%% *} "; cmd="${cmd#* }"
  done
  if [[ "$first" == "$cmd" ]]; then rest=""; else rest=" ${cmd#* }"; fi
  resolve_tool "$first" "$dir" >/dev/null || {
    fail "cannot run '${cmd}' in ${dir#./}: ${first} is not installed. Add it to mise.toml ([tools] ${first} = \"…\") and run 'mise install', or install it on PATH."
  }
  # Run the WHOLE command under `mise exec` whenever a mise config applies
  # here, even when the tool itself came from PATH: the installer usually needs
  # the pinned interpreter more than it needs itself pinned.
  if mise_applies "$dir"; then run="mise exec -- ${first}${rest}"
  else run="$(resolve_tool "$first" "$dir")${rest}"; fi
  note "auto-install: ${dir#./} \$ ${prefix}${cmd}"
  vnote "running: ${prefix}${run}"
  ( cd "$dir" && eval "${prefix}${run}" ) || {
    fail "auto-install failed in ${dir#./}: ${prefix}${cmd}
  If it could not find an interpreter (a Python or Node version), pin that
  version in mise.toml for that directory and run 'mise install' — the command
  above runs under 'mise exec', so whatever mise provides there is what it uses."
  }
}

# Packages installed OUTSIDE the repository still need scanning: poetry keeps
# its virtualenv in a cache directory by default, so a Django dependency is on
# disk with its licence in the dist-info, and a scan of the tree sees only the
# lockfile that carries none. Every populated location the preflight verifies
# outside the repo root becomes an auxiliary scan target.
record_external_locations() { # record_external_locations <dir> <paths>
  local base="$1" paths_csv="$2" p full
  local IFS=':'
  for p in $paths_csv; do
    [[ -z "$p" ]] && continue
    # Machine-wide caches are not project installs: the Go module cache holds
    # every module this machine ever downloaded, and scanning it costs minutes
    # for nothing — syft resolves Go licences from it directly (see
    # LICENSING_SYFT_ENV). Only project-scoped locations are worth reading.
    case "$p" in *%GOMODCACHE%*) continue ;; esac
    full="$(resolve_install_path "$p" "$base")"
    unset IFS
    [[ -z "$full" || ! -d "$full" ]] && { IFS=':'; continue; }
    case "$full" in
      "${REPO_ROOT}"/*|./*|[!/]*) ;;                 # inside the tree already
      *) echo "dir:${full}" >> "$EXTERNAL_LOCATIONS" ;;
    esac
    IFS=':'
  done
}

# Stop (or install) when a manifest is present but its packages are not.
# Every manifest in the tree is checked, not just the first: a monorepo has one
# per workspace, each with its own node_modules, and each needs its own install
# run in its own directory.
install_preflight() {
  [[ "$LICENSING_INSTALL_CHECK" == 1 ]] || { vnote "install preflight disabled"; return 0; }
  vnote "checking every dependency manifest for installed packages"
  progress_step

  local entry label glob paths cmd
  local find_expr=() first=1

  # One pass over the tree for every manifest name any ecosystem cares about.
  # node_modules / vendor are pruned: a manifest inside an installed dependency
  # belongs to that dependency, not to this repository.
  for entry in ${LICENSING_INSTALL_CHECKS[@]+"${LICENSING_INSTALL_CHECKS[@]}"}; do
    glob="${entry#*|}"; glob="${glob%%|*}"
    if [[ "$first" == 1 ]]; then find_expr=(-name "$glob"); first=0
    else find_expr+=(-o -name "$glob"); fi
  done
  [[ "$first" == 1 ]] && return 0

  # A directory carrying its OWN .git is ANOTHER CHECKOUT, and every manifest
  # under it is that checkout's. So .git is PRINTED before it is pruned, and
  # the walk reports where those checkouts are: a git worktree spells .git as a
  # FILE holding a `gitdir:` pointer, a clone or a populated submodule spells
  # it as a directory, and `-name` finds both.
  #
  # This is not tidiness. A repository holding a worktree of itself — an agent
  # worktree under .claude/worktrees/<id>/, a release branch checked out beside
  # the trunk — holds a second copy of every manifest it has, so the preflight
  # demanded an install for each of them and stopped the run over a path the
  # commit does not contain, at exactly the moment somebody was trying to
  # commit. The scan half never had it: the scan excludes what .gitignore
  # excludes, and this walk answered to nothing.
  #
  # A nested MODULE is deliberately not a boundary. This script gates every
  # module in the tree on purpose — a monorepo's second go.mod or second
  # package.json is a workspace whose dependencies do need installing — so the
  # question is whose CHECKOUT a file is in, not whose module.
  local walked line nested=() nroot skip manifests=""
  walked="$(find . -name .git -print -prune -o \
      \( -name node_modules -o -name vendor \) -prune -o \
      -type f \( "${find_expr[@]}" \) -print 2>/dev/null | LC_ALL=C sort)"

  while IFS= read -r line; do
    # "./.git" is this repository's own; pruning "." would end the walk here.
    [[ "$line" == */.git && "$line" != "./.git" ]] && nested+=("${line%.git}")
  done <<EOF
${walked}
EOF

  # Two passes rather than one, so a checkout whose .git sorts after one of its
  # own manifests still excludes it.
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == */.git ]] && continue
    skip=0
    for nroot in ${nested[@]+"${nested[@]}"}; do
      case "$line" in "$nroot"*) skip=1; break ;; esac
    done
    [[ "$skip" == 1 ]] && continue
    manifests="${manifests}${line}"$'\n'
  done <<EOF
${walked}
EOF
  manifests="${manifests%$'\n'}"
  [[ "${#nested[@]}" -gt 0 ]] && vnote "preflight: ${#nested[@]} nested checkout(s) are not this one's: ${nested[*]}"
  [[ -z "$manifests" ]] && return 0

  # One record per uninstalled location, unit-separated: an empty command field
  # must survive the read, and IFS collapses runs of whitespace separators.
  local rec="${TMPDIR_RUN}/preflight"; : > "$rec"
  local US; US="$(printf '\037')"
  local dirs dir family claimed found f shown tools n=0

  # Group by directory, then walk the ecosystem table in ITS order, so a
  # workspace holding both poetry.lock and requirements.txt (or yarn.lock and
  # package-lock.json) yields one install for that directory, chosen by the
  # table's priority rather than by which filename sorts first.
  dirs="$(echo "$manifests" | while IFS= read -r m; do [[ -n "$m" ]] && dirname "$m"; done | LC_ALL=C sort -u)"
  local skip skipped_dir
  while IFS= read -r dir; do
    [[ -z "$dir" ]] && continue
    skipped_dir=0
    for skip in ${LICENSING_INSTALL_CHECK_SKIP[@]+"${LICENSING_INSTALL_CHECK_SKIP[@]}"}; do
      case "${dir#./}/" in "${skip%/}"/*) skipped_dir=1; break ;; esac
    done
    [[ "$skipped_dir" == 1 ]] && continue
    claimed=" "
    for entry in ${LICENSING_INSTALL_CHECKS[@]+"${LICENSING_INSTALL_CHECKS[@]}"}; do
      label="${entry%%|*}"; entry="${entry#*|}"
      glob="${entry%%|*}"; entry="${entry#*|}"
      paths="${entry%%|*}"; cmd="${entry#*|}"
      family="${label%% *}"
      case "$claimed" in *" ${family} "*) continue ;; esac

      found=""
      for f in "$dir"/$glob; do [[ -f "$f" ]] && { found="$f"; break; }; done
      [[ -z "$found" ]] && continue
      claimed="${claimed}${family} "

      if any_populated "$dir" "$paths"; then
        record_external_locations "$dir" "$paths"
        continue
      fi
      shown="$(display_paths "$dir" "$paths")"
      tools="$(install_cmd_tools "$cmd")"
      cmd="$(pick_install_cmd "$dir" "$cmd" "$(basename "$found")")"
      printf '%s%s%s%s%s%s%s: %s — nothing installed under %s\n' \
        "$dir" "$US" "$cmd" "$US" "$tools" "$US" "$label" "${found#./}" "$shown" >> "$rec"
      n=$((n + 1))
    done
  done <<EOF
${dirs}
EOF

  [[ "$n" == 0 ]] && return 0

  local rdir rcmd rtools rline unhandled="" installed=0 t0=$SECONDS
  local US; US="$(printf '\037')"
  if [[ "$LICENSING_AUTO_INSTALL" == 1 ]]; then
    # Install everything that CAN be installed, then report only what is left.
    while IFS="$US" read -r rdir rcmd rtools rline; do
      [[ -z "$rdir" ]] && continue
      if [[ -z "$rcmd" ]]; then
        unhandled="${unhandled}
  ${rline}"
        [[ -n "$rtools" ]] && unhandled="${unhandled}
      needs ${rtools}, none of which is installed"
        continue
      fi
      run_install "$rdir" "$rcmd"
      installed=$((installed + 1))
    done < "$rec"
    [[ $installed -gt 0 ]] && note "auto-install: ${installed} location(s) installed in $(since $t0)"

    [[ -z "$unhandled" ]] && return 0
    {
      echo "${ME}: installed every location it could; these are left to you:${unhandled}"
      echo
      echo "Install the named tool (mise.toml is the place to pin it), install those"
      echo "dependencies by hand, or add a command for them to LICENSING_INSTALL_CHECKS"
      echo "in ${CONF##*/} — alternatives separated by ' || ', first available tool wins:"
      echo
      echo "  LICENSING_INSTALL_CHECKS+=(\"python|requirements*.txt|.venv|uv venv && uv pip install -r %MANIFEST%\")"
      echo
      echo "Or scan the tree as it is with --skip-install-check."
    } >&2
    exit 2
  fi

  {
    echo "${ME}: dependencies are not installed in ${n} location(s), so no licence can be read."
    while IFS="$US" read -r rdir rcmd rtools rline; do
      [[ -n "$rdir" ]] && echo "  ${rline}"
    done < "$rec"
    echo
    echo "A manifest or lockfile records versions, not licences (yarn.lock carries"
    echo "none at all), so licences are only readable once the packages are on disk."
    echo "Scanning now would report those components as \"none detected\". Run:"
    echo
    while IFS="$US" read -r rdir rcmd rtools rline; do
      [[ -z "$rdir" ]] && continue
      if [[ -z "$rcmd" ]]; then
        if [[ -n "$rtools" ]]; then
          echo "  # ${rdir#./}: needs ${rtools} — none is installed. Pin one in mise.toml,"
          echo "  #   or install these dependencies yourself"
        else
          echo "  # ${rdir#./}: no command configured — install it yourself, or add one"
          echo "  #   to LICENSING_INSTALL_CHECKS in ${CONF##*/}"
        fi
      elif [[ "$rdir" == "." ]]; then
        echo "  ${rcmd}"
      else
        echo "  (cd ${rdir#./} && ${rcmd})"
      fi
    done < "$rec"
    echo
    echo "then re-run. Or pass --auto-install to run every command above (the"
    echo "commented ones are left to you), or --skip-install-check to scan as is."
  } >&2
  exit 2
}

# ---------------------------------------------------------------------------
# delta scoping
# ---------------------------------------------------------------------------
changed_files() {
  git rev-parse --verify -q HEAD >/dev/null || return 1
  { git diff --name-only HEAD; git ls-files --others --exclude-standard; } | LC_ALL=C sort -u
}

# Did this working tree touch anything that can change the dependency graph?
deps_touched() {
  local files pat f
  files="$(changed_files)" || { echo "ALL"; return 0; }   # no HEAD → treat as full
  for f in $files; do
    for pat in "${LICENSING_TRIGGER_PATHS[@]}"; do
      # shellcheck disable=SC2053
      [[ "$f" == $pat || "$f" == ${pat%/\*}/* ]] && { echo "$f"; break; }
    done
  done | LC_ALL=C sort -u
}

# Components introduced by the current diff: those catalogued from a changed
# manifest whose name appears on an added line of it. If a manifest changed but
# no name matched (binary lockfile, reformat), every component from it is in
# scope — never silently narrow to nothing.
delta_scope() { # -> lines "type|name|version"
  local touched="$1" f added path type name ver rest matched
  local scopefile="${TMPDIR_RUN}/scope"; : > "$scopefile"
  for f in $touched; do
    added="${TMPDIR_RUN}/added"
    if git rev-parse --verify -q "HEAD:$f" >/dev/null 2>&1; then
      git diff -U0 HEAD -- "$f" | grep '^+' > "$added" || true
    else
      cat "$f" > "$added" 2>/dev/null || : > "$added"
    fi
    matched=0
    while IFS='|' read -r type name ver path rest; do
      case ",$path" in *",/$f,"*) ;; *) continue ;; esac
      if grep -qF -- "$name" "$added" 2>/dev/null; then
        printf '%s|%s|%s\n' "$type" "$name" "$ver" >> "$scopefile"; matched=1
      fi
    done < "$SCAN"
    if [[ "$matched" == 0 ]]; then
      while IFS='|' read -r type name ver path rest; do
        case ",$path" in *",/$f,"*) printf '%s|%s|%s\n' "$type" "$name" "$ver" >> "$scopefile" ;; esac
      done < "$SCAN"
    fi
  done
  LC_ALL=C sort -u "$scopefile"
}

# ---------------------------------------------------------------------------
# half 1 — dependency licence gate
# ---------------------------------------------------------------------------
is_exception() {
  [[ -f "$LICENSING_EXCEPTIONS" ]] || return 1
  awk -v m="$1" 'NF { sub(/#.*/,""); sub(/=.*/,""); gsub(/[ \t]/,""); if ($0==m) f=1 } END{exit !f}' "$LICENSING_EXCEPTIONS"
}

# Say out loud what was not verified. Never silent: an unchecked component is
# a real gap, even when the gap is the machine's and not the repository's.
report_lockfile_only() {
  [[ "${lockonly:-0}" -gt 0 ]] || return 0
  local sample
  sample="$(LC_ALL=C sort -u "$lockonly_file" | head -3 | tr '\n' ' ')"
  note "deps: ${lockonly} component(s) are named in a lockfile but were never unpacked on this machine, so no licence could be read (${sample}…). Nearly always a platform-specific optional package the package manager skipped for this OS or CPU — a Windows or Linux binding on a Mac. NOTHING TO DO unless one of them is a package you do ship on this platform: no install produces a licence for them here, and the same run on that platform reads them, which is why CI on Linux is where this list should be empty. --verbose names every one; they are listed under LicenseRef-NOT-INSTALLED-HERE in --components; LICENSING_LOCKFILE_ONLY=review fails the gate on them instead."
}

# The duties attached to the licences this tree actually carries. Printed at
# the end of the run, on --obligations, for every licence the gate SAW —
# allowed ones included, because those are the ones you ship and therefore the
# ones whose duties are yours.
# ---------------------------------------------------------------------------
# porcelain — the same answers, for a program instead of a person
# ---------------------------------------------------------------------------
# One record per line on STDOUT, tab separated, first field the record type, no
# colour and no headers. In this mode — and only in this mode — every human
# line this script writes goes to stderr instead of stdout, so
# `licensing.sh check --porcelain > licences.tsv` is the whole report and
# nothing else. Records:
#
#   duty     <code> <what it obliges you to do>
#   licence  <SPDX id> <components> <duty codes, space separated> <note>
#   pair     <SPDX id> <component|file|annotation> <name or path> <version> <type>
#   finding  <DENY|REVIEW> <type> <name> <version> <licences> <where>
#   summary  <gated> <deny> <review> <exempt> <lockfile-only>
#
# An empty duty-codes field means the licence asks nothing; "?" means nothing
# is on file for it, which is not the same answer. The second field of a pair
# says where the licence came from: a catalogued component, a file's own SPDX
# header, or a REUSE.toml annotation — and for the last two, version and type
# are empty, because a file has neither.
#
# The format is versioned: --porcelain=v1 pins it, --porcelain takes the
# current one. New record types may be added, so ignore the ones you do not
# know; the fields of a type you do know will not be reordered or removed.
LICENSING_PORCELAIN_VERSIONS="v1"

porcelain_obligations() { # porcelain_obligations <rows file> <pairs file>
  local entry
  for entry in ${LICENSING_DUTIES[@]+"${LICENSING_DUTIES[@]}"}; do
    printf 'duty\t%s\t%s\n' "${entry%%|*}" "${entry#*|}"
  done
  awk -F'\t' '{ printf "licence\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4 }' "$1"
  # The label this script builds for a component is "<name>@<version> (<type>)",
  # and a caller should not have to take it apart again — so it goes back out
  # as the fields it was made of. A licence that came from a file's own header
  # or from a REUSE.toml annotation has a path where a name would be, and no
  # version and no ecosystem: those fields are empty rather than invented.
  awk -F'\t' '{
      comp = $2; src = "component"; type = ""; ver = ""
      if (comp ~ /\[inline SPDX\]$/) src = "file"
      else if (comp ~ /\[REUSE\.toml\]$/) src = "annotation"
      sub(/ \[(inline SPDX|REUSE\.toml)\]$/, "", comp)
      if (src == "component" && match(comp, / \([^()]*\)$/)) {
        type = substr(comp, RSTART + 2, RLENGTH - 3)
        comp = substr(comp, 1, RSTART - 1)
        if ((j = match(comp, /@[^@]*$/)) > 0) {
          ver = substr(comp, j + 1); comp = substr(comp, 1, j - 1)
        }
      }
      printf "pair\t%s\t%s\t%s\t%s\t%s\n", $1, src, comp, ver, type
    }' "$2"
  return 0
}

# The gate's own verdicts, from the files it already wrote. "<type> <name>@<ver>"
# is split on the LAST @: a version holds none, a scoped npm name can.
porcelain_findings() { # porcelain_findings <deny file> <review file>
  local f
  for f in "$1" "$2"; do
    [[ -s "$f" ]] || continue
    awk -F'\t' '{
      nv = $3
      i = index(nv, " "); type = substr(nv, 1, i - 1); nv = substr(nv, i + 1)
      j = match(nv, /@[^@]*$/)
      if (j > 0) { name = substr(nv, 1, j - 1); ver = substr(nv, j + 1) }
      else       { name = nv; ver = "" }
      printf "finding\t%s\t%s\t%s\t%s\t%s\t%s\n", $1, type, name, ver, $2, $4
    }' "$f"
  done
  return 0
}

# Every component in the inventory and the licence it carries, for the runs
# where the gate did not produce that list itself: a delta run that skipped the
# scan, `--only toml`, a tree where every component was exempt. The duties you
# are under are a property of what you SHIP, not of what a particular run
# happened to gate, so the report asks for the inventory rather than waiting to
# be handed one.
licences_from_scan() { # -> writes <component>TAB<expression> lines to LIC_SEEN_FILE
  ensure_scan
  local type name ver path lics l out OLDIFS
  local ignore_types=" ${LICENSING_IGNORE_TYPES[*]-} "
  while IFS='|' read -r type name ver path lics; do
    [[ -z "$name" ]] && continue
    in_list "$type" "$ignore_types" && continue
    name_matches "$name" LICENSING_SELF_NAMES && continue
    out=""
    OLDIFS="$IFS"; IFS=';'
    for l in $lics; do
      IFS="$OLDIFS"
      [[ -z "$l" || "$l" == sha256:* ]] && { IFS=';'; continue; }
      # The same fast path the gate takes: an id the policy already names needs
      # no parsing and no subshell, and there are thousands of these.
      case " $LICENSING_ALLOW $LICENSING_DENY " in
        *" $l "*) out="${out:+$out, }${l}" ;;
        *)        out="${out:+$out, }$(normalize_expr "$l")" ;;
      esac
      IFS=';'
    done
    IFS="$OLDIFS"
    # The same two sentinels the gate records, for the ones nothing identified:
    # the two paths into this report must show the same inventory, or which of
    # them a run happened to take would change what it says you ship.
    if [[ -z "$out" ]]; then
      if lockfile_only "$path"; then out="LicenseRef-NOT-INSTALLED-HERE"; else out="NOASSERTION"; fi
    fi
    printf '%s@%s (%s)\t%s\n' "$name" "$ver" "$type" "$out"
  done < "$SCAN" > "$LIC_SEEN_FILE"
  return 0
}

report_obligations() {
  [[ "${OBLIGATIONS:-0}" == 1 ]] || return 0
  local f="${LIC_SEEN_FILE:-}"
  if [[ -z "$f" || ! -s "$f" ]]; then
    LIC_SEEN_FILE="${TMPDIR_RUN}/licences_seen"; f="$LIC_SEEN_FILE"
    licences_from_scan
  fi
  color_init

  # <licence id>TAB<component>, one pair per line: split each recorded
  # expression on every operator, since a duty attaches to a LEAF and never to
  # the choice, and keep the component beside it so --components can say which
  # packages put you under which duty. LC_ALL=C sort -u puts both the licences
  # and, within each, the components in alphabetical order, and drops the
  # repeats a component earns by declaring the same licence twice.
  local pairs="${TMPDIR_RUN}/obligation_pairs"
  local seen="${TMPDIR_RUN}/licences_seen_all"
  cat "$f" > "$seen"
  reuse_head_licences >> "$seen"
  inline_spdx_licences >> "$seen"
  awk -F'\t' '
    {
      comp = $1; e = $2
      gsub(/[()]/, " ", e)
      gsub(/ OR /, "|", e); gsub(/ AND /, "|", e); gsub(/, /, "|", e)
      n = split(e, a, "|")
      for (i = 1; i <= n; i++) {
        id = a[i]
        gsub(/^[ \t]+|[ \t]+$/, "", id)
        if (id != "") print id "\t" comp
      }
    }
  ' "$seen" | LC_ALL=C sort -u > "$pairs"
  [[ -s "$pairs" ]] || return 0

  # <id>TAB<count>TAB<duty codes>TAB<note>, alphabetical, for the licences this
  # tree actually carries. An id with no entry in the table gets no row: it is
  # reported underneath as unanswered, which is not the same as free.
  # A licence with no entry in the table gets a row all the same, carrying the
  # "?" sentinel instead of duty codes: it is a column of ??? in the matrix and
  # a named gap underneath. Leaving it out of the table entirely would have
  # read as "nothing to do here", which is the one thing it does not mean.
  local present="${TMPDIR_RUN}/obligation_rows" unknown_ids="" id n entry codes note
  : > "$present"
  while read -r n id; do
    codes=""; note=""; entry=""
    for entry in ${LICENSING_OBLIGATIONS[@]+"${LICENSING_OBLIGATIONS[@]}"}; do
      if [[ "${entry%%|*}" == "$id" ]]; then
        entry="${entry#*|}"; codes="${entry%%|*}"; note="${entry#*|}"
        [[ "$note" == "$codes" ]] && note=""
        printf '%s\t%s\t%s\t%s\n' "$id" "$n" "$codes" "$note" >> "$present"
        break
      fi
      entry=""
    done
    [[ -z "$entry" ]] && {
      unknown_ids="${unknown_ids}${id} "
      printf '%s\t%s\t?\t%s\n' "$id" "$n" "" >> "$present"
    }
  done < <(cut -f1 "$pairs" | uniq -c)

  # A program gets the records and nothing else; the tables below are for a
  # person, and a person is not reading this run.
  if [[ "${PORCELAIN:-0}" == 1 ]]; then
    porcelain_obligations "$present" "$pairs"
    return 0
  fi

  {
    echo
    echo "${C_HEAD}OBLIGATIONS — what these licences ask of you once you ship them${C_RESET}"
    echo "  A checklist for the common case (distributing a binary or a service),"
    echo "  not legal advice. Static linking and firmware change some answers."
    echo
    # Both, when both were asked for: the detail first and the matrix last,
    # because the matrix is the summary and a summary belongs at the end of
    # what it summarises.
    if [[ "${OBLIGATION_COMPONENTS:-0}" == 1 ]]; then
      obligations_detailed "$present" "$pairs"
    fi
    if [[ "${OBLIGATION_MATRIX:-0}" == 1 ]]; then
      obligations_matrix "$present"
      [[ "${OBLIGATION_COMPONENTS:-0}" == 1 ]] || {
        echo
        echo "  --components lists the duties per licence, with the packages under each."
      }
    fi
    if [[ -n "$unknown_ids" ]]; then
      echo
      echo "  NO OBLIGATION TEXT ON FILE — which is not the same as no obligation."
      echo "  Add each to ${CONF##*/}:"
      echo "    LICENSING_OBLIGATIONS+=(\"<SPDX-ID>|<duty codes>|<note>\")"
      echo
      # Always name the components, not only under --components. An id nobody
      # has answered for is usually an id nobody RECOGNISES — free text out of
      # some package.json, a licence file named in prose — and the first
      # question about it is which package it came from. Answering that here is
      # the difference between a report and a puzzle.
      local ucap=3
      [[ "${OBLIGATION_COMPONENTS:-0}" == 1 ]] && ucap=0
      while IFS=$'\t' read -r id n codes note; do
        [[ "$codes" == "?" ]] || continue
        printf '  %s%s%s %s(%s component%s)%s\n' \
          "$C_LIC" "$id" "$C_RESET" "$C_PATH" "$n" "$([[ "$n" == 1 ]] || echo s)" "$C_RESET"
        print_components_for "$pairs" "$id" "$ucap"
      done < "$present"
    fi
    [[ ! -s "$present" && -z "$unknown_ids" ]] && echo "  (no licences were recorded)"
  } >&3
  return 0
}

# Third-party code annotated BY HAND in REUSE.toml, above the generated
# marker. syft catalogues dependencies, not source files somebody copied into
# this repository — a vendored .go file is not a component and never appears
# in the scan — so without this the duties attached to those files would go
# unreported while the files themselves ship.
#
# Annotations carrying this project's OWN outbound licence are skipped: that
# is the licence you grant, not one you owe. Everything below the marker is
# generated from the same scan the rest of this report reads, so including it
# would count those components twice.
reuse_head_licences() { # -> <component>TAB<licence expression> lines
  [[ -f "$LICENSING_REUSE_TOML" ]] || return 0
  awk -v marker="$LICENSING_REUSE_MARKER" \
      -v own="$LICENSING_LICENSE" -v owndoc="$LICENSING_DOC_LICENSE" '
    function addpaths(l,   n, a, i) {
      n = split(l, a, "\"")
      for (i = 2; i <= n; i += 2) { np++; if (np == 1) first = a[i] }
    }
    $0 == marker { exit }
    /^\[\[annotations\]\]/ { inblk = 1; np = 0; first = ""; incoll = 0; next }
    !inblk { next }
    /^[ \t]*path[ \t]*=/ {
      addpaths($0)
      incoll = ($0 ~ /\[/ && $0 !~ /\]/)
      next
    }
    incoll { addpaths($0); if ($0 ~ /\]/) incoll = 0; next }
    /^[ \t]*SPDX-License-Identifier[ \t]*=/ {
      n = split($0, a, "\"")
      id = (n >= 2) ? a[2] : ""
      inblk = 0
      if (id == "" || id == own || id == owndoc) next
      label = first
      if (np > 1) label = first " (+" (np - 1) ")"
      print label " [REUSE.toml]\t" id
    }
  ' "$LICENSING_REUSE_TOML"
}

# REUSE-IgnoreStart — this function matches on the header tag, and every
# mention of it below is a pattern, not a declaration about this file.
#
# Third-party files copied into this repository that carry their own inline
# SPDX header, rather than being annotated in REUSE.toml. A vendored .c file
# with an SPDX licence tag naming GPL-2.0-only at the top is not a component,
# is not an annotation, and ships anyway — it is the last place an obligation
# can hide.
#
# The vendor roots are left out: those files ARE catalogued by the scan, and
# counting them here would count them twice. So are the project's own outbound
# licences, which is what almost every header in a healthy repository says.
inline_spdx_licences() { # -> <component>TAB<licence expression> lines
  have git || return 0
  git rev-parse --git-dir >/dev/null 2>&1 || return 0
  local excludes=() r
  for r in ${LICENSING_VENDOR_ROOTS[@]+"${LICENSING_VENDOR_ROOTS[@]}"}; do
    excludes+=(":(exclude)${r}/**")
  done
  # No \b: git grep's regex engine does not know it, and a pattern it cannot
  # compile silently matches nothing. Exit 1 means "no matches", which is a
  # perfectly good answer and must not take `set -e` with it.
  git grep -I -E "$SPDX_ID_TAG" -- . ${excludes[@]+"${excludes[@]}"} 2>/dev/null \
    | awk -v tag="$SPDX_ID_TAG" -v own="$LICENSING_LICENSE" -v owndoc="$LICENSING_DOC_LICENSE" '
      {
        i = index($0, ":")
        if (i == 0) next
        path = substr($0, 1, i - 1)
        if (path in seen) next
        rest = substr($0, i + 1)
        j = index(rest, tag)
        if (j == 0) next
        # Only comment punctuation may precede the tag. A tag inside a string
        # (`const hdr = "<tag> LGPL-3.0-only"`) is a source-code literal,
        # not a declaration about the file it sits in, and the letters and the
        # quote in front of the tag are what say so.
        if (substr(rest, 1, j - 1) ~ /[A-Za-z0-9"\047]/) next
        id = substr(rest, j + length(tag))
        # Trim the whitespace, then whatever the comment syntax put after it.
        sub(/^[ \t]+/, "", id)
        sub("[ \t]*(\\*/|-->|#|\"|\047|,).*$", "", id)
        sub("\\\\n.*$", "", id)
        sub(/[ \t]+$/, "", id)
        # A licence expression and nothing else: the same string appearing in
        # a source-code literal is not a declaration about that file.
        if (id !~ /^[A-Za-z0-9][A-Za-z0-9.+()-]*([ ](OR|AND|WITH)[ ][A-Za-z0-9.+()-]+)*$/) next
        if (id == own || id == owndoc) next
        seen[path] = 1
        print path " [inline SPDX]\t" id
      }
    ' || true
  # `|| true` above, and not only the comment further up: git grep exits 1 when
  # nothing matched, pipefail hands that to the pipeline, and `set -e` would
  # take the whole run down without printing a word — which is what a
  # repository whose files carry no inline SPDX header used to get instead of
  # its obligations report.
  return 0
}
# REUSE-IgnoreEnd

# duty x licence, one column per licence found. Column headers are the ids
# themselves while they fit the terminal, and numbered with a legend when they
# do not — a matrix that wraps is not a matrix.
obligations_matrix() { # obligations_matrix <rows file>
  [[ -s "$1" ]] || return 0
  local duties="${TMPDIR_RUN}/duty_table" entry
  : > "$duties"
  for entry in ${LICENSING_DUTIES[@]+"${LICENSING_DUTIES[@]}"}; do
    printf '%s\t%s\n' "${entry%%|*}" "${entry#*|}" >> "$duties"
  done

  # LC_ALL=C: awk then counts bytes on every platform, which dw() below
  # expects, and GNU awk accepts its byte range (in a UTF-8 locale it refuses
  # it with "Invalid collation character" and prints nothing).
  LC_ALL=C awk -F'\t' -v cols="$(term_cols)" -v cH="$C_HEAD" -v cL="$C_LIC" \
      -v cY="$C_NAME" -v cP="$C_PATH" -v cU="$C_REVIEW" -v cZ="$C_RESET" '
    # Display width, not byte count. A UTF-8 continuation byte is part of the
    # character before it and occupies no column of its own, so it is
    # subtracted; padding by bytes would shift every column after it.
    function dw(s,   t, n) { t = s; n = gsub(/[\200-\277]/, "", t); return length(s) - n }
    function rule(w,   o) { o = "+"; while (w-- > 0) o = o "-"; return o }
    function pad(s, w,   d) { d = w - dw(s); if (d < 0) d = 0; return s sp(d) }
    function sp(n,   o) { o = ""; while (n-- > 0) o = o " "; return o }
    function ctr(s, w,   d, l) {
      d = w - dw(s); if (d < 0) d = 0
      l = int(d / 2); return sp(l) s sp(d - l)
    }
    NR == FNR { dcode[++nd] = $1; dtext[$1] = $2; next }
    {
      nl++; lid[nl] = $1; lcount[nl] = $2; lnote[nl] = $4
      # "?" is the no-entry sentinel: not "no duties", but "nobody has said".
      if ($3 == "?") { unknown[$1] = 1; next }
      split($3, cs, " ")
      for (i in cs) if (cs[i] != "") has[$1, cs[i]] = 1
    }
    END {
      if (nl == 0) { print "  (no licences with a known duty)"; exit }

      # Only the duties something here actually triggers: an all-empty row
      # tells you nothing and costs a line.
      for (d = 1; d <= nd; d++) {
        used = 0
        for (l = 1; l <= nl; l++) if ((lid[l] SUBSEP dcode[d]) in has) used = 1
        if (used) rows[++nr] = dcode[d]
      }
      if (nr == 0) {
        un = ""
        for (l = 1; l <= nl; l++) if (unknown[lid[l]]) un = un (un == "" ? "" : ", ") lid[l]
        if (un != "") print "  no duty is on file for any of these licences: " un
        else print "  none of these licences asks anything of you."
        exit
      }

      # Nothing is truncated: a duty you can only read half of is a duty you
      # cannot act on, and the row it sits in would come out short.
      wd = dw("components")
      for (r = 1; r <= nr; r++) if (dw(dtext[rows[r]]) > wd) wd = dw(dtext[rows[r]])

      # Every column is as wide as the widest thing that goes IN it — the
      # header, the marks, and the count, which is the one that grows without
      # anybody expecting it: 6394 does not fit the 3 columns "yes" needs.
      wide = 0; wnum = 0
      for (l = 1; l <= nl; l++) {
        if (dw(lid[l]) > wide) wide = dw(lid[l])
        if (dw(lcount[l] "") > wnum) wnum = dw(lcount[l] "")
      }
      widx = dw(nl "")
      wfull = (wide > wnum ? wide : wnum); if (wfull < 3) wfull = 3

      # Full ids as headers while the table fits; numbers plus a legend when
      # it does not. Numbered, the count moves INTO the legend rather than
      # taking a row: one component count of 123456 would otherwise widen
      # every column in the grid from 3 to 6 to hold a number that has nothing
      # to do with the marks below it.
      numbered = (2 + 2 + wd + 1 + nl * (wfull + 3)) > cols
      wc = numbered ? (widx > 3 ? widx : 3) : wfull

      line = "  " rule(wd + 2)
      for (l = 1; l <= nl; l++) line = line rule(wc + 2)
      line = line "+"

      print line
      head = "  | " cH pad("DUTY", wd) cZ " |"
      for (l = 1; l <= nl; l++) head = head " " cL ctr(numbered ? l "" : lid[l], wc) cZ " |"
      print head
      print line
      for (r = 1; r <= nr; r++) {
        out = "  | " pad(dtext[rows[r]], wd) " |"
        for (l = 1; l <= nl; l++) {
          # Three states, and the third is the point: "yes" is a duty, blank is
          # a licence that has been read and asks nothing HERE, and "???" is a
          # licence nobody has answered for. A blank in that column would be a
          # claim this table is not entitled to make.
          if (unknown[lid[l]]) { mark = "???"; c = cU }
          else if ((lid[l] SUBSEP rows[r]) in has) { mark = "yes"; c = cY }
          else { mark = ""; c = cP }
          out = out " " c ctr(mark, wc) cZ " |"
        }
        print out
      }
      print line
      if (!numbered) {
        out = "  | " cP pad("components", wd) cZ " |"
        for (l = 1; l <= nl; l++) out = out " " cP ctr(lcount[l] "", wc) cZ " |"
        print out
        print line
      } else {
        print ""
        for (l = 1; l <= nl; l++)
          printf "  %s%s%s %s%s%s %s(%s component%s)%s\n", \
            cP, ctr(l "", widx), cZ, cL, pad(lid[l], wide), cZ, \
            cP, lcount[l], (lcount[l] == 1 ? "" : "s"), cZ
      }
      free = ""; unl = ""
      for (l = 1; l <= nl; l++) {
        if (unknown[lid[l]]) { unl = unl (unl == "" ? "" : ", ") lid[l]; continue }
        any = 0
        for (r = 1; r <= nr; r++) if ((lid[l] SUBSEP rows[r]) in has) any = 1
        if (!any) free = free (free == "" ? "" : ", ") lid[l]
      }
      if (free != "") { print ""; print "  Asks nothing of you: " free }
      if (unl != "") { print ""; print "  ??? — no duty on file, which is not the same as none: " unl }
      n = 0
      for (l = 1; l <= nl; l++) if (lnote[l] != "") n++
      if (n > 0) {
        print ""
        for (l = 1; l <= nl; l++) if (lnote[l] != "") printf "  %s%s%s: %s\n", cL, lid[l], cZ, lnote[l]
      }
    }
  ' "$duties" "$1"
}

# One block per licence: its duties spelled out, and the packages that put you
# under them. The reason --components exists is that a passing gate otherwise
# never tells you WHICH dependency you are complying on behalf of.
# The components carrying one licence, one line per PACKAGE rather than per
# version. get-intrinsic is in this tree ten times over and used to be ten
# lines of the same name; "get-intrinsic@1.1.2,1.1.3,…" is the same
# information and the list becomes readable. Versions arrive sorted, because
# the pairs file is.
#
# A label that is not "<name>@<version> (<type>)" — a REUSE.toml annotation or
# a file's own SPDX header, which have a path where a name would be — is
# printed as it stands: there is nothing to collapse and nothing to invent.
print_components_for() { # print_components_for <pairs file> <licence id> [cap]
  awk -F'\t' -v want="$2" -v cap="${3:-0}" -v c="$C_NAME" -v z="$C_RESET" -v p="$C_PATH" '
    $1 != want { next }
    {
      comp = $2
      if (match(comp, / \([^()]*\)$/)) {
        type = substr(comp, RSTART + 2, RLENGTH - 3)
        base = substr(comp, 1, RSTART - 1)
        j = match(base, /@[^@]*$/)
        if (j > 0) { nm = substr(base, 1, j - 1); vr = substr(base, j + 1) }
        else       { nm = base; vr = "" }
        k = nm "\034" type
        if (!(k in seen)) { seen[k] = 1; ord[++n] = k; nmof[k] = nm; tpof[k] = type }
        if (vr != "" && !((k "\034" vr) in vseen)) {
          vseen[k "\034" vr] = 1
          vs[k] = vs[k] (vs[k] == "" ? "" : ",") vr
        }
      } else if (!(comp in seenp)) {
        seenp[comp] = 1; ord[++n] = comp; plain[comp] = 1
      }
    }
    END {
      for (i = 1; i <= n; i++) {
        k = ord[i]
        if (cap > 0 && i > cap) { hidden++; continue }
        if (k in plain) print "        " c k z
        else print "        " c nmof[k] (vs[k] != "" ? "@" vs[k] : "") " (" tpof[k] ")" z
      }
      if (hidden > 0)
        printf "        %s… and %d more (--components lists every one)%s\n", p, hidden, z
    }
  ' "$1"
}

obligations_detailed() { # obligations_detailed <rows file> <pairs file>
  local id n codes note code entry
  while IFS=$'\t' read -r id n codes note; do
    # "?" is the no-entry sentinel: the block underneath the matrix says what
    # to do about it, and saying it twice helps nobody.
    [[ "$codes" == "?" ]] && continue
    printf '  %s%-24s%s %s%s component(s)%s\n' "$C_LIC" "$id" "$C_RESET" "$C_PATH" "$n" "$C_RESET"
    if [[ -z "${codes// /}" ]]; then
      echo "      - nothing"
    else
      # In the table's order, not the entry's, so a duty sits in the same
      # place here as it does in the matrix row it corresponds to.
      for entry in ${LICENSING_DUTIES[@]+"${LICENSING_DUTIES[@]}"}; do
        code="${entry%%|*}"
        in_list "$code" " $codes " && echo "      - ${entry#*|}"
      done
    fi
    [[ -n "$note" ]] && echo "      (${note})"
    print_components_for "$2" "$id"
    echo
  done < "$1"
}

gate_deps() { # gate_deps <mode>
  local mode="$1" touched="" scopefile=""

  if [[ "$mode" == delta ]]; then
    touched="$(deps_touched)"
    if [[ -z "$touched" ]]; then
      snote "deps: no dependency manifest changed vs HEAD — skipping the component scan"
      return 0
    fi
    if [[ "$touched" == "ALL" ]]; then
      mode=full; touched=""
    fi
  fi

  ensure_scan
  if [[ "$mode" == delta ]]; then
    scopefile="${TMPDIR_RUN}/scope.final"
    delta_scope "$touched" > "$scopefile"
    if [[ ! -s "$scopefile" ]]; then
      snote "deps: manifests changed but introduced no new component — nothing to gate"
      return 0
    fi
    snote "deps: $(wc -l < "$scopefile" | tr -d ' ') component(s) introduced by this change"
  fi

  local type name ver path lics where l OLDIFS bad=0 checked=0 skipped=0 selfskip=0 exempt=0 l denied allowed shown key seen_as
  local ignore_types=" ${LICENSING_IGNORE_TYPES[*]-} "
  local exempt_types=" ${LICENSING_REVIEW_EXEMPT_TYPES[*]-} "
  local lockfiles="" blind_types="" subskip=0 lockonly=0
  local lockonly_file="${TMPDIR_RUN}/lockonly"; : > "$lockonly_file"
  local deny_file="${TMPDIR_RUN}/deny" review_file="${TMPDIR_RUN}/review"
  local deny_ids_file="${TMPDIR_RUN}/deny_ids"
  LIC_SEEN_FILE="${TMPDIR_RUN}/licences_seen"; : > "$LIC_SEEN_FILE"
  local names_file="${TMPDIR_RUN}/names" ids_file="${TMPDIR_RUN}/ids"
  local unknown_file="${TMPDIR_RUN}/unknown"
  : > "$deny_file"; : > "$review_file"; : > "$names_file"; : > "$ids_file"; : > "$unknown_file"
  : > "$deny_ids_file"
  while IFS='|' read -r type name ver path lics; do
    [[ -z "$name" ]] && continue
    in_list "$type" "$ignore_types" && { skipped=$((skipped+1)); continue; }
    # An npm package name is "name" or "@scope/name". Anything else with a
    # slash is a sub-directory package.json inside a package (libphonenumber-js
    # ships several, for module resolution), not a dependency of ours.
    if [[ "$LICENSING_SKIP_NESTED_SUBPACKAGES" == 1 && "$type" == npm ]]; then
      case "$name" in
        @*/*/*) subskip=$((subskip+1)); continue ;;
        @*/*) ;;
        */*) subskip=$((subskip+1)); continue ;;
      esac
      # "<%= name %>" and friends: a template placeholder in a scaffold's
      # package.json. npm names cannot hold < > % or spaces.
      case "$name" in
        *[\<\>%\ ]*) subskip=$((subskip+1)); continue ;;
      esac
      # A package.json deeper than the package root — lib/cjs/package.json
      # carrying only {"type":"commonjs"} — has no version and is not a
      # package. The real one is catalogued separately, with its version.
      if [[ -z "$ver" || "$ver" == UNKNOWN ]] && nested_manifest_only "$name" "$path"; then
        subskip=$((subskip+1)); continue
      fi
    fi
    if name_matches "$name" LICENSING_SELF_NAMES; then selfskip=$((selfskip+1)); continue; fi
    if [[ -n "$scopefile" ]]; then
      grep -qxF "${type}|${name}|${ver}" "$scopefile" || continue
    fi
    checked=$((checked+1))

    denied=""; allowed=0; shown=""; : > "$unknown_file"
    OLDIFS="$IFS"; IFS=';'
    for l in $lics; do
      IFS="$OLDIFS"
      [[ -z "$l" || "$l" == sha256:* ]] && { IFS=';'; continue; }
      # Fast path: a bare id already on a list needs no parsing and no
      # subshell. With 18,000 components the subshells cost minutes.
      case " $LICENSING_DENY " in *" $l "*) shown="${shown:+$shown, }${l}"; denied="${denied}${l} "; IFS=';'; continue ;; esac
      case " $LICENSING_ALLOW " in *" $l "*) shown="${shown:+$shown, }${l}"; allowed=1; IFS=';'; continue ;; esac
      # Everything else is free text until proven otherwise: map the leaves and
      # canonicalise the operators, so "GPL 2.0/LGPL 2.1 or MIT" is read as the
      # choice it is rather than as its first leaf.
      memo_expr norm "$l"; l="$MEMO_OUT"
      shown="${shown:+$shown, }${l}"
      case " $LICENSING_DENY " in *" $l "*) denied="${denied}${l} "; IFS=';'; continue ;; esac
      case " $LICENSING_ALLOW " in *" $l "*) allowed=1; IFS=';'; continue ;; esac
      memo_expr verdict "$l"
      case "$MEMO_OUT" in
        allow) allowed=1 ;;
        deny)  denied="${denied}${l} " ;;
        *)     unknown_leaves "$l" >> "$unknown_file" ;;
      esac
      IFS=';'
    done
    IFS="$OLDIFS"
    # Every licence this component carries, allowed or not: --obligations
    # reports on what you SHIP, which is mostly the allowed ones.
    # Name first, so --components sorts by package rather than by ecosystem.
    #
    # A component whose licence NOTHING could state goes in under a sentinel
    # rather than being left out. Leaving it out is what this used to do, and
    # it made the one component you most need to see — a dependency nothing on
    # disk describes — the one component the report could not show you at all:
    # gated as exempt, counted in a total, and named nowhere. An inventory that
    # silently omits what it could not identify is not an inventory.
    #
    # TWO sentinels, though, because there are two different situations and one
    # of them is not a question for you. NOT-INSTALLED-HERE is a package a
    # lockfile names that this machine never unpacked — a Windows or Linux
    # binding on a Mac — and there is nothing on disk to read and no install
    # that would produce one; a run on that platform answers it. NOASSERTION is
    # a package that IS here and still says nothing about its licence, which is
    # a real question for a person. Mixing them buried a dozen of the second in
    # several hundred of the first.
    if [[ "${OBLIGATIONS:-0}" == 1 ]]; then
      if [[ -n "$shown" ]]; then seen_as="$shown"
      elif lockfile_only "$path"; then seen_as="LicenseRef-NOT-INSTALLED-HERE"
      else seen_as="NOASSERTION"
      fi
      printf '%s@%s (%s)\t%s\n' "$name" "$ver" "$type" "$seen_as" >> "$LIC_SEEN_FILE"
    fi

    where_from_paths "$path"; where="$WHERE_OUT"
    if [[ -n "$denied" ]]; then
      # Every licence found, not only the deny-listed one: a component under
      # two licences is refused on the strength of the whole set, and the set
      # is what you need in order to argue with the verdict. The ids that did
      # the refusing are named under the table.
      printf 'DENY\t%s\t%s %s@%s\t%s\n' "$shown" "$type" "$name" "$ver" "$WHERE_ONE" >> "$deny_file"
      deny_leaves "$shown" >> "$deny_ids_file"
      bad=1; continue
    fi
    [[ "$allowed" == 1 ]] && continue
    key="$name"
    is_exception "$key" && continue
    if [[ "$LICENSING_LOCKFILE_ONLY" == exempt ]] && lockfile_only "$path"; then
      lockonly=$((lockonly+1))
      echo "$name" >> "$lockonly_file"
      # Named, like every other thing this gate decides not to look at. The
      # summary line quotes three of them, and three out of several hundred is
      # not a list you can check a particular dependency against.
      vnote "named only in a lockfile, nothing on disk to read a licence from: ${type} ${name}@${ver} (${WHERE_ONE})"
      continue
    fi
    [[ -z "$shown" ]] && shown="none detected"
    if in_list "$type" "$exempt_types"; then
      exempt=$((exempt+1))
      vnote "${type} ${name}@${ver} — no licence metadata (type is review-exempt)"
      continue
    fi
    printf 'REVIEW\t%s\t%s %s@%s\t%s\n' "$shown" "$type" "$name" "$ver" "$WHERE_ONE" >> "$review_file"
    echo "$name" >> "$names_file"
    cat "$unknown_file" >> "$ids_file"
    bad=1
    if [[ "$shown" == "none detected" ]]; then
      case " $blind_types " in *" $type "*) ;; *) blind_types="${blind_types} ${type}" ;; esac
    fi
    case " $lockfiles " in *" $where "*) ;; *) lockfiles="${lockfiles} ${where}" ;; esac
  done < "$SCAN"

  if [[ "${PORCELAIN:-0}" == 1 ]]; then
    porcelain_findings "$deny_file" "$review_file"
    printf 'summary\t%s\t%s\t%s\t%s\t%s\n' "$checked" \
      "$(wc -l < "$deny_file" | tr -d ' ')" "$(wc -l < "$review_file" | tr -d ' ')" \
      "$exempt" "$lockonly"
  fi

  if [[ "$bad" == 1 ]]; then
    local n_deny n_review
    n_deny="$(wc -l < "$deny_file" | tr -d ' ')"
    n_review="$(wc -l < "$review_file" | tr -d ' ')"

    # How many findings print is LICENSING_MAX_FINDINGS' business and nobody
    # else's: --verbose says how much a run explains itself, never how much of
    # the answer it is willing to show. Set it to 0 for all of them.
    local cap=0
    [[ "${LICENSING_MAX_FINDINGS:-0}" -gt 0 && "$n_review" -gt "$LICENSING_MAX_FINDINGS" ]] && cap="$LICENSING_MAX_FINDINGS"
    local all_file="${TMPDIR_RUN}/findings"
    cat "$deny_file" "$review_file" > "$all_file"
    echo >&3
    render_findings "$all_file" "$cap"
    if [[ "$n_deny" -gt 0 ]]; then
      local deny_ids; deny_ids="$(LC_ALL=C sort -u "$deny_ids_file" | tr '\n' ' ')"
      [[ -n "${deny_ids// /}" ]] && echo "  deny-listed above: ${deny_ids% }" >&3
    fi

    {
      echo
      echo "✗ ${n_deny} deny-listed, ${n_review} unreviewed, out of ${checked} component(s) gated."
      echo

      # Unknown ids split by what you can actually do with each. An SPDX id
      # goes on the allow list; free text cannot (the list is space
      # separated) and needs an alias that maps it to an id.
      local ids_spdx ids_text
      ids_spdx="$(LC_ALL=C sort -u "$ids_file" | grep -v '^$' | grep -v ' ' | head -12 | tr '\n' ' ')"
      ids_text="$(LC_ALL=C sort -u "$ids_file" | grep -v '^$' | grep ' ' | grep -vE ' (AND|OR|WITH) ' | head -8)"

      if [[ -n "$ids_spdx" ]]; then
        echo "LICENCES YOUR POLICY DOES NOT COVER — decide on each:"
        echo "  ${ids_spdx% }"
        echo
        echo "  Accept them (append to the list already in ${CONF##*/}):"
        echo "    LICENSING_ALLOW+=(${ids_spdx% })"
        echo "  Refuse them (DENY beats ALLOW, so this is final):"
        echo "    LICENSING_DENY+=(${ids_spdx% })"
        echo
      fi

      # An expression, not free text: it has spaces because SPDX put them
      # there. It cannot go on the space-separated lists either, but the answer
      # is different — name the whole thing, do not alias it to something else.
      local ids_expr
      ids_expr="$(LC_ALL=C sort -u "$ids_file" | grep -E ' (AND|OR|WITH) ' | head -6)"
      if [[ -n "$ids_expr" ]]; then
        echo "SPDX EXPRESSIONS YOUR POLICY DOES NOT COVER:"
        echo "  An \"A AND B\" must satisfy BOTH, and \"A WITH B\" is a licence plus an"
        echo "  exception that modifies it — neither fits a space-separated list. Decide"
        echo "  on the expression as a whole, in ${CONF##*/}:"
        echo
        while IFS= read -r one; do
          [[ -z "$one" ]] && continue
          echo "    LICENSING_ALLOW_EXPRESSIONS+=(\"${one}\")"
        done <<EXPRS
${ids_expr}
EXPRS
        echo
        echo "  Or allow the id that is missing from LICENSING_ALLOW and the expression"
        echo "  follows: \"BSD-3-Clause AND TCL\" clears the moment TCL is allowed."
        echo
      fi

      if [[ -n "$ids_text" ]]; then
        echo "DECLARED AS FREE TEXT, NOT AN SPDX ID OR EXPRESSION:"
        echo "  These cannot go on the allow list — it is space separated. Map each to"
        echo "  the id it means, in ${CONF##*/}, and the verdict follows your policy:"
        echo
        while IFS= read -r one; do
          [[ -z "$one" ]] && continue
          local lower
          lower="$(echo "$one" | tr '[:upper:]' '[:lower:]')"
          echo "    LICENSING_LICENSE_ALIASES+=(\"${lower}|<SPDX-ID>\")   # ${one}"
        done <<INNER
${ids_text}
INNER
        echo
        echo "  A leading/trailing * makes it a glob: \"bsd license*|BSD-3-Clause\"."
        echo
      fi

      # Scopes this repository PUBLISHES, read from its own manifests — not the
      # scopes that happen to fail, which are somebody else's packages.
      local own_scopes
      own_scopes="$(git ls-files '*package.json' 2>/dev/null | grep -v node_modules \
        | while IFS= read -r f; do [[ -f "$f" ]] && grep -h '"name"' "$f" 2>/dev/null; done \
        | sed -n 's|.*"name"[ ]*:[ ]*"\(@[^/"]*\)/.*|\1/*|p' | LC_ALL=C sort -u | head -5 | tr '\n' ' ')"
      echo "PACKAGES THAT ARE YOURS, NOT DEPENDENCIES:"
      echo "  Workspaces of this repository are the product, not something it absorbs."
      echo "  Name them (globs work) in ${CONF##*/} and they leave the gate."
      echo "  What is matched is the NAME alone — what the table above prints before"
      echo "  the \"@\", for every ecosystem at once. So a row reading"
      echo "  \"npm acme@1.2.3\" is named by the bare word acme. The whole name has"
      echo "  to match, so \"acme\" does not cover \"acme-web\" and \"acme*\" does."
      echo "  Quote any pattern containing a glob character:"
      echo
      if [[ -n "$own_scopes" ]]; then
        echo "    LICENSING_SELF_NAMES=(${own_scopes% })   # scopes THIS repo publishes"
      else
        echo "    LICENSING_SELF_NAMES=(\"@yourscope/*\" \"yourapp-*\")"
      fi
      echo
      echo "REVIEWED AND FINE, BUT syft CANNOT MAP THE LICENCE:"
      echo "  Record the package in ${LICENSING_EXCEPTIONS}, one per line, with a reason."
      echo "  Where the scan read NO licence, add the one you found as <name> = <SPDX id>:"
      echo
      LC_ALL=C sort -u "$names_file" | head -3 | sed 's|^|    |; s|$|   # reviewed <date>: <licence>, <why it is fine>|'
      echo
      echo "NOT SHIPPED AT ALL (dev tooling, a sample app, generated fixtures):"
      echo "  LICENSING_IGNORE_PATHS=(\"*/fixtures/*\")    # by WHERE it was found; costs no re-scan"
      echo "  LICENSING_EXCLUDE=(\"./path/**\")            # keep it out of the scan entirely"
      echo "  LICENSING_IGNORE_TYPES=(\"<type>\")          # a whole ecosystem"
      echo "  LICENSING_INSTALL_CHECK_SKIP=(\"apps/demo\")  # a workspace you do not gate"
      echo
      echo "  The paths behind the rows above, most common first:"
      awk -F'\t' '{ p = $4; sub(/ \(\+[0-9]+\)$/, "", p); n = split(p, a, "/")
                    if (n > 2) print "    */" a[n-2] "/" a[n-1] "/*"; else print "    " p }' \
        "$review_file" | LC_ALL=C sort | uniq -c | LC_ALL=C sort -rn | head -5 \
        | awk '{ c = $1; $1 = ""; sub(/^ /, ""); printf "  %-44s # %d component(s)\n", $0, c }'
    } >&3
    report_lockfile_only
    return 1
  fi
  report_lockfile_only
  local extra=""
  [[ $exempt  -gt 0 ]] && extra="${extra}, ${exempt} without licence metadata on a review-exempt type (LICENSING_VERBOSE=1 to list)"
  [[ $skipped  -gt 0 ]] && extra="${extra}, ${skipped} ignored by type"
  [[ $selfskip -gt 0 ]] && extra="${extra}, ${selfskip} skipped as this project itself"
  [[ $subskip  -gt 0 ]] && extra="${extra}, ${subskip} nested sub-package manifest(s) ignored"
  snote "deps: ✓ ${checked} component(s) gated, all outbound-compatible${extra}"
}

# ---------------------------------------------------------------------------
# half 2 — REUSE.toml vendored annotations, from the SAME scan
# ---------------------------------------------------------------------------
toml_enabled() {
  [[ -f "$LICENSING_REUSE_TOML" ]] && grep -qxF "$LICENSING_REUSE_MARKER" "$LICENSING_REUSE_TOML"
}

# Everything in REUSE.toml above the marker, verbatim.
reuse_head() {
  awk -v m="$LICENSING_REUSE_MARKER" '$0==m {exit} {print}' "$LICENSING_REUSE_TOML"
}

# An expression, one id per line.
expr_leaves() { # expr_leaves  (reads stdin)
  awk '{ e = $0; gsub(/[()]/, " ", e); gsub(/ OR /, "\n", e); gsub(/ AND /, "\n", e); print e }' \
    | sed 's/^[ \t]*//; s/[ \t]*$//' | grep -v '^$'
}

# Every licence id this tree ALREADY accounts for: the annotations written by
# hand above the marker, the inline SPDX header of every tracked file, the
# vendored-component blocks this run is about to write, and the project's own
# outbound licences. A text one of those references is a text REUSE already
# calls used — and the notice file exists for the ones nothing accounts for.
#
# Non-circular by construction: reuse_head_licences stops at the marker, so
# the notice annotation from the previous run is never part of this answer.
notice_claimed_ids() { # notice_claimed_ids <generated vendor annotations>
  { [[ -n "$LICENSING_LICENSE" ]] && echo "$LICENSING_LICENSE"
    [[ -n "$LICENSING_DOC_LICENSE" ]] && echo "$LICENSING_DOC_LICENSE"
    reuse_head_licences | cut -f2
    inline_spdx_licences | cut -f2
    [[ -s "$1" ]] && awk -F'"' '/^SPDX-License-Identifier/ { print $2 }' "$1"
  } | expr_leaves | LC_ALL=C sort -u
}

# The dependency licences the notice file has to answer for, AND-joined: found
# by the component scan, holding a text in LICENSES/, and claimed by nothing
# else. Each of the three is load-bearing — see LICENSING_NOTICE_FILE.
notice_licence_expr() { # notice_licence_expr <generated vendor annotations>
  local here="${TMPDIR_RUN}/notice.here" want="${TMPDIR_RUN}/notice.want"
  local claimed="${TMPDIR_RUN}/notice.claimed" id out=""
  licences_present | LC_ALL=C sort -u > "$here"
  syft_wanted_ids | LC_ALL=C sort -u > "$want"
  notice_claimed_ids "$1" > "$claimed"
  while IFS= read -r id; do
    # An id REUSE can read. Anything else would be a "bad license" in the file
    # this annotation is supposed to make compliant.
    case "$id" in
      ""|*[!A-Za-z0-9.+-]*) continue ;;
      [A-Za-z0-9]*) ;;
      *) continue ;;
    esac
    out="${out:+$out AND }${id}"
  done < <(LC_ALL=C comm -12 "$want" "$here" | LC_ALL=C comm -23 - "$claimed")
  echo "$out"
}

# REUSE-IgnoreStart — this function WRITES an SPDX header, so the tag below is
# a template and not a statement about this script. Without the markers the
# lint fails on the file that runs the lint.
#
# The notice file itself, seeded once. Deliberately says nothing that changes:
# the list of licences lives in the REUSE.toml annotation, which the drift
# check keeps honest, and the component-by-licence breakdown is a command away.
# A generated file that went stale in the tree would be worse than no file.
write_notice_file() {
  [[ -e "$LICENSING_NOTICE_FILE" ]] && return 0
  local holder="$LICENSING_COPYRIGHT" lic=""
  # No `git config user.name` fallback: this text is committed and compared
  # across machines, and a holder that differs per developer is drift. The
  # components own their copyright anyway — this file only collects it.
  [[ -z "$holder" ]] && holder="The authors of the components listed in ${LICENSING_LICENSES_DIR}/"
  [[ -n "$LICENSING_DOC_LICENSE" ]] && lic="$LICENSING_DOC_LICENSE"
  [[ -z "$lic" && -n "$LICENSING_LICENSE" ]] && lic="$LICENSING_LICENSE"
  {
    echo "<!--"
    echo "SPDX-FileCopyrightText: ${holder}"
    # Only when the policy names one. Without it the REUSE.toml annotation is
    # the file's licensing information, which is enough for the lint and
    # avoids inventing an outbound licence for a document that collects
    # somebody else's.
    [[ -n "$lic" ]] && echo "${SPDX_ID_TAG} ${lic}"
    echo "-->"
    echo
    echo "# Third-party licences"
    echo
    echo "This product ships components released by their own authors under their"
    echo "own licences. The full text of every one of those licences is in"
    echo "\`${LICENSING_LICENSES_DIR}/\`, and \`${LICENSING_REUSE_TOML}\` names them all against this"
    echo "file, so nothing here is claimed as this project's own work."
    echo
    echo "For which component is under which licence, and what each licence asks of"
    echo "you:"
    echo
    echo "    ${ME} check --obligations --components"
    echo
    echo "Both this file and that list are maintained by \`${ME} download\`."
  } > "$LICENSING_NOTICE_FILE"
  note "wrote ${LICENSING_NOTICE_FILE} — the document that accounts for the dependency licence texts in ${LICENSING_LICENSES_DIR}/. Commit it; edit it freely, it is never rewritten."
  return 0
}
# REUSE-IgnoreEnd

# One annotation claiming those licences for the notice file, so the texts
# they need are texts the tree references.
notice_annotation() { # notice_annotation <expression>
  local expr="$1"
  [[ -n "$LICENSING_NOTICE_FILE" && -n "$expr" ]] || return 0
  if [[ ! -f "$LICENSING_NOTICE_FILE" && "$CMD" == download ]]; then
    # Only a dry run gets here: a real download writes the file first.
    [[ -n "${NOTICE_DRY_NOTED:-}" ]] || note "download: would write ${LICENSING_NOTICE_FILE}"
    NOTICE_DRY_NOTED=1
    return 0
  fi
  if [[ ! -f "$LICENSING_NOTICE_FILE" ]]; then
    note "warning: ${LICENSING_NOTICE_FILE} does not exist, so ${LICENSING_LICENSES_DIR}/ holds licence texts nothing in the tree accounts for and 'reuse lint' fails on them. Run '$(how download --fix)' to write it, or clear LICENSING_NOTICE_FILE and drop the texts with 'download --fix' instead."
    return 0
  fi
  vnote "notice file: ${LICENSING_NOTICE_FILE} accounts for $(echo "$expr" | expr_leaves | wc -l | tr -d ' ') dependency licence(s)"
  printf '\n[[annotations]]\npath = "%s"\nprecedence = "aggregate"\n' "$LICENSING_NOTICE_FILE"
  # Only when the policy states it: a holder derived from `git config
  # user.name` would differ per developer, and REUSE.toml is diffed.
  [[ -n "$LICENSING_COPYRIGHT" ]] && printf 'SPDX-FileCopyrightText = "%s"\n' "$LICENSING_COPYRIGHT"
  printf 'SPDX-License-Identifier = "%s"\n' "$expr"
  return 0
}

# One [[annotations]] block per vendor root git tracks. REUSE needs licensing
# information for every committed file, and vendored files carry no SPDX header
# of this project's. The real licence of each package is checked from the
# component scan and listed in the SBOM; here the root is covered as a whole, so
# REUSE.toml stays the same whatever a given syft version reports.
LICENSING_VENDOR_LICENCE="LicenseRef-vendored-packages"
vendor_annotations() {
  local root
  for root in "${LICENSING_VENDOR_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    # REUSE only ever looks at files git tracks, so an ignored tree (node_modules
    # in nearly every repository) needs no annotation.
    if [[ -z "$(git ls-files -- "$root" | head -1)" ]]; then
      vnote "vendor root ${root} holds no tracked files — no annotation needed"
      continue
    fi
    printf '\n[[annotations]]\npath = "%s/**"\nSPDX-FileCopyrightText = "The authors of each package in %s/"\nSPDX-License-Identifier = "%s"\n' \
      "$root" "$root" "$LICENSING_VENDOR_LICENCE"
  done
  return 0
}

# The text behind that id, written by `download` once and never rewritten.
write_vendor_licence() {
  local f="${LICENSING_LICENSES_DIR}/${LICENSING_VENDOR_LICENCE}.txt"
  [[ -e "$f" ]] && return 0
  mkdir -p "$LICENSING_LICENSES_DIR"
  cat > "$f" <<EOF
${LICENSING_VENDOR_LICENCE}
$(printf '%s' "$LICENSING_VENDOR_LICENCE" | tr '[:print:]' '=')

This is not a licence. It marks third-party code committed to this repository,
in the directories REUSE.toml annotates with it. Each package there keeps its
own licence, stated in the package's own files.

Those licences are checked by licensing.sh against .licensing.conf on every
commit, and listed per package in the SBOM it writes (licensing.sh sbom) and in
its obligations report (licensing.sh check --obligations).
EOF
  note "wrote ${f}"
}

gen_toml() { # gen_toml <out file> [create-notice]
  ensure_scan
  local out="$1" vend="${TMPDIR_RUN}/vendor.toml" expr
  # The vendored blocks first: what they claim is what the notice file does
  # NOT have to claim, so they have to exist before the question is asked.
  vendor_annotations > "$vend"
  expr="$(notice_licence_expr "$vend")"
  # `download` may write the file; `check` may not — it reports and gates, it does
  # not mutate the tree it is gating.
  [[ -n "$expr" && "${2:-}" == create-notice && -n "$LICENSING_NOTICE_FILE" ]] && write_notice_file
  [[ -s "$vend" && "${2:-}" == create-notice ]] && write_vendor_licence
  {
    reuse_head
    echo "$LICENSING_REUSE_MARKER"
    echo "${LICENSING_SYFT_STAMP}$(syft_version)"
    notice_annotation "$expr"
    cat "$vend"
  } > "$out"
}

check_toml() {
  toml_enabled || { snote "toml: ${LICENSING_REUSE_TOML} carries no generated section — hand-maintained, lint only"; return 0; }
  local gen="${TMPDIR_RUN}/REUSE.toml.gen"
  gen_toml "$gen"
  [[ -n "${LICENSING_DEBUG_DIR:-}" ]] && cp "$gen" "${LICENSING_DEBUG_DIR}/REUSE.gen"
  [[ -f "$LICENSING_REUSE_TOML" ]] && warn_syft_changed "$LICENSING_REUSE_TOML"
  without_stamp "$gen" > "${gen}.cmp"
  without_stamp "$LICENSING_REUSE_TOML" > "${TMPDIR_RUN}/REUSE.toml.cur" 2>/dev/null || true
  if [[ ! -f "$LICENSING_REUSE_TOML" ]] || ! diff -q "${TMPDIR_RUN}/REUSE.toml.cur" "${gen}.cmp" >/dev/null; then
    echo "✗ ${LICENSING_REUSE_TOML} is out of date with the component scan:" >&3
    diff -u "${TMPDIR_RUN}/REUSE.toml.cur" "${gen}.cmp" 2>/dev/null | head -40 >&3 || true
    echo >&3
    echo "Run: $(how download --fix)" >&3
    return 1
  fi
  snote "toml: ✓ ${LICENSING_REUSE_TOML} matches the component scan ($(grep -c '^\[\[annotations\]\]' "$LICENSING_REUSE_TOML") annotation blocks)"
}

# Bring the generated section of REUSE.toml up to date. `download` runs this, so
# the licence texts in LICENSES/ and the annotations that account for them are
# maintained by one command. A REUSE.toml with no marker line is hand-maintained
# and left alone; --dry-run only says whether it would change.
sync_toml() {
  toml_enabled || { vnote "toml: ${LICENSING_REUSE_TOML} has no marker line — hand-maintained, left as it is"; return 0; }
  local gen="${TMPDIR_RUN}/REUSE.toml.gen"
  if [[ "$DRY_RUN" == 1 ]]; then
    gen_toml "$gen"
    # download runs this twice; say it once.
    if [[ -z "${TOML_DRY_NOTED:-}" ]] && ! diff -q "$LICENSING_REUSE_TOML" "$gen" >/dev/null 2>&1; then
      note "download: would update ${LICENSING_REUSE_TOML}"; TOML_DRY_NOTED=1
    fi
    return 0
  fi
  gen_toml "$gen" create-notice
  diff -q "$LICENSING_REUSE_TOML" "$gen" >/dev/null 2>&1 && return 0
  cp "$gen" "$LICENSING_REUSE_TOML"
  note "download: updated ${LICENSING_REUSE_TOML} ($(grep -c '^\[\[annotations\]\]' "$LICENSING_REUSE_TOML") annotation blocks)"
}

# ---------------------------------------------------------------------------
# half 2b — REUSE lint over the whole tree
# ---------------------------------------------------------------------------
reuse_wanted() {
  if [[ "$LICENSING_REUSE" == 0 ]]; then
    note "warning: REUSE lint is switched OFF (LICENSING_REUSE=0). File-level SPDX licensing is unchecked — this is an onboarding escape hatch, not a steady state."
    return 1
  fi
  return 0
}

# How many offending files to name per category under --verbose. A tree that
# has never been annotated fails on every file in it, and forty thousand paths
# is not a report.
LICENSING_LINT_MAX_FILES=200

# What each of reuse's non-compliance categories means, and what closes it.
# <json key>|<what it is>|<what to do>
LICENSING_LINT_CATEGORIES=(
  "missing_licensing_info|files with no licence information|add an inline SPDX-License-Identifier header, or a REUSE.toml annotation above the marker"
  "missing_copyright_info|files with no copyright information|add an inline SPDX-FileCopyrightText header, or a REUSE.toml annotation above the marker"
  "missing_licenses|licences referred to but absent from ${LICENSING_LICENSES_DIR}/|$(how download --all)"
  "unused_licenses|licence texts in ${LICENSING_LICENSES_DIR}/ that nothing refers to|$(how download --fix)"
  "bad_licenses|licence ids SPDX does not recognise|fix the id, or map it in LICENSING_LICENSE_ALIASES"
  "deprecated_licenses|licence ids SPDX has deprecated|replace with the current id (GPL-2.0 -> GPL-2.0-only, and so on)"
  "licenses_without_extension|licence texts whose file name has no .txt|rename them to <SPDX-ID>.txt"
  "read_errors|files reuse could not read|check the permissions"
)

# The failing categories, with counts, from reuse's own machine-readable
# report. `reuse lint -q` says only that something failed, and the fixed
# checklist that used to print here was a GUESS at why — a guess that was
# wrong in the case that prompted this: REUSE.toml had a missing comma, reuse
# never parsed it, not one file had been looked at, and the output said to go
# add SPDX headers.
lint_files() {
  reuse_wanted || return 0
  need_reuse || missing_tool reuse '"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }'
  local t0=$SECONDS
  tnote "linting every file for SPDX copyright + licence info"
  if "${REUSE[@]}" lint -q; then
    snote "lint: ✓ every file carries SPDX copyright + licence info ($(since $t0))"
    return 0
  fi

  local json="${TMPDIR_RUN}/reuse-lint.json" jerr="${TMPDIR_RUN}/reuse-lint.err"
  "${REUSE[@]}" lint --json > "$json" 2> "$jerr" || :
  if ! grep -q '"non_compliant"' "$json" 2>/dev/null; then
    # reuse could not produce a report at all, so it never reached the files.
    # Its own message is the answer here and the checklist below is noise.
    {
      echo
      echo "✗ REUSE lint could not run — it did not get as far as looking at any file:"
      echo
      sed 's/^/    /' "$jerr" | grep -v '^ *$' | head -12
      [[ -s "$json" ]] && sed 's/^/    /' "$json" | grep -v '^ *$' | head -6
      echo
      echo "  A REUSE.toml that will not parse is the usual cause — the message above"
      echo "  names the line. Everything ABOVE the marker line is hand-written, so that"
      echo "  is where to look; $(how download --fix) regenerates only what is below it."
    } >&3
    return 1
  fi

  # <key>TAB<count>, in the order reuse emitted them, plus the file lists for
  # --verbose. Two-space indent is the nesting, the same shape reuse_wanted_ids
  # relies on.
  local counts="${TMPDIR_RUN}/lint-counts"
  awk '
    /^  "non_compliant": \{$/ { sect = 1; next }
    !sect                     { next }
    /^  [\]}]/               { exit }
    /^    "[a-z_]+": [\[{]$/ { key = $0; sub(/^    "/, "", key); sub(/".*/, "", key)
                                order[++k] = key; n[key] = 0; next }
    /^    [\]}]/             { key = ""; next }
    key == ""                 { next }
    /^      "/                { n[key]++
                                v = $0; sub(/^[ \t]*"/, "", v); sub(/"[,:].*$/, "", v); sub(/",?[ \t]*$/, "", v)
                                if (index(v, root) == 1) v = substr(v, length(root) + 1)
                                # RS-separated, not newline separated: this is
                                # one TSV field and a newline would end the
                                # record the shell reads it out of.
                                if (n[key] <= cap) f[key] = f[key] "\036" v
                                next }
    END { for (i = 1; i <= k; i++) if (n[order[i]] > 0) printf "%s\t%d\t%s\n", order[i], n[order[i]], f[order[i]] }
  ' root="${REPO_ROOT}/" cap="$LICENSING_LINT_MAX_FILES" "$json" > "$counts"

  local key cnt files entry what todo total=0
  {
    echo
    echo "✗ REUSE lint failed. What it objected to:"
    echo
    while IFS=$'\t' read -r key cnt files; do
      [[ -z "$key" ]] && continue
      total=$(( total + cnt ))
      what="$key"; todo=""
      for entry in ${LICENSING_LINT_CATEGORIES[@]+"${LICENSING_LINT_CATEGORIES[@]}"}; do
        [[ "${entry%%|*}" == "$key" ]] || continue
        entry="${entry#*|}"; what="${entry%%|*}"; todo="${entry#*|}"
        break
      done
      printf '  %s%-6s%s %s\n' "$C_REVIEW" "$cnt" "$C_RESET" "$what"
      [[ -n "$todo" ]] && echo "         -> ${todo}"
      if [[ -n "${LICENSING_VERBOSE:-}" && -n "$files" ]]; then
        printf '%s\n' "${files//$'\036'/$'\n        '}" | grep -v '^ *$'
        [[ "$cnt" -gt "$LICENSING_LINT_MAX_FILES" ]] && \
          echo "        … and $(( cnt - LICENSING_LINT_MAX_FILES )) more (${REUSE[*]} lint prints all of them)"
      fi
    done < "$counts"
    echo
    [[ -z "${LICENSING_VERBOSE:-}" ]] && echo "  --verbose lists the files under each. So does '${REUSE[*]} lint'."
    echo "  New third-party or vendored code?  ->  $(how download --fix)"
    echo "  First-party source or doc?         ->  add an inline SPDX header"
  } >&3
  return 1
}

# ---------------------------------------------------------------------------
# download — LICENSES/ in step with what the tree actually carries
# ---------------------------------------------------------------------------
# `reuse download --all` fetches the texts REUSE can see: the ids in inline
# headers and in REUSE.toml. It cannot see the component scan, and it never
# takes anything away — so LICENSES/ drifts in both directions at once. A
# vendored module is dropped and its licence text stays behind forever; a
# dependency arrives under a licence whose text was never fetched. Both halves
# of this script already know which licences the tree carries, so both halves
# answer the question here, and `--fix` answers the other direction too.
#
# `reuse lint` fails on an UNUSED licence text as readily as on a missing one,
# which is why the removal half exists and why LICENSING_LICENSE_SOURCES
# matters: a text fetched for a component that is not IN the tree (a
# dependency downloaded at build time rather than vendored) is unused by
# REUSE's reckoning and fails the lint. A repository that vendors its
# dependencies wants both sources; one that does not wants "reuse".

# Every id LICENSES/ already holds a text for, one per line. The extension is
# stripped rather than required: REUSE wants .txt, and a text saved without
# one is a file the lint complains about but this command must still see.
licences_present() {
  local f b
  [[ -d "$LICENSING_LICENSES_DIR" ]] || return 0
  for f in "$LICENSING_LICENSES_DIR"/*; do
    [[ -f "$f" ]] || continue
    b="${f##*/}"
    case "$b" in .*) continue ;; esac
    b="${b%.txt}"; b="${b%.md}"
    echo "$b"
  done
}

# The file(s) holding the text for one id — the inverse of licences_present.
licence_files_for_id() { # licence_files_for_id <id>
  local f b
  [[ -d "$LICENSING_LICENSES_DIR" ]] || return 0
  for f in "$LICENSING_LICENSES_DIR"/*; do
    [[ -f "$f" ]] || continue
    b="${f##*/}"; b="${b%.txt}"; b="${b%.md}"
    [[ "$b" == "$1" ]] && echo "$f"
  done
  return 0
}

# Every id REUSE needs a text for: the ones it found in the tree, plus the
# ones it is already reporting as missing. Read from `reuse lint --json`,
# which is the only place that answers BOTH in one pass — and which exits 1
# on a non-compliant tree, the normal case for a command whose whole job is
# to make it compliant.
reuse_wanted_ids() {
  need_reuse || missing_tool reuse '"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }'
  local json="${TMPDIR_RUN}/reuse-lint.json"
  "${REUSE[@]}" lint --json > "$json" 2> "${json}.err" || true
  if ! grep -q '"summary"' "$json"; then
    # Its own message, not just the fact that there wasn't one: the usual
    # cause is a REUSE.toml that will not parse, and reuse names the line.
    die "'${REUSE[*]} lint --json' produced no report, so there is no way to tell which licences this tree uses. It said:
$(sed 's/^/    /' "${json}.err" 2>/dev/null | grep -v '^ *$' | head -8)"
  fi
  # reuse writes this with a two-space indent, so the nesting is the column:
  # a key at column 3 opens a section, a key at column 5 opens a list, and
  # everything inside one is a bare quoted string.
  awk '
    /^  "non_compliant": \{$/ { sect = "nc";  next }
    /^  "summary": \{$/       { sect = "sum"; next }
    /^  "/                    { sect = ""; key = ""; next }
    sect == ""                { next }
    /^    "[a-z_]+": \[$/     { key = $0; sub(/^    "/, "", key); sub(/".*/, "", key); next }
    /^    [\]}]/              { key = ""; next }
    key == ""                 { next }
    (sect == "nc" && key == "missing_licenses") ||
    (sect == "sum" && key == "used_licenses") {
      v = $0; sub(/^[ \t]*"/, "", v); sub(/",?[ \t]*$/, "", v)
      if (v != "") print v
    }
  ' "$json"
}

# Every id the component scan found, as leaves: a duty — and a licence text —
# attaches to a leaf and never to the choice between two of them.
syft_wanted_ids() {
  ensure_scan
  local raw
  awk -F'|' '{ print $5 }' "$SCAN" | tr ';' '\n' | LC_ALL=C sort -u \
    | while IFS= read -r raw; do
        [[ -z "$raw" || "$raw" == sha256:* ]] && continue
        placeholder_lic "$raw" && continue
        normalize_expr "$raw"
      done \
    | awk '
        {
          e = $0
          gsub(/[()]/, " ", e)
          gsub(/ OR /, "|", e); gsub(/ AND /, "|", e); gsub(/, /, "|", e)
          n = split(e, a, "|")
          for (i = 1; i <= n; i++) {
            id = a[i]
            gsub(/^[ \t]+|[ \t]+$/, "", id)
            if (id != "") print id
          }
        }'
}

# An id `reuse download` can actually fetch: an SPDX id, and not a
# LicenseRef-, which names a text that exists nowhere but in this repository.
downloadable_id() { # downloadable_id <id>
  case "$1" in
    LicenseRef-*|"") return 1 ;;
    *[!A-Za-z0-9.+-]*) return 1 ;;
    [A-Za-z0-9]*) return 0 ;;
    *) return 1 ;;
  esac
}

cmd_download() { # cmd_download <all|fix>
  local what="$1" src id f rc=0
  local want="${TMPDIR_RUN}/lic.want" here="${TMPDIR_RUN}/lic.here"
  local missing_ids="" byhand_ids="" failed_ids="" stale_ids=""
  local got=0 gone=0

  progress_init
  progress_plan 2
  : > "$want"
  for src in $LICENSING_LICENSE_SOURCES; do
    case "$src" in
      reuse) reuse_wanted_ids >> "$want" ;;
      syft)  syft_wanted_ids  >> "$want" ;;
      *) die "unknown entry in LICENSING_LICENSE_SOURCES: ${src} (reuse syft)" ;;
    esac
  done
  progress_step
  LC_ALL=C sort -u -o "$want" "$want"
  licences_present | LC_ALL=C sort -u > "$here"
  vnote "licences in use: $(tr '\n' ' ' < "$want")"
  vnote "texts on disk:   $(tr '\n' ' ' < "$here")"

  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    if downloadable_id "$id"; then missing_ids="${missing_ids}${id} "
    else byhand_ids="${byhand_ids}${id} "; fi
  done < <(LC_ALL=C comm -23 "$want" "$here")
  while IFS= read -r id; do
    [[ -n "$id" ]] && stale_ids="${stale_ids}${id} "
  done < <(LC_ALL=C comm -13 "$want" "$here")

  for id in $missing_ids; do
    if [[ "$DRY_RUN" == 1 ]]; then
      note "download: would fetch ${LICENSING_LICENSES_DIR}/${id}.txt"
      got=$((got+1)); continue
    fi
    if "${REUSE[@]}" download "$id" >/dev/null 2>&1; then
      note "download: + ${LICENSING_LICENSES_DIR}/${id}.txt"
      got=$((got+1))
    else
      failed_ids="${failed_ids}${id} "
    fi
  done

  if [[ "$what" == fix ]]; then
    for id in $stale_ids; do
      while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ "$DRY_RUN" == 1 ]]; then
          note "download: would remove ${f} (no file and no component uses ${id})"
          gone=$((gone+1)); continue
        fi
        if git ls-files --error-unmatch -- "$f" >/dev/null 2>&1; then
          git rm -q -f -- "$f"
        else
          rm -f -- "$f"
        fi
        note "download: - ${f} (no file and no component uses ${id})"
        gone=$((gone+1))
      done < <(licence_files_for_id "$id")
    done
  fi
  progress_step

  [[ -n "$byhand_ids" ]] && {
    note "download: no text on disk for ${byhand_ids}— a LicenseRef- names a text only this repository has, so write it into ${LICENSING_LICENSES_DIR}/ by hand"
    rc=1
  }
  [[ -n "$failed_ids" ]] && {
    note "download: could not fetch: ${failed_ids}(unknown to the SPDX licence list, or no network)"
    rc=1
  }
  if [[ "$what" != fix && -n "$stale_ids" ]]; then
    note "download: unused text(s) on disk for ${stale_ids}— nothing in the tree and no component carries them; 'download --fix' removes them (reuse lint fails on an unused licence)"
  fi
  if [[ "$got" == 0 && "$gone" == 0 ]]; then
    snote "download: ✓ ${LICENSING_LICENSES_DIR}/ already holds every licence this tree uses ($(wc -l < "$here" | tr -d ' ') text(s))"
  else
    note "download: ${got} fetched, ${gone} removed$([[ "$DRY_RUN" == 1 ]] && echo " (dry run — nothing was written)")"
  fi
  progress_end "$rc"
  return "$rc"
}

# ---------------------------------------------------------------------------
# sbom
# ---------------------------------------------------------------------------
# SPDX 2.3 JSON, written from the MERGED INVENTORY rather than from a syft
# invocation of its own — because a single syft invocation cannot see what this
# script's inventory has already established.
#
# On a monorepo with a poetry-managed Python service, one `syft scan dir:.`
# catalogued its 236 packages from poetry.lock and reported a licence for NONE
# of them: poetry keeps the installed packages in a cache directory, syft was
# pointed at the tree, and a lockfile carries versions and not licences. The
# inventory behind `check` had 222 of those licences, because it also reads the
# package caches the preflight found, re-scans the manifests that must be read
# in isolation, and
# falls back to dist-info metadata and the LICENSE text a package ships. An
# SBOM is a statement about what you ship and under what terms; emitting the
# poorer of the two answers because it came out of one command would be a
# strange thing to do.
#
# What is given up by not using syft's own writer: CPEs and syft's per-package
# metadata blocks. Package URLs are emitted for the ecosystems where they can
# be built unambiguously, which is what a vulnerability scanner matches on. For
# syft's native formats — CycloneDX, syft-json, tag-value — run syft directly;
# just know that what comes back is the tree and nothing else.
emit_sbom() {
  local out="${1:-sbom.spdx.json}"
  ensure_scan
  [[ -s "$SCAN" ]] || fail "sbom: the scan found no components — refusing to write an empty SBOM to ${out}"

  # Licence values, normalised ONCE per distinct string rather than once per
  # component: there are a few hundred of the former and ten thousand of the
  # latter, and normalize_expr is a subshell.
  local map="${TMPDIR_RUN}/sbom.licmap" l
  awk -F'|' '{ n = split($5, a, ";"); for (i = 1; i <= n; i++) if (a[i] != "") print a[i] }' "$SCAN" \
    | LC_ALL=C sort -u \
    | while IFS= read -r l; do
        [[ -z "$l" || "$l" == sha256:* ]] && continue
        printf '%s\t%s\n' "$l" "$(normalize_expr "$l")"
      done > "$map"

  local created ns name
  created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  name="$(basename "$REPO_ROOT")"
  # A namespace has to be unique per document, and the SBOM of a tree that has
  # not changed should still be a different document each time it is written.
  ns="https://spdx.org/spdxdocs/${name}-$(printf '%s' "${REPO_ROOT}${created}" | digest)"

  awk -F'\t' -v created="$created" -v ns="$ns" -v docname="$name" \
      -v tool="licensing.sh-$(script_version)" -v syftv="$(syft_version)" '
    function esc(s,   t) {
      t = s
      gsub(/\\/, "\\\\", t); gsub(/"/, "\\\"", t)
      gsub(/\t/, "\\t", t); gsub(/\r/, "\\r", t); gsub(/\n/, "\\n", t)
      return t
    }
    # A licence goes into an SBOM as an SPDX expression or not at all. Anything
    # the grammar would reject becomes a LicenseRef- carrying the same text, so
    # the information survives in the one shape a reader is allowed to parse;
    # nothing is silently downgraded to NOASSERTION that actually said
    # something.
    function spdx_expr(e,   r) {
      if (e == "") return "NOASSERTION"
      if (e ~ /^[A-Za-z0-9.+()-]+([ ](AND|OR|WITH)[ ][A-Za-z0-9.+()-]+)*$/) return e
      r = e
      gsub(/[^A-Za-z0-9.-]/, "-", r)
      gsub(/-+/, "-", r); sub(/^-/, "", r); sub(/-$/, "", r)
      if (length(r) > 60) r = substr(r, 1, 60)
      if (r == "") return "NOASSERTION"
      return "LicenseRef-" r
    }
    # Package URL for the ecosystems whose name alone identifies the package.
    # java-archive needs a Maven group that the scan does not carry, and a purl
    # invented without one would point at the wrong artifact — so those get no
    # externalRef rather than a wrong one.
    function purl(type, n, v,   pt) {
      pt = ""
      if (type == "npm") pt = "npm"
      else if (type == "python") pt = "pypi"
      else if (type == "rust-crate") pt = "cargo"
      else if (type == "go-module") pt = "golang"
      else if (type == "gem") pt = "gem"
      else if (type == "dart-pub") pt = "pub"
      else if (type == "pod") pt = "cocoapods"
      else if (type == "github-action" || type == "github-action-workflow") pt = "github"
      if (pt == "" || n == "") return ""
      return "pkg:" pt "/" n (v != "" && v != "UNKNOWN" ? "@" v : "")
    }
    # FILENAME, not NR == FNR: with no licence anywhere the map is empty, and
    # NR == FNR is then true for every inventory line, which emptied the SBOM.
    FILENAME == ARGV[1] { norm[$1] = $2; next }
    {
      # The inventory is pipe separated; this pass reads it as such.
      nf = split($0, f, "|")
      if (nf < 5) next
      type = f[1]; pname = f[2]; ver = f[3]; lics = f[5]
      if (pname == "") next
      n = split(lics, a, ";")
      expr = ""
      for (i = 1; i <= n; i++) {
        one = a[i]
        if (one == "" || one ~ /^sha256:/) continue
        one = (one in norm) ? norm[one] : one
        if (one == "" || (one in seen_in_row)) continue
        seen_in_row[one] = 1
        expr = expr (expr == "" ? "" : " AND ") spdx_expr(one)
      }
      delete seen_in_row
      if (expr == "") expr = "NOASSERTION"
      npkg++
      id[npkg] = "SPDXRef-Package-" npkg
      pn[npkg] = pname; pv[npkg] = ver; pl[npkg] = expr; pu[npkg] = purl(type, pname, ver)
    }
    END {
      print "{"
      print "  \"spdxVersion\": \"SPDX-2.3\","
      print "  \"dataLicense\": \"CC0-1.0\","
      print "  \"SPDXID\": \"SPDXRef-DOCUMENT\","
      print "  \"name\": \"" esc(docname) "\","
      print "  \"documentNamespace\": \"" esc(ns) "\","
      print "  \"creationInfo\": {"
      print "    \"created\": \"" created "\","
      print "    \"creators\": [\"Tool: " esc(tool) "\", \"Tool: syft-" esc(syftv) "\"]"
      print "  },"
      print "  \"packages\": ["
      for (k = 1; k <= npkg; k++) {
        print "    {"
        print "      \"SPDXID\": \"" id[k] "\","
        print "      \"name\": \"" esc(pn[k]) "\","
        print "      \"versionInfo\": \"" esc(pv[k]) "\","
        print "      \"downloadLocation\": \"NOASSERTION\","
        print "      \"filesAnalyzed\": false,"
        print "      \"licenseConcluded\": \"" esc(pl[k]) "\","
        print "      \"licenseDeclared\": \"" esc(pl[k]) "\","
        print "      \"copyrightText\": \"NOASSERTION\"" (pu[k] != "" ? "," : "")
        if (pu[k] != "") {
          print "      \"externalRefs\": [{"
          print "        \"referenceCategory\": \"PACKAGE-MANAGER\","
          print "        \"referenceType\": \"purl\","
          print "        \"referenceLocator\": \"" esc(pu[k]) "\""
          print "      }]"
        }
        print "    }" (k < npkg ? "," : "")
      }
      print "  ],"
      print "  \"relationships\": ["
      for (k = 1; k <= npkg; k++)
        print "    {\"spdxElementId\": \"SPDXRef-DOCUMENT\", \"relatedSpdxElement\": \"" id[k] "\", \"relationshipType\": \"DESCRIBES\"}" (k < npkg ? "," : "")
      print "  ]"
      print "}"
    }
  ' "$map" "$SCAN" > "$out"

  local total withlic
  total="$(wc -l < "$SCAN" | tr -d ' ')"
  withlic="$(awk -F'|' '$5 !~ /^[ \t;]*$/' "$SCAN" | wc -l | tr -d ' ')"
  note "sbom: wrote ${out} — ${total} component(s), ${withlic} with a licence"
}

# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------
write_template() {
  if [[ -e "$CONF" ]]; then
    note "${CONF##*/} already exists — kept as is"
    return 0
  fi
  cat > "$CONF" <<'TEMPLATE'
# Licensing policy for this repository — read by licensing.sh.
#
# The script ships NO licence policy of its own and will not run without this
# file. A licence policy is a statement about what this product may absorb, so
# it is written down in the repository it governs and reviewed in a pull
# request, never inherited from whatever version of a script happens to be
# installed.
#
# Sourced as bash. Only the two lists below are mandatory; every other setting
# has a default, documented in README.md of
# https://github.com/bokysan/pre-commit-hooks.
#
# Verdict order per component: DENY beats everything, then ALLOW, then
# .license-exceptions.txt, then REVIEW (fail). A licence on both lists is
# denied; a licence on neither fails as "needs review" rather than passing
# quietly.

# Both lists are ARRAYS, one SPDX id per element. One id per line so that
# adding or removing one is a one-line diff and two branches doing it do not
# conflict. A whole EXPRESSION ("BSD-3-Clause AND TCL", or a licence with an
# SPDX exception) has a space in it and goes in the _EXPRESSIONS arrays at the
# bottom instead — it is refused here, with the line to write.

# What this product's outbound licence can absorb. As written this is the
# strictest useful policy and works as-is: permissive + public domain in, no
# copyleft of any strength. Widen it deliberately — alternatives below.
LICENSING_ALLOW=(
  MIT
  MIT-0
  BSD-2-Clause
  BSD-3-Clause
  BSD-3-Clause-Clear
  Apache-2.0
  ISC
  CC0-1.0
  Unlicense
  0BSD
  Zlib
  BSL-1.0
  BlueOak-1.0.0
  Python-2.0
  PSF-2.0
  CNRI-Python
)

# Never acceptable, whatever ALLOW says. DENY beats ALLOW, so an id you decide
# to allow must also be removed from here.
LICENSING_DENY=(
  GPL-1.0-only
  GPL-1.0-or-later
  GPL-2.0-only
  GPL-2.0-or-later
  GPL-3.0-only
  GPL-3.0-or-later
  AGPL-1.0
  AGPL-3.0-only
  AGPL-3.0-or-later
  LGPL-2.0
  LGPL-2.1-only
  LGPL-2.1-or-later
  LGPL-3.0-only
  LGPL-3.0-or-later
  CDDL-1.0
  CDDL-1.1
  EPL-1.0
  EPL-2.0
  EUPL-1.1
  EUPL-1.2
  MS-PL
  MS-RL
  SSPL-1.0
  BUSL-1.1
  Commons-Clause
  FSL-1.1-MIT
  FSL-1.1-ALv2
  Elastic-2.0
)

# --- alternatives: replace the two lists above with one of these ------------
#
#   # MPL-2.0 product — the strict policy plus per-file copyleft. MPL is not
#   # denied above, so this is one line added to ALLOW:
#   LICENSING_ALLOW+=(MPL-2.0)
#
#   # All weak copyleft (MPL/EPL/CDDL/LGPL). DENY beats ALLOW, so the same ids
#   # must also leave the deny list — edit them out of it rather than adding
#   # here alone, or nothing changes:
#   LICENSING_ALLOW+=(MPL-2.0 EPL-2.0 CDDL-1.1 LGPL-2.1-or-later LGPL-3.0-or-later)
#
#   # GPL-licensed product — strong copyleft in, source-available out:
#   LICENSING_ALLOW+=(MPL-2.0 GPL-2.0-or-later GPL-3.0-only LGPL-3.0-or-later)
#   LICENSING_DENY=(AGPL-3.0-only AGPL-3.0-or-later SSPL-1.0 BUSL-1.1 Commons-Clause)
#
#   # Inventory / audit run — nothing pre-approved, every component reported
#   # so a human can classify it:
#   LICENSING_ALLOW=()
#
#   # A licence with an SPDX exception, or an "A AND B" you have decided on as
#   # a whole. These take a full expression, spaces and all:
#   LICENSING_ALLOW_EXPRESSIONS=("GPL-2.0-only WITH Classpath-exception-2.0"
#                                "BSD-3-Clause AND TCL")
#   LICENSING_DENY_EXPRESSIONS=("MIT AND Commons-Clause")

# --- this project's own identity, used when seeding REUSE.toml --------------
# The whole SPDX-FileCopyrightText value, so a company (not the individual in
# `git config user.name`) can hold the copyright, with a year range if needed.
# LICENSING_COPYRIGHT="2019-2026 ACME Inc."
# LICENSING_LICENSE="Apache-2.0"          # outbound licence of the code
# LICENSING_DOC_LICENSE="CC-BY-4.0"       # outbound licence of the docs

# --- optional: uncomment what differs from the documented defaults ----------
# LICENSING_SCAN_TARGET="dir:."           # or "file:go.mod", "dir:src", …
# LICENSING_SELF_NAMES=("github.com/you/project")  # this project, not a dep
# LICENSING_EXCEPTIONS=".license-exceptions.txt"
# LICENSING_EXCLUDE=("./testdata/**")     # extra syft --exclude globs
# LICENSING_IGNORE_TYPES=()               # component types outside the gate
# LICENSING_REVIEW_EXEMPT_TYPES=("github-action" "github-action-workflow")  # no licence metadata is OK
# LICENSING_VENDOR_ROOTS=("vendor" "node_modules")
# LICENSING_TOOL_RUNNER="auto"            # auto|mise|path — how syft/reuse run
# LICENSING_REUSE="1"                     # 1 = REUSE lint required (default)
# LICENSING_LICENSES_DIR="LICENSES"       # where `download` puts licence texts
# LICENSING_LICENSE_SOURCES="reuse syft"  # what `download` counts as "in use";
#                                         # drop syft if you do not vendor
# LICENSING_NOTICE_FILE="THIRD-PARTY-LICENSES.md"  # the document that accounts
#                                         # for the dependency licence texts;
#                                         # `download` writes it when needed.
#                                         # "" = never; drop the texts instead
# LICENSING_LOCAL_MODE="full"             # mode for `--mode auto` outside CI
# LICENSING_SCAN_JOBS="auto"              # parallel syft workers; 1 = one scan
# LICENSING_CACHE=1                       # re-use the last scan when nothing changed
# LICENSING_CACHE_MAX_AGE_DAYS=30         # how long an unused cache entry lives
# LICENSING_IGNORE_PATHS=("*/fixtures/*") # not a dependency; matched on the path
# LICENSING_LICENSE_ALIASES+=("<lowercased glob>|<SPDX-ID>")   # declared text -> id
# LICENSING_LICENSE_ALIASES_LAST+=("<glob>|<SPDX-ID>")         # ... as a last resort
# LICENSING_SKIP_VENDORED_SUBPATHS=1      # drop npm fixtures/templates/bundled copies
# LICENSING_SCAN_HEAVY_MIN_ENTRIES=200    # installed packages that make it split
# LICENSING_PROGRESS="auto"               # OSC 9;4 progress bar: auto|on|off
# LICENSING_COLOR="auto"                  # coloured findings table: auto|on|off
# LICENSING_DUTIES+=("<code>|<what it obliges you to do>")   # a matrix row
# LICENSING_OBLIGATIONS+=("<SPDX-ID>|<duty codes>|<note>")   # which apply where
# LICENSING_MAX_FINDINGS=0                # 0 = print every failing component;
#                                         # a positive N shows the first N

# REUSE.toml is edited in place, not generated from here: write your own
# annotations at the top of it, then put the marker line above where the
# vendored-component section should go. `licensing.sh download` rewrites everything
# below the marker and leaves everything above it alone. No marker = the file
# is hand-maintained and only linted.
TEMPLATE
  # The identity `init` was given (environment, see the init branch below) is
  # written in as real settings: `download` and `check` use it on every run, so
  # it cannot live only in the environment of the one run that seeded the tree.
  local k v
  for k in LICENSING_COPYRIGHT LICENSING_LICENSE LICENSING_DOC_LICENSE; do
    v="${!k}"
    [[ -n "$v" ]] || continue
    awk -v k="$k" -v v="$v" '
      !done && index($0, "# " k "=") == 1 { print k "=\"" v "\""; done = 1; next } { print }
    ' "$CONF" > "${CONF}.new" && mv "${CONF}.new" "$CONF"
  done
  note "wrote ${CONF}"
}

# Starter REUSE.toml: version, the marker, and annotations for the files that
# typically cannot carry an inline SPDX header. Source files that CAN carry one
# should — precedence="closest" lets a header win over every glob here.
write_reuse_toml() {
  if [[ -e "$LICENSING_REUSE_TOML" ]]; then
    if toml_enabled; then
      note "${LICENSING_REUSE_TOML} already exists — kept as is"
    else
      note "${LICENSING_REUSE_TOML} already exists with no generated section — kept as is. To have vendored components filled in, add this line where that section should start:"
      note "  ${LICENSING_REUSE_MARKER}"
    fi
    return 0
  fi
  local holder lic doclic
  holder="$LICENSING_COPYRIGHT"
  if [[ -z "$holder" ]]; then
    holder="$(git config user.name 2>/dev/null || true)"
    [[ -z "$holder" ]] && holder="<COPYRIGHT HOLDER>"
    holder="$(date +%Y) ${holder}"
  fi
  lic="${LICENSING_LICENSE:-<SPDX-LICENSE-ID>}"
  doclic="${LICENSING_DOC_LICENSE:-<SPDX-DOC-LICENSE-ID>}"
  cat > "$LICENSING_REUSE_TOML" <<EOF
version = 1
# REUSE (https://reuse.software) annotations for files that cannot carry an
# inline SPDX header: config, data, fixtures, binaries, vendored code.
#
# Source files that CAN carry a header should carry one — precedence="closest"
# lets an inline header win over every glob below, and a header travels with
# the file when someone copies it out of this repository.
#
# Hand-written above the marker line; everything below it is written by
# \`${ME} download\` from the component scan. Do not edit below the marker.
#
# Any <SPDX-…> placeholder below must be replaced: \`reuse lint\` fails until
# the ids are real (deliberate — a wrong-but-valid default would lint green
# while declaring the wrong licence). Set LICENSING_COPYRIGHT /
# LICENSING_LICENSE / LICENSING_DOC_LICENSE in .licensing.conf to have them
# filled in for you.

# build, packaging, tooling, CI, config and test data
[[annotations]]
path = [
    "*.sh", "*.bash", "*.yml", "*.yaml", "*.toml", "*.json", "*.ini", "*.cfg",
    "Dockerfile", "Dockerfile.*", "docker-compose*.yml", ".dockerignore",
    "Makefile", "Justfile", "Taskfile.yml",
    ".gitignore", ".gitattributes", ".editorconfig", ".gitmodules",
    ".pre-commit-config.yaml", ".licensing.conf", ".license-exceptions.txt",
    ".vale.ini", ".vale/**",
    ".github/**", ".forgejo/**", ".gitlab-ci.yml", ".githooks/**",
    "scripts/**", "tools/**", "contrib/**", "examples/**",
    "**/testdata/**", "**/fixtures/**",
    "go.mod", "go.sum", "vendor/modules.txt",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.toml", "Cargo.lock", "requirements*.txt", "pyproject.toml",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "Package.swift",
]
precedence = "closest"
SPDX-FileCopyrightText = "${holder}"
SPDX-License-Identifier = "${lic}"

# documentation
[[annotations]]
path = ["*.md", "docs/**", "specs/**"]
precedence = "closest"
SPDX-FileCopyrightText = "${holder}"
SPDX-License-Identifier = "${doclic}"

${LICENSING_REUSE_MARKER}
EOF
  if grep -q 'SPDX-License-Identifier = "<' "$LICENSING_REUSE_TOML"; then
    note "wrote ${LICENSING_REUSE_TOML} — replace the <SPDX-…> placeholders (or set LICENSING_LICENSE / LICENSING_DOC_LICENSE and delete the file to re-seed)"
  else
    note "wrote ${LICENSING_REUSE_TOML}"
  fi
}

# REUSE-IgnoreStart — the heredoc below WRITES an SPDX header, one tag per
# line, and `reuse lint` reads a tag wherever it finds one: without these
# markers the template's own licence tag with "${LICENSING_LICENSE...}" in it
# is read as this script's licence, and an unexpanded shell parameter is not an
# SPDX expression. The lint then fails on the file whose whole job is to run it.
#
# The exceptions file, empty but explained. `check` names this file whenever a
# component fails review, and a person following that advice should find
# something that already says what an exception means and what one looks like,
# rather than a filename they have to invent the format of. Every example is
# commented out, so a fresh repository starts with no exceptions at all — which
# is the only honest starting point for a file whose entries each waive a gate.
write_exceptions_file() {
  if [[ -e "$LICENSING_EXCEPTIONS" ]]; then
    note "${LICENSING_EXCEPTIONS} already exists — kept as is"
    return 0
  fi
  local holder
  holder="$LICENSING_COPYRIGHT"
  if [[ -z "$holder" ]]; then
    holder="$(git config user.name 2>/dev/null || true)"
    [[ -z "$holder" ]] && holder="<COPYRIGHT HOLDER>"
    holder="$(date +%Y) ${holder}"
  fi
  cat > "$LICENSING_EXCEPTIONS" <<EOF
# SPDX-FileCopyrightText: ${holder}
# ${SPDX_ID_TAG} ${LICENSING_LICENSE:-<SPDX-LICENSE-ID>}
#
# Dependency licences reviewed BY HAND and found acceptable — read by
# ${ME}.
#
# An entry here exempts one component from the REVIEW failure: the case where
# a licence could not be mapped to an id your policy names, and a person has
# since read it and decided it is fine. It NEVER exempts a deny-listed
# licence — those fail whatever this file says, because the point of a deny
# list is that no single reviewer overrides it.
#
# Reach for this LAST. A licence that keeps coming back is a licence to map
# once in .licensing.conf, where the answer applies to every component that
# declares it:
#
#   LICENSING_LICENSE_ALIASES+=("<lowercased glob>|<SPDX-ID>")
#   LICENSING_ALLOW+=(<SPDX-ID>)
#
# and something that is not a dependency at all belongs in
# LICENSING_SELF_NAMES or LICENSING_IGNORE_PATHS instead. What is left for
# this file is the genuine one-off: one package, one odd licence, one person
# who read it.
#
# FORMAT. One component NAME per line — no version, no ecosystem, exactly the
# name in the COMPONENT column of the failing row, with anything after a # as
# a comment. Blank lines are ignored. Write down WHO decided, WHEN, and WHY:
# the next person to see this line will be someone deciding whether it still
# holds, and a bare name tells them nothing.
#
# When the scan read NO licence at all (NOASSERTION) and you found one by
# reading the package upstream, record it after an = sign:
#
#   <name> = <SPDX expression>   # reason
#
# The licence then goes into the inventory for that component — the gate,
# --porcelain, the SBOM and REUSE.toml all see it — and is judged against
# ALLOW and DENY like any licence the scan read. It only ever fills a gap: a
# component the scan did read a licence for keeps that one, and the run says
# the two disagree.
#
# Examples (commented out — a new repository has no exceptions):
#
#   example.com/foo/bar    # reviewed 2026-06-03 by <you>: custom BSD-equivalent
#                          #   header, no copyleft clause, LICENSE in the module root
#   @acme/widget-icons     # reviewed 2026-06-11 by <you>: CC-BY-4.0 icons, declared
#                          #   as free text npm cannot map; attribution is in NOTICE
#   some-python-package    # reviewed 2026-07-02 by <you>: PSF-2.0, declared only in
#                          #   a trove classifier the alias table does not cover
#   example.com/no/licence = MIT   # reviewed 2026-07-09 by <you>: the module zip
#                          #   ships no LICENSE; MIT in the upstream repository
EOF
  note "wrote ${LICENSING_EXCEPTIONS}"
}
# REUSE-IgnoreEnd

init_repo() {
  write_template
  [[ "$LICENSING_REUSE" == 0 ]] || write_reuse_toml
  write_exceptions_file
  cat <<EOF

Next:
  1. edit ${CONF##*/} — set LICENSING_ALLOW / LICENSING_DENY
  2. edit ${LICENSING_REUSE_TOML} — replace the <SPDX-…> placeholders
  3. run  $(how download --fix) — fetch the licence texts and fill in REUSE.toml
  4. run  $(how check) — run the gate
  5. add the licensing hook to .pre-commit-config.yaml and to CI — see README.md in
     https://github.com/bokysan/pre-commit-hooks
EOF
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
CMD="check"; MODE="auto"; ONLY="deps,toml,lint"; SBOM_OUT=""; AUTO_INSTALL=""; SKIP_INSTALL_CHECK=""; JOBS_OVERRIDE=""; PROGRESS_OVERRIDE=""; NO_CACHE=""
OBLIGATIONS=0; OBLIGATION_MATRIX=0; OBLIGATION_COMPONENTS=0; LIC_SEEN_FILE=""
DOWNLOAD_WHAT="all"; DRY_RUN=0; PORCELAIN=0
case "${1:-}" in
  check|download|sbom|init) CMD="$1"; shift ;;
  -h|--help) usage 0 ;;
  -V|--version) echo "${ME} $(script_version)"; exit 0 ;;
  --progress-test) progress_test; exit 0 ;;
  --completion) completion_script "${2:?--completion needs a shell (${LICENSING_VALUES_completion})}"; exit 0 ;;
  --completion=*) completion_script "${1#*=}"; exit 0 ;;
  "") ;;
  -*) ;;
  *) die "unknown command: $1 (try --help)" ;;
esac
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?}"; shift 2 ;;
    --mode=*) MODE="${1#*=}"; shift ;;
    --only) ONLY="${2:?}"; shift 2 ;;
    --only=*) ONLY="${1#*=}"; shift ;;
    -o|--output) SBOM_OUT="${2:?}"; shift 2 ;;
    --auto-install) AUTO_INSTALL=1; shift ;;
    -v|--verbose) LICENSING_VERBOSE=1; shift ;;
    --progress-test) progress_test; exit 0 ;;
    --progress) PROGRESS_OVERRIDE="${2:?}"; shift 2 ;;
    --progress=*) PROGRESS_OVERRIDE="${1#*=}"; shift ;;
    --jobs) JOBS_OVERRIDE="${2:?}"; shift 2 ;;
    --jobs=*) JOBS_OVERRIDE="${1#*=}"; shift ;;
    --skip-install-check) SKIP_INSTALL_CHECK=1; shift ;;
    --no-cache) NO_CACHE=1; shift ;;
    --completion) completion_script "${2:?--completion needs a shell (${LICENSING_VALUES_completion})}"; exit 0 ;;
    --completion=*) completion_script "${1#*=}"; exit 0 ;;
    --all) DOWNLOAD_WHAT=all; shift ;;
    --fix) DOWNLOAD_WHAT=fix; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --porcelain) PORCELAIN=1; shift ;;
    --porcelain=*) PORCELAIN=1
      in_list "${1#*=}" " $LICENSING_PORCELAIN_VERSIONS " \
        || die "unknown porcelain format: ${1#*=} (${LICENSING_PORCELAIN_VERSIONS})"
      shift ;;
    --obligations) OBLIGATION_MATRIX=1; shift ;;
    --components) OBLIGATION_COMPONENTS=1; shift ;;
    --color) LICENSING_COLOR="${2:?}"; shift 2 ;;
    --color=*) LICENSING_COLOR="${1#*=}"; shift ;;
    -h|--help) usage 0 ;;
    -V|--version) echo "${ME} $(script_version)"; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

if [[ "$CMD" == init ]]; then
  # Seed from an existing policy file when there is one, so `init` run a second
  # time (to add REUSE.toml) picks up the configured identity. Environment
  # values win, for a one-shot `LICENSING_COPYRIGHT="ACME Inc." … init`.
  env_copyright="${LICENSING_COPYRIGHT:-}"; env_lic="${LICENSING_LICENSE:-}"; env_doclic="${LICENSING_DOC_LICENSE:-}"
  # shellcheck disable=SC1090
  [[ -f "$CONF" ]] && . "$CONF"
  [[ -n "$env_copyright" ]] && LICENSING_COPYRIGHT="$env_copyright"
  [[ -n "$env_lic" ]]       && LICENSING_LICENSE="$env_lic"
  [[ -n "$env_doclic" ]]    && LICENSING_DOC_LICENSE="$env_doclic"
  init_repo
  exit 0
fi

if [[ ! -f "$CONF" ]]; then
  cat >&2 <<EOF
${ME}: no policy file at ${CONF}.

This script ships no licence policy of its own: what a product may absorb is
written down in the repository it governs. Create one with

  $(how init)

then edit LICENSING_ALLOW / LICENSING_DENY in it. Point elsewhere with
LICENSING_CONF=<path>.
EOF
  exit 2
fi
# The config is SOURCED, so a file that is secretly a copy of this script
# re-runs main from inside itself, forever, printing nothing — the recursion
# happens before the first line of output. Cheap to spot, so spot it.
if head -1 "$CONF" | grep -q '^#!' || grep -q '^script_version()' "$CONF"; then
  die "${CONF##*/} looks like a copy of ${ME}, not a policy file. It is sourced as bash, so this would recurse into itself with no output. The policy file holds only LICENSING_* settings — see '$(how init)'."
fi
# shellcheck disable=SC1090
. "$CONF"

missing=""
for k in $LICENSING_REQUIRED_KEYS; do
  # declare -p, not ${k+x}: an EMPTY array is a policy — "nothing is
  # pre-approved, report every component" is what LICENSING_ALLOW=() says —
  # and ${LICENSING_ALLOW+x} reads element zero, which an empty array does not
  # have. Testing for the parameter itself tells set-but-empty from unset.
  declare -p "$k" >/dev/null 2>&1 || missing="${missing} ${k}"
done
if [[ -n "$missing" ]]; then
  die "${CONF##*/} does not define:${missing}. These carry policy, so they have no default — set them explicitly ($(how init) writes a strict starting point)."
fi
for k in $LICENSING_REQUIRED_KEYS; do normalize_policy_list "$k"; done

# Either flag turns the report on; together they print both halves of it.
[[ "$OBLIGATION_MATRIX" == 1 || "$OBLIGATION_COMPONENTS" == 1 ]] && OBLIGATIONS=1
# --porcelain is a whole report in itself: it carries the obligations whether or
# not they were asked for, since a caller that wanted less would not be parsing
# records. Colour is for a person and would corrupt a field. And the records
# own stdout here, so the human stream moves to stderr for the duration: the
# promise is that `check --porcelain > licences.tsv` is the whole report and
# nothing else, and a warning line landing among the records would break every
# parser reading it.
if [[ "$PORCELAIN" == 1 ]]; then OBLIGATIONS=1; LICENSING_COLOR=off; exec 3>&2; fi
[[ -n "$AUTO_INSTALL" ]] && LICENSING_AUTO_INSTALL=1
[[ -n "$SKIP_INSTALL_CHECK" ]] && LICENSING_INSTALL_CHECK=0
[[ -n "$NO_CACHE" ]] && LICENSING_CACHE=0
[[ -n "$JOBS_OVERRIDE" ]] && LICENSING_SCAN_JOBS="$JOBS_OVERRIDE"
[[ -n "$PROGRESS_OVERRIDE" ]] && LICENSING_PROGRESS="$PROGRESS_OVERRIDE"

if [[ "$CMD" == download ]]; then
  need_syft
  need_reuse || missing_tool reuse '"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }'
  # REUSE.toml first, so a dropped dependency's licence is no longer claimed and
  # --fix can remove its text; then again, so the texts just fetched are claimed.
  sync_toml
  dlrc=0
  cmd_download "$DOWNLOAD_WHAT" || dlrc=$?
  sync_toml
  exit "$dlrc"
fi
# --all / --fix / --dry-run steer `download` and nothing else. Silently
# ignoring one on `check` would read as "I asked for a dry run and it wrote
# anyway", which is the report nobody wants to have to make.
if [[ "$DOWNLOAD_WHAT" != all || "$DRY_RUN" == 1 ]]; then
  die "--all / --fix / --dry-run belong to '$(how download)', not to '${CMD}'"
fi

[[ "$CMD" == sbom ]] && { emit_sbom "$SBOM_OUT"; exit 0; }

case "$MODE" in
  auto)  if [[ -n "${CI:-}" ]]; then MODE=full; else MODE="$LICENSING_LOCAL_MODE"; fi ;;
  full|delta) ;;
  *) die "unknown mode: $MODE (full|delta|auto)" ;;
esac

wants() { case ",${ONLY}," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# Both tools up front, before any mode shortcut: a delta run that happens to skip
# the scan today would otherwise pass on a machine that cannot scan at all, and
# fail the commit that does touch a manifest. mise first, PATH second (see
# resolve_tool); neither is a hard stop, with the line that says how to fix it.
if wants deps || wants toml; then
  need_syft
fi
if wants lint && [[ "$LICENSING_REUSE" != 0 ]]; then
  need_reuse || missing_tool reuse '"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }'
fi

rc=0

snote "mode=${MODE} target=${LICENSING_SCAN_TARGET}"

# The shape of this run: preflight, the scan itself, and one step per half the
# caller asked for. Workers and auxiliary scans add themselves as they appear.
progress_init
progress_plan 2                       # install preflight + the tree scan
wants deps && progress_plan 1
wants toml && progress_plan 1
wants lint && progress_plan 1

wants deps && { gate_deps "$MODE" || rc=1; progress_step; }
wants toml && { check_toml || rc=1; progress_step; }
wants lint && { lint_files || rc=1; progress_step; }
# Last, and whatever the verdict was: the duties are the same whether the gate
# passed or not, and a failing run is exactly when you want to see them.
# Whatever the gate did or skipped: the duties are a property of the tree, and
# a delta run that scanned nothing still ships every component it did not look
# at. report_obligations reads the inventory itself when it has to.
[[ "$OBLIGATIONS" == 1 ]] && report_obligations
progress_end "$rc"
exit "$rc"
