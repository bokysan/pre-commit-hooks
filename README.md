<!--
SPDX-FileCopyrightText: 2026 Bojan Čekrlić
SPDX-License-Identifier: CC-BY-4.0
-->

# pre-commit-hooks

[pre-commit](https://pre-commit.com) hooks for checking a project's licensing.

The main hook, `licensing`, runs `licensing.sh` on every commit. It checks that every third-party dependency has a
licence your policy allows, and that every file in the repository has SPDX copyright and licence information, as
[REUSE](https://reuse.software) defines it. The same scan can also write an SPDX SBOM.

Repository: <https://github.com/bokysan/pre-commit-hooks>.

| Hook                 | What it does                                                                                                                            |
| :------------------- | :-------------------------------------------------------------------------------------------------------------------------------------- |
| `licensing`          | Runs on every commit. Checks dependency licences against your policy, checks `REUSE.toml` against the same scan, and runs `reuse lint`. |
| `licensing-init`     | Manual stage. Writes a starter `.licensing.conf`, `REUSE.toml` and `.license-exceptions.txt`. Never overwrites a file.                  |
| `licensing-download` | Manual stage. Updates `LICENSES/` and the generated part of `REUSE.toml` after a dependency change.                                     |
| `licensing-sbom`     | Manual stage. Writes `sbom.spdx.json` from the same inventory the check uses.                                                           |
| `licensing-cli`      | Manual stage. The script with no command, for any other command line you give it in `args:`.                                            |

## Licences a scanner cannot see, and how licensing.sh finds them

A licence scanner such as [syft](https://github.com/anchore/syft) reports the licences it can see in your repository. In
most repositories, many licences aren't there:

- **They are outside the repository.** Go keeps modules in its module cache, poetry puts its virtualenv in your home
  directory, Dart and Rust keep packages in `~/.pub-cache` and the Cargo registry.
- **They don't exist until you install the dependencies.** A lockfile lists names and versions, not licences. The
  licence comes with the package, in `node_modules`, a virtualenv or `vendor/`.
- **They are only on the web.** A GitHub Action has no manifest at all; only GitHub can say what its licence is.
- **The package doesn't say.** Its metadata is empty or says "UNKNOWN", and the licence is in the `LICENSE` file it
  ships or in its Python classifiers.
- **They are on files, not packages.** A font, an icon set or a downloaded dataset committed to the repository has its
  own licence, and syft doesn't look at files. [REUSE](https://reuse.software) does: it requires every file to state its
  copyright and licence.

Scan such a repository with syft alone and many dependencies come back with no licence, and the more languages it mixes,
the more do.

`licensing.sh` collects them as well as it can, and runs syft and REUSE together in one command. It makes sure the
dependencies are installed, and tells you how if they aren't. It scans the repository with syft, then fills the gaps
from the package caches, the licence files, the classifiers and GitHub. It does this for every language in the
repository at once, so a Go service, a Node frontend and a Python tool in one repository give one result. Then
`reuse lint` checks every file. Whatever it still can't find shows as `NOASSERTION` and fails the check until someone
looks at it.

The result is used for:

- **the policy check.** You list the licences you allow and refuse in `.licensing.conf`, and record components you
  checked by hand in `.license-exceptions.txt`.
- **REUSE.** `REUSE.toml` covers committed third-party code, and `LICENSES/` gets the licence texts REUSE needs,
  including your dependencies'.
- **obligations.** For every licence in the repository, from dependencies and from files alike, `licensing.sh` prints
  what it obliges you to do: keep the copyright notice, ship the NOTICE file, publish your changes, and so on. It is a
  general guide to help you keep up with your obligations; read each licence nevertheless.
- **a complete SPDX SBOM**, which tools like [grype](https://github.com/anchore/grype) can scan for vulnerabilities.

## Tasks and the command for each

| Task                                                                              | Command               | Result                                                                                                                   |
| :-------------------------------------------------------------------------------- | :-------------------- | :----------------------------------------------------------------------------------------------------------------------- |
| Check dependency licences against your policy, and SPDX information in every file | `check`               | A table of every refused or unreviewed component, then `reuse lint`'s findings by category. Exit code 1 if there is any. |
| Keep `LICENSES/` and `REUSE.toml` in step with your dependencies                  | `download --fix`      | Missing licence texts fetched, unused ones deleted, the generated part of `REUSE.toml` updated                           |
| Produce an SBOM for a release or a vulnerability scan                             | `sbom`                | `sbom.spdx.json` in SPDX 2.3 JSON, which [grype can scan](#scanning-the-sbom-for-vulnerabilities-with-grype)             |
| See what your licences oblige you to do                                           | `check --obligations` | A matrix of duties (reproduce the notice, offer source, …) against every licence in the tree                             |
| Feed the results to another tool                                                  | `check --porcelain`   | Tab-separated records on stdout                                                                                          |
| Start a new repository                                                            | `init`                | A strict starter policy, `REUSE.toml` and exceptions file                                                                |

## Add the licensing hook to your project

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bokysan/pre-commit-hooks
    rev: v1.40.0
    hooks:
      - id: licensing # runs on every commit
      - id: licensing-init # the rest run only when you ask
      - id: licensing-download
      - id: licensing-sbom
```

`licensing` runs `licensing.sh check --mode auto` on every commit, over the whole repository, since new files need
headers too. `auto` picks one of two modes:

- In CI (when the `CI` environment variable is set, as GitHub Actions and most CI systems do), it runs `full`: it scans
  all dependencies, checks `REUSE.toml` and runs `reuse lint`.
- On your machine it runs `LICENSING_LOCAL_MODE`, which is `full` too unless you set it to `delta`. `delta` runs
  `reuse lint` on every commit, but scans dependencies only when the commit changes a manifest or a lockfile, and then
  checks only the dependencies that commit added. Use it on large repositories and/or when a full scan makes every
  commit slow.

The other hooks run only when you call them with `pre-commit run <hook> --hook-stage manual`.

### Tools and files the hook needs

The hook needs two tools and a policy file. It takes the tools from [mise](https://mise.jdx.dev) if mise has them,
otherwise from `PATH`, and stops with an error if neither has them.

| Need                                    | Version used here | Notes                                                                                                     |
| :-------------------------------------- | :---------------- | :-------------------------------------------------------------------------------------------------------- |
| [syft](https://github.com/anchore/syft) | 1.51.0            | Builds the component inventory. Any version works, but releases detect licences differently, so pin one.  |
| [reuse](https://reuse.software)         | 6.2.0             | Runs `reuse lint`. Set `LICENSING_REUSE=0` to skip it while you are still adding headers to a repository. |
| `.licensing.conf`                       |                   | Your policy. You need to set at least `LICENSING_ALLOW` and `LICENSING_DENY`.                             |

The script itself needs bash 3.2 or later, git, and POSIX `awk`, `sed`, `sort`, `diff`, `find` and `xargs`. It runs on
macOS and in a busybox image.

Pin the tools in your `mise.toml`, so every developer and every CI run uses the same versions:

```toml
[tools]
syft = "1.51.0"
python = "3.13"
uv = "0.9.7"
"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }
```

`reuse` is a Python package. The `pipx:` entry installs it into a Python environment, so mise also needs `python` and an
installer, `uv`. Then run `mise install`.

Committed third-party code, such as Go's or Rust's `vendor/`, Composer's and Bundler's `vendor/`, `third_party/` or
CocoaPods' `Pods/`, has no SPDX headers of yours, and `reuse lint` checks every committed file. `licensing-download`
covers each such directory with one entry in `REUSE.toml`:

```toml
[[annotations]]
path = "vendor/**"
SPDX-FileCopyrightText = "The authors of each package in vendor/"
SPDX-License-Identifier = "LicenseRef-vendored-packages"
```

`LicenseRef-vendored-packages` is not a licence; REUSE needs a text for every id, so `licensing-download` writes a short
`LICENSES/LicenseRef-vendored-packages.txt` saying so. The real licence of each vendored package is checked against your
policy like any other dependency, and listed in the SBOM and the obligations report.

The entry doesn't depend on what syft finds, so upgrading syft doesn't change it. The only part of `REUSE.toml` that
does is the list of dependency licences in `LICENSES/` it claims for `THIRD-PARTY-LICENSES.md`. `licensing-download`
records the syft version next to it, and the check warns when you run a different one; if it then reports `REUSE.toml`
out of date, run `licensing-download`.

### Set up your repository for the first time

1. **Write the starter files.** This creates `.licensing.conf`, `REUSE.toml` and `.license-exceptions.txt`. It never
   overwrites a file that already exists:

   ```sh
   pre-commit run licensing-init --hook-stage manual
   ```

2. **Set the licences you allow.** Open `.licensing.conf` and see
   [Settings to set in .licensing.conf](#settings-to-set-in-licensingconf) lists and what to fill in.

3. **Fetch the licence texts and fill in `REUSE.toml`:**

   ```sh
   pre-commit run licensing-download --hook-stage manual
   ```

   pre-commit shows `Failed` with `files were modified by this hook`, because the hook changed `REUSE.toml` and
   `LICENSES/`. Review the changes and run it again. Run it again whenever you add, remove or upgrade a dependency.

From then on `licensing` runs on every commit.

### Run the check in CI

In a GitHub Actions workflow:

```yaml
- uses: actions/checkout@v4
- uses: jdx/mise-action@v2 # installs the pinned tools
- run: pre-commit run licensing --all-files
  env:
    LICENSING_AUTO_INSTALL: "1" # install npm, Python, Go, … dependencies the check needs
```

The check reads licences from installed packages. On a fresh CI runner nothing is installed, so either install your
dependencies in an earlier step or let the check do it with `LICENSING_AUTO_INSTALL`.

## Run any command through pre-commit

`pre-commit run` can't pass arguments to a hook, so you put them in the hook's `args:` in the config. To have several
variants of one hook, give each an `alias:` and run it by that name:

```yaml
hooks:
  - id: licensing
  - id: licensing-sbom
    args: [-o, release/sbom.spdx.json]
  - id: licensing-cli
    alias: licensing-obligations
    args: [check, --mode, full, --obligations]
  - id: licensing-cli
    alias: licensing-download-dry-run
    args: [download, --fix, --dry-run]
```

```sh
pre-commit run licensing-obligations --hook-stage manual
pre-commit run licensing-download-dry-run --hook-stage manual
```

`args: [--help]` on `licensing-cli` prints the commands and options.

## Four commands: check, download, sbom and init

| Command    | Hook                                | What it does                                                                                                       |
| :--------- | :---------------------------------- | :----------------------------------------------------------------------------------------------------------------- |
| `check`    | `licensing`                         | The default command. Checks dependency licences, `REUSE.toml` drift and file licensing. Changes nothing.           |
| `download` | `licensing-download` (with `--fix`) | Updates `LICENSES/` and the generated part of `REUSE.toml`. With `--fix`, also deletes licence texts nothing uses. |
| `sbom`     | `licensing-sbom`                    | Writes an SPDX 2.3 JSON SBOM of every component in the inventory.                                                  |
| `init`     | `licensing-init`                    | Writes a starter `.licensing.conf`, `REUSE.toml` and `.license-exceptions.txt`, skipping any that exist.           |

### check judges dependencies, REUSE.toml and every file

`check` runs three parts, which `--only` can narrow to a comma-separated subset:

1. `deps` checks every dependency against your policy. It fails as _DENY_ if the licence is on `LICENSING_DENY`, and as
   _REVIEW_ if no licence was found or the licence is on neither list.
2. `toml` fails if the generated part of `REUSE.toml` is out of date. Run `download --fix` to update it.
3. `lint` runs `reuse lint` and lists its findings by category, with what to do about each.

If a manifest's packages are not installed, the check stops with exit code 2 and prints the install command.
`--auto-install` runs it for you.

A passing run prints nothing. `--verbose` shows what it did. On this repository, whose only dependencies are GitHub
Actions:

```console
$ pre-commit run licensing-cli --hook-stage manual    # args: [check, --mode, full, --verbose]
licensing.sh: mode=full target=dir:.
licensing.sh:   checking every dependency manifest for installed packages
licensing.sh: scan: 2 component(s) from cache — nothing a scan reads has changed (--no-cache re-scans)
    github-action    2
licensing.sh: deps: ✓ 2 component(s) gated, all outbound-compatible
licensing.sh: toml: REUSE.toml carries no generated section — hand-maintained, lint only
licensing.sh: linting every file for SPDX copyright + licence info
licensing.sh: lint: ✓ every file carries SPDX copyright + licence info (1s)
```

Failures are printed as a table, followed by hints on which setting fixes what. Here is a Go project checked against a
policy that refuses MPL-2.0 (shortened):

```console
$ pre-commit run licensing --all-files
   STATUS  LICENCE COMPONENT                                           PATH
   DENY    MPL-2.0 go-module github.com/hashicorp/errwrap@v1.1.0       go.mod
   DENY    MPL-2.0 go-module github.com/hashicorp/go-multierror@v1.1.1 go.mod
   DENY    MPL-2.0 go-module github.com/hashicorp/go-uuid@v1.0.3       go.mod
  deny-listed above: MPL-2.0

✗ 3 deny-listed, 0 unreviewed, out of 174 component(s) gated.

PACKAGES THAT ARE YOURS, NOT DEPENDENCIES:
  Workspaces of this repository are the product, not something it absorbs.
  …
```

`--obligations` prints what each licence in the tree requires of you, as a table of duties by licence. `???` means the
script has no entry for that licence. `--components` prints the same per licence, with the components under each. It
assumes you distribute a binary or run a service, and is not legal advice. The same Go project's table, shortened:

```console
$ pre-commit run licensing-obligations --hook-stage manual    # args: [check, --mode, full, --obligations]
  +--------------------------------------------------------+-----+-----+-----+-----+-----+-----+-----+-----+
  | DUTY                                                   |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |
  +--------------------------------------------------------+-----+-----+-----+-----+-----+-----+-----+-----+
  | reproduce the copyright notice and the licence text    | yes | yes | yes |     | yes | yes | yes |     |
  | do not use the authors' names to endorse your product  |     |     | yes |     |     |     |     |     |
  | pass on the contents of the NOTICE file                | yes |     |     |     |     |     |     |     |
  | offer the source of the licensed files you modified    |     |     |     |     |     |     | yes |     |
  | no licence was granted: ask the author before shipping |     |     |     |     |     |     |     | yes |
  +--------------------------------------------------------+-----+-----+-----+-----+-----+-----+-----+-----+

  1 Apache-2.0   (49 components)
  2 BSD-2-Clause (3 components)
  3 BSD-3-Clause (45 components)
  4 CC0-1.0      (1 component)
  5 ISC          (2 components)
  6 MIT          (95 components)
  7 MPL-2.0      (3 components)
  8 NOASSERTION  (2 components)
```

`--porcelain` prints the results as tab-separated records for other tools (see
[Machine-readable output](#machine-readable-output-for-scripts)):

```console
$ pre-commit run licensing-porcelain --hook-stage manual    # args: [check, --mode, full, --porcelain]
summary	174	0	0	1	0
duty	notice	reproduce the copyright notice and the licence text
licence	Apache-2.0	49	notice notice-file state-changes patent-retaliation
pair	Apache-2.0	component	docker/build-push-action	v6	github-action
…
```

### download keeps LICENSES and REUSE.toml in step with your dependencies

Run `download --fix` after adding, removing or upgrading a dependency. It does three things:

1. **Fetches missing licence texts** into `LICENSES/`, including your dependencies' licences, which
   `reuse download --all` doesn't know about. It can't fetch a `LicenseRef-` licence; it tells you to write that one.
2. **Deletes unused licence texts** (`--fix` only). `reuse lint` fails on a text nothing uses.
3. **Updates the generated part of `REUSE.toml`**, everything below this line:

   ```toml
   # --- generated by licensing.sh: vendored components (do not edit below) ---
   ```

   Everything above the line is yours and is left alone; a `REUSE.toml` without the line is never changed. The generated
   part covers committed third-party code (see [Tools and files the hook needs](#tools-and-files-the-hook-needs)), and
   claims your dependencies' licence texts for `THIRD-PARTY-LICENSES.md`. REUSE would otherwise call them unused,
   because the dependencies themselves sit in ignored directories like `node_modules`. `download` writes that file the
   first time it is needed and never rewrites it.

`--dry-run` lists what would change and writes nothing. To keep no dependency licence texts at all, see
`LICENSING_LICENSE_SOURCES`.

### sbom writes an SPDX 2.3 SBOM from the checked inventory

`sbom` writes `sbom.spdx.json` (or the file given with `-o`) from the same scan the check uses. Each package has its
name, version, licence and, where possible, a package URL. It includes the licences found outside the repository, which
a plain `syft scan dir:.` misses. For CycloneDX or syft's own format, run syft directly.

```console
$ pre-commit run licensing-sbom --hook-stage manual
licensing.sh: sbom: wrote sbom.spdx.json — 175 component(s), 173 with a licence

$ jq '.packages[] | select(.name == "github.com/quic-go/quic-go")' sbom.spdx.json
{
  "SPDXID": "SPDXRef-Package-126",
  "name": "github.com/quic-go/quic-go",
  "versionInfo": "v0.60.0",
  "licenseConcluded": "MIT",
  "licenseDeclared": "MIT",
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceType": "purl",
      "referenceLocator": "pkg:golang/github.com/quic-go/quic-go@v0.60.0"
    }
  ],
  …
}
```

### Scanning the SBOM for vulnerabilities with grype

[grype](https://github.com/anchore/grype) reads the SBOM directly, so the vulnerability scan covers the same components
the licence check judged, including those found only in package caches outside the repository. Pin it in `mise.toml`
beside syft (`grype = "0.120.0"`).

Write the SBOM with this script, then list the known vulnerabilities, with the version that fixes each one (example
output):

```console
$ pre-commit run licensing-sbom --hook-stage manual
licensing.sh: sbom: wrote sbom.spdx.json — 175 component(s), 173 with a licence

$ grype sbom:./sbom.spdx.json
NAME                          INSTALLED  FIXED IN  TYPE       VULNERABILITY        SEVERITY  EPSS         RISK
github.com/example/parser     v1.4.0     1.4.2     go-module  GHSA-xxxx-xxxx-xxxx  High      1.2% (65th)  0.9
github.com/example/transport  v3.1.1     3.1.5     go-module  GHSA-yyyy-yyyy-yyyy  Medium    0.6% (49th)  0.3
@example/date-utils           2.0.3      2.0.4     npm        GHSA-zzzz-zzzz-zzzz  Low       0.1% (5th)   < 0.1
…
```

Fail when anything at or above a severity is found. grype exits with code 2 and prints
`discovered vulnerabilities at or above the severity threshold`:

```sh
grype sbom:./sbom.spdx.json --fail-on high
```

Show only the vulnerabilities an upgrade fixes:

```sh
grype sbom:./sbom.spdx.json --only-fixed
```

Write a SARIF report for GitHub code scanning, or JSON to process further:

```sh
grype sbom:./sbom.spdx.json -o sarif=grype.sarif
grype sbom:./sbom.spdx.json -o json | jq -r '.matches[] | [.vulnerability.severity, .artifact.name, .artifact.version, .vulnerability.id] | @tsv'
```

In a GitHub Actions workflow, after the licence check:

```yaml
- run: pre-commit run licensing-sbom --hook-stage manual
- run: grype sbom:./sbom.spdx.json --fail-on high -o table -o sarif=grype.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always() # upload the report even when grype failed the job
  with:
    sarif_file: grype.sarif
```

grype downloads its vulnerability database on first use and updates it when it is older than a few days. On a machine
without network access, set `GRYPE_DB_AUTO_UPDATE=false` to scan with the database already on disk.

### init writes a strict starter policy

`init` writes a strict starting policy that allows permissive licences and refuses all copyleft, a `REUSE.toml` for
files that can't have a header, and an empty `.license-exceptions.txt` with examples. If you set `LICENSING_COPYRIGHT`,
`LICENSING_LICENSE` and `LICENSING_DOC_LICENSE` in the environment, `init` uses them in all three files and writes them
into `.licensing.conf`, where `download` and `check` read them later. Otherwise set them in `.licensing.conf` yourself.

```console
$ LICENSING_LICENSE=MIT LICENSING_DOC_LICENSE=CC-BY-4.0 pre-commit run licensing-init --hook-stage manual
licensing.sh: wrote .licensing.conf
licensing.sh: wrote REUSE.toml
licensing.sh: wrote .license-exceptions.txt

Next:
  1. edit .licensing.conf — set LICENSING_ALLOW / LICENSING_DENY
  2. edit REUSE.toml — replace the <SPDX-…> placeholders
  3. run  pre-commit run licensing-download --hook-stage manual — fetch the licence texts and fill in REUSE.toml
  4. run  pre-commit run licensing --all-files — run the gate
  5. add the licensing hook to .pre-commit-config.yaml and to CI — see README.md in
     https://github.com/bokysan/pre-commit-hooks
```

## Command-line options

| Option                 | Commands                    | What it does                                                                                                                                  |
| :--------------------- | :-------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| `--mode`               | `check`                     | `auto` (default), `full` or `delta`. See [Modes](#modes-full-delta-and-auto).                                                                 |
| `--only`               | `check`                     | Run only some of `deps`, `toml` and `lint`, comma-separated.                                                                                  |
| `-o`                   | `sbom`                      | Short form of `--output`.                                                                                                                     |
| `--output`             | `sbom`                      | Where to write the SBOM. Default `sbom.spdx.json`.                                                                                            |
| `--all`                | `download`                  | Fetch every missing licence text. The default.                                                                                                |
| `--fix`                | `download`                  | Fetch missing texts and delete unused ones.                                                                                                   |
| `--dry-run`            | `download`                  | Print what would change and write nothing.                                                                                                    |
| `--auto-install`       | `check`, `download`, `sbom` | Run the install command for each uninstalled dependency manifest instead of stopping.                                                         |
| `--skip-install-check` | `check`, `download`, `sbom` | Scan the tree as it is. This also skips finding package directories outside the repository, so licences that exist only there go missing.     |
| `--no-cache`           | `check`, `download`, `sbom` | Scan even when a cached scan matches.                                                                                                         |
| `--jobs`               | `check`, `download`, `sbom` | How many syft processes to run at once: `auto`, `1` or a number.                                                                              |
| `--obligations`        | `check`                     | Print the duty × licence matrix after the verdict.                                                                                            |
| `--components`         | `check`                     | Print each licence's duties and the components under it.                                                                                      |
| `--porcelain`          | `check`                     | Print tab-separated records on stdout. `--porcelain=v1` pins the format. See [Machine-readable output](#machine-readable-output-for-scripts). |
| `--color`              | all                         | Colour in the findings table: `auto`, `on` or `off`.                                                                                          |
| `--progress`           | all                         | The terminal progress bar: `auto`, `on` or `off`.                                                                                             |
| `--progress-test`      | none                        | Show whether this terminal draws the progress bar.                                                                                            |
| `--completion`         | none                        | Print a `bash`, `zsh` or `fish` completion script.                                                                                            |
| `-v`                   | all                         | Short form of `--verbose`.                                                                                                                    |
| `--verbose`            | all                         | Show progress, timings, counts, install commands and what was skipped.                                                                        |
| `-V`                   | none                        | Short form of `--version`.                                                                                                                    |
| `--version`            | none                        | Print the version.                                                                                                                            |
| `-h`                   | none                        | Short form of `--help`.                                                                                                                       |
| `--help`               | none                        | Print the commands and options.                                                                                                               |

## Files in your repository that the script reads and writes

Paths are relative to the root of your repository.

| File                      | Read or written by                                | Purpose                                                                                              |
| :------------------------ | :------------------------------------------------ | :--------------------------------------------------------------------------------------------------- |
| `.licensing.conf`         | read by every command, written by `init`          | Your policy and settings, sourced as bash. Required. `LICENSING_CONF` points to a different file.    |
| `.license-exceptions.txt` | read by `check`, written by `init`                | Components a person reviewed. See [Recording a review](#reviewed-components-in-the-license-exceptionstxt-file). |
| `REUSE.toml`              | read by `check`, written by `init` and `download` | REUSE annotations. Yours above the marker line, generated below it.                                  |
| `LICENSES`                | written by `download`                             | One licence text per SPDX id the tree uses.                                                          |
| `THIRD-PARTY-LICENSES.md` | written once by `download`                        | The document that accounts for dependency licence texts. Never rewritten.                            |
| `sbom.spdx.json`          | written by `sbom`                                 | The SBOM.                                                                                            |

The scan cache is kept in `~/.cache/licensing.sh` (or `$XDG_CACHE_HOME/licensing.sh`), outside the repository, so
`reuse lint` doesn't see it.

### Reviewed components in the `.license-exceptions.txt` file

One component per line, named as in the COMPONENT column without the type and version: `silent-pkg` for
`npm silent-pkg@1.0.0`. Add a `#` comment saying who decided, when and why.

```text
example.com/foo/bar          # reviewed 2026-06-03 by <you>: BSD-style header, no copyleft clause
silent-pkg = MIT             # reviewed 2026-07-09 by <you>: ships no LICENSE; MIT upstream
```

A name on its own stops the component failing as _REVIEW_. `<name> = <SPDX id>` gives a licence to a component where the
scan found none; it is then used in the check, the SBOM and `REUSE.toml`, and still checked against your policy. If the
scan did find a licence, the scan wins and the check warns you. Nothing in this file overrides _DENY_.

If the same licence spelling keeps showing up, map it once in `LICENSING_LICENSE_ALIASES` instead. For something that
isn't a dependency, use `LICENSING_SELF_NAMES` or `LICENSING_IGNORE_PATHS`.

## Scanning, licence evaluation, modes and caching

### Where licences are read from, per ecosystem

`licensing.sh` runs syft on the repository. It tells syft to skip what git ignores, except package directories such as
`node_modules` and `.venv`, where the installed packages and their licences are. It also runs syft on package caches
outside the repository, such as `~/.pub-cache`, and on each `go.mod` on its own. On a large repository it runs several
syft processes in parallel, and it caches the combined result, so an unchanged repository isn't scanned again.

Then `licensing.sh` fills in what syft didn't find. If a package's metadata has no licence, it reads the licence file
the package ships. For Python it also reads trove classifiers, for Rust the crate's `Cargo.toml` in the Cargo registry,
and for GitHub Actions it asks GitHub.

| Ecosystem           | What syft can tell         | Where licences come from                            |
| :------------------ | :------------------------- | :-------------------------------------------------- |
| Go                  | components and licences    | the module cache or `vendor/`                       |
| npm, yarn, pnpm     | components and licences    | `node_modules`, which must be installed             |
| Python              | components and licences    | a virtualenv, which must be installed               |
| Maven               | components and licences    | `~/.m2` or Maven Central                            |
| Gradle              | nothing without a lockfile | `gradle.lockfile` or built jars                     |
| Rust                | components                 | the unpacked crate's `Cargo.toml`                   |
| Dart, Flutter       | components                 | `~/.pub-cache`                                      |
| CocoaPods, Swift PM | components only            | nowhere: exempt the type or record each package     |
| GitHub Actions      | components                 | GitHub's licence API; exempt from review by default |

A package that is in a lockfile but not installed is usually an optional package for another platform, like a Linux
binary on a Mac. It is listed but doesn't fail the check (see `LICENSING_LOCKFILE_ONLY`).

### Licence expressions and aliases

Packages often write their licence in words instead of an SPDX id; `LICENSING_LICENSE_ALIASES` translates the common
ones. Expressions are judged as a whole:

- `A OR B` passes if either is allowed.
- `A AND B` passes if both are allowed.
- `A WITH exception` is judged as `A`, unless you allow the whole expression in `LICENSING_ALLOW_EXPRESSIONS`.
- A licence on `LICENSING_DENY` always fails.

### Modes: full, delta and auto

| Mode    | What runs                                                                                                                                                                              |
| :------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `full`  | The whole scan, every component judged, `REUSE.toml` checked, `reuse lint`.                                                                                                            |
| `delta` | `reuse lint` always. The scan and the dependency check only when the commit changes a dependency manifest (`LICENSING_TRIGGER_PATHS`), and then only the components that change added. |
| `auto`  | `full` when `CI` is set, otherwise `LICENSING_LOCAL_MODE` (default `full`).                                                                                                            |

### The scan cache and what invalidates it

The cache is invalidated when a manifest, a lockfile, an installed package directory, the scan settings, the syft
version or the script changes. It cannot see a file edited by hand inside `node_modules`; use `--no-cache` if a result
looks wrong.

## Settings in the policy file

`.licensing.conf` is sourced as bash. A list is a bash array; append to a built-in one with `+=`. A default shown as
`(…)` is a long built-in list; read it in `licensing.sh`.

## Settings to set in .licensing.conf

### `LICENSING_ALLOW` and `LICENSING_DENY`

_Required._ Two arrays of SPDX ids. Neither has a default, and the run stops when either is missing.

A dependency passes when its licence is on `LICENSING_ALLOW` (for an expression: every part of an `AND`, or one branch
of an `OR`). It fails as _DENY_ when its licence is on `LICENSING_DENY`, even if something else allows it. A licence on
neither list fails as _REVIEW_ until someone records a decision in `.license-exceptions.txt`, so leave a licence off
both lists to decide it case by case. Keep deprecated ids such as `GPL-3.0` next to the current ones; packages still use
them.

`init` writes a strict policy for a proprietary product. Or paste one of these. They are starting points, not legal
advice.

```bash
# Permissive project (MIT, BSD, Apache-2.0), or a commercial product you distribute.
# Caveat: MPL, LGPL, EPL and CDDL are on neither list: usually fine, but check each against how you ship.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
)
LICENSING_DENY=(
  # Strong copyleft: the combined work is distributed under the GPL.
  GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
  # Network copyleft: network users of a modified version can ask for its source.
  AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

```bash
# MPL-2.0 project.
# Caveat: LGPL, EPL and CDDL are on neither list.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
  # File-level copyleft: your changes to these files stay open.
  MPL-2.0
)
LICENSING_DENY=(
  # Strong copyleft: the combined work is distributed under the GPL.
  GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
  # Network copyleft: network users of a modified version can ask for its source.
  AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

```bash
# GPL-3.0-or-later project. For GPL-2.0-only, also deny Apache-2.0, LGPL-3.0 and GPL-3.0.
# Caveat: AGPL is on neither list: GPLv3 can be combined with it, but its network clause then applies.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
  # File-level copyleft: your changes to these files stay open.
  MPL-2.0
  # Library copyleft: users must be able to relink the library.
  LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later
  # GPL that GPLv3 can be combined with.
  GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
)
LICENSING_DENY=(
  # GPLv2 only: cannot be combined with GPLv3.
  GPL-2.0 GPL-2.0-only
  # Weak copyleft that the GPL cannot be combined with.
  EPL-1.0 EPL-2.0 CDDL-1.0 CDDL-1.1
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

```bash
# Commercial service you only host, never ship. GPL and LGPL ask for source only on distribution.
# Caveat: AGPL is on neither list, because it also covers network use. Ship anything, and use the permissive list.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
  # File-level copyleft: your changes to these files stay open.
  MPL-2.0
  # Library copyleft: users must be able to relink the library.
  LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later
  # Weak copyleft that the GPL cannot be combined with.
  EPL-1.0 EPL-2.0 CDDL-1.0 CDDL-1.1
  # Strong copyleft: the combined work is distributed under the GPL.
  GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
)
LICENSING_DENY=(
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

```bash
# Commercial service you only host, AGPL allowed: you use AGPL components unmodified,
# or you publish your changes to them.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
  # File-level copyleft: your changes to these files stay open.
  MPL-2.0
  # Library copyleft: users must be able to relink the library.
  LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later
  # Weak copyleft that the GPL cannot be combined with.
  EPL-1.0 EPL-2.0 CDDL-1.0 CDDL-1.1
  # Strong copyleft: the combined work is distributed under the GPL.
  GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
  # Network copyleft: network users of a modified version can ask for its source.
  AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later
)
LICENSING_DENY=(
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

```bash
# Open-core product under the AGPL.
# Caveat: a commercial edition of the same code needs the permissive list; you cannot relicense GPL or AGPL code you do not own.
LICENSING_ALLOW=(
  # Permissive: keep the copyright notice, no other conditions.
  MIT MIT-0 BSD-2-Clause BSD-3-Clause Apache-2.0 ISC 0BSD Zlib BSL-1.0 Unlicense CC0-1.0
  PSF-2.0 Python-2.0 BlueOak-1.0.0 UPL-1.0
  # File-level copyleft: your changes to these files stay open.
  MPL-2.0
  # Library copyleft: users must be able to relink the library.
  LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later
  # GPL that GPLv3 can be combined with.
  GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later
  # Network copyleft: network users of a modified version can ask for its source.
  AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later
)
LICENSING_DENY=(
  # GPLv2 only: cannot be combined with GPLv3.
  GPL-2.0 GPL-2.0-only
  # Weak copyleft that the GPL cannot be combined with.
  EPL-1.0 EPL-2.0 CDDL-1.0 CDDL-1.1
  # Source-available, not open source: limits on competing, hosting or selling.
  SSPL-1.0 BUSL-1.1 Elastic-2.0 Commons-Clause FSL-1.1-MIT FSL-1.1-ALv2
)
```

### `LICENSING_SELF_NAMES`

_Recommended._ Your own packages: the Go main module, the root `package.json`, the workspaces of a monorepo. The scan
finds them like any dependency, and unlisted they are checked against your policy. Listed, they are not checked at all.

An array of bash globs, matched against the whole name the COMPONENT column prints between the type and the `@` (`acme`
for `npm acme@1.2.3`), in every ecosystem. Quote patterns with a glob character. A passing run prints how many
components this excluded, so a pattern that is too wide shows up as a large number.

```bash
LICENSING_SELF_NAMES=("github.com/acme/product" "@acme/*" "acme-*")
```

Default: none.

### `LICENSING_COPYRIGHT`, `LICENSING_LICENSE` and `LICENSING_DOC_LICENSE`

_Recommended._ Who owns this project, and the SPDX ids of the licences of its code and its documentation. `init` writes
them into the `REUSE.toml` and `.license-exceptions.txt` it creates: the code licence for configuration, build and
script files, the documentation licence for `*.md`, `docs/` and `specs/`. `--obligations` leaves out components under
your own licences.

Set them in `.licensing.conf`: `download` writes the copyright into `REUSE.toml` and the notice file on every run, and
`check` compares against that. When you run `init` with them set in the environment, it writes them into
`.licensing.conf` for you. Empty, `init` uses the current year and `git config user.name` as the copyright, which for a
company is usually the wrong holder, and placeholders for the licences, which `reuse lint` fails on until you replace
them.

```bash
# Open-source project.
LICENSING_COPYRIGHT="2019-2026 ACME Inc. and contributors"
LICENSING_LICENSE="MIT"
LICENSING_DOC_LICENSE="CC-BY-4.0"
```

```bash
# Proprietary product. There is no SPDX id for "all rights reserved": name your own
# LicenseRef- and write its text to LICENSES/LicenseRef-ACME-Proprietary.txt yourself.
LICENSING_COPYRIGHT="2026 ACME Inc."
LICENSING_LICENSE="LicenseRef-ACME-Proprietary"
LICENSING_DOC_LICENSE="LicenseRef-ACME-Proprietary"
```

Default: none.

## Settings the defaults cover

Leave these alone unless your repository is special.

### Policy refinements

#### `LICENSING_ALLOW_EXPRESSIONS` and `LICENSING_DENY_EXPRESSIONS`

_Optional._ Whole licence expressions, decided as one unit rather than part by part. You need them for a licence with an
exception: `WITH` is judged on the base licence, so `GPL-2.0-only WITH Classpath-exception-2.0` fails while
`GPL-2.0-only` is denied, until you allow the whole expression. Deny an expression to refuse a combination whose parts
are each allowed. Write expressions as the findings table prints them.

```bash
LICENSING_ALLOW_EXPRESSIONS=("GPL-2.0-only WITH Classpath-exception-2.0")
LICENSING_DENY_EXPRESSIONS=("MIT AND Commons-Clause")
```

Default: none.

#### `LICENSING_REVIEW_EXEMPT_TYPES` and `LICENSING_LOCKFILE_ONLY`

_Optional._ Components with no licence that are reported without failing the check. A denied licence fails regardless.

`LICENSING_REVIEW_EXEMPT_TYPES` lists component types, as the COMPONENT column prints them (`npm`, `go-module`, `pod`,
`swift`, `github-action`, …). GitHub Actions are exempt by default as build infrastructure. Add CocoaPods and Swift PM
if you use them: they carry no licence metadata, so otherwise every package needs a review.

`LICENSING_LOCKFILE_ONLY` covers packages a lockfile names but nothing installed, usually optional packages for another
platform, such as a Linux binary on a Mac. Set it to `review` in a CI job on the platform you ship, where a missing
package is a real gap.

```bash
LICENSING_REVIEW_EXEMPT_TYPES+=(pod swift)
```

Defaults:

```bash
LICENSING_REVIEW_EXEMPT_TYPES=("github-action" "github-action-workflow")
LICENSING_LOCKFILE_ONLY="exempt"
```

#### `LICENSING_EXCEPTIONS`

_Optional._ Where the reviewed-components file is, relative to the repository root.

Default:

```bash
LICENSING_EXCEPTIONS=".license-exceptions.txt"
```

### What is scanned

#### `LICENSING_IGNORE_PATHS`, `LICENSING_EXCLUDE` and `LICENSING_IGNORE_TYPES`

_Optional._ Three ways to leave out something that is not a dependency of yours. Use the first one you can: it is the
narrowest, and the only one that does not invalidate the scan cache.

- `LICENSING_IGNORE_PATHS`: shell globs over where a component was found, where `*` also matches `/`. A component is
  dropped only when every place it was found matches. Use it for a binary a package bundles, a demo app, test fixtures.
- `LICENSING_EXCLUDE`: syft `--exclude` globs, starting with `./`, `*/` or `**/`. The paths are not scanned at all. Use
  it for manifests that confuse the scan, such as the test tooling inside a vendored module.
- `LICENSING_IGNORE_TYPES`: whole component types, for an ecosystem in the tree you never ship.

```bash
LICENSING_IGNORE_PATHS=("*/fixtures/*" "node_modules/clipboardy/fallbacks/*")
LICENSING_EXCLUDE=("./vendor/**/package.json")
```

Default: none.

#### `LICENSING_SCAN_TARGET`

_Optional._ What syft scans: `dir:<path>` or `file:<manifest>`. Set `file:go.mod` to check one manifest only; nothing
else in the tree is then checked.

Default:

```bash
LICENSING_SCAN_TARGET="dir:."
```

#### `LICENSING_EXCLUDE_GITIGNORED` and `LICENSING_INCLUDE_GITIGNORED`

_Optional._ What git ignores is not scanned, except directories named in `LICENSING_INCLUDE_GITIGNORED`, because
installed packages and their licences live there. Add the directory your package manager installs into if it is not
listed, such as `bower_components`.

Defaults:

```bash
LICENSING_EXCLUDE_GITIGNORED=1
LICENSING_INCLUDE_GITIGNORED=("node_modules" "vendor" "site-packages" ".venv" "venv"
                              "Pods" ".build" "SourcePackages" "Carthage")
```

#### `LICENSING_NESTED_ROOTS`, `LICENSING_NESTED_MANIFESTS`, `LICENSING_SKIP_VENDORED_SUBPATHS` and `LICENSING_SKIP_NESTED_SUBPACKAGES`

_Optional._ Files inside installed packages that belong to those packages rather than to your project, and are left out.
A manifest under one of `LICENSING_NESTED_ROOTS` belongs to the package that ships it, such as a `Cargo.lock` inside an
npm package. For npm, a `package.json` anywhere but `node_modules/<name>` or `node_modules/@scope/<name>` is a fixture
or a bundled copy (`LICENSING_SKIP_VENDORED_SUBPATHS`), and a component named like a path inside another package is a
resolution stub (`LICENSING_SKIP_NESTED_SUBPACKAGES`). The packages that ship them are checked themselves.

Defaults:

```bash
LICENSING_NESTED_ROOTS=("node_modules" "vendor" "site-packages" "Pods" ".build" ".dart_tool")
LICENSING_NESTED_MANIFESTS=(…)   # see licensing.sh
LICENSING_SKIP_VENDORED_SUBPATHS=1
LICENSING_SKIP_NESTED_SUBPACKAGES=1
```

#### `LICENSING_ISOLATED_MANIFESTS`

_Optional._ Manifests that are also scanned on their own, in a scratch directory. In a large tree, syft sometimes gives
every component of a manifest a licence it found elsewhere in the tree. Add a manifest name if all of a manifest's
dependencies show your project's own licence.

Default:

```bash
LICENSING_ISOLATED_MANIFESTS=("go.mod")
```

#### `LICENSING_AUX_SCAN_TARGETS` and `LICENSING_CARGO_REGISTRY_SRC`

_Optional._ Package caches outside the repository, read only to fill in licences for components the scan already found.
Dart keeps its packages in `~/.pub-cache` and Rust in the Cargo registry, which follows `CARGO_HOME`. Add the cache of
another ecosystem whose components come back unlicensed.

Defaults:

```bash
LICENSING_AUX_SCAN_TARGETS=(
  "dir:${HOME}/.pub-cache/hosted"
)
LICENSING_CARGO_REGISTRY_SRC="${CARGO_HOME:-${HOME}/.cargo}/registry/src"
```

### Licence detection

#### `LICENSING_LICENSE_ALIASES`, `LICENSING_LICENSE_ALIASES_LAST` and `LICENSING_PLACEHOLDER_LICENCES`

_Optional._ How a licence written in words becomes an SPDX id. Each alias is `"<lowercased glob>|<SPDX id>"`, and the
first match wins.

`LICENSING_LICENSE_ALIASES` is applied first, before the script reads a package's licence file. About 100 built-in
aliases cover common spellings (`Apache License, Version 2.0`), licence URLs and Python trove classifiers. Add one when
the check reports a licence in words under _REVIEW_ and the words name exactly one licence.

`LICENSING_LICENSE_ALIASES_LAST` is applied last, only when the package ships no licence file. Put a name here when it
could mean more than one licence: "Mozilla Public License" with no version is MPL-1.1 or MPL-2.0, and the package's
licence file, if there is one, settles which. In the first list it would override that file.

`LICENSING_PLACEHOLDER_LICENCES` lists values that name no licence at all ("Dual License", "UNKNOWN"); the script then
looks at the classifiers and the licence file instead.

```bash
LICENSING_LICENSE_ALIASES+=("acme public license*|LicenseRef-acme")
LICENSING_LICENSE_ALIASES_LAST+=("eclipse public license|EPL-1.0")   # no version given
```

Defaults:

```bash
LICENSING_LICENSE_ALIASES=(…)   # see licensing.sh
LICENSING_LICENSE_ALIASES_LAST=(
  "mozilla public license*|MPL-1.1"
  "mpl|MPL-1.1"
)
LICENSING_PLACEHOLDER_LICENCES="…"   # see licensing.sh
```

#### `LICENSING_LICENCE_FILE_GLOBS`, `LICENSING_LICENCE_FILE_DIRS`, `LICENSING_FOREIGN_MANIFESTS` and `LICENSING_LOCKFILE_NAMES`

_Optional._ When a package's metadata names no licence, the script reads the licence file next to it. These say which
files count as licence files and where in a package to look. Next to a lockfile or a dependency manifest
(`LICENSING_FOREIGN_MANIFESTS`), the licence file belongs to the project that wrote it, not to the packages it lists, so
it is not used. `LICENSING_LOCKFILE_NAMES` also decides which components are lockfile-only. Leave them unless your
ecosystem uses names not listed.

Defaults:

```bash
LICENSING_LICENCE_FILE_GLOBS=(LICENSE LICENCE COPYING "LICENSE.*" "LICENCE.*"
                              "COPYING.*" "LICEN[SC]E-*")
LICENSING_LICENCE_FILE_DIRS=(. licenses license_files)
LICENSING_FOREIGN_MANIFESTS=(${LICENSING_LOCKFILE_NAMES} "requirements*.txt"
                             go.mod go.sum pom.xml Gemfile Pipfile Podfile pubspec.yaml)
LICENSING_LOCKFILE_NAMES="…"   # see licensing.sh
```

#### `LICENSING_SYFT_ENV`, `LICENSING_ADD_CATALOGERS` and `LICENSING_CATALOGERS`

_Optional._ How syft is run. The environment turns on Go and Java licence lookups, including over the network, and
includes npm development dependencies. Remove `SYFT_GOLANG_SEARCH_REMOTE_LICENSES` and `SYFT_JAVA_USE_NETWORK` for a run
without network access. `LICENSING_ADD_CATALOGERS` adds the catalogers for installed `node_modules` and `site-packages`,
which syft skips by default; `LICENSING_CATALOGERS` replaces syft's selection outright
(`--override-default-catalogers`).

Defaults:

```bash
LICENSING_SYFT_ENV=(…)   # see licensing.sh
LICENSING_ADD_CATALOGERS=("javascript-package-cataloger" "python-installed-package-cataloger")
LICENSING_CATALOGERS=""
```

#### `LICENSING_GITHUB_LICENCES` and `LICENSING_GITHUB_API`

_Optional._ GitHub Actions have no manifest to read a licence from, so the script asks GitHub's API, once per action;
answers are cached. Set `GITHUB_TOKEN` or `GH_TOKEN` if a large tree hits GitHub's limit of 60 calls an hour,
`LICENSING_GITHUB_LICENCES=0` for a run without network access, and `LICENSING_GITHUB_API` for GitHub Enterprise Server.

Defaults:

```bash
LICENSING_GITHUB_LICENCES=1
LICENSING_GITHUB_API="https://api.github.com"
```

### Install preflight

#### `LICENSING_INSTALL_CHECK`, `LICENSING_AUTO_INSTALL`, `LICENSING_INSTALL_CHECKS` and `LICENSING_INSTALL_CHECK_SKIP`

_Optional._ Licences are read from installed packages; a lockfile alone has none. So the check stops when a manifest's
packages are not installed, and prints the command that installs them. Without this, every dependency of that manifest
would fail as unlicensed. `LICENSING_INSTALL_CHECK=0` turns the stop off: do that only when your packages are installed
somewhere the check does not look, such as a global Python environment, and it keeps asking you to install them.
`LICENSING_AUTO_INSTALL=1` runs the install command instead of stopping; set it in the environment of a CI job that does
not install dependencies itself. `LICENSING_INSTALL_CHECK_SKIP` lists directories you do not check at all, such as a
sample app; add a comment saying why. `LICENSING_INSTALL_CHECKS` holds one
`"<label>|<manifest glob>|<install paths>|<install command>"` entry per ecosystem: replace an entry to change its
install command.

```bash
LICENSING_INSTALL_CHECK_SKIP=("examples/demo-app")   # not shipped
```

Defaults:

```bash
LICENSING_INSTALL_CHECK=1
LICENSING_AUTO_INSTALL="0"
LICENSING_INSTALL_CHECKS=(…)   # see licensing.sh
LICENSING_INSTALL_CHECK_SKIP=()
```

### REUSE files

#### `LICENSING_REUSE`

_Optional._ Set `0` to skip `reuse lint` while a repository is getting its first SPDX headers. Every run then says so.

Default:

```bash
LICENSING_REUSE="1"
```

#### `LICENSING_LICENSE_SOURCES` and `LICENSING_NOTICE_FILE`

_Optional._ What to do with your dependencies' licence texts. By default `download` puts them in `LICENSES/`, writes
`LICENSING_NOTICE_FILE` once and annotates it in `REUSE.toml`, because `reuse lint` otherwise calls the texts unused.
Point `LICENSING_NOTICE_FILE` at the document you ship, such as `NOTICE`. To keep no dependency texts in the repository,
set `LICENSING_LICENSE_SOURCES="reuse"` and `LICENSING_NOTICE_FILE=""`.

Defaults:

```bash
LICENSING_LICENSE_SOURCES="reuse syft"
LICENSING_NOTICE_FILE="THIRD-PARTY-LICENSES.md"
```

#### `LICENSING_VENDOR_ROOTS`

_Optional._ Directories of committed third-party code. For each one git tracks, `download` writes one `REUSE.toml` entry
covering all of it. Add the directory you commit third-party code to, such as `external`.

Default:

```bash
LICENSING_VENDOR_ROOTS=("vendor" "node_modules" "third_party" "Pods" "Carthage")
```

#### `LICENSING_REUSE_TOML`, `LICENSING_REUSE_MARKER` and `LICENSING_LICENSES_DIR`

_Optional._ The REUSE file names and the marker line `download` writes below. REUSE expects these names. Change the
marker only to adopt a `REUSE.toml` that already has a different one.

Defaults:

```bash
LICENSING_REUSE_TOML="REUSE.toml"
LICENSING_REUSE_MARKER="# --- generated by licensing.sh: vendored components (do not edit below) ---"
LICENSING_LICENSES_DIR="LICENSES"
```

### Mode, speed and cache

#### `LICENSING_LOCAL_MODE` and `LICENSING_TRIGGER_PATHS`

_Optional._ Set `LICENSING_LOCAL_MODE="delta"` when the full scan makes commits slow: `reuse lint` still runs on every
commit, the dependency scan only when a commit changes a file in `LICENSING_TRIGGER_PATHS`. CI always runs a full check.

Defaults:

```bash
LICENSING_LOCAL_MODE="full"
LICENSING_TRIGGER_PATHS=(…)   # see licensing.sh
```

#### `LICENSING_SCAN_JOBS`, `LICENSING_SCAN_HEAVY_DIRS`, `LICENSING_SCAN_HEAVY_MIN_ENTRIES` and `LICENSING_SCAN_NOSPLIT`

_Optional._ On a tree with many installed packages, the scan runs one syft per top-level directory, up to the number of
CPUs. Set `LICENSING_SCAN_JOBS=1` if that runs out of memory, or a number to cap it.

Defaults:

```bash
LICENSING_SCAN_JOBS=auto
LICENSING_SCAN_HEAVY_DIRS=("node_modules" "vendor" ".venv" "venv" "Pods" "target" "build")
LICENSING_SCAN_HEAVY_MIN_ENTRIES=200
LICENSING_SCAN_NOSPLIT=(".github" ".forgejo" ".gitlab" ".circleci" ".azuredevops" ".gitea")
```

#### `LICENSING_CACHE`, `LICENSING_CACHE_DIR` and `LICENSING_CACHE_MAX_AGE_DAYS`

_Optional._ The scan cache. Run with `LICENSING_CACHE=0` in the environment when a result looks stale. Point
`LICENSING_CACHE_DIR` at a directory your CI caches to keep it between jobs. Both can be set in the environment.

Defaults:

```bash
LICENSING_CACHE="1"
LICENSING_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/licensing.sh"
LICENSING_CACHE_MAX_AGE_DAYS=30
```

#### `LICENSING_TOOL_RUNNER`

_Optional._ How syft and reuse are found: `auto` tries mise, then `PATH`. `mise` fails unless mise provides the tool,
which enforces the pinned versions. `path` ignores mise, for a CI image that has the tools and no mise.

Default:

```bash
LICENSING_TOOL_RUNNER="auto"
```

### Output

#### `LICENSING_MAX_FINDINGS` and `LICENSING_LINT_MAX_FILES`

_Optional._ How much is printed. `LICENSING_MAX_FINDINGS` caps the failing components listed, for a first run on a large
tree; `0` lists all. With `--verbose`, `LICENSING_LINT_MAX_FILES` caps the files listed per `reuse lint` category; raise
it when you add headers in bulk and want the whole list.

Defaults:

```bash
LICENSING_MAX_FINDINGS=0
LICENSING_LINT_MAX_FILES=200
```

#### `LICENSING_COLOR` and `LICENSING_PROGRESS`

_Optional._ Colour in the findings table, and the progress bar some terminals draw in their tab or taskbar. Same as
`--color` and `--progress`, and both can be set in the environment. `auto` colours only a terminal, and draws the bar
only in terminals known to support it. Set `LICENSING_PROGRESS=off` if your terminal shows a notification per update
instead of a bar.

Defaults:

```bash
LICENSING_COLOR="auto"
LICENSING_PROGRESS="auto"
```

### Obligations report

#### `LICENSING_OBLIGATIONS` and `LICENSING_DUTIES`

_Optional._ What each licence asks of you, for `--obligations`. `LICENSING_OBLIGATIONS` maps about 55 licences to duty
codes from `LICENSING_DUTIES`. A licence with no entry shows as `???`: add one, or replace an entry your legal review
reads differently.

```bash
LICENSING_OBLIGATIONS+=("LicenseRef-acme|notice no-endorse|our vendor agreement, section 4")
```

Defaults:

```bash
LICENSING_OBLIGATIONS=(…)   # see licensing.sh
LICENSING_DUTIES=(…)   # see licensing.sh
```

### Per-run settings, environment only

#### `LICENSING_CONF`, `LICENSING_VERBOSE` and `LICENSING_DEBUG_DIR`

_Optional._ Set in the environment for one run, never in the policy file. `LICENSING_CONF` reads another policy file
instead of `.licensing.conf`, such as one per product in a monorepo. `LICENSING_VERBOSE=1` is `--verbose`.
`LICENSING_DEBUG_DIR=<dir>` saves the raw scan (`scan.txt`) and the `REUSE.toml` the run would generate (`REUSE.gen`)
there, to see why `check` reports drift. None has a default.

## Environment variables from other tools

The script also reads these variables, which other tools or your shell set. None of them needs setting for a normal run.

| Variable                                   | Value the script looks for                               | Effect                                                                                                                                                                                                                                                           |
| :----------------------------------------- | :------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CI`                                       | any non-empty value                                      | `--mode auto` runs a full check. GitHub Actions, GitLab CI and most CI systems set it for you.                                                                                                                                                                   |
| `PRE_COMMIT`                               | `1`                                                      | Hints in the output name the `pre-commit run` command for a fix instead of the script's path in pre-commit's cache. pre-commit sets it when it runs a hook.                                                                                                      |
| `NO_COLOR`                                 | any non-empty value                                      | No colour in the findings table, but only while `LICENSING_COLOR` is `auto`. This is the [shared convention](https://no-color.org) for turning colour off in every tool at once; `LICENSING_COLOR` exists to set colour for this tool alone, and to force it on. |
| `GITHUB_TOKEN`, `GH_TOKEN`                 | a GitHub token; `GITHUB_TOKEN` is used when both are set | Authenticates the calls `LICENSING_GITHUB_LICENCES` makes, raising GitHub's limit above 60 calls an hour. A token with no scopes is enough for public repositories.                                                                                              |
| `CARGO_HOME`                               | a directory                                              | Where cargo keeps its registry; `LICENSING_CARGO_REGISTRY_SRC` follows it. Default `~/.cargo`.                                                                                                                                                                   |
| `XDG_CACHE_HOME`                           | a directory                                              | The base of `LICENSING_CACHE_DIR`. Default `~/.cache`.                                                                                                                                                                                                           |
| `TERM`                                     | the terminal type                                        | Empty or `dumb` means no colour under `LICENSING_COLOR=auto`.                                                                                                                                                                                                    |
| `TERM_PROGRAM`, `WT_SESSION`, `ConEmuANSI` | set by the terminal                                      | Identify the terminals that draw the progress bar under `LICENSING_PROGRESS=auto`.                                                                                                                                                                               |

## Machine-readable output for scripts

`check --porcelain` prints one record per line on stdout, fields separated by tabs, the first field naming the record
type. Human-readable lines move to stderr.

```text
duty     <code> <what it obliges you to do>
licence  <SPDX id> <components> <duty codes> <note>
pair     <SPDX id> <component|file|annotation> <name> <version> <type>
finding  <DENY|REVIEW> <type> <name> <version> <licences> <where>
summary  <gated> <deny> <review> <exempt> <lockfile-only>
```

An empty duty-codes field means the licence asks nothing; `?` means nothing is recorded for it. Ignore record types you
do not know, or pin the format with `--porcelain=v1`.

## Exit codes: 0 passed, 1 violation, 2 cannot run

| Code | Meaning                                                                                                                                                |
| :--- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Everything passed.                                                                                                                                     |
| 1    | A policy violation: a denied or unreviewed licence, `REUSE.toml` drift, a file without SPDX information, or a licence text `download` could not fetch. |
| 2    | A usage error, a missing policy file, uninstalled dependencies, or a missing tool.                                                                     |

## Developing this repository

```sh
mise install                                                     # pinned tools
pre-commit install --install-hooks -t pre-commit -t commit-msg -t pre-push
pre-commit run --all-files                                       # all checks
bats tests                                                       # ~30 s, also runs on pre-push and in CI
```

This repository checks itself: `.pre-commit-config.yaml` runs `./licensing.sh` on its own files. `scripts/check-docs.sh`
fails when this README and `licensing.sh` disagree about a setting, option, command, hook or default file. Commits
follow [Conventional Commits](https://www.conventionalcommits.org). See [CONTRIBUTING.md](CONTRIBUTING.md) for
versioning and releases.

## Licence of this repository

Code: [MPL-2.0](LICENSE). Documentation: [CC-BY-4.0](LICENSES/CC-BY-4.0.txt).
