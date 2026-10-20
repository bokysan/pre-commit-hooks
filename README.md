<!--
SPDX-FileCopyrightText: 2026 Bojan Čekrlić
SPDX-License-Identifier: CC-BY-4.0
-->

# pre-commit-hooks

[pre-commit](https://pre-commit.com) hooks by Bojan Čekrlić.

| Hook                 | What it does                                                                                                                                                                                                                |
| :------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `licensing`          | One gate over a project's whole licensing story: every third-party dependency carries a licence your outbound licence can absorb, `REUSE.toml` matches the same scan, and every file carries SPDX copyright + licence info. |
| `licensing-fix`      | Manual stage. Regenerates `REUSE.toml`'s vendored section, then runs the check.                                                                                                                                             |
| `licensing-download` | Manual stage. Fetches missing texts into `LICENSES/`, removes unused ones.                                                                                                                                                  |
| `licensing-sbom`     | Manual stage. Writes `sbom.spdx.json` from the inventory the gate checks.                                                                                                                                                   |

Home: <https://git.b8.si/boky/pre-commit-hooks>. Mirror: <https://github.com/bokysan/pre-commit-hooks>.

## Use it

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://git.b8.si/boky/pre-commit-hooks # or https://github.com/bokysan/pre-commit-hooks
    rev: v1.36.0
    hooks:
      - id: licensing
```

The tag is the version of `licensing.sh`: `rev: v1.36.0` runs `licensing.sh 1.36.0`.

The hook runs `licensing.sh check --mode auto` on every commit (`always_run`, no filenames: a new file needs a header, so it is never scoped to changed paths). `auto` means a fast delta locally and a full scan when the `CI` environment variable is set.

### Requirements

The hook needs two tools and a policy file. It looks for each tool through [mise](https://mise.jdx.dev) first, then on `PATH`. If it finds a tool through neither, it stops before doing any work and says so.

| Need                                    | Version used here | Notes                                                                                                                                  |
| :-------------------------------------- | :---------------- | :------------------------------------------------------------------------------------------------------------------------------------- |
| [syft](https://github.com/anchore/syft) | 1.51.0            | Component inventory. Pin the same version in your policy file as `LICENSING_SYFT_VERSION`; licence detection changes between releases. |
| [reuse](https://reuse.software)         | 6.2.0             | `reuse lint`. Skippable with `LICENSING_REUSE=0` while a repository is growing headers.                                                |
| `.licensing.conf`                       |                   | Your policy: `LICENSING_ALLOW` and `LICENSING_DENY` have no defaults.                                                                  |

Pin the tools in your `mise.toml` so every developer and CI run uses the same versions:

```toml
[tools]
syft = "1.51.0"
"pipx:reuse" = { version = "6.2.0", extras = "charset-normalizer" }
```

Then `mise install`. Without mise the script uses whatever is on `PATH` and warns when syft differs from `LICENSING_SYFT_VERSION`.

### First setup in a repository

```sh
licensing.sh init      # writes .licensing.conf, a starter REUSE.toml, .license-exceptions.txt
licensing.sh fix       # fills REUSE.toml's vendored section from the scan
licensing.sh check     # the gate
```

See "Running the other commands" to get `licensing.sh` on your path. `licensing.sh --help` documents every command, mode and knob; the policy file is described in the comments `init` writes.

### CI

```yaml
- uses: actions/checkout@v4
- uses: jdx/mise-action@v2 # installs the pinned tools
- run: pre-commit run licensing --all-files
```

## Running the other commands

`init`, `sbom`, `fix`, `download` and the flags (`--obligations`, `--porcelain`, `--only deps`, …) are the same script. The script works on the git repository it is **run from**, not the one it lives in, so it can be called from any repository. Three ways:

### 1. The manual-stage hooks (nothing to install)

```sh
pre-commit run licensing-fix      --hook-stage manual --all-files
pre-commit run licensing-download --hook-stage manual --all-files
pre-commit run licensing-sbom     --hook-stage manual --all-files   # writes sbom.spdx.json
```

Add them to your config next to `licensing` (`- id: licensing-fix`, …) to use them. They have no arguments; for a different invocation use way 2 or 3.

### 2. A checkout on your `PATH` (full CLI, including `init`)

```sh
git clone https://git.b8.si/boky/pre-commit-hooks ~/.local/share/pre-commit-hooks
git -C ~/.local/share/pre-commit-hooks checkout v1.36.0       # match your rev
ln -s ~/.local/share/pre-commit-hooks/licensing.sh ~/.local/bin/licensing.sh

cd your-repo
licensing.sh init
licensing.sh sbom -o release/sbom.spdx.json
licensing.sh check --porcelain --only deps
```

### 3. Straight from pre-commit's cache

pre-commit keeps the hook repository checked out under `~/.cache/pre-commit/repo*/` (`$PRE_COMMIT_HOME` if set). The directory name is a hash, so find it rather than hard-coding it:

```sh
ls ~/.cache/pre-commit/repo*/licensing.sh      # one per fetched version of any hook repo that ships it
~/.cache/pre-commit/repoXXXXXXXX/licensing.sh sbom
```

This runs whichever version pre-commit last fetched. Prefer way 2 when you care which.

`licensing.sh` also takes `LICENSING_CONF=<path>` to read a policy file other than `./.licensing.conf`.

## Development

```sh
mise install                                                     # pinned tools
pre-commit install --install-hooks -t pre-commit -t commit-msg -t pre-push
pre-commit run --all-files                                       # every gate
bats tests                                                       # ~30 s, also on pre-push and in CI
```

The repository uses its own hook: `.pre-commit-config.yaml` runs `./licensing.sh` on this tree. Commits follow [Conventional Commits](https://www.conventionalcommits.org). See [CONTRIBUTING.md](CONTRIBUTING.md) for versioning, releases and the mirror.

## Licence

Code: [MPL-2.0](LICENSES/MPL-2.0.txt). Documentation: [CC-BY-4.0](LICENSES/CC-BY-4.0.txt).
