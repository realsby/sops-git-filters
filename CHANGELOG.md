# Changelog

Every release is a tag. The same notes are on the [releases page](https://github.com/realsby/sops-git-filters/releases). After an update, run `install.sh` again in every clone.

## v3.0.0 — 2026-11-24

[All changes since v2.1.0](https://github.com/realsby/sops-git-filters/compare/v2.1.0...v3.0.0)

### Why this is a major version

Git no longer runs the scripts of your checkout of the tool. It runs a copy that `install.sh` puts inside the git directory. **After an update of the tool, a clone keeps running the old code until `install.sh` has run there again.** Before, a submodule bump or a new vendored copy took effect at once.

### Upgrading

1. Check out the tag in the submodule (or replace your vendored copy; it needs the new `smudge-filter.sh` too).
2. Run `install.sh` in every clone, from a checkout you trust. Once per clone is enough: linked worktrees share the copy.

Until step 2 is done in a clone, that clone works as before with the old settings.

### Behaviour changes

- **Git runs an installed copy.** `install.sh` copies `clean-filter.sh`, `smudge-filter.sh`, `merge-driver.sh`, `harden-permissions.sh` and `lib.sh` into `sops-git-filters/` inside the common git directory. `filter.sops.clean`, `filter.sops.smudge`, `merge.sops.driver` and the five hooks name that copy, with a path that is resolved when the command runs: `"$(git rev-parse --git-common-dir)"/sops-git-filters/...`. Checking out a branch can no longer swap the code that sees the plaintext. Before, with a vendored copy of the tool, a checkout ran the branch's `harden-permissions.sh` through the post-checkout hook, and the next `git status` ran its `clean-filter.sh`.
- **The installed copy says when it is behind.** When the checkout of the tool holds a newer version than the copy, the clean filter, the smudge filter, the merge driver and the hooks print one line on stderr that names `install.sh`. The version is the `SGF_VERSION` line of `lib.sh`, read as text.
- **The smudge filter is a script.** `filter.sops.smudge` was a bare `sops decrypt`. It is `smudge-filter.sh` now: the same decryption and the same fail-closed result (git stops, nothing is written in place of the secret), plus lines under the `sops` error that say what to check for the kinds of key the file names. The storage format is part of the command, as before (`smudge-filter.sh dotenv %f`): after a change of `SOPS_STORE_FORMAT`, `install.sh` has to run again.
- **Linked worktrees need nothing of their own.** With the submodule layout, `git status` and `git add` failed in a new linked worktree until `git submodule update --init` ran there, and secrets stayed `0644`. Now the filter and the hooks work straight after `git worktree add`.
- **The line for a shared hooks directory changed.** v2.1.0 printed a line that named one repository by its absolute path and ran `harden-permissions.sh` of its working tree. The new line runs the installed copy of whatever repository the hook runs in, and does nothing where `install.sh` never ran. If you added the old line to your hooks, replace it.
- **The path of the tool is in no git setting any more.** A tool directory with a space or shell syntax in its name, or outside the repository, no longer shows up in `.git/config`, and the warning about a tool outside the repository is gone.

### Added

- `smudge-filter.sh`.
- `preflight.sh` no longer counts files as different sets of keys because different releases of `sops` wrote them: one decryption answers for all files with the same key groups, keys and threshold.
- README, "Security model": what runs from where, and that a SOPS document names its own key service, so a blob from someone else can make `sops` contact a key service with your credentials.

## v2.1.0 — 2026-11-22

[All changes since v2.0.0](https://github.com/realsby/sops-git-filters/compare/v2.0.0...v2.1.0)

### Security

- **`install.sh` wrote hooks into a shared hooks directory, and they ran code from any repository.** With `core.hooksPath` pointing at a directory that several repositories use (a machine-wide `~/.githooks`, say), `install.sh` up to v2.0.0 wrote its `post-checkout` and `post-merge` hooks into that directory. Git then ran them in every repository of the user, and each run called `utilities/sops-git-filters/harden-permissions.sh` (the path of the tool in the repository where `install.sh` had run) inside the repository at hand. Cloning or checking out any repository that ships an executable file at that path executed it.

  Affected: you ran `install.sh` of v1.1.0 to v2.0.0 while `core.hooksPath` named a directory that other repositories use too. A clone that uses the default `.git/hooks` is not affected.

  Fix: update to v2.1.0 and run `install.sh` again in one of your clones. It removes the two hooks from the shared directory (only files that are byte for byte what `install.sh` wrote; it tells you when it finds one that was changed by hand) and never writes there again. Or delete `post-checkout` and `post-merge` from that directory yourself if their second line is `# managed by sops-git-filters (secret file permissions)`.

  Advisory: [GHSA-h5c9-chvh-476w](https://github.com/realsby/sops-git-filters/security/advisories/GHSA-h5c9-chvh-476w).

### Behaviour changes

- **Shared hooks directory: nothing is written there any more, and what was written is removed.** If git runs this repository's hooks from a directory that is not the repository's own (`core.hooksPath` to a place outside it, a machine-wide `core.hooksPath`, a symlinked `.git/hooks`), `install.sh` installs no hooks. The filters work as before; what is missing is the step that sets secrets back to `0600` after a checkout, merge, rebase or commit. `install.sh` prints one line that you can add to your own hooks in that directory. That line names the repository by its absolute path and does nothing in any other repository.
- **A file with NUL bytes stops `git add`.** A keystore, a DER certificate or UTF-16 text under a `filter=sops` path was stored without its NUL bytes, with exit status 0: the file in git was damaged. Now the clean filter refuses it and says why. `git status`, `git diff`, `git stash` and `git commit -a` fail the same way while such a file sits in the working tree and git has to read it. Store a text form of the secret (base64, PEM, UTF-8), or take `filter=sops` off that path. If you committed such a file with an earlier version, the copy in git is damaged: restore the original from somewhere else.
- **`SOPS_FILE_MODE` accepts owner and group bits only.** A value such as `644`, `666` or `4600` (any bit for others, setuid, setgid, sticky) is refused: `harden-permissions.sh` sets the files to `600`, prints an error and exits 1. Before, it applied whatever the file said.
- **Three more hooks.** Next to `post-checkout` and `post-merge`, `install.sh` now writes `post-rewrite`, `post-applypatch` and `post-commit`. They do the same one thing (run `harden-permissions.sh`). A hook of that name that already exists and was not written by this tool is left alone, and `install.sh` prints the line to add to it. A hook that is a symlink is never written through.
- **A secret tracked as executable keeps its execute bit.** A `filter=sops` file with mode `100755` in git gets `0700` (or `0740` with `SOPS_FILE_MODE=640`) instead of `0600`, so git no longer shows it as modified for ever.
- **The example `.gitattributes` uses wildcards.** `examples/gitattributes` and the README now send `.env`, `.env.*` and `*.env` through the filter and take `.env.example` out again. Your own `.gitattributes` is not changed by an update; compare it with the example.

### Added

- **`preflight.sh`**: asks whether `sops` can decrypt, before git needs it. It decrypts one stored blob per set of keys (key groups, keys and threshold) to `/dev/null` and exits 0, 1 (cannot decrypt) or 2 (could not check, or could not check everything). Run it before a pull, checkout or rebase: `./utilities/sops-git-filters/preflight.sh && git pull`.
- **README: "When sops cannot decrypt: preflight and recovery".** What a pull, checkout or rebase leaves behind when it stops in the smudge filter, and the way back.
- **Hints by kind of key.** When decryption fails, the clean filter, `install.sh` and `preflight.sh` name what to check for the keys the file was encrypted for (age, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault, PGP), not only for AWS.
- **Mode 0600 after more commands**: rebase, `commit --amend`, cherry-pick, revert, `git am`, and the first commit of a new secret (the three new hooks). Not covered, because git runs no hook: `git stash`, `git stash pop`, `git reset --hard`, `git sparse-checkout add`.
- **`SECURITY.md`**, and private vulnerability reporting on GitHub.

### Fixed

- A refused `SOPS_FILE_MODE` no longer leaves the files at the umask mode: they get `600` first, then the error ([#12](https://github.com/realsby/sops-git-filters/pull/12), [#14](https://github.com/realsby/sops-git-filters/pull/14)).
- A secret tracked as `100755` lost its execute bit ([#13](https://github.com/realsby/sops-git-filters/pull/13)).
- A tool path with a space, a quote, `;`, `$(...)` or `%` in it: `install.sh` now quotes it in the filter and merge commands and in the hooks. Before, a space made `git add` fail and shell syntax in a directory name was executed. A tool reached through a symlinked path is recognised as inside the repository ([#18](https://github.com/realsby/sops-git-filters/pull/18)).
- An exported `CDPATH` could make the scripts look for `lib.sh` in another directory ([#17](https://github.com/realsby/sops-git-filters/pull/17)).
- The re-smudge pass of `install.sh` no longer writes a file whose stored version has NUL bytes without them; it leaves the ciphertext and reports the file (exit status 3).
- The clean filter no longer takes a stored version with NUL bytes for "unchanged".

### Documentation

- `core.autocrlf` needs `-text` on the managed paths ([#11](https://github.com/realsby/sops-git-filters/pull/11)).
- Where plaintext appears outside the object store, and `export-ignore` ([#10](https://github.com/realsby/sops-git-filters/pull/10)).
- A new linked worktree with the submodule layout needs `git submodule update --init` first ([#9](https://github.com/realsby/sops-git-filters/pull/9)).
- `git add -p` stages a managed file whole ([#8](https://github.com/realsby/sops-git-filters/pull/8)).
- `examples/sops-filter.conf`: dotenv comments are encrypted, and the README section it points to exists ([#6](https://github.com/realsby/sops-git-filters/pull/6), [#7](https://github.com/realsby/sops-git-filters/pull/7)).
- Updating: check out the latest tag instead of pulling `main`.
- Limitations: commands after which mode 0600 does not come back, and what a secret with uncommitted changes costs in key-service calls.
- "Repository policy" describes this repository only.

## v2.0.0 — 2026-11-11

[Release notes](https://github.com/realsby/sops-git-filters/releases/tag/v2.0.0) · [all changes since v1.1.0](https://github.com/realsby/sops-git-filters/compare/v1.1.0...v2.0.0) · [#5](https://github.com/realsby/sops-git-filters/pull/5)

- `sops` 3.11.0 or newer is required.
- The clean filter checks what `sops` returns and refuses anything that is not a completely encrypted SOPS document; the dotenv format refuses input it would store in clear.
- No blind re-encryption when the stored version cannot be decrypted; ciphertext input is stored unchanged; `SOPS_FILTER_FORCE_REENCRYPT=1`.
- The guard checks the structure of every tracked SOPS-managed blob.
- `install.sh` always writes `filter.sops.required`, reports plaintext in git, exits 3 when files need attention, and sets `core.trustctime=false`.
- New: `merge-driver.sh` (`merge=sops`), `rekey.sh`, a test suite and CI.

## v1.1.0 — 2026-09-15

- `harden-permissions.sh`: SOPS-managed files are set to `0600`, by `install.sh` and by `post-checkout` and `post-merge` hooks.

## v1.0.0 — 2026-07-20

- First release: clean and smudge filters, `install.sh`, the pre-commit guard.
