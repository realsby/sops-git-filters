# Changelog

Every release is a tag. The same notes are on the [releases page](https://github.com/realsby/sops-git-filters/releases). After an update, run `install.sh` again in every clone.

## Unreleased

### Security

- **Windows: the guard did not read the global and system attributes files**, because git prints their paths as `C:/...` and the guard took them for relative paths. A macro there that turns `filter` off (`[attr]binary -filter`) let a plaintext secret through. Such a path now counts as absolute.

### Performance

- **The clean filter remembers its answer for 10 minutes** ([#21](https://github.com/realsby/sops-git-filters/issues/21)). Git runs it each time it looks at a secret with uncommitted changes, and each run decrypted the stored version and encrypted the edit: two requests to a key service, and a new ciphertext every time. Now the first look after an edit costs that; later `git status`, `git diff --stat`, `git add` and `git commit -a` call `sops` no more, and `git diff` once (for the text it shows). They all see the same ciphertext for the same edit. On disk, in `.git/sops-git-filters/cache/`: HMACs under a random key of the repository, and object ids, never plaintext. `SOPS_FILTER_CACHE=0` turns it off. README: "What the clean filter remembers".
- **`rekey.sh` lists the SOPS-managed files with one git call**, as the guard does, instead of a bash loop over every tracked file: 0.4 seconds instead of 19 with 60,000 tracked files. When git cannot list the index or answers out of order, it now stages nothing.

### Behaviour changes

- **A comparison that worked is not repeated for 10 minutes.** Keys that become unavailable in that time (an expired session) are noticed at the first run after it, or at once with `SOPS_FILTER_CACHE=0`. A file you can encrypt but not decrypt still fails at its next check, as before.
- **`git status` and `git diff` write the ciphertext they get into the object store**, as `git add` would, so that the next command can reuse it. `git gc` removes those that nothing refers to.

### Fixed

- **Windows (Git Bash): every `git add` and checkout of a secret failed.** The scripts gave `sops` the file `/dev/stdin`, which Git Bash hands to a Windows program as `C:\proc\self\fd\0`, a path that does not exist. `sops` now reads stdin itself.
- **Windows: a machine-wide `core.hooksPath` (`~/.githooks`) was taken for a directory inside the repository**, because git prints it as `C:/...` too: `install.sh` wrote the permission hooks there, where git never runs them, instead of leaving the shared directory alone.
- **Windows: `install.sh` stopped (exit status 128) at a secret whose path holds a character such as `` ` ``.** Git Bash hands git such an absolute path unconverted, and git cannot open it. It now names the file from the top of the working tree.
- **`harden-permissions.sh` no longer says "set to 600" where the file system keeps no Unix modes** (Windows); it says that it changed nothing. The clean filter keeps no cache there, for the same reason (its directory must be closed to others).
- **busybox awk up to 1.30:** the clean filter failed when the keys of a secret changed ("Call to undefined function").

### Documentation

- The merge driver needs git 2.34 (`git stash pop`: 2.37): older git aborts a merge that the driver resolved. The permission hook runs after `git cherry-pick` and `git revert` from git 2.25 on.
- Windows: what NTFS and Git Bash do not have (file modes, symbolic links), a hook script for the guard in place of the symlink, and `path_regex` rules: `sops` matches them against the path with backslashes there, so write `[/\\]` for the separator.

### CI

- Three more jobs, not required checks: the tests on Windows (Git Bash), in Alpine Linux (busybox awk) and with git 2.18.

## v3.1.0 — 2026-11-25

[All changes since v3.0.0](https://github.com/realsby/sops-git-filters/compare/v3.0.0...v3.1.0)

After the update, run `install.sh` again in every clone: git runs the copy under the git directory, and that copy stays at v3.0.0 until `install.sh` replaces it. The clean filter, the smudge filter, the merge driver and the hooks say so on stderr until then.

### Security

- **The guard let plaintext through in three local states.** Each needs the clean filter to have been bypassed first, which is the case the guard is there for. The guard now blocks all three.
  - It read `.gitattributes` from the working tree. A local `-filter` line that was not staged let a plaintext secret into a commit whose own `.gitattributes` still marked it `filter=sops`. It now reads the attributes of the index, the ones the commit carries.
  - A line in `.git/info/attributes` that sets or unsets `filter` overrides every `.gitattributes`, with the same result. So does a macro (`[attr]…`) that turns `filter` off, defined in that file, in the global attributes file (`core.attributesFile`) or in the system one, when a committed `.gitattributes` uses it. The guard now blocks while one of these files can change the filter of a path, and prints the lines to remove. A local `filter=lfs` line in `.git/info/attributes` blocks too: on a secret's path it would be the same bypass. A fresh checkout, as in CI, has none of these files.
  - On macOS, the awk that checks a blob ends a line at a NUL byte, so plaintext after a NUL byte was never looked at. A blob with a NUL byte is now refused: a SOPS document never has one.
- **The `ENC[...]` check looks at the whole value.** It was an alphabet test, so `ENC[AES256_GCM,data:MyPassword123,iv:x,tag:y,type:str]` passed as ciphertext. It now checks the field order, the base64 shape, the iv and tag lengths that every sops release writes, and the type.
- **`install.sh` no longer writes plaintext through a link.** The re-smudge pass followed a symlink in place of a secret, a symlinked directory on its path, and a hard link, and wrote the plaintext outside the working tree. Such a file is now left encrypted and reported (exit status 3). `harden-permissions.sh` no longer changes the mode of a file reached through a symlinked directory.

### Behaviour changes

- **A SOPS document is stored unchanged only when it is the stored version.** Before, any input that looked like a SOPS document was stored as it was. A `.env` copied from another project (encrypted for its keys) or an edited one went into git with exit status 0 and broke every teammate's checkout. Now:
  - the ciphertext of the stored version (a clone where `install.sh` could not decrypt) is still stored unchanged, without a key, also with CRLF line endings;
  - any other SOPS document must decrypt with your keys, and is then encrypted for the keys of `.sops.yaml` like any other plaintext (unchanged content reuses the stored blob);
  - one that does not decrypt is refused, with two ways back: one that needs no key and one that does.

  A clone without keys meets this after a command that moves the index but not the working tree (`git reset HEAD~1`, `git restore --staged --source=…`): the working copy then holds ciphertext that is no longer the stored version, and `git status` stops with that message instead of showing the file as modified. The README has the way back.
- **A change of keys is named.** When the clean filter re-encrypts a file for other keys than the stored version had (after a change to `.sops.yaml`), it prints the keys added and removed.
- **The guard lets a commit pass while a secret has an intent-to-add entry** (`git add -N`). Such an entry never reaches a commit as an empty file; before, it blocked every commit.
- **`install.sh` keeps a hook that was changed by hand.** It replaces only a hook that is byte for byte one it wrote, and names the others with the line to add.
- **`install.sh` stops on a `filter.sops.process` from another git config file before it writes anything**, and writes `filter.sops.required` only once the filter commands follow. A stopped run no longer leaves a new clone where every edit of a secret fails.
- **`install.sh` decrypts a checkout with CRLF line endings** (`core.autocrlf=true` without `-text`), instead of leaving the ciphertext and exiting 0.
- **`preflight.sh --quiet`** still prints the warning about managed files that are not SOPS documents, on stderr.
- **`rekey.sh`** reads the attributes of the index, like the guard.
- **The permission hook counts an unmerged path once** in its "Permissions: N" line.

### Fixed

- **Speed in large repositories.** The guard and the permission hooks walked every tracked file in a bash loop. With 60,000 files and 11 secrets: guard 8.5 s → 0.4 s, permission hook 1.5 s → 0.04 s, `git commit` with both 10 s → 0.5 s, `install.sh` 3.7 s → 0.8 s, `preflight.sh` 1.9 s → 0.35 s.
- **The scripts run in a checkout with CRLF line endings.** A `.gitattributes` keeps `*.sh` at LF. With `core.autocrlf=true` (the default of Git for Windows) they failed at their first line. A vendored copy needs the same file next to the scripts (README, option B).
- **A secret named like an index stage** (`2:prod.secret`) was compared with the wrong version and re-encrypted at every check.
- **`GIT_LITERAL_PATHSPECS` and the other `GIT_*_PATHSPECS` variables** of the caller no longer make the permission hook, `install.sh` or `preflight.sh` miss or fail on the managed files.
- **Commands printed for you to paste** take the path literally, not as a pattern: for a secret named `[ab].env`, `git checkout -- …` no longer also restores `a.env`. They name the file by its full path, so they work from any directory; the merge driver's hints did not.

### Documentation

- `-text` in `examples/gitattributes` and in the walkthrough.
- The guard checks the structure of every managed blob; in CI, run `encryption-guard.sh` instead of a grep.
- Copies of a secret that the wildcards miss (`.env~`, `#.env#`, `.env-2026-11-24`, …), and `.gitignore` lines for them.
- The plaintext files `git mergetool` writes and leaves; `mergetool.writeToTemp true` and `mergetool.keepBackup false`.
- Review every change to `.sops.yaml`: it decides who can read every secret edited after it.
- A rule in `.sops.yaml` that does not list your key: `git add` works, `git commit` fails, and what to do.
- `SOPS_FILTER_FORCE_REENCRYPT=1` reaches every file git checks: set it on `git add`, commit without it.
- `preflight.sh` checks the index only.
- What the git minimum (2.18) rests on, and which git CI runs.
- With `core.hooksPath` inside the working tree the permission hooks show as untracked files.
- Limitations: a commit that takes `filter=sops` off a path passes the guard with that file in plaintext.
- `git status` may also contact the key service that a SOPS document in a managed path names.

### CI

- A job checks out the tool with `core.autocrlf=true` and runs `install.sh` and the guard from it.
- Time limits per job.
- Dependabot proposes updates of the pinned actions, weekly.
- Greptile reviews only when asked (`greptile.json`).

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
