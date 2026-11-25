# sops-git-filters

[![Greptile: The War on Bugs](https://www.greptile.com/badge.svg)](https://www.greptile.com/?utm_source=oss_badge&utm_medium=readme&utm_campaign=greptile_for_open_source)

Transparent, git-crypt-style secret encryption for git — powered by [SOPS](https://github.com/getsops/sops).

Files you list in `.gitattributes` are **plaintext in your working tree** and **SOPS-encrypted in git**. You edit `.env` normally; git stores ciphertext; `git diff` still shows readable changes.

```
git pull / checkout   →  decrypted automatically   (smudge filter)
git add / commit      →  encrypted automatically   (clean filter)
git diff / log -p     →  shows plaintext changes   (textconv)
git merge / rebase    →  merges the plaintext      (merge driver, opt-in)
git commit            →  guarded by a pre-commit hook that blocks
                         plaintext from ever reaching history
```

A handful of small bash scripts. No daemon, no gpg, no custom key format — keys are whatever SOPS supports (age, AWS/GCP/Azure KMS, Vault, PGP), so you get multi-recipient and break-glass keys for free.

## Contents

- [Why this exists](#why-this-exists)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setup walkthrough](#setup-walkthrough)
- [Storage formats: json vs dotenv](#storage-formats-json-vs-dotenv)
- [Onboarding a teammate / a new machine](#onboarding-a-teammate--a-new-machine)
- [The pre-commit guard](#the-pre-commit-guard)
- [Merging secrets](#merging-secrets)
- [Changing recipients (re-key)](#changing-recipients-re-key)
- [When sops cannot decrypt: preflight and recovery](#when-sops-cannot-decrypt-preflight-and-recovery)
- [Security model](#security-model)
- [Repository policy](#repository-policy)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Tests](#tests)

## Why this exists

Running `sops` by hand (`sops encrypt`, edit, `sops decrypt`) works until the day someone commits the decrypted file. Git clean/smudge filters automate it, but a naive filter setup has four sharp edges this repo rounds off:

1. **SOPS is non-deterministic.** Encrypting the same plaintext twice yields different ciphertext (fresh IV every run). A naive clean filter makes git see every SOPS file as "modified" after every checkout, forever. `clean-filter.sh` decrypts what's already stored and **reuses the existing ciphertext byte-for-byte when the plaintext is unchanged** — no false diffs.

2. **Filters that "fail open" leak secrets.** Many setups pass plaintext through when SOPS isn't configured, so one missing `.sops.yaml` silently commits your secrets. Here the clean filter **fails hard** (and `filter.sops.required=true` makes git abort the `git add`), and a pre-commit guard independently checks every SOPS-managed blob in the index and rejects one that is not a complete SOPS document with every value encrypted.

3. **Absolute paths in `.git/config` rot, and scripts in the working tree can be swapped.** Move or rename the repo directory and a naively configured filter breaks — worse, some breakages are *silent* and the next `git add` stages plaintext. And a filter that lives in the working tree is replaced by whatever branch you check out. `install.sh` puts a **private copy of the scripts under `.git/`** and writes filter commands that find it when they run (`"$(git rev-parse --git-common-dir)"/sops-git-filters/...`): no path to rot, the same commands in every worktree, and no checkout can change the code that sees your plaintext. The guard catches anything that slips through.

4. **Fresh clones hold ciphertext.** Filters live in `.git/config`, which is not cloned — files checked out before setup are raw ciphertext in the working tree. `install.sh` detects and decrypts them in place (only when the working copy is byte-identical to the stored blob, so local edits are never overwritten).

The pre-commit stash dance is also handled: the clean filter compares against the **index**, not HEAD, so [pre-commit](https://pre-commit.com)'s stash/unstash cycle doesn't corrupt staged files or create stash-pop conflicts.

## How it works

```
        ┌────────────────────┐  filter.sops.clean (clean-filter.sh)  ┌──────────────────┐
        │   Working tree     │ ─────────── git add ────────────────▶ │    Git object    │
        │   .env (plaintext) │                                       │  store & remote  │
        │                    │ ◀────────── checkout ──────────────── │   (ciphertext)   │
        └────────────────────┘  filter.sops.smudge (smudge-filter.sh) └──────────────────┘
                                                                            │
                 git diff / git log -p ◀── diff.sops.textconv ──────────────┘
                 (plaintext diffs)          (routes diffs through smudge)

                 git commit ──▶ encryption-guard.sh (pre-commit)
                                rejects any tracked secret that is not an
                                encrypted SOPS document
```

Git does not run these scripts from your checkout of the tool. `install.sh` copies the ones git needs (`clean-filter.sh`, `smudge-filter.sh`, `merge-driver.sh`, `harden-permissions.sh` and `lib.sh`) into `sops-git-filters/` inside the git directory, and the filter, the merge driver and the hooks name that copy. **After an update of the tool, nothing changes until `install.sh` has run again**; the installed copy prints a line when it sees a newer version in the checkout. See [Security model](#security-model) for the reason.

`smudge-filter.sh` is one `sops decrypt` (the plaintext goes from `sops` straight to git). When that fails it adds what to check for the kinds of key the file names, and exits non-zero: git stops, and nothing is written in place of the secret. `install.sh` writes the storage format into the smudge command: the filter cannot read `.sops-filter.conf` itself, because in a new working tree git checks `.env` out before that file.

`clean-filter.sh` decision tree on every `git add`:

1. No `sops` on PATH, or no `.sops.yaml`? → **exit non-zero, git aborts the add.** Plaintext is never stored.
2. Input already is a SOPS document? If it is the ciphertext git holds (the stored blob of step 4, byte for byte or with CRLF line endings that `core.autocrlf` added: a working copy that was never decrypted) → store that blob **unchanged**, with no key and no call to `sops`. Any other SOPS document must **decrypt with your keys**, or the add fails: a copy from another project, encrypted for that project's keys, or a forged one. Its plaintext then goes on to step 3 like any edit, so it is encrypted for the recipients in `.sops.yaml`, not kept with its own. Nothing is encrypted twice.
3. File is new (not in index or HEAD)? → encrypt.
4. File exists? → decrypt the stored blob, compare plaintexts:
   - cannot decrypt (no key, expired cloud session) → **exit non-zero** with the `sops` error. No blind re-encryption.
   - identical → output the **existing** ciphertext (no new IV → no false diff)
   - different → re-encrypt, for the keys `.sops.yaml` names now. When they are not those of the stored version, one line names the keys added and removed.
   - a run of the last 10 minutes answered the same question → give its answer again, without `sops` (see [What the clean filter remembers](#what-the-clean-filter-remembers)).
5. Whatever `sops` returned is checked before git gets it: it must be a SOPS document with every value encrypted. If it is not, **exit non-zero**. (A creation rule with `encrypted_regex` and the like, or an old `sops`, can leave content in clear inside a valid-looking envelope.)

`SOPS_FILTER_FORCE_REENCRYPT=1` skips the comparison in step 4 and always re-encrypts (storage-format change, fresh data keys). It acts on every run of the filter in the git command it is set on, not only on the file you mean: git runs the filter for each managed file it checks again (one whose timestamp changed, or one it cannot trust its timestamp for). So set it on `git add` and commit without it: `SOPS_FILTER_FORCE_REENCRYPT=1 git add <file>`, then `git commit`. `git add <file>` stages that file only. On `git commit -a` the variable re-encrypts every managed file the commit checks again, and unchanged secrets are committed with new ciphertext: a diff nobody made. On a plain `git commit` it stages nothing new, and the extra runs cost only calls to `sops`.

### What the clean filter remembers

Git cannot tell whether a SOPS-managed file changed without running the clean filter, and it runs it again each time it looks at a secret with uncommitted changes. Each run decrypted the stored version and encrypted the edit: with a key service (AWS KMS, GCP KMS, Azure Key Vault, Vault) two requests, every time, and a new ciphertext every time ([issue #21](https://github.com/realsby/sops-git-filters/issues/21)). So a run now remembers its answer for 10 minutes, and a later run asked the same question gives the same answer without `sops`. Calls to `sops` for one secret with an edit that keeps its size, measured with git 2.54:

| Command | Before (decrypt / encrypt) | Now |
|---|---|---|
| first `git status` after the edit | 1 / 1 | 1 / 1 |
| each further `git status` | 1 / 1 | 0 / 0 |
| `git diff` | 3 / 2 | 1 / 0 (the stored version, for the text of the diff) |
| `git diff --stat` | 2 / 2 | 0 / 0 |
| `git add`, `git commit -a` | 1 / 1 | 0 / 0 |

`git status`, `git diff` and `git add` now see the same ciphertext for the same edit, and `git add` stores it.

- **The question** is everything that decides what the filter returns: the plaintext, the stored version (its object id), the path, the storage format, the text of `.sops.yaml`, the `SOPS_*` variables, the version of this tool. A change to any of them is a new question: a recipient added to `.sops.yaml` takes effect at the next run, as before.
- **The answers** are two. *Unchanged*: the stored version; remembered only after a decrypt showed it, so a run never skips a decrypt that never worked (a file `git add` encrypted for a rule you are not a recipient of still fails at the next check). *Changed*: a blob this filter encrypted a moment ago. The filter writes it into the object store itself (ciphertext; `git status` does not keep what the filter returns), and before it is given again it must still be there and pass the same check as a new encryption. It is remembered only when `.sops.yaml` still holds the text of the question after `sops` returned: `sops` reads the file itself, a moment later, and an edit or a checkout in between gave the blob the recipients of other rules.
- **What is on disk**, in `.git/sops-git-filters/cache/` (the common git directory, mode `0700`, files `0600`): a random key made at the first use, and one small file per answer holding an object id and two halves of an HMAC-SHA256 of the question under that key. No plaintext, and no plain hash of it (a hash of a short password can be tested against guesses offline; the HMAC cannot be without the key). An entry is not used after 10 minutes, and the filter removes old ones (it looks once every 10 minutes, when it runs); at most 512 are kept. The encrypted blobs the filter wrote into the object store are unreferenced objects, which `git gc` removes in its time, as it does those of a `git add` that was undone.
- **It needs** `sha256sum`, `openssl` or `shasum` on PATH (the HMAC is computed from a plain SHA-256, so that its key is never an argument of a process), and `od` and `/dev/urandom` for the key. Without them, and when the directory or the key is a symlink, belongs to someone else or is open to the group or others, the filter works as before, without the cache. So it does with `SOPS_FILTER_FORCE_REENCRYPT=1` (which asks for a new encryption), with `SOPS_CONFIG` set, and when the filter is run by hand outside the top of the working tree (in both cases `sops` would read another `.sops.yaml`).
- **To turn it off**, set `SOPS_FILTER_CACHE=0` in the environment of git (your shell profile, or the environment your editor runs git in). To clear it, delete the directory.

`harden-permissions.sh` closes the mode gap the smudge filter leaves. Git stores only the executable bit, so a decrypted secret lands with your umask — `0644` on a default workstation. `install.sh` runs the script once and installs five hooks that re-run it (`post-checkout`, `post-merge`, `post-rewrite`, `post-applypatch`, `post-commit`), so private keys and kubeconfigs are `0600` again after a checkout, pull, merge, rebase, cherry-pick, revert, `git am` and commit. A hook file that is already there is replaced only when it is, byte for byte, one that `install.sh` wrote (this release or an earlier one); any other, also one of these with a line added by hand, is left alone, and `install.sh` prints the line to add to it. A few commands run no hook (`git stash`, `git stash pop`, `git reset --hard`): see [Limitations](#limitations) and [Security model](#security-model).

## Requirements

- `git` ≥ 2.18, `bash` ≥ 3.2 (macOS stock bash is fine). The git minimum comes from reading the scripts, not from a test run: the newest git feature they use is `git config --type=path` (2.18); the `attr:` pathspec and `git rev-parse --absolute-git-dir` need 2.13, and `git add --renormalize`, which the messages tell you to run, 2.16. CI runs the git of its Ubuntu and macOS runner images, a current release, and no older one.
- [`sops`](https://github.com/getsops/sops) ≥ 3.11.0 on PATH. `install.sh` refuses older versions: up to 3.10.2, `sops` stores the whole file in clear when the matching `.sops.yaml` rule uses `encrypted_regex`, `unencrypted_regex`, `encrypted_suffix` or `unencrypted_suffix`. Tested up to 3.13.3. The checks accept only the metadata fields `sops` writes up to that release: if a later `sops` adds a field, its documents are refused (never let through) and the message names the field. Update this tool then.
- A SOPS key backend: [age](https://github.com/FiloSottile/age) (simplest), or any KMS SOPS supports

## Installation

Pick one:

### A. Git submodule (recommended — pinned version, easy updates)

```sh
git submodule add https://github.com/realsby/sops-git-filters.git utilities/sops-git-filters
./utilities/sops-git-filters/install.sh
```

Updating later: check out the latest release tag, not `main` (`main` is where the work between two releases happens):

```sh
git -C utilities/sops-git-filters fetch --tags origin
git -C utilities/sops-git-filters checkout v3.1.0     # the latest tag on the releases page
git add utilities/sops-git-filters && git commit -m "sops-git-filters v3.1.0"
./utilities/sops-git-filters/install.sh
```

Read the [release notes](https://github.com/realsby/sops-git-filters/releases) first; they list what behaves differently ([CHANGELOG.md](CHANGELOG.md) holds the same text). Every clone needs `git submodule update --init`, and `install.sh` once more after an update — put both in your setup task (see below). The last line is not optional: git runs the copy that `install.sh` put under `.git/`, so a clone where it has not run again still runs the old version. That copy says so on stderr ("git runs the installed copy, version …") when it sees a newer version in the checkout.

### B. Vendored copy (no submodule mechanics)

Copy every `*.sh` file (`clean-filter.sh`, `smudge-filter.sh`, `install.sh`, `encryption-guard.sh`, `harden-permissions.sh`, `merge-driver.sh`, `rekey.sh`, `preflight.sh`, and `lib.sh`, which the others load) into your repo (e.g. `utilities/sops-git-filters/`), keep them executable, run `install.sh`. You own updates, and after each one `install.sh` has to run again in every clone.

Copy [`.gitattributes`](.gitattributes) into the same directory too. It holds one rule, `*.sh text eol=lf`, and an attributes file in a directory applies to the files below it. Without it, a clone made with `core.autocrlf=true` (the default of Git for Windows) gets the scripts with CRLF line endings, and bash cannot run them: `env: bash\r: No such file or directory`, from `install.sh`, and from the guard as a pre-commit hook, which then stops every commit. A clone that already has them with CRLF gets LF once they are written again: delete the `*.sh` files and run `git checkout -- utilities/sops-git-filters/`. The submodule (A) and the clone the pre-commit framework makes (C) read the file from this repository and need nothing.

### C. Guard only, via pre-commit remote

If you only want the commit-time guard (e.g. filters are managed some other way):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/realsby/sops-git-filters
    rev: v3.1.0
    hooks:
      - id: sops-encryption-guard
```

This does **not** install the clean/smudge filters — files won't auto-encrypt, but plaintext commits are blocked.

## Setup walkthrough

From zero to encrypted secrets in five steps. All files go in **your** repo's root.

**1. Create a key** (age shown; any SOPS backend works):

```sh
# Linux
mkdir -p ~/.config/sops/age && age-keygen -o ~/.config/sops/age/keys.txt
# macOS
mkdir -p "$HOME/Library/Application Support/sops/age" && age-keygen -o "$HOME/Library/Application Support/sops/age/keys.txt"
# Public key: age1abc... ← goes into .sops.yaml
```

`sops` looks for the key in those two places by default. On macOS it does **not** read `~/.config/sops/age/keys.txt` unless `XDG_CONFIG_HOME` is set. A key anywhere else needs `export SOPS_AGE_KEY_FILE=/path/to/keys.txt` in your shell profile. Get this wrong and encryption still works (it needs only the public key in `.sops.yaml`) while every decryption fails.

**2. Create `.sops.yaml`** (see [`examples/sops.yaml`](examples/sops.yaml)):

```yaml
creation_rules:
  - path_regex: \.env(\.[^/]+)?$     # .env, .env.local, prod.env
    key_groups:
      - age:
          - age1abc...          # you
          - age1xyz...          # break-glass key, stored offline
```

**3. Mark files in `.gitattributes`** (see [`examples/gitattributes`](examples/gitattributes)):

```
.env           filter=sops diff=sops merge=sops -text
.env.*         filter=sops diff=sops merge=sops -text
*.env          filter=sops diff=sops merge=sops -text
.env.example   !filter !diff !merge !text
```

A pattern without a slash matches at every depth. The wildcards also cover `.env.local`, `.env.production` and `prod.env`: a name that a hand-written list misses is committed in plaintext without a word, and the wildcards rule that out for the usual names of a dotenv file (not for every copy, see below). Their price is the last line, which takes a template without secrets out again (it must come after the others; `!` and not `-`, because `-diff` would make git treat the file as binary). `-text` keeps git from converting line endings, see [`core.autocrlf`](#storage-formats-json-vs-dotenv) below. A template you forget to list is stored encrypted, which is harmless. The rule in `.sops.yaml` must match the same names.

The wildcards still miss copies that editors, tools and people make under other names. None of these matches the four lines, so `git add -A` stages them in plaintext, and the guard lets them through: it checks only the paths that have `filter=sops`.

- `.env~` (a backup that Emacs or Vim writes) and `#.env#` (an Emacs auto-save file)
- copies made by hand: `.env-2026-11-24`, `.env_backup`, `env`, `env.production.txt`
- what `git mergetool` writes next to `.env.production` and `prod.env`: `.env_LOCAL_1234.production` and its `_REMOTE_`, `_BASE_` and `_BACKUP_` siblings, and the backup `prod.env.orig` (see [Merging secrets](#merging-secrets))

(`.env.bak`, `.env.orig` and `.env.swp` match `.env.*` and go through the filter; a Vim swap file then fails `git add`, as it holds NUL bytes.) Keep the editor and merge-tool files out of git in `.gitignore`, and give a copy you keep a name the patterns cover (`.env.2026-11-24`, not `.env-2026-11-24`):

```
*~
\#*#
*.orig
*.swp
*_LOCAL_*
*_REMOTE_*
*_BASE_*
*_BACKUP_*
```

The backslash is needed: a line that starts with `#` is a comment.

`merge=sops` is optional but you want it as soon as two branches can change the same secret: see [Merging secrets](#merging-secrets).

**4. (Optional) choose a storage format** in `.sops-filter.conf` — see next section. Skip it to store as JSON.

**5. Install the filters and stage your secrets:**

```sh
./utilities/sops-git-filters/install.sh
git add .sops.yaml .gitattributes .sops-filter.conf utilities/sops-git-filters
git add .env            # ← encrypted transparently; check with: git show :.env
git commit
```

Verify before your first push: `git show :.env` must print SOPS ciphertext (`ENC[AES256_GCM,...`), never plaintext.

**Wire it into your setup task** so new clones are one command away (example for [mise](https://mise.jdx.dev), same idea for Makefiles/justfiles):

```toml
[tasks.setup]
run = """
git submodule update --init utilities/sops-git-filters
pre-commit install
./utilities/sops-git-filters/install.sh
"""
```

`install.sh` exits 3 when the filters and hooks are installed but something is left to do: files it could not decrypt (no key, expired cloud session), files it did not decrypt because the working copy is reached through a symbolic link or a hard link, files tracked in plaintext, or a storage-format change that is not finished. It prints which. A setup task that should carry on in that case can run `./utilities/sops-git-filters/install.sh || [ $? -eq 3 ]`. Exit status 1 means the filters were not set up (sops missing or too old, a bad `.sops-filter.conf`, a `filter.sops.process` setting outside `.git/config`, ...) and the repository is as it was, except that one whose filters were set up before gets `filter.sops.required=true` back, so that a failing filter still stops git. One exit 1 comes later, with the message "another git config file overrides the filter settings": a filter setting from a place that outranks `.git/config` (a worktree's config, `git -c`, `GIT_CONFIG_COUNT`). By then `.git/config` holds the new settings and `.git/sops-git-filters/` the scripts, but no hooks were installed and no file was decrypted. Remove the override and run `install.sh` again.

## Storage formats: json vs dotenv

`.sops-filter.conf` at your repo root selects how ciphertext is stored in git — and, via `SOPS_FILE_MODE`, the permission mode applied to the decrypted files (see [`examples/sops-filter.conf`](examples/sops-filter.conf) and [Security model](#security-model)):

| | `json` (default) | `dotenv` |
|---|---|---|
| Works for | any text file (keys, PEM, YAML, .env) | `KEY=value` files only |
| Stored as | one SOPS JSON document, whole body encrypted | key names readable, values and comments `ENC[...]` |
| Readable diffs in git hosting UI | no (use local `git diff`) | partially (key names visible) |
| Deploy-time native decryption by file extension (e.g. doco-cd for `.env`) | no | yes |
| Blank lines in the file | fine | **not representable** — use lone `#` lines as separators, or the unchanged-content check breaks and re-encrypts on every add |
| Values that span several lines | fine | **refused** — see below |
| `.sops.yaml` rules that encrypt only some keys | ignored by `sops` (the whole file is one value) | **refused** — every value must be encrypted |

```
# .sops-filter.conf
SOPS_STORE_FORMAT=dotenv
```

**What the dotenv format refuses.** `sops` reads a dotenv file line by line and stores everything left of the first `=` as a key, in clear. The clean filter therefore checks the file before `sops` sees it and refuses (naming the line number, never the content):

- a line that is neither `# comment` nor `KEY=VALUE` (`#` must be the first character of a comment line);
- a key with characters outside `A-Z a-z 0-9 _ . -` (a leading `export ` is fine);
- a value that opens a quote it does not close on the same line, i.e. a multi-line value. Its continuation lines would become plaintext keys. Use `\n` inside one line, or the json format.

It also refuses the result if any value came back unencrypted: a creation rule with `encrypted_regex`, `unencrypted_regex`, `encrypted_suffix` or `unencrypted_suffix`, or a key ending in `_unencrypted` (the `sops` default suffix).

**`core.autocrlf` needs `-text`, for every storage format.** With `core.autocrlf=true` (common on Windows), git adds CRLF line endings to the ciphertext before the smudge filter sees it; `sops` then fails to decrypt the dotenv ciphertext and the checkout stops. Mark the managed paths `-text` in `.gitattributes`, as the walkthrough and [`examples/gitattributes`](examples/gitattributes) do: `.env filter=sops diff=sops merge=sops -text`. Do this for the json format too, where checkouts still decrypt: without `-text` a fresh clone holds the ciphertext with CRLF line endings until `install.sh` runs, and `git add` may warn that LF will be replaced by CRLF. `install.sh` decrypts such a copy all the same, in both formats: without its CRs it is the stored blob. The plaintext it writes has LF line endings, as the smudge filter's has, and `git status` is clean.

Pick the format **before the first encrypted commit**. Migrating later, on a clone with the files decrypted:

1. Change `SOPS_STORE_FORMAT` in `.sops-filter.conf`.
2. Re-run `install.sh` (it writes the new format into the smudge command; it exits 3 and lists the files still in the old format).
3. Re-encrypt every managed file: `SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize .`
4. Commit `.sops-filter.conf` and the files together.

Until step 3 is done, the clean filter and the guard refuse those files and name this command. Other clones must pull and re-run `install.sh`.

## Onboarding a teammate / a new machine

1. Clone the repo. **The working tree now contains ciphertext** for SOPS-managed files — that's expected; filters live in `.git/config`, which isn't cloned.
2. Get decryption access: receive the age private key (or have your cloud identity added to the KMS key policy) and put it where `sops` looks, see [step 1 of the walkthrough](#setup-walkthrough), or point `SOPS_AGE_KEY_FILE` at it. With a key service, sign in first (AWS: `aws sso login`; GCP: `gcloud auth application-default login`; Azure: `az login`; Vault: `vault login`).
3. Run the setup task (or directly `./utilities/sops-git-filters/install.sh`). The install re-smudges the ciphertext files into plaintext in place.
4. Sanity check: `cat .env` shows plaintext, `git status` is clean, `git show :.env` shows ciphertext.

If step 3 ends with `STILL ENCRYPTED IN THE WORKING TREE` and exit status 3, `sops` could not decrypt: its own error is printed above that list (no key, expired session). Fix it and re-run `install.sh`. Until then the files stay ciphertext in your working tree. That state is safe while each working copy is the ciphertext the index holds: git treats such a file as unchanged and the clean filter stores it as it is, without a key, so nothing is encrypted twice. A command that moves the index and leaves the working tree alone (`git reset HEAD~1`, `git reset <commit> -- <file>`, `git restore --staged --source=<commit>`, `git read-tree`) ends that: the working copy is then ciphertext that git no longer holds, which the filter must decrypt to check, so without your keys `git status`, `git diff`, `git add` and `git commit -a` fail on it with "… is a SOPS document that does not decrypt with your keys". That is on purpose: stored as it is, such a stale copy could replace whatever the index holds now, a newer secret for example. To get back without the keys, put the version git holds in its place with the `git cat-file blob <id> > <file>` line that error prints, or undo the command that moved the index; with the keys, `git status` works again and shows the file as modified (see [Troubleshooting](#troubleshooting), "… is a SOPS document that does not decrypt with your keys").

**CI / servers that don't need plaintext** (e.g. they only lint or build): do nothing — without the filters configured, checkouts contain raw ciphertext and nothing decrypts. Deploy tooling that *does* need plaintext should use its own SOPS integration (native SOPS support, `sops exec-env`, or run `install.sh` with a deploy key present).

## The pre-commit guard

`encryption-guard.sh` is the independent second line of defense, for the cases where the filter is missing, misconfigured or bypassed.

- Looks at **every** file in the index whose git attribute is `filter=sops` (via `git check-attr`, so nested `.gitattributes` work), not only at the files staged for this commit. A secret that was committed in plaintext earlier blocks every commit until it is fixed. The attributes come from the `.gitattributes` files in the index, the ones the commit carries: an edit of `.gitattributes` that is not staged (say `.env -filter`, which also keeps `git add` from running the filter) does not take a path out of the check. Git also reads attribute files that no commit carries, and `$GIT_DIR/info/attributes` outranks every `.gitattributes`: a line there such as `.env -filter` keeps `git add` from running the filter while the commit still marks the path. The guard blocks while that file sets `filter` to anything but `sops`, or sets or redefines a macro, and while it, `core.attributesFile` or the system attributes file defines a macro that does (`[attr]binary -filter` reaches every path marked `filter=sops binary`). It names the file and the line; remove the line, and put what a path needs into `.gitattributes`. A CI checkout has none of these files, so the guard run there is not affected.
- Reads each blob by object id and checks its structure, to the last byte. In the json format it must be `{"data": "<one ENC[...] value>", "sops": {...}}` and nothing else: no third key, and inside `sops` only the fields `sops` writes, with an encrypted `mac` and a `version`. In the dotenv format every value and every comment must be `ENC[...]`, and the `sops_` metadata must be there. Only the `sops_` lines that `sops` writes count as metadata; any other line that starts with `sops_` must be encrypted like a value. Each `ENC[...]` value must have the shape `sops` writes, from its first character to its last: `data`, `iv`, `tag` and `type` in that order, `data` in base64, an `iv` of 32 bytes and a `tag` of 16 (44 and 24 characters), a `type` that `sops` can decrypt, and nothing after the closing bracket. That narrows what a hand-made document can carry, but only `sops decrypt` can prove that a value is ciphertext: a short password made of base64 characters is valid base64. A blob with a NUL byte is refused in either format: `sops` never writes one, and the `awk` of macOS would not look past it on its line. A search for the string `ENC[AES256_GCM` is not enough: a plaintext file can mention it, and a SOPS envelope can carry plaintext while its MAC is `ENC[...]`. The values of the metadata fields are not checked; some are free text by design (a KMS encryption context, an `encrypted_regex`).
- Skips symlinks and submodules (git never filters them).
- Skips a file added with `git add -N` (intent to add) while its index entry is still empty: a plain `git commit` leaves such an entry out, and `git commit -a` or `git commit -- <file>` stage the content through the filter before the guard runs. Only an empty entry that is missing from the tree git builds for the commit counts; when the guard cannot tell, it checks the entry and blocks.
- Blocks the commit if `.sops.yaml` is missing while SOPS-managed files are tracked.
- Takes time per SOPS-managed file, not per tracked file: git lists the index and its attributes, and only the managed entries are checked one by one. With 60,000 tracked files and 11 secrets a run takes about 0.4 s.
- Fails closed: if it cannot list the index, read the attributes or read a blob, the commit is blocked.

It does not stop a commit made with `--no-verify`, and git runs no pre-commit hook for a merge that needs no manual step. Run the same script in CI to cover those (it needs only a checkout, no keys).

To fix a file it reports: run `install.sh`, then `git add --renormalize -- <file>`, and rotate the secret if it was ever pushed.

With the [pre-commit framework](https://pre-commit.com), using the submodule path:

```yaml
- repo: local
  hooks:
    - id: sops-encryption-guard
      name: Verify SOPS-managed files are encrypted
      language: script
      entry: utilities/sops-git-filters/encryption-guard.sh
      pass_filenames: false
      always_run: true
      stages: [pre-commit]
```

Or as a plain git hook: `ln -s ../../utilities/sops-git-filters/encryption-guard.sh .git/hooks/pre-commit`.

## Merging secrets

Git merges what it stores, and for a SOPS-managed file that is ciphertext. Every edit re-encrypts the whole file, so when two branches both changed a secret the two blobs differ on every line. Git then writes conflict markers *into the ciphertext*, the smudge filter cannot decrypt that, and the merge dies half-way: no `MERGE_HEAD`, nothing to abort, the working copy of the file deleted. `git rebase`, `git cherry-pick`, `git stash pop` and `git stash --keep-index` followed by `pop` fail the same way.

`merge-driver.sh` merges the **plaintext** instead. It decrypts the three versions (common ancestor, ours, theirs), runs `git merge-file` on them and encrypts the result with the clean filter. Turn it on per path:

```
.env   filter=sops diff=sops merge=sops -text
```

`install.sh` registers the driver (`merge.sops.driver`), so existing clones must run it once more.

- **Changes to different lines** merge by themselves.
- **A real conflict, json format:** the working copy gets the usual `<<<<<<<` `=======` `>>>>>>>` markers, in plaintext. Edit the file, `git add` it, continue. Git never sees the marked-up plaintext: what it stores during the conflict is encrypted like everything else.
- **A real conflict, dotenv format:** marker lines are not `KEY=VALUE` and cannot be stored. Our version is kept and the conflict is reported. Take a side with `git checkout --theirs -- <file>` (or `--ours`), or use `git mergetool` (mind the plaintext files it writes, below); then `git add`.
- **No keys, no merge:** the driver has to decrypt. Without a key or cloud session git reports `failed to execute internal merge` and changes nothing; sign in and run the merge again.
- **Plaintext on disk:** for the length of the merge the three decrypted versions sit in a private directory (mode 0700) under `.git/`, removed on exit. `git merge-file` needs real files. If a run is killed, the next merge removes what it left, once that process is gone or the directory is an hour old; the files of a merge that is still running are left alone.
- **`git mergetool` writes plaintext next to the secret.** While the merge tool runs, the three versions and a copy of the working file sit in plaintext in the directory of the secret: `_LOCAL_1234.env`, `_REMOTE_1234.env`, `_BASE_1234.env` and `_BACKUP_1234.env` for `.env`, `.env_LOCAL_1234.production` and the like for `.env.production` (1234 is a process id). Git removes them when the tool exits normally; they stay when it is killed. Afterwards `<file>.orig` is left behind: the working copy from before the tool ran, in plaintext (with the conflict markers in the json format), and with the mode of that working copy: in the json format `0644` with the usual umask (git wrote the file during the merge, and no hook runs after a merge that stops on a conflict), in the dotenv format the `0600` it had (the driver left the file alone). A name like `prod.env.orig` or `.env_LOCAL_1234.production` matches none of the walkthrough's patterns, so `git add -A` would commit it unencrypted and the guard would not see it. Before you start it, set `git config mergetool.keepBackup false` (no backup) and `git config mergetool.writeToTemp true` (the temporary files go to a private directory outside the working tree), and keep the `.gitignore` lines of [step 3](#setup-walkthrough).

Without `merge=sops`, the minimum is `merge=binary` on the same paths: git then reports an ordinary conflict and keeps your version, instead of dying.

## Changing recipients (re-key)

After you add or remove a key in `.sops.yaml`, the files already in git are still encrypted for the old recipients. Editing nothing and re-adding them does not help: the clean filter reuses the stored blob whenever the plaintext is unchanged. Re-key the stored blobs instead:

```sh
./utilities/sops-git-filters/rekey.sh --dry-run   # which files would change
./utilities/sops-git-filters/rekey.sh             # re-key and stage them
git diff --cached --stat && git commit
```

`rekey.sh` copies each SOPS-managed blob from the index into a private directory under `.git/` (ciphertext only), runs `sops updatekeys` on it against your `.sops.yaml`, and stages the result with `git update-index`. The working tree is not touched. It needs decryption access, and it accepts paths to limit the run.

**Review every change to `.sops.yaml`.** It decides who can read every secret edited after it, whether or not anyone runs `rekey.sh`: the next edit of a file re-encrypts it for the keys `.sops.yaml` names then. A one-line change that adds a recipient is easy to wave through. The clean filter prints a line when a re-encryption changes the keys of a file, for example `sops clean filter: the keys of .env change with this version (from .sops.yaml): added: age age1…`, but by then the change is merged. Put `.sops.yaml` under CODEOWNERS or a required review.

**Removing a recipient is not revocation.** `sops updatekeys` keeps the data key, and history keeps the old blobs: whoever was removed could read everything up to now. Rotate the secret values. Editing a value re-encrypts that file with a fresh data key; to do that for files you did not edit, run `SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize .`

## When sops cannot decrypt: preflight and recovery

Git removes a SOPS-managed file from the working tree *before* it runs the smudge filter. If `sops` cannot decrypt at that moment (a session with the key service that expired, a key that is not on this machine), the command stops right there. That is on purpose: the filter fails closed and never writes ciphertext or an empty file where a secret belongs. But the command is left half-done.

**Ask first.** `preflight.sh` decrypts stored blobs to `/dev/null`, one for every set of keys that your tracked secrets name (with one `.sops.yaml` rule for all files that is a single decryption; a set is the whole access rule: key groups, the keys in each, the threshold), and names what to check when that fails:

```sh
./utilities/sops-git-filters/preflight.sh && git pull
```

Exit status 0: decryption works. 1: it does not, so do not pull, check out, merge or rebase now. 2: the check could not run or is incomplete (not a repository, `sops` missing, the index or a stored blob unreadable). It writes nothing and prints no plaintext; `--quiet` prints nothing when decryption works, except the warning (on stderr) that some SOPS-managed files are not encrypted SOPS documents and were not checked. It checks the versions in the index, those of the current checkout, and no other commit: not the commits a `git pull` would fetch, and not a local branch, tag or stash you switch to, merge or rebase onto. A file there may be encrypted for other keys (a `.sops.yaml` rule that changed in between, a file under a rule only the deploy key opens), and git then stops half-way all the same. A script or an assistant that runs git for you should call it before any command that changes the working tree.

**What a stopped command leaves behind** (measured with git 2.54):

- `git pull`, `git merge`, `git checkout <branch>`, `git switch`: exit status 128 at the first secret that changed, with `fatal: <file>: smudge filter sops failed` under the `sops` error and the lines of the smudge filter (what to check for the keys of that file). `HEAD` has not moved. In `git status --short` that secret shows as ` D` (git removed it), the files git wrote before it show as ` M` (they hold the *new* version) or `??` (files the new commits add), and everything later in sort order is as it was.
- `git rebase`: the same, with the rebase left in progress.
- `git checkout -- <secret>` and `git restore <secret>`: the working copy of that secret is gone (` D`).
- `git log -p`, `git show` and `git diff` over a commit that touches a secret: exit status 128, nothing changed.

**Do not run `git commit -a`, `git add -A` or `git stash` in that state.** They would record the deletion of the secret.

**The way back:**

1. Make the keys or the session available again and check with `./utilities/sops-git-filters/preflight.sh`.
2. A rebase: `git rebase --abort` puts the branch and the files back. Then start it again.
3. Anything else: put the working tree back to what `HEAD` says, then repeat the command.

   ```sh
   git status --short
   git checkout -- <each " D" secret, and each " M" file you did not edit yourself>
   rm <each "??" file that the stopped command created>
   ```

   Not sure which files those are? Repeat the command: git stops again before it changes anything and names the files in its way ("Your local changes to the following files would be overwritten", "The following untracked working tree files would be overwritten"). Your own uncommitted edits to other files stay as they are through all of this.

## Security model

What you get:

- **Fail-closed staging.** The clean filter exits non-zero when it can't encrypt (`sops` missing, `.sops.yaml` missing, encryption error) and `filter.sops.required=true` turns that into an aborted `git add` — the failure mode is a loud error, never a plaintext commit. `install.sh` writes that flag on every run, first, and stops if a `filter.sops.process` setting would override the filter.
- **`.sops.yaml` alone decides the recipients.** `sops` lets `SOPS_AGE_RECIPIENTS`, `SOPS_KMS_ARN`, `SOPS_GCP_KMS_IDS`, `SOPS_AZURE_KEYVAULT_URLS`, `SOPS_VAULT_URIS`, `SOPS_PGP_FP` and `SOPS_HUAWEICLOUD_KMS_IDS` replace the keys of a creation rule. The clean filter drops them (with a one-line note), so a variable left over in your shell cannot encrypt a secret for the wrong keys.
- **No blind re-encryption.** If the stored version of a secret cannot be decrypted, the clean filter stops with the `sops` error. A comparison that worked is remembered for 10 minutes: in that time a run asked the same question does not decrypt again, so keys that became unavailable (an expired session, a revoked grant) are noticed at the first run after that, or at once with `SOPS_FILTER_CACHE=0`. What is remembered holds no plaintext: see [What the clean filter remembers](#what-the-clean-filter-remembers). Input that already is ciphertext is stored unchanged only when it is the version git holds. Any other SOPS document must decrypt with your keys first: one encrypted for another project's keys, or a forged one, is refused instead of being committed for teammates to find at their next checkout.
- **The output is checked, twice.** The clean filter refuses what `sops` returns unless it is a completely encrypted SOPS document. The guard then re-checks every tracked SOPS-managed blob at commit time, with no dependency on the filter machinery.
- **Git runs a copy that no checkout can change.** `install.sh` copies the scripts git needs into `sops-git-filters/` inside the git directory (the common one, shared by all worktrees), and git config and the hooks name that copy with a path that is resolved when the command runs. Before v3.0.0 they named the scripts in the working tree: with a vendored copy of the tool, checking out a branch ran that branch's `harden-permissions.sh` through the post-checkout hook, and the next `git status` ran its `clean-filter.sh` with your plaintext on stdin. What still runs from the working tree is what you start yourself: `install.sh`, `rekey.sh`, `preflight.sh`, and `encryption-guard.sh` through your pre-commit configuration. So run `install.sh` only from a checkout you trust (your main branch, a release tag): it is the step that decides which code git runs from then on.
- **No plaintext in the remote, the object store or the stash.** They hold ciphertext only. Plaintext still appears in a few places outside the object store: the temporary files git writes for `textconv` (`$TMPDIR/git-blob-XXXXXX/`, mode 0600 in a 0700 directory; one stays behind after `kill -9`), `.git/COMMIT_EDITMSG` after `git commit -v` (it holds the plaintext diff), the output of `git diff`, `git show` and `git log -p`, and `git archive`, which emits plaintext. To keep secrets out of archives, add `export-ignore` to the managed paths in `.gitattributes`, for example `.env filter=sops diff=sops merge=sops export-ignore`. Multi-recipient keys and break-glass access come from SOPS key groups.
- **Mode 0600 on decrypted files.** Git only round-trips the executable bit, so every smudge — clone, `checkout`, `pull`, the re-smudge pass in `install.sh` — writes the decrypted secret with your *umask*, which is `0644` on a default workstation: a world-readable deploy key, API key, kubeconfig or cluster-secrets bundle (and OpenSSH flatly refuses a `0644` private key). `harden-permissions.sh` chmods every `filter=sops` file to `0600` (a file tracked as executable, mode `100755`, gets `0700`, so git sees no mode change); `install.sh` runs it and installs five hooks that run it again (the installed copy of it): `post-checkout`, `post-merge`, `post-rewrite`, `post-applypatch` and `post-commit`, which covers checkout, switch, pull, merge, rebase, `commit --amend`, `git am`, commit, cherry-pick and revert (what is not covered is under [Limitations](#limitations)). The hooks go into the repository's own hooks directory, nowhere else: when `core.hooksPath` names a directory that other repositories use too (a machine-wide `~/.githooks`, say), `install.sh` writes nothing there, and it prints one line to add to your own hooks instead. A `core.hooksPath` inside the working tree (`.githooks`, say) is the repository's own, so the five hooks land in the working tree: `git status` lists them as untracked and `git add -A` commits them. That is harmless, as the hook text is the same in every repository and runs only the installed copy, where there is one; commit them or add them to `.gitignore`, as you prefer. That line runs the installed copy of the repository the hook runs in, and does nothing where `install.sh` never ran. Hooks that `install.sh` wrote into such a directory up to v2.0.0 are removed on the next run. Override the mode with `SOPS_FILE_MODE` in `.sops-filter.conf` (owner and group bits only, such as `640`, which gives `740` to an executable file; a setuid, setgid or sticky digit or any bit for others is refused: the files then get `0600` and the script exits with an error), or skip the hook install with `SOPS_FILTER_INSTALL_HOOKS=0`. Because a chmod changes a file's inode change time, `install.sh` also sets `core.trustctime=false` in the repository: git would otherwise take a freshly chmod-ed secret for locally modified. A value you set yourself (`git config core.trustctime true`) is left alone.

What you must still do:

- **Protect working trees.** Checked-out secrets are plaintext on disk — that's the point. `0600` keeps other local accounts out; full-disk encryption and access control against everything else are on you.
- **Re-run the tightening where hooks don't reach.** The hooks live in `.git/hooks`, which is not cloned, so a clone that never runs `install.sh` gets neither the filters nor the permissions. Anything that materialises secrets outside git (`sops decrypt > file`, a deploy script, an editor's temp copy) sets its own mode — run `harden-permissions.sh` afterwards or set the mode yourself. Do the same after `git stash`, `git stash pop` and `git reset --hard`: git runs no hook for them.
- **Mind whose branches you check out while a session is live.** The smudge filter decrypts whatever a checkout brings, and a SOPS document says in its own metadata which key to ask for: an age recipient, a KMS key, a Vault address. `sops` follows that. A blob in a branch from someone else can name a key service you never use, and `sops` contacts it with your credentials. With HashiCorp Vault this was reproduced: `sops decrypt` sent the `X-Vault-Token` header to the address in the blob. With AWS it would be a signed `Decrypt` call for a foreign key ARN (not tested). This tool cannot stop it, because git hands the blob to the filter as part of the checkout. The clean filter does the same outside a checkout: a SOPS document in a managed path that is not the blob git holds (a copy from somewhere else, or one written into the working tree by a script) is decrypted to check it at the next `git status` or `git add`, so `sops` contacts the key service that document names. Read a change to a SOPS-managed file as ciphertext first (`git diff --no-textconv`, or the pull request page: the `sops` metadata with the key names is in clear), and do not check out branches of people you do not trust with a token or session for a key service in your environment.
- **Review changes to `.sops.yaml`.** It decides who can read every secret edited after it. Put it under CODEOWNERS or a required review; see [Changing recipients](#changing-recipients-re-key).
- **Client-side hooks are opt-in.** A collaborator who never runs `install.sh`/`pre-commit install` has no filter and no guard; if they create a *new* secret file it lands in plaintext. Mitigate with a CI check: run `encryption-guard.sh` on a checkout of the repository, from the submodule (check out with submodules) or from a checkout of a release tag of this tool. It needs no keys. It catches a new file only when `.gitattributes` marks its name, which the wildcards are for. A search for `ENC[AES256_GCM` is not enough: a dotenv file with one encrypted value next to plaintext ones passes it, and so does a SOPS envelope that carries plaintext (its MAC is always `ENC[...]`).
- **History is forever.** Anything committed in plaintext *before* adoption stays in history — rewrite history or rotate those secrets.
- **Rotate on suspicion.** Ciphertext in a public/leaked repo is only as strong as your key custody.

## Repository policy

`main` carries GitHub branch protection (no force-push, no deletion, enforced for admins), and a release tag (`v*`) cannot be moved or deleted once it is pushed. To report a security problem, see [SECURITY.md](SECURITY.md).

## Limitations

- **Text files only.** File content passes through shell variables, and a shell variable cannot hold a NUL byte. A file with NUL bytes (a keystore, a DER certificate, UTF-16 text) is refused: `git add` fails and says why, instead of storing the file damaged. Store a text form of it (base64, PEM, UTF-8). Fine for `.env`, PEM/OpenSSH keys, YAML, JSON.
- **Trailing-newline normalization.** Content round-trips exactly, except exotic cases like a file whose last line has no terminating newline *and* SOPS dotenv format (which appends one).
- **Merges need the driver.** Without `merge=sops` (or at least `merge=binary`) on a path, two branches that both changed that secret cannot be merged; see [Merging secrets](#merging-secrets).
- **Files nobody edits keep their recipients until `rekey.sh`.** Touching and re-adding a file does not re-encrypt it; editing it does, for the keys `.sops.yaml` names then. See [Changing recipients](#changing-recipients-re-key).
- **One filter name.** Everything is registered under the `sops` filter/diff driver; per-path different formats aren't supported (one `SOPS_STORE_FORMAT` per repo).
- **`git add -p` stages a managed file whole.** Git shows the ciphertext, not your plaintext edit, and cannot stage part of the file. Stage the whole file with `git add`.
- **Mode 0600 does not come back after every command.** Git runs no hook after `git stash`, `git stash pop`, `git reset --hard` and `git sparse-checkout add`. A secret that one of them writes again has your umask mode (usually `0644`) until the next commit, checkout or merge, or until you run `harden-permissions.sh`. A new secret has the umask mode until its first commit.
- **A secret with uncommitted changes costs key-service calls, the first time git looks at it.** Git runs the clean filter again whenever it compares the file: twice for one `git diff`, up to once for one `git status` (measured with git 2.54). The first run after an edit decrypts the stored version and encrypts the new one; later runs give the same answer for 10 minutes without `sops` ([What the clean filter remembers](#what-the-clean-filter-remembers)). `git diff` still decrypts the stored version for the text it shows, and so does any command that shows a SOPS-managed file in clear.
- **A commit can take its own secret out of the guard's view.** The guard checks the paths that the `.gitattributes` of the commit marks `filter=sops` (and blocks while a local attribute file could override them, see [The pre-commit guard](#the-pre-commit-guard)). A commit that stages `.env -filter` in `.gitattributes` together with a plaintext `.env` passes it: in that commit the path is not SOPS-managed, and git did what the attributes say. Review changes to `.gitattributes` as you review changes to `.sops.yaml` (CODEOWNERS, a required review).

## Troubleshooting

**`git add` fails with "filter 'sops' failed" / ERROR: .sops.yaml missing**
Working as designed — encryption isn't possible, so staging is refused. Create `.sops.yaml` (or fix `sops` on PATH) and retry.

**`install.sh` stops with "filter.sops.process is set outside this repository's .git/config"**
Another tool registered a long-running filter under the same driver name (`sops`), in your global or system git config. Git prefers it over the clean/smudge commands, so `clean-filter.sh` would never run. Remove that setting (`git config --global --unset filter.sops.process`) and re-run `install.sh`. A copy in the repository's own `.git/config` is removed for you.

**Fresh clone: `.env` is full of `ENC[...]` gibberish**
Filters aren't configured yet on this clone. Run `install.sh` — it configures `.git/config` and decrypts pre-setup checkouts in place. Still ciphertext afterwards? `install.sh` then ended with `STILL ENCRYPTED IN THE WORKING TREE` and the `sops` error above it: your key or cloud session isn't available. Fix that and re-run.

**`git status`, `git add` or `git commit` fails with "cannot decrypt the version of … that git holds"**
To know whether a secret changed, the clean filter decrypts the stored version. That failed, and the `sops` message above the error says why: usually a session with the key service that expired (AWS: `aws sso login`; GCP: `gcloud auth application-default login`; Azure: `az login`; Vault: `vault login`) or a key `sops` cannot find (age: `SOPS_AGE_KEY_FILE`, on macOS see [step 1 of the walkthrough](#setup-walkthrough); PGP: the secret key in your gpg keyring). The lines under the error name what to check for the kinds of key this file uses. Git runs the filter for every SOPS-managed file whose timestamp changed, so one touched secret is enough to stop these commands until decryption works again. The filter does not re-encrypt blindly: that would show unchanged secrets as modified and commit them again. `SOPS_FILTER_FORCE_REENCRYPT=1 git add <file>` re-encrypts on purpose; commit without the variable (see [How it works](#how-it-works)).

`git add` worked and `git commit` fails this way, with keys that work for other files? Then the rule for that path in `.sops.yaml` may not list your key. `sops` encrypts with the public keys of the rule, so you can add a secret for a rule you are not a recipient of (a `prod/` rule for the deploy key, say), but not decrypt it, and git checks the file again at the commit. Have a recipient add the file, or commit what is staged with `SOPS_FILTER_FORCE_REENCRYPT=1 git commit` (not with `-a`, which would re-encrypt every managed file it stages). Git checks the file again whenever its timestamp changes, and each check fails the same way while the plaintext is in the working tree. Once you no longer need it there, put the ciphertext git holds in its place, from the top of the working tree: `git cat-file blob :0:<file> > <file> && git add <file>`. The filter takes that copy without a key.

**`git add` or `git status` fails with "… is a SOPS document that does not decrypt with your keys"**
The working copy holds ciphertext, but not the version git holds, and `sops` cannot decrypt it (its message is above the error). Usually the file was copied from another project and is encrypted for that project's keys, or it was edited by hand and its MAC no longer matches. Stored as it is, it would break the next checkout of everyone who cannot decrypt it, so the filter refuses it. Decrypt it where its keys are and save the plaintext in its place: `git add` then encrypts it for the recipients in `.sops.yaml`. Or get back the version git holds: as ciphertext, with no key needed, `git cat-file blob <id> > <file>`; decrypted (needs your keys), `rm <file> && git checkout -- <file>`. Without your keys the checkout fails and leaves the file deleted. The error prints both commands with the object id and the full path filled in, ready to paste. In the git commands a name with a character git takes for a wildcard (`*`, `?`, `[`, `\`) comes as `':(literal)<path>'`: as a plain pathspec, `[ab].env` names `a.env` too, and the checkout would throw away its edits. A SOPS document that does decrypt with your keys is taken like any edit: its plaintext is encrypted for `.sops.yaml`, and the working copy keeps the ciphertext until you check the file out again. Without your keys, the same error stops `git status`, `git diff`, `git add` and `git commit -a` when the working copy holds ciphertext that git no longer holds, for example in a clone where `install.sh` could not decrypt, after a command that moves the index and leaves the working tree alone (`git reset HEAD~1`, `git reset <commit> -- <file>`, `git restore --staged --source=<commit>`, `git read-tree`). That is on purpose: stored as it is, the stale copy could replace a newer secret. Make the keys available (the file then shows as modified, which it is), put the blob git holds in its place with the `git cat-file` command above, or undo the command that moved the index.

**Every `git status` shows my secret file as modified**
With dotenv format, check for blank lines (not representable — the round-trip comparison then never matches; use `#` separator lines) and for a missing newline at the end of the file. Otherwise you are likely running an older clean filter: update, re-run `install.sh` and re-add the file once.

**A file got double-encrypted (ciphertext inside ciphertext)**
Older versions of the clean filter did this when ciphertext sitting in the working tree was `git add`-ed after the filters were configured. The current filter never encrypts a SOPS document again: it stores the ciphertext git holds unchanged, and decrypts any other SOPS document first. To repair a blob from before: `git show :file | sops decrypt --input-type <fmt> --output-type <fmt2> --filename-override file` repeatedly until you see actual plaintext, write that to the working tree, `git add`.

**Repo directory moved/renamed and filters broke**
With this version, they don't — the commands in `.git/config` hold no path to the repository or to the tool; they find the installed copy when they run. If you migrated from an older setup, run `install.sh` once to rewrite them.

**A line says "git runs the installed copy, version X, but … holds Y"**
You updated the tool (a submodule bump, a new vendored copy) and `install.sh` has not run in this clone since. Git still runs the older copy under `.git/`. Run `install.sh` from a checkout you trust. No line appears when the checkout is older than the copy (an old branch, a bisect).

**`git add` or `git checkout` fails with ".../sops-git-filters/clean-filter.sh: No such file or directory" (or `smudge-filter.sh`)**
The git settings are there but the copy of the scripts inside the git directory is not (the git directory was rebuilt, or the settings were copied from another clone). Run `install.sh`. Nothing was staged in plaintext: a filter that cannot run stops git.

**`git rebase` stops with "Your local changes to the following files would be overwritten by merge" on a secret you did not edit**
The permission hook chmod-ed the file after git checked it out, and git read the new inode change time as a local change. This happened now and then, when the chmod fell into a later second than the checkout. Re-run `install.sh` (it sets `core.trustctime=false`), then `git rebase --continue`.

**`git stash` / pre-commit stash conflicts on secret files**
The filter compares against the index specifically to keep stash blobs identical, which is what the [pre-commit](https://pre-commit.com) framework's stash needs. `git stash pop` itself is a three-way merge: if the secret changed on both sides (a newer commit, or `git stash --keep-index` with staged and unstaged edits), it needs `merge=sops` on that path like any other merge. See [Merging secrets](#merging-secrets).

**`git pull`, `git checkout` or `git rebase` stops with "smudge filter sops failed" under a key or credentials error from `sops`**
`sops` could not decrypt, and git had already removed the working copy of the secret. Do not commit or stash now. The way back is under [When sops cannot decrypt](#when-sops-cannot-decrypt-preflight-and-recovery); `preflight.sh` tells you beforehand.

**`git merge`, `rebase`, `cherry-pick` or `stash pop` dies with "smudge filter sops failed", and `sops` complains about the document, not about keys**
Both sides changed a secret and the path has no `merge=sops`: git merged the ciphertext and wrote conflict markers into it. Get back to a clean state (`git checkout -- <file>` restores the working copy; `git rebase --abort` if a rebase is in progress), add `merge=sops` to the path in `.gitattributes`, re-run `install.sh`, and merge again.

**Guard blocks a commit but `git show :file` looks encrypted**
The guard wants a *completely* encrypted SOPS document in the format set in `.sops-filter.conf`: one `ENC[...]` value under `"data"` (json), or every value and comment as `ENC[...]` (dotenv). A blob with one value in clear or with extra keys is refused: rebuild it with `git add --renormalize -- <file>`. A blob that is encrypted in the *other* storage format is reported separately ("stored in the other format"): that is a format change that was not finished, see [Storage formats](#storage-formats-json-vs-dotenv). The guard also names files you did not touch in this commit: it checks everything that is tracked.

**`install.sh` ends with "STORED IN THE OTHER FORMAT" (exit status 3)**
`.sops-filter.conf` names one storage format and git still holds the listed files in the other one. Nothing leaked. Re-encrypt them as described under [Storage formats](#storage-formats-json-vs-dotenv) and commit.

**`install.sh` ends with "NOT ENCRYPTED IN GIT" (exit status 3)**
The filters and hooks are installed, but the listed files are tracked in plaintext: they were committed before the filter existed, or from a clone that never ran `install.sh`. Run `git add --renormalize -- <file>`, commit, and rotate those secrets — the plaintext stays in history.

**`git add` fails with "sops did not encrypt … completely"**
`sops` returned a document with content in clear, and the clean filter refused it. The matching `.sops.yaml` rule has `encrypted_regex`, `unencrypted_regex`, `encrypted_suffix` or `unencrypted_suffix` (give the SOPS-managed paths a rule of their own without those), a dotenv key ends in `_unencrypted`, or `sops` is older than 3.11.0. The line that starts with `Found:` says what the check saw. If it is "a key in the sops metadata that sops does not write", your `sops` is newer than this tool knows: update sops-git-filters. The guard and `install.sh` give the same reason next to each file they list.

**`git add`, `git status` or `git commit` fails with "holds NUL bytes"**
The file is binary (a keystore, a DER certificate) or UTF-16 text. Its content cannot pass through this tool, which would store it without the NUL bytes, so it is refused. Store a text form (base64, PEM, UTF-8), or take `filter=sops` off that path and encrypt the file with `sops` by hand. Before v2.1.0 such a file was stored damaged with exit status 0: if you have one in git, restore the original from a backup, not from git.

**`install.sh` ends with "NUL BYTES IN THE CONTENT" (exit status 3)**
The stored version of the listed files decrypts to content with NUL bytes; it was written to git without this tool's clean filter. `install.sh` left the working copy as ciphertext instead of writing it damaged. See the entry above.

**`install.sh` ends with "NOT DECRYPTED: REACHED THROUGH A LINK" (exit status 3)**
The working copy of these secrets still holds the ciphertext git holds, but it is a symbolic link, it lies in a directory that is a symbolic link (a shared or dotfiles folder, say), or it has a second name (a hard link). Writing the plaintext there would put it where the link leads, possibly outside the working tree, where `.gitignore` does not reach, so `install.sh` leaves it encrypted. The permission hooks do not follow a symbolic link either. Git does not write through a symbolic link either: `git status` lists such a path as deleted (` D`) or as a type change (` T`). Put the file itself in its place (for a hard link, a copy: `cp <file> <file>.new && mv <file>.new <file>`), or the directory itself instead of the link, and run `install.sh` again.

**`install.sh` says git runs the hooks "from a directory that is not its own"**
`core.hooksPath` (or a symlinked `.git/hooks`) points at a directory that other repositories use too. `install.sh` does not write into a directory it shares with others. The filters work all the same; only the step that sets secrets back to `0600` after a checkout, merge, rebase or commit is missing. Add the line that `install.sh` prints to your own hooks in that directory, or run `harden-permissions.sh` by hand. The line runs the copy that `install.sh` put inside the git directory of the repository at hand and does nothing where there is none. If you added the line that v2.1.0 printed (it named one repository by its absolute path), replace it: that one runs a script of the working tree.

**`git add` fails with "cannot be stored in the dotenv format"**
The file has a line the dotenv format would store in clear or not at all; the message names the line number. See [what the dotenv format refuses](#storage-formats-json-vs-dotenv).

**`install.sh` stops with "sops X.Y.Z is too old"**
Install `sops` 3.11.0 or newer. Older versions can store a whole file unencrypted (see [Requirements](#requirements)).

**`git diff` errors with "unable to read files" on encrypted paths**
Diffing managed files requires decryption (git routes the blobs through the smudge filter); without keys it fails loudly (list changed files with `git diff --stat` or `--no-textconv` instead). Re-run `install.sh` after key setup.

**Why is `diff.sops.textconv` set to `cat`?**
Not a bug. Git materializes textconv temp files *through the smudge filter*, so textconv already receives plaintext — `cat` is just the switch that makes git use that path instead of diffing raw ciphertext blobs. A `sops decrypt` textconv would double-decrypt and error.

## FAQ

**Why not git-crypt?** git-crypt is unmaintained-ish, GPG-centric, all-or-nothing per file pattern, and has no KMS/cloud-identity story. SOPS gives age + every major KMS, multi-recipient key groups, key rotation (`updatekeys`), and audited, actively maintained crypto. Same transparent-filter UX.

**Why not transcrypt?** Same core idea (OpenSSL + filters), but a single shared symmetric passphrase — no per-person or cloud-identity access, no break-glass separation, rotation means re-keying everyone at once.

**Why store JSON instead of SOPS YAML?** The clean filter treats file content as opaque (`--input-type binary`), so the *stored* representation must carry SOPS metadata alongside an arbitrary payload — JSON is SOPS's canonical container for that. For `KEY=value` files the `dotenv` format is available and keeps git-side diffs partially readable.

**Can I mix formats per file?** Not currently — one `SOPS_STORE_FORMAT` per repo.

**Does this work with worktrees/submodules as the *secret* repo?** Yes. Everything resolves paths via `git rev-parse`, and `install.sh` targets whatever repo you run it from (it refuses to configure its own checkout and picks the superproject instead). A new linked worktree works as is, with either layout: the filter and the hooks find the installed copy in the common git directory, which all worktrees share, so secrets are decrypted and `0600` straight after `git worktree add`. With the submodule layout the tool's own directory is empty in a new worktree until `git submodule update --init` runs there; you need that only to start `install.sh`, `rekey.sh` or `preflight.sh` from that worktree. (Before v3.0.0, `git status` and `git add` failed there until the submodule was initialised.)

## Tests

```sh
tests/run.sh            # everything
tests/run.sh guard      # only the tests whose name contains "guard"
```

Needs `git`, `sops` and `age-keygen` on PATH. Every test builds a throwaway repository with a throwaway age key. The runner restarts itself in an empty environment, so it reads nothing from your own git, sops or AWS configuration, and it never touches the network. `SGF_TOOL_DIR=<other checkout> tests/run.sh` runs the same tests against the scripts of another checkout, which is how a fix is shown to fail before and pass after.

Two tests drive the [pre-commit](https://pre-commit.com) framework (or `prek`) and are skipped when neither is on PATH. `SGF_HOOK_RUNNER=prek` picks the one to use, and `SGF_NO_SKIP=1` turns a skipped test into a failure. A selection that matches no test fails too.

CI (`.github/workflows/tests.yml`) runs shellcheck and the suite on Linux and macOS, with the oldest `sops` that `install.sh` accepts and with a current one. It downloads `sops`, `age`, `prek` and shellcheck from their GitHub releases and checks each file against a SHA-256 pinned in the repository (`tests/ci-install-tools.sh`) before using it. The two hook tests run there with that `prek`, and `SGF_NO_SKIP=1` is set: a test that skips itself fails the job. One more job sets `core.autocrlf=true`, adds this repository as a submodule of a new repository, runs `install.sh` from it and commits a secret with the guard as the pre-commit hook: it fails when a script is checked out with CRLF line endings.

## Code review by Greptile

Greptile reviews a pull request only when it is asked: write a comment on the pull request
that says `@greptileai` (a focus may follow, for example "`@greptileai` check the migration").
It does not review by itself: `greptile.json` sets `"autoReview": []`, and a repository's file
wins over the setting in Greptile's dashboard. Ask for a review when a pull request is big,
complex or critical; a small one does not need it.

## License

[MIT](LICENSE)
