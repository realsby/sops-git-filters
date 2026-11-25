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

2. **Filters that "fail open" leak secrets.** Many setups pass plaintext through when SOPS isn't configured, so one missing `.sops.yaml` silently commits your secrets. Here the clean filter **fails hard** (and `filter.sops.required=true` makes git abort the `git add`), and a pre-commit guard independently rejects any staged blob that lacks SOPS ciphertext markers.

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
2. Input already is a SOPS document (the working copy still holds ciphertext)? → store it **unchanged**. Nothing is encrypted twice.
3. File is new (not in index or HEAD)? → encrypt.
4. File exists? → decrypt the stored blob, compare plaintexts:
   - cannot decrypt (no key, expired cloud session) → **exit non-zero** with the `sops` error. No blind re-encryption.
   - identical → output the **existing** ciphertext (no new IV → no false diff)
   - different → re-encrypt
5. Whatever `sops` returned is checked before git gets it: it must be a SOPS document with every value encrypted. If it is not, **exit non-zero**. (A creation rule with `encrypted_regex` and the like, or an old `sops`, can leave content in clear inside a valid-looking envelope.)

`SOPS_FILTER_FORCE_REENCRYPT=1` skips the comparison in step 4 and always re-encrypts (storage-format change, fresh data keys).

`harden-permissions.sh` closes the mode gap the smudge filter leaves. Git stores only the executable bit, so a decrypted secret lands with your umask — `0644` on a default workstation. `install.sh` runs the script once and installs five hooks that re-run it (`post-checkout`, `post-merge`, `post-rewrite`, `post-applypatch`, `post-commit`), so private keys and kubeconfigs are `0600` again after a checkout, pull, merge, rebase, cherry-pick, revert, `git am` and commit. A few commands run no hook (`git stash`, `git stash pop`, `git reset --hard`): see [Limitations](#limitations) and [Security model](#security-model).

## Requirements

- `git` ≥ 2.18, `bash` ≥ 3.2 (macOS stock bash is fine)
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
git -C utilities/sops-git-filters checkout v3.0.0     # the latest tag on the releases page
git add utilities/sops-git-filters && git commit -m "sops-git-filters v3.0.0"
./utilities/sops-git-filters/install.sh
```

Read the [release notes](https://github.com/realsby/sops-git-filters/releases) first; they list what behaves differently ([CHANGELOG.md](CHANGELOG.md) holds the same text). Every clone needs `git submodule update --init`, and `install.sh` once more after an update — put both in your setup task (see below). The last line is not optional: git runs the copy that `install.sh` put under `.git/`, so a clone where it has not run again still runs the old version. That copy says so on stderr ("git runs the installed copy, version …") when it sees a newer version in the checkout.

### B. Vendored copy (no submodule mechanics)

Copy every `*.sh` file (`clean-filter.sh`, `smudge-filter.sh`, `install.sh`, `encryption-guard.sh`, `harden-permissions.sh`, `merge-driver.sh`, `rekey.sh`, `preflight.sh`, and `lib.sh`, which the others load) into your repo (e.g. `utilities/sops-git-filters/`), keep them executable, run `install.sh`. You own updates, and after each one `install.sh` has to run again in every clone.

### C. Guard only, via pre-commit remote

If you only want the commit-time guard (e.g. filters are managed some other way):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/realsby/sops-git-filters
    rev: v3.0.0
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
.env           filter=sops diff=sops merge=sops
.env.*         filter=sops diff=sops merge=sops
*.env          filter=sops diff=sops merge=sops
.env.example   !filter !diff !merge
```

A pattern without a slash matches at every depth. The wildcards also cover `.env.local`, `.env.production` and `prod.env`: a name that a hand-written list misses is committed in plaintext without a word, and that is the mistake to rule out. Their price is the last line, which takes a template without secrets out again (it must come after the others; `!` and not `-`, because `-diff` would make git treat the file as binary). A template you forget to list is stored encrypted, which is harmless. The rule in `.sops.yaml` must match the same names.

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

`install.sh` exits 3 when the filters and hooks are installed but something is left to do: files it could not decrypt (no key, expired cloud session), files tracked in plaintext, or a storage-format change that is not finished. It prints which. A setup task that should carry on in that case can run `./utilities/sops-git-filters/install.sh || [ $? -eq 3 ]`. Exit status 1 means nothing was installed.

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

**`core.autocrlf` needs `-text`, for every storage format.** With `core.autocrlf=true` (common on Windows), git adds CRLF line endings to the ciphertext before the smudge filter sees it; `sops` then fails to decrypt the dotenv ciphertext and the checkout stops. Mark the managed paths `-text` in `.gitattributes`, for example `.env filter=sops diff=sops merge=sops -text`. Do this for the json format too: there later checkouts decrypt, but a fresh clone gets CRLF ciphertext in the working tree, and the re-smudge pass in `install.sh` does not recognise that copy as ciphertext. It leaves the file encrypted, prints nothing about it and still exits 0. The same happens to dotenv files on a fresh clone.

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

If step 3 ends with `STILL ENCRYPTED IN THE WORKING TREE` and exit status 3, `sops` could not decrypt: its own error is printed above that list (no key, expired session). Fix it and re-run `install.sh`. Until then the files stay ciphertext in your working tree. That state is safe: git treats them as unchanged and the clean filter stores them as they are, so nothing is encrypted twice.

**CI / servers that don't need plaintext** (e.g. they only lint or build): do nothing — without the filters configured, checkouts contain raw ciphertext and nothing decrypts. Deploy tooling that *does* need plaintext should use its own SOPS integration (native SOPS support, `sops exec-env`, or run `install.sh` with a deploy key present).

## The pre-commit guard

`encryption-guard.sh` is the independent second line of defense, for the cases where the filter is missing, misconfigured or bypassed.

- Looks at **every** file in the index whose git attribute is `filter=sops` (via `git check-attr`, so nested `.gitattributes` work), not only at the files staged for this commit. A secret that was committed in plaintext earlier blocks every commit until it is fixed. The attributes come from the `.gitattributes` files in the index, the ones the commit carries: an edit of `.gitattributes` that is not staged (say `.env -filter`, which also keeps `git add` from running the filter) does not take a path out of the check.
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
.env   filter=sops diff=sops merge=sops
```

`install.sh` registers the driver (`merge.sops.driver`), so existing clones must run it once more.

- **Changes to different lines** merge by themselves.
- **A real conflict, json format:** the working copy gets the usual `<<<<<<<` `=======` `>>>>>>>` markers, in plaintext. Edit the file, `git add` it, continue. Git never sees the marked-up plaintext: what it stores during the conflict is encrypted like everything else.
- **A real conflict, dotenv format:** marker lines are not `KEY=VALUE` and cannot be stored. Our version is kept and the conflict is reported. Take a side with `git checkout --theirs -- <file>` (or `--ours`), or use `git mergetool`; then `git add`.
- **No keys, no merge:** the driver has to decrypt. Without a key or cloud session git reports `failed to execute internal merge` and changes nothing; sign in and run the merge again.
- **Plaintext on disk:** for the length of the merge the three decrypted versions sit in a private directory (mode 0700) under `.git/`, removed on exit. `git merge-file` needs real files. If a run is killed, the next merge removes what it left, once that process is gone or the directory is an hour old; the files of a merge that is still running are left alone.
- **`git mergetool` leaves a backup:** `<file>.orig` holds your side in plaintext, and `.env.orig` does not match a `.env` pattern in `.gitattributes`, so `git add -A` would commit it unencrypted and the guard would not see it. Set `git config mergetool.keepBackup false`, or ignore `*.orig`.

Without `merge=sops`, the minimum is `merge=binary` on the same paths: git then reports an ordinary conflict and keeps your version, instead of dying.

## Changing recipients (re-key)

After you add or remove a key in `.sops.yaml`, the files already in git are still encrypted for the old recipients. Editing nothing and re-adding them does not help: the clean filter reuses the stored blob whenever the plaintext is unchanged. Re-key the stored blobs instead:

```sh
./utilities/sops-git-filters/rekey.sh --dry-run   # which files would change
./utilities/sops-git-filters/rekey.sh             # re-key and stage them
git diff --cached --stat && git commit
```

`rekey.sh` copies each SOPS-managed blob from the index into a private directory under `.git/` (ciphertext only), runs `sops updatekeys` on it against your `.sops.yaml`, and stages the result with `git update-index`. The working tree is not touched. It needs decryption access, and it accepts paths to limit the run.

**Removing a recipient is not revocation.** `sops updatekeys` keeps the data key, and history keeps the old blobs: whoever was removed could read everything up to now. Rotate the secret values. Editing a value re-encrypts that file with a fresh data key; to do that for files you did not edit, run `SOPS_FILTER_FORCE_REENCRYPT=1 git add --renormalize .`

## When sops cannot decrypt: preflight and recovery

Git removes a SOPS-managed file from the working tree *before* it runs the smudge filter. If `sops` cannot decrypt at that moment (a session with the key service that expired, a key that is not on this machine), the command stops right there. That is on purpose: the filter fails closed and never writes ciphertext or an empty file where a secret belongs. But the command is left half-done.

**Ask first.** `preflight.sh` decrypts stored blobs to `/dev/null`, one for every set of keys that your tracked secrets name (with one `.sops.yaml` rule for all files that is a single decryption; a set is the whole access rule: key groups, the keys in each, the threshold), and names what to check when that fails:

```sh
./utilities/sops-git-filters/preflight.sh && git pull
```

Exit status 0: decryption works. 1: it does not, so do not pull, check out, merge or rebase now. 2: the check could not run or is incomplete (not a repository, `sops` missing, the index or a stored blob unreadable). It writes nothing and prints no plaintext; `--quiet` prints nothing at all when decryption works. It cannot know the commits you have not fetched yet: they may name other keys. A script or an assistant that runs git for you should call it before any command that changes the working tree.

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
- **No blind re-encryption.** If the stored version of a secret cannot be decrypted, the clean filter stops with the `sops` error. Input that already is ciphertext is stored unchanged.
- **The output is checked, twice.** The clean filter refuses what `sops` returns unless it is a completely encrypted SOPS document. The guard then re-checks every tracked SOPS-managed blob at commit time, with no dependency on the filter machinery.
- **Git runs a copy that no checkout can change.** `install.sh` copies the scripts git needs into `sops-git-filters/` inside the git directory (the common one, shared by all worktrees), and git config and the hooks name that copy with a path that is resolved when the command runs. Before v3.0.0 they named the scripts in the working tree: with a vendored copy of the tool, checking out a branch ran that branch's `harden-permissions.sh` through the post-checkout hook, and the next `git status` ran its `clean-filter.sh` with your plaintext on stdin. What still runs from the working tree is what you start yourself: `install.sh`, `rekey.sh`, `preflight.sh`, and `encryption-guard.sh` through your pre-commit configuration. So run `install.sh` only from a checkout you trust (your main branch, a release tag): it is the step that decides which code git runs from then on.
- **No plaintext in the remote, the object store or the stash.** They hold ciphertext only. Plaintext still appears in a few places outside the object store: the temporary files git writes for `textconv` (`$TMPDIR/git-blob-XXXXXX/`, mode 0600 in a 0700 directory; one stays behind after `kill -9`), `.git/COMMIT_EDITMSG` after `git commit -v` (it holds the plaintext diff), the output of `git diff`, `git show` and `git log -p`, and `git archive`, which emits plaintext. To keep secrets out of archives, add `export-ignore` to the managed paths in `.gitattributes`, for example `.env filter=sops diff=sops merge=sops export-ignore`. Multi-recipient keys and break-glass access come from SOPS key groups.
- **Mode 0600 on decrypted files.** Git only round-trips the executable bit, so every smudge — clone, `checkout`, `pull`, the re-smudge pass in `install.sh` — writes the decrypted secret with your *umask*, which is `0644` on a default workstation: a world-readable deploy key, API key, kubeconfig or cluster-secrets bundle (and OpenSSH flatly refuses a `0644` private key). `harden-permissions.sh` chmods every `filter=sops` file to `0600` (a file tracked as executable, mode `100755`, gets `0700`, so git sees no mode change); `install.sh` runs it and installs five hooks that run it again (the installed copy of it): `post-checkout`, `post-merge`, `post-rewrite`, `post-applypatch` and `post-commit`, which covers checkout, switch, pull, merge, rebase, `commit --amend`, `git am`, commit, cherry-pick and revert (what is not covered is under [Limitations](#limitations)). The hooks go into the repository's own hooks directory, nowhere else: when `core.hooksPath` names a directory that other repositories use too (a machine-wide `~/.githooks`, say), `install.sh` writes nothing there, and it prints one line to add to your own hooks instead. That line runs the installed copy of the repository the hook runs in, and does nothing where `install.sh` never ran. Hooks that `install.sh` wrote into such a directory up to v2.0.0 are removed on the next run. Override the mode with `SOPS_FILE_MODE` in `.sops-filter.conf` (owner and group bits only, such as `640`, which gives `740` to an executable file; a setuid, setgid or sticky digit or any bit for others is refused: the files then get `0600` and the script exits with an error), or skip the hook install with `SOPS_FILTER_INSTALL_HOOKS=0`. Because a chmod changes a file's inode change time, `install.sh` also sets `core.trustctime=false` in the repository: git would otherwise take a freshly chmod-ed secret for locally modified. A value you set yourself (`git config core.trustctime true`) is left alone.

What you must still do:

- **Protect working trees.** Checked-out secrets are plaintext on disk — that's the point. `0600` keeps other local accounts out; full-disk encryption and access control against everything else are on you.
- **Re-run the tightening where hooks don't reach.** The hooks live in `.git/hooks`, which is not cloned, so a clone that never runs `install.sh` gets neither the filters nor the permissions. Anything that materialises secrets outside git (`sops decrypt > file`, a deploy script, an editor's temp copy) sets its own mode — run `harden-permissions.sh` afterwards or set the mode yourself. Do the same after `git stash`, `git stash pop` and `git reset --hard`: git runs no hook for them.
- **Mind whose branches you check out while a session is live.** The smudge filter decrypts whatever a checkout brings, and a SOPS document says in its own metadata which key to ask for: an age recipient, a KMS key, a Vault address. `sops` follows that. A blob in a branch from someone else can name a key service you never use, and `sops` contacts it with your credentials. With HashiCorp Vault this was reproduced: `sops decrypt` sent the `X-Vault-Token` header to the address in the blob. With AWS it would be a signed `Decrypt` call for a foreign key ARN (not tested). This tool cannot stop it, because git hands the blob to the filter as part of the checkout. Read a change to a SOPS-managed file as ciphertext first (`git diff --no-textconv`, or the pull request page: the `sops` metadata with the key names is in clear), and do not check out branches of people you do not trust with a token or session for a key service in your environment.
- **Client-side hooks are opt-in.** A collaborator who never runs `install.sh`/`pre-commit install` has no filter and no guard; if they create a *new* secret file it lands in plaintext. Mitigate with a server-side/CI check (a grep for `ENC[AES256_GCM` on managed paths is enough).
- **History is forever.** Anything committed in plaintext *before* adoption stays in history — rewrite history or rotate those secrets.
- **Rotate on suspicion.** Ciphertext in a public/leaked repo is only as strong as your key custody.

## Repository policy

`main` carries GitHub branch protection (no force-push, no deletion, enforced for admins), and a release tag (`v*`) cannot be moved or deleted once it is pushed. To report a security problem, see [SECURITY.md](SECURITY.md).

## Limitations

- **Text files only.** File content passes through shell variables, and a shell variable cannot hold a NUL byte. A file with NUL bytes (a keystore, a DER certificate, UTF-16 text) is refused: `git add` fails and says why, instead of storing the file damaged. Store a text form of it (base64, PEM, UTF-8). Fine for `.env`, PEM/OpenSSH keys, YAML, JSON.
- **Trailing-newline normalization.** Content round-trips exactly, except exotic cases like a file whose last line has no terminating newline *and* SOPS dotenv format (which appends one).
- **Merges need the driver.** Without `merge=sops` (or at least `merge=binary`) on a path, two branches that both changed that secret cannot be merged; see [Merging secrets](#merging-secrets).
- **Recipients change only through `rekey.sh`.** Touching and re-adding a file does not re-encrypt it; see [Changing recipients](#changing-recipients-re-key).
- **One filter name.** Everything is registered under the `sops` filter/diff driver; per-path different formats aren't supported (one `SOPS_STORE_FORMAT` per repo).
- **`git add -p` stages a managed file whole.** Git shows the ciphertext, not your plaintext edit, and cannot stage part of the file. Stage the whole file with `git add`.
- **Mode 0600 does not come back after every command.** Git runs no hook after `git stash`, `git stash pop`, `git reset --hard` and `git sparse-checkout add`. A secret that one of them writes again has your umask mode (usually `0644`) until the next commit, checkout or merge, or until you run `harden-permissions.sh`. A new secret has the umask mode until its first commit.
- **A secret with uncommitted changes costs key-service calls each time git looks at it.** Git runs the clean filter again whenever it compares the file: twice for one `git diff`, up to once for one `git status` (measured with git 2.54). Each run decrypts the stored version and encrypts the new one. Nothing is cached, on purpose: a cache would put data derived from the plaintext on disk.

## Troubleshooting

**`git add` fails with "filter 'sops' failed" / ERROR: .sops.yaml missing**
Working as designed — encryption isn't possible, so staging is refused. Create `.sops.yaml` (or fix `sops` on PATH) and retry.

**`install.sh` stops with "filter.sops.process is set outside this repository's .git/config"**
Another tool registered a long-running filter under the same driver name (`sops`), in your global or system git config. Git prefers it over the clean/smudge commands, so `clean-filter.sh` would never run. Remove that setting (`git config --global --unset filter.sops.process`) and re-run `install.sh`. A copy in the repository's own `.git/config` is removed for you.

**Fresh clone: `.env` is full of `ENC[...]` gibberish**
Filters aren't configured yet on this clone. Run `install.sh` — it configures `.git/config` and decrypts pre-setup checkouts in place. Still ciphertext afterwards? `install.sh` then ended with `STILL ENCRYPTED IN THE WORKING TREE` and the `sops` error above it: your key or cloud session isn't available. Fix that and re-run.

**`git status`, `git add` or `git commit` fails with "cannot decrypt the version of … that git holds"**
To know whether a secret changed, the clean filter decrypts the stored version. That failed, and the `sops` message above the error says why: usually a session with the key service that expired (AWS: `aws sso login`; GCP: `gcloud auth application-default login`; Azure: `az login`; Vault: `vault login`) or a key `sops` cannot find (age: `SOPS_AGE_KEY_FILE`, on macOS see [step 1 of the walkthrough](#setup-walkthrough); PGP: the secret key in your gpg keyring). The lines under the error name what to check for the kinds of key this file uses. Git runs the filter for every SOPS-managed file whose timestamp changed, so one touched secret is enough to stop these commands until decryption works again. The filter does not re-encrypt blindly: that would show unchanged secrets as modified and commit them again. `SOPS_FILTER_FORCE_REENCRYPT=1 git add <file>` re-encrypts on purpose.

**Every `git status` shows my secret file as modified**
With dotenv format, check for blank lines (not representable — the round-trip comparison then never matches; use `#` separator lines) and for a missing newline at the end of the file. Otherwise you are likely running an older clean filter: update, re-run `install.sh` and re-add the file once.

**A file got double-encrypted (ciphertext inside ciphertext)**
Older versions of the clean filter did this when ciphertext sitting in the working tree was `git add`-ed after the filters were configured. The current filter stores input that already is a SOPS document unchanged, so it no longer happens. To repair a blob from before: `git show :file | sops decrypt --input-type <fmt> --output-type <fmt2> --filename-override file /dev/stdin` repeatedly until you see actual plaintext, write that to the working tree, `git add`.

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

CI (`.github/workflows/tests.yml`) runs shellcheck and the suite on Linux and macOS, with the oldest `sops` that `install.sh` accepts and with a current one. It downloads `sops`, `age`, `prek` and shellcheck from their GitHub releases and checks each file against a SHA-256 pinned in the repository (`tests/ci-install-tools.sh`) before using it. The two hook tests run there with that `prek`, and `SGF_NO_SKIP=1` is set: a test that skips itself fails the job.

## License

[MIT](LICENSE)
