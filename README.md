# sops-git-filters

Transparent, git-crypt-style secret encryption for git — powered by [SOPS](https://github.com/getsops/sops).

Files you list in `.gitattributes` are **plaintext in your working tree** and **SOPS-encrypted in git**. You edit `.env` normally; git stores ciphertext; `git diff` still shows readable changes.

```
git pull / checkout   →  decrypted automatically   (smudge filter)
git add / commit      →  encrypted automatically   (clean filter)
git diff / log -p     →  shows plaintext changes   (textconv)
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

3. **Absolute paths in `.git/config` rot.** Move or rename the repo directory and a naively configured filter breaks — worse, some breakages are *silent* and the next `git add` stages plaintext. `install.sh` writes a **repo-relative** filter path (git runs filters from the repo root), so the config survives moves. The guard catches anything that slips through.

4. **Fresh clones hold ciphertext.** Filters live in `.git/config`, which is not cloned — files checked out before setup are raw ciphertext in the working tree. `install.sh` detects and decrypts them in place (only when the working copy is byte-identical to the stored blob, so local edits are never overwritten).

The pre-commit stash dance is also handled: the clean filter compares against the **index**, not HEAD, so [pre-commit](https://pre-commit.com)'s stash/unstash cycle doesn't corrupt staged files or create stash-pop conflicts.

## How it works

```
        ┌────────────────────┐  filter.sops.clean (clean-filter.sh)  ┌──────────────────┐
        │   Working tree     │ ─────────── git add ────────────────▶ │    Git object    │
        │   .env (plaintext) │                                       │  store & remote  │
        │                    │ ◀────────── checkout ──────────────── │   (ciphertext)   │
        └────────────────────┘  filter.sops.smudge (sops decrypt)    └──────────────────┘
                                                                            │
                 git diff / git log -p ◀── diff.sops.textconv ──────────────┘
                 (plaintext diffs)          (routes diffs through smudge)

                 git commit ──▶ encryption-guard.sh (pre-commit)
                                rejects any tracked secret that is not an
                                encrypted SOPS document
```

`clean-filter.sh` decision tree on every `git add`:

1. No `sops` on PATH, or no `.sops.yaml`? → **exit non-zero, git aborts the add.** Plaintext is never stored.
2. File is new (not in index or HEAD)? → encrypt, done.
3. File exists? → decrypt the stored blob, compare plaintexts:
   - identical → output the **existing** ciphertext (no new IV → no false diff)
   - different → re-encrypt
4. Whatever `sops` returned is checked before git gets it: it must be a SOPS document with every value encrypted. If it is not, **exit non-zero**. (A creation rule with `encrypted_regex` and the like, or an old `sops`, can leave content in clear inside a valid-looking envelope.)

`harden-permissions.sh` closes the mode gap the smudge filter leaves. Git stores only the executable bit, so a decrypted secret lands with your umask — `0644` on a default workstation. `install.sh` runs the script once and installs `post-checkout` and `post-merge` hooks that re-run it, so private keys and kubeconfigs stay `0600` after every checkout, pull and merge. See [Security model](#security-model).

## Requirements

- `git` ≥ 2.18, `bash` ≥ 3.2 (macOS stock bash is fine)
- [`sops`](https://github.com/getsops/sops) ≥ 3.11.0 on PATH. `install.sh` refuses older versions: up to 3.10.2, `sops` stores the whole file in clear when the matching `.sops.yaml` rule uses `encrypted_regex`, `unencrypted_regex`, `encrypted_suffix` or `unencrypted_suffix`.
- A SOPS key backend: [age](https://github.com/FiloSottile/age) (simplest), or any KMS SOPS supports

## Installation

Pick one:

### A. Git submodule (recommended — pinned version, easy updates)

```sh
git submodule add https://github.com/realsby/sops-git-filters.git utilities/sops-git-filters
./utilities/sops-git-filters/install.sh
```

Updating later: `git -C utilities/sops-git-filters pull origin main`, then commit the new submodule pointer. Every clone needs `git submodule update --init` — put it in your setup task (see below).

### B. Vendored copy (no submodule mechanics)

Copy every `*.sh` file (`clean-filter.sh`, `install.sh`, `encryption-guard.sh`, `harden-permissions.sh` and `lib.sh`, which the others load) into your repo (e.g. `utilities/sops-git-filters/`), keep them executable, run `install.sh`. You own updates.

### C. Guard only, via pre-commit remote

If you only want the commit-time guard (e.g. filters are managed some other way):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/realsby/sops-git-filters
    rev: v1.0.0
    hooks:
      - id: sops-encryption-guard
```

This does **not** install the clean/smudge filters — files won't auto-encrypt, but plaintext commits are blocked.

## Setup walkthrough

From zero to encrypted secrets in five steps. All files go in **your** repo's root.

**1. Create a key** (age shown; any SOPS backend works):

```sh
age-keygen -o ~/.config/sops/age/keys.txt
# Public key: age1abc... ← goes into .sops.yaml
```

**2. Create `.sops.yaml`** (see [`examples/sops.yaml`](examples/sops.yaml)):

```yaml
creation_rules:
  - path_regex: \.env$
    key_groups:
      - age:
          - age1abc...          # you
          - age1xyz...          # break-glass key, stored offline
```

**3. Mark files in `.gitattributes`** (see [`examples/gitattributes`](examples/gitattributes)):

```
.env      filter=sops diff=sops
**/.env   filter=sops diff=sops
```

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
./utilities/sops-git-filters/install.sh
pre-commit install
"""
```

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

Pick the format **before the first encrypted commit**. Migrating later means: change `.sops-filter.conf`, re-run `install.sh` (it updates the smudge/textconv commands), then force re-encryption of every managed file (`touch` them, `git add`) — old clones must re-run `install.sh` too.

## Onboarding a teammate / a new machine

1. Clone the repo. **The working tree now contains ciphertext** for SOPS-managed files — that's expected; filters live in `.git/config`, which isn't cloned.
2. Get decryption access: receive the age private key (or have your cloud identity added to the KMS key policy), e.g. `~/.config/sops/age/keys.txt` or `SOPS_AGE_KEY_FILE`.
3. Run the setup task (or directly `./utilities/sops-git-filters/install.sh`). The install re-smudges the ciphertext files into plaintext in place.
4. Sanity check: `cat .env` shows plaintext, `git status` is clean, `git show :.env` shows ciphertext.

If step 3 warns `Could not decrypt ... keys unavailable` — your key isn't set up yet; fix it and re-run `install.sh`. Until then the file stays ciphertext in your working tree (safe, just unusable).

**CI / servers that don't need plaintext** (e.g. they only lint or build): do nothing — without the filters configured, checkouts contain raw ciphertext and nothing decrypts. Deploy tooling that *does* need plaintext should use its own SOPS integration (native SOPS support, `sops exec-env`, or run `install.sh` with a deploy key present).

## The pre-commit guard

`encryption-guard.sh` is the independent second line of defense, for the cases where the filter is missing, misconfigured or bypassed.

- Looks at **every** file in the index whose git attribute is `filter=sops` (via `git check-attr`, so nested `.gitattributes` work), not only at the files staged for this commit. A secret that was committed in plaintext earlier blocks every commit until it is fixed.
- Reads each blob by object id and checks its structure. In the json format it must be `{"data": "<one ENC[...] value>", "sops": {...}}` and nothing else. In the dotenv format every value and every comment must be `ENC[...]`, and the `sops_` metadata must be there. A search for the string `ENC[AES256_GCM` is not enough: a plaintext file can mention it, and a SOPS envelope can carry plaintext while its MAC is `ENC[...]`.
- Skips symlinks and submodules (git never filters them).
- Blocks the commit if `.sops.yaml` is missing while SOPS-managed files are tracked.
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

## Security model

What you get:

- **Fail-closed staging.** The clean filter exits non-zero when it can't encrypt (`sops` missing, `.sops.yaml` missing, encryption error) and `filter.sops.required=true` turns that into an aborted `git add` — the failure mode is a loud error, never a plaintext commit. `install.sh` writes that flag on every run, first, and stops if a `filter.sops.process` setting would override the filter.
- **`.sops.yaml` alone decides the recipients.** `sops` lets `SOPS_AGE_RECIPIENTS`, `SOPS_KMS_ARN`, `SOPS_GCP_KMS_IDS`, `SOPS_AZURE_KEYVAULT_URLS`, `SOPS_VAULT_URIS`, `SOPS_PGP_FP` and `SOPS_HUAWEICLOUD_KMS_IDS` replace the keys of a creation rule. The clean filter drops them (with a one-line note), so a variable left over in your shell cannot encrypt a secret for the wrong keys.
- **The output is checked, twice.** The clean filter refuses what `sops` returns unless it is a completely encrypted SOPS document. The guard then re-checks every tracked SOPS-managed blob at commit time, with no dependency on the filter machinery.
- **No plaintext at rest in git.** Remote, object store, and stash hold ciphertext only. Multi-recipient keys and break-glass access come from SOPS key groups.
- **Mode 0600 on decrypted files.** Git only round-trips the executable bit, so every smudge — clone, `checkout`, `pull`, the re-smudge pass in `install.sh` — writes the decrypted secret with your *umask*, which is `0644` on a default workstation: a world-readable deploy key, API key, kubeconfig or cluster-secrets bundle (and OpenSSH flatly refuses a `0644` private key). `harden-permissions.sh` chmods every `filter=sops` file to `0600`; `install.sh` runs it and installs `post-checkout` and `post-merge` hooks that run it again after each checkout and merge. Override the mode with `SOPS_FILE_MODE` in `.sops-filter.conf`, or skip the hook install with `SOPS_FILTER_INSTALL_HOOKS=0`.

What you must still do:

- **Protect working trees.** Checked-out secrets are plaintext on disk — that's the point. `0600` keeps other local accounts out; full-disk encryption and access control against everything else are on you.
- **Re-run the tightening where hooks don't reach.** The hooks live in `.git/hooks`, which is not cloned, so a clone that never runs `install.sh` gets neither the filters nor the permissions. Anything that materialises secrets outside git (`sops decrypt > file`, a deploy script, an editor's temp copy) sets its own mode — run `harden-permissions.sh` afterwards or set the mode yourself.
- **Client-side hooks are opt-in.** A collaborator who never runs `install.sh`/`pre-commit install` has no filter and no guard; if they create a *new* secret file it lands in plaintext. Mitigate with a server-side/CI check (a grep for `ENC[AES256_GCM` on managed paths is enough).
- **History is forever.** Anything committed in plaintext *before* adoption stays in history — rewrite history or rotate those secrets.
- **Rotate on suspicion.** Ciphertext in a public/leaked repo is only as strong as your key custody.

## Repository policy

`main` carries GitHub branch protection (no force-push, no deletion, enforced for admins) — this repository is public, so the Free plan allows it. The three private consumer repositories in this estate cannot have server-side protection on GitHub Free ("Upgrade to GitHub Pro or make this repository public"); by decision of 2026-09-15 they stay on Free and rely on client-side `no-commit-to-branch` pre-commit hooks instead. Recorded here so an audit of the tooling does not re-raise it.

## Limitations

- **Text files only.** File content passes through shell variables; NUL bytes are not preserved. Fine for `.env`, PEM/OpenSSH keys, YAML, JSON — not for binary blobs.
- **Trailing-newline normalization.** Content round-trips exactly, except exotic cases like a file whose last line has no terminating newline *and* SOPS dotenv format (which appends one).
- **`sops updatekeys` workflow.** After changing recipients in `.sops.yaml`, re-encrypt managed files by touching and re-adding them (the stored ciphertext must be rebuilt to include new recipients); `sops updatekeys` on the *stored* blob also works: `git show :.env | sops updatekeys ...`.
- **One filter name.** Everything is registered under the `sops` filter/diff driver; per-path different formats aren't supported (one `SOPS_STORE_FORMAT` per repo).

## Troubleshooting

**`git add` fails with "filter 'sops' failed" / ERROR: .sops.yaml missing**
Working as designed — encryption isn't possible, so staging is refused. Create `.sops.yaml` (or fix `sops` on PATH) and retry.

**`install.sh` stops with "filter.sops.process is set outside this repository's .git/config"**
Another tool registered a long-running filter under the same driver name (`sops`), in your global or system git config. Git prefers it over the clean/smudge commands, so `clean-filter.sh` would never run. Remove that setting (`git config --global --unset filter.sops.process`) and re-run `install.sh`. A copy in the repository's own `.git/config` is removed for you.

**Fresh clone: `.env` is full of `ENC[...]` gibberish**
Filters aren't configured yet on this clone. Run `install.sh` — it configures `.git/config` and decrypts pre-setup checkouts in place. Still ciphertext afterwards? Your key isn't available; check `SOPS_AGE_KEY_FILE` / KMS credentials and re-run.

**Every `git status` shows my secret file as modified**
You're likely running a naive filter (or an older version of it) that re-encrypts unconditionally. Re-run `install.sh` and re-add the file once. With dotenv format, also check for blank lines (not representable — the round-trip comparison then never matches; use `#` separator lines).

**A file got double-encrypted (ciphertext inside ciphertext)**
Happens if ciphertext sitting in the working tree gets `git add`-ed *after* filters are configured (the filter treats the ciphertext as plaintext to protect). Fix: `git show :file | sops decrypt --input-type <fmt> --output-type <fmt2> --filename-override file /dev/stdin` repeatedly until you see actual plaintext, write that to the working tree, `git add`. Prevention is exactly what the `install.sh` re-smudge pass and its byte-identical check are for.

**Repo directory moved/renamed and filters broke**
With this version, they don't — the clean path in `.git/config` is repo-relative. If you migrated from an absolute-path setup, run `install.sh` once to rewrite it.

**`git stash` / pre-commit stash conflicts on secret files**
The filter compares against the index specifically to keep stash blobs identical. If you hit a conflict anyway you're likely on an older clean filter — re-run `install.sh` on a current checkout.

**Guard blocks a commit but `git show :file` looks encrypted**
The guard wants a *completely* encrypted SOPS document in the format set in `.sops-filter.conf`: one `ENC[...]` value under `"data"` (json), or every value and comment as `ENC[...]` (dotenv). A blob with one value in clear or with extra keys is refused: rebuild it with `git add --renormalize -- <file>`. A blob that is encrypted in the *other* storage format is reported separately ("stored in the other format"): that is a format change that was not finished, see [Storage formats](#storage-formats-json-vs-dotenv). The guard also names files you did not touch in this commit: it checks everything that is tracked.

**`install.sh` ends with "STORED IN THE OTHER FORMAT" (exit status 3)**
`.sops-filter.conf` names one storage format and git still holds the listed files in the other one. Nothing leaked. Re-encrypt them as described under [Storage formats](#storage-formats-json-vs-dotenv) and commit.

**`install.sh` ends with "NOT ENCRYPTED IN GIT" (exit status 3)**
The filters and hooks are installed, but the listed files are tracked in plaintext: they were committed before the filter existed, or from a clone that never ran `install.sh`. Run `git add --renormalize -- <file>`, commit, and rotate those secrets — the plaintext stays in history.

**`git add` fails with "sops did not encrypt … completely"**
`sops` returned a document with content in clear, and the clean filter refused it. The matching `.sops.yaml` rule has `encrypted_regex`, `unencrypted_regex`, `encrypted_suffix` or `unencrypted_suffix` (give the SOPS-managed paths a rule of their own without those), a dotenv key ends in `_unencrypted`, or `sops` is older than 3.11.0.

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

**Does this work with worktrees/submodules as the *secret* repo?** Yes — everything resolves paths via `git rev-parse`, and `install.sh` targets whatever repo you run it from (it refuses to configure its own checkout and picks the superproject instead).

## Tests

```sh
tests/run.sh            # everything
tests/run.sh guard      # only the tests whose name contains "guard"
```

Needs `git`, `sops` and `age-keygen` on PATH. Every test builds a throwaway repository with a throwaway age key. The runner restarts itself in an empty environment, so it reads nothing from your own git, sops or AWS configuration, and it never touches the network. `SGF_TOOL_DIR=<other checkout> tests/run.sh` runs the same tests against the scripts of another checkout, which is how a fix is shown to fail before and pass after.

## License

[MIT](LICENSE)
