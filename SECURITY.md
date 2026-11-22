# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: open the [Security tab](https://github.com/realsby/sops-git-filters/security) of this repository and choose **Report a vulnerability**, or go straight to <https://github.com/realsby/sops-git-filters/security/advisories/new>. Only the maintainer sees the report.

Please include:

- the version you used (a tag or a commit id), your git and `sops` versions and your operating system;
- what happens, and what you expected instead;
- the steps to reproduce it, in a throwaway repository with a throwaway key if you can. Do not send real secrets or real keys.

This tool has one maintainer. You get an answer as soon as the report is read; a fix is released as a new tag, with a security advisory on this repository that names the affected and the fixed versions.

## What counts

Anything that breaks what the README promises under [Security model](README.md#security-model), for example:

- plaintext that reaches the git index, a commit or the stash while git reports success;
- a check (the clean filter's output check, the pre-commit guard) that lets an unencrypted or partly encrypted file through;
- a way to make the scripts run code they were not meant to run (through file names, configuration values, hooks or paths);
- decrypted content written somewhere it should not be, or left with wider permissions than documented.

The limits the README already lists under [Limitations](README.md#limitations) and "What you must still do" are known and not vulnerabilities, but a report that shows one of them is worse than described is welcome.

## Supported versions

Fixes go into the latest release. Check out the latest tag (see [Installation](README.md#installation)) and run `install.sh` again in every clone.

Published advisories: <https://github.com/realsby/sops-git-filters/security/advisories>
