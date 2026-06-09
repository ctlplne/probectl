# Repo hygiene

A few rules about what is allowed to live in the git history. The theme: the
repository holds **source, never build output and never secrets**. Both rules are
enforced by CI, so a violation is caught on push, not at audit time.

## No build artifacts are tracked

`git ls-files` contains no compiled binaries and no coverage files — only source.

[`.gitignore`](../../.gitignore) keeps it that way: it ignores `/bin/` (where
`make build` puts every binary), the stray root-level binaries a manual
`go build` can drop (`/probectl`, `/probectl-control`, `/probectl-agent`,
`/probectl-ebpf-agent`, `/probectl-endpoint`), and coverage output (`*.out`,
`*.test`, `*.coverprofile`, `coverage.*`).

So if you see a large `./probectl-control` after building, that is a normal,
**untracked** local artifact — not something that got committed. (Tip: send build
output to `/bin/` by using `make build` rather than a bare `go build` at the repo
root.)

Why: shipped binaries are rebuilt reproducibly from source at release time (see
[`../releasing.md`](../releasing.md)); committing them just bloats the clone and
invites "which binary is this, really?" questions. Coverage files are
per-run noise.

## No secrets, ever

This is a hard guardrail: credentials, tokens, and private keys never enter the
repo or its history.

How it's enforced: the `secret-scan` CI job
([`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) runs
[gitleaks](https://github.com/gitleaks/gitleaks) over the working tree on every
push and pull request. The only strings it tolerates are the *deliberately fake*
secrets inside redaction tests, allow-listed by SHA in
[`.gitleaks.toml`](../../.gitleaks.toml) — nothing real.

There is no real key material anywhere in the tree, including in tests. For
example, the mock OIDC identity provider used in tests **generates its signing
key at test setup** (`internal/crypto.GenerateRSAKeyPEM`) instead of reading a
committed key file. A test that needs a key makes one on the spot; the repo never
has to hold one.

## History

The repo has never cut a release from a dirty working tree, and published history
is not rewritten. If a fresh clone looks bloated from dangling objects, that is
the cloner's `git gc` to run — not a defect in the repository.
