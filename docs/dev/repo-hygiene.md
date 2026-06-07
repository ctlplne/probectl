# Repo hygiene

- **No binaries or coverage files are tracked** (CODE-003, verified at HEAD:
  `git ls-files` contains none). `.gitignore` covers `/bin/`, `/probectl*`
  root binaries, `*.out`, `*.test`, and coverage files — keep it that way;
  the local 36MB `./probectl-control` you may see is an untracked build
  artifact (`make build` outputs belong in `/bin/`).
- **No secrets, ever** (CODE-006 / guardrail 6): the `secret-scan` CI job runs
  gitleaks over the tree on every push/PR (`.gitleaks.toml` allowlists only
  the deliberate fake secrets inside redaction tests). The former OIDC
  test-key fixture is gone — the mock IdP generates its key at test setup via
  `internal/crypto.GenerateRSAKeyPEM`.
- **History:** the repo has never shipped a release from a dirty history; we
  do not rewrite published history. Local clone bloat from dangling objects
  is the cloner's `git gc` business, not a repo defect.
