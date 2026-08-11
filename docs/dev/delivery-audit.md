# Independent delivery audit

The delivery audit answers a stricter question than unit or integration tests:
**can an independent operator use the release artifact, through the real CLI
and rendered web UI, against real services at one exact source revision?**

It has two lanes:

- `make delivery-audit-gate` is the fast, offline policy lane. It tests strict
  receipt decoding, bounded artifact hashing, Ed25519 signing through
  `internal/crypto`, exact-source promotion, out-of-band signer trust, the
  repository-only packaging boundary, and a planted fixture-only rejection.
- `make delivery-audit` is the Docker-backed human-path lane. It builds the
  actual release control and CLI artifacts at the current clean commit, starts
  TLS-only Postgres, Kafka, ClickHouse, Prometheus, Dex, and control services,
  seeds two tenants, exercises the CLI and a real WebKit browser, and writes
  screenshots, network observations, store probes, and signed receipts.

The fast lane proves the acceptance policy itself is alive. It is not a
substitute for the real-stack lane.

## Trust model

A receipt envelope contains its signing public key so anyone can verify byte
integrity. That embedded key is **not authority**: otherwise an implementer
could generate a new key and approve their own work. Promotion requires a
public key or `sha256:<64 lowercase hex>` fingerprint obtained from the
independent auditor through a separate channel.

The states are deliberately distinct:

| State | Meaning |
|---|---|
| `SIGNATURE_VALID_UNTRUSTED` | Signature and artifact hashes verify, but no independently pinned signer was supplied. |
| `NON_PROMOTABLE` | Trust or semantic delivery evidence failed. |
| `FAILED` | The signed audit honestly records a failed human path. |
| `CURRENT_CHECKOUT_DIRTY` | The checkout no longer represents one exact source tree. |
| `STALE_SHA` | The receipt names a different commit or tree. |
| `VERIFIED_CURRENT` | Trusted signer, delivery semantics, clean checkout, commit, tree, signature, and artifact hashes all agree. |

Only `VERIFIED_CURRENT` may promote a completeness-loop item.

## Repository-only command

`probectl-delivery-audit` is an auditor tool, not a customer binary. CI proves
it is absent from the release binary list, release workflow, and offline
customer bundle. Its command contract is:

```text
probectl-delivery-audit certs  --out DIR [--ttl 6h]
probectl-delivery-audit seal   --draft FILE --artifacts DIR --key FILE --out FILE
probectl-delivery-audit lint   --receipt FILE [--artifacts DIR]
probectl-delivery-audit verify --receipt FILE [--artifacts DIR]
                               [--trusted-public-key FILE]
                               [--trusted-fingerprint sha256:<64hex>]
                               [--require-current --repo DIR]
probectl-delivery-audit selftest
```

`seal` creates the output path once and never overwrites it. Receipt drafts,
envelopes, and attachments are size-bounded, strict-schema, regular files;
absolute paths, traversal, duplicate paths, and every symlink component are
rejected. Private signer keys must be real mode-`0600` files.

## Independent run

1. Start from a clean committed checkout. Evidence must live outside that Git
   tree; otherwise writing the evidence would make the checkout dirty and
   correctly prevent promotion.
2. The independent auditor runs `make delivery-audit`. The runner prints its
   evidence directory and signer fingerprint. It also retains a signed real
   receipt, a signed failed/test-only example, and the planted linter output.
3. The auditor sends the signer fingerprint to the verifier separately from
   the receipt bundle.
4. The verifier checks the exact checkout:

   ```sh
   go run ./cmd/probectl-delivery-audit verify \
     --receipt /absolute/evidence/receipt.json \
     --artifacts /absolute/evidence \
     --trusted-fingerprint 'sha256:<auditor-pin>' \
     --require-current \
     --repo /absolute/path/to/probectl
   ```

5. Record `VERIFIED_CURRENT`, the full commit SHA, tree SHA, receipt hash, and
   signer fingerprint in the completeness-loop audit receipt. A later source
   change makes the prior receipt stale by design.

## TLS and secret handling

The audit CA is generated locally for each run, lives for at most six hours,
and is never copied into a release image. The browser first proves the site is
rejected without that CA, then installs the CA into its disposable trust store
and launches WebKit with normal verification (`ignoreHTTPSErrors: false`). All
service leaves are named; private keys stay owner-only inside disposable audit
storage.

Runtime credentials are generated outside Git, passed through files or runtime
environment, redacted from transcripts, and destroyed with the disposable
stack. ClickHouse credentials are sent as headers, never URL userinfo or query
parameters. Provider credential-bearing CLI requests accept only
`--body-file <0600-file|->`; inline `--body` is refused so passwords, enrollment
tokens, and TOTP values do not enter process arguments or shell history.

The harness does not enable dev authentication, browser request interception,
fixture APIs, plaintext listeners, certificate-validation bypasses, or provider
license shortcuts. A missing secure channel, credential, or expected
two-tenant isolation observation produces a signed failure, not a partial green
receipt.
