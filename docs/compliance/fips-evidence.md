# FIPS 140-3 Evidence

Evidence date: 2026-06-21

## What is validated

probectl's FIPS distribution is a build artifact, not a runtime feature flag. It
is built with `GOFIPS140=v1.0.0` and `-tags probectl_fips` (`make build-fips`),
then verified by `make fips-gate`.

The validated cryptographic module is the **Go Cryptographic Module v1.0.0**:

- Official Go FIPS documentation: <https://go.dev/doc/security/fips140>
- NIST CMVP certificate: <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247>
- NIST CAVP details: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/details?product=19371>

As of this evidence date, the NIST CMVP page lists certificate **#5247** for the
**Go Cryptographic Module**, standard **FIPS 140-3**, status **Active**, overall
level **1**, software module type, initial validation date **2026-04-27**, and
sunset date **2031-04-26**. The Go documentation lists Go Cryptographic Module
**v1.0.0** as available in Go 1.24+ and covered by **CMVP Certificate #5247**
plus **CAVP Certificate A6650**.

## What probectl claims

Accurate claim:

> probectl's FIPS artifact builds against and operates the FIPS 140-3-validated
> Go Cryptographic Module v1.0.0 (CMVP #5247), with a power-on self-test asserting
> the validated module is active.

Non-claim:

> probectl does not have a separate CMVP certificate for the whole product.

That boundary matters. The repo evidence proves the crypto module and build path;
it does not replace customer/acquirer compliance review, deployment hardening, or
any future certification-grade STIG/CIS package.

## Repo controls

- `internal/crypto` is the only place probectl code imports cryptographic
  primitives; `scripts/check_crypto_imports.sh` enforces the seam.
- `internal/crypto/fips.go` marks FIPS distribution artifacts with the
  `probectl_fips` build tag.
- `internal/crypto/selftest.go` runs known-answer tests and, in a FIPS-tagged
  build, fails closed unless `crypto/fips140.Enabled()` is true.
- `Makefile` targets:
  - `make build-fips` builds every `FIPS_BINARIES` entry with
    `GOFIPS140=v1.0.0` and `-tags probectl_fips`: all normal `BINARIES` plus
    security-sensitive local/router tools (`probectl-license`,
    `probectl-bmp-listener`).
  - `make fips-gate` runs the FIPS-tagged self-test with the module active and
    a CI policy test that keeps `FIPS_BINARIES`, POST-bearing entrypoints, and
    the build loop in sync.
