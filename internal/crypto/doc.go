// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package crypto is probectl's cryptographic abstraction — the single place that
// imports cryptographic primitives, so a FIPS 140-3 validated module can be
// compiled in later (docs/guardrails.md G7-3). A CI guard
// (scripts/check_crypto_imports.sh) fails the build if any other package imports
// a crypto primitive.
//
// It provides: the Provider interface + stdlib default (Hash, Random,
// AES-256-GCM Encrypt/Decrypt, HMAC-SHA256 Sign/Verify); OAuth PKCE S256
// verifier/challenge construction; envelope encryption
// (Envelope + a pluggable KeyProvider; StaticKeyProvider for dev) for sensitive
// columns; a hardened TLS server config (ConfigureServerTLS) and mTLS configs
// (ServerMTLSConfig/ClientMTLSConfig); a tenant-bound SPIFFE-style agent
// identity; and dev/test CA + certificate generation. The FIPS module (S-EE1),
// SVID issuance, and key rotation/BYOK (S-EE3, F56) build on these.
//
// crypto/tls and crypto/x509 are allowed outside this package (transport / PKI,
// FIPS-swapped at build time); the TLS security policy still lives here.
package crypto
