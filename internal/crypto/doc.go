// Package crypto is netctl's cryptographic abstraction — the single place that
// imports cryptographic primitives, so a FIPS 140-3 validated module can be
// compiled in later (CLAUDE.md §7 guardrail 3). A CI guard
// (scripts/check_crypto_imports.sh) fails the build if any other package imports
// a crypto primitive.
//
// It provides: the Provider interface + stdlib default (Hash, Random,
// AES-256-GCM Encrypt/Decrypt, HMAC-SHA256 Sign/Verify); envelope encryption
// (Envelope + a pluggable KeyProvider; StaticKeyProvider for dev) for sensitive
// columns; a hardened TLS server config (ConfigureServerTLS) and mTLS configs
// (ServerMTLSConfig/ClientMTLSConfig); a tenant-bound SPIFFE-style agent
// identity; and dev/test CA + certificate generation. The FIPS module (S-EE1),
// SVID issuance, and key rotation/BYOK (S-EE3, F56) build on these.
//
// crypto/tls and crypto/x509 are allowed outside this package (transport / PKI,
// FIPS-swapped at build time); the TLS security policy still lives here.
package crypto
