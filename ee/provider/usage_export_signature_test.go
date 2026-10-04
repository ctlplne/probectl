// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/ee/billing"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/license"
)

// TestUsageExportIsSigned is the AUD-21 regression: a usage/billing export was
// served as plain CSV/JSON Lines with NO detached signature, so neither the MSP
// nor probectl could prove its origin or completeness. Every export must now
// carry an Ed25519 detached signature over the EXACT bytes, plus the public key
// to verify it — and the signature must FAIL for a tampered body.
func TestUsageExportIsSigned(t *testing.T) {
	f, _, token := meteredFixture(t)

	for _, format := range []string{"csv", "jsonl"} {
		path := "/provider/v1/usage/export?rollup=day&format=" + format
		rec := f.doAuthed(t, token, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s export: %d %s", format, rec.Code, rec.Body.String())
		}
		body := rec.Body.Bytes()
		if len(body) == 0 {
			t.Fatalf("%s export: empty body", format)
		}

		if alg := rec.Header().Get(hdrUsageSigAlg); alg != "ed25519" {
			t.Fatalf("%s export: signature alg = %q, want ed25519", format, alg)
		}
		sig, err := base64.StdEncoding.DecodeString(rec.Header().Get(hdrUsageSig))
		if err != nil || len(sig) != crypto.Ed25519SignatureSize {
			t.Fatalf("%s export: bad signature header (%d bytes, err=%v)", format, len(sig), err)
		}
		pubPEM, err := base64.StdEncoding.DecodeString(rec.Header().Get(hdrUsageSigKey))
		if err != nil || len(pubPEM) == 0 {
			t.Fatalf("%s export: bad signing-key header: %v", format, err)
		}
		if fp := rec.Header().Get(hdrUsageSigFingerprint); fp != "sha256:"+hexFingerprint(pubPEM) {
			t.Fatalf("%s export: fingerprint header %q does not match the key", format, fp)
		}

		// The signature verifies over the EXACT exported bytes.
		ok, err := crypto.VerifyEd25519(pubPEM, body, sig)
		if err != nil {
			t.Fatalf("%s export: verify: %v", format, err)
		}
		if !ok {
			t.Fatalf("%s export: signature does not verify over the exported bytes", format)
		}

		// Tampering with a single byte breaks verification — the whole point of
		// signing: a verifier can prove the export was altered.
		tampered := append([]byte(nil), body...)
		tampered[len(tampered)/2] ^= 0xFF
		if ok, _ := crypto.VerifyEd25519(pubPEM, tampered, sig); ok {
			t.Fatalf("%s export: signature verified a TAMPERED body", format)
		}
	}
}

// TestUsageExportFailsClosedWithoutSigningKey: an export that cannot be signed
// (no deployment signing key) is refused, never served unsigned (AUD-21 /
// docs/guardrails.md G7-12 — missing signature fails closed).
func TestUsageExportFailsClosedWithoutSigningKey(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	*f.now = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	store := billing.NewMemStore()
	f.h.WithMetering(&Metering{Store: store}) // deliberately NO SignKey
	token := f.bootstrapAndLoginFast(t)
	seedUsage(t, store, *f.now)

	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/usage/export?rollup=day", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unsigned export must fail closed, got %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct == "text/csv; charset=utf-8" {
		t.Fatal("fail-closed export must not stream a CSV body")
	}
	if rec.Header().Get(hdrUsageSig) != "" {
		t.Fatal("fail-closed export must not carry a signature header")
	}
}

// hexFingerprint mirrors the handler's fingerprint computation (sha256 of the
// public-key PEM, hex) so the test asserts the two agree.
func hexFingerprint(pubPEM []byte) string {
	const hexdigits = "0123456789abcdef"
	sum := crypto.Hash(pubPEM)
	out := make([]byte, len(sum)*2)
	for i, b := range sum {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
