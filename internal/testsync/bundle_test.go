// SPDX-License-Identifier: LicenseRef-probectl-TBD

package testsync

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// ARCH-001: a bundle signed by the control plane's key verifies against the
// matching build-baked public key; a tampered bundle, a wrong key, and a
// replayed older epoch are all REFUSED (fail closed — the agent keeps its last
// verified set rather than apply an unsigned/forged/stale one).
func TestSignedBundleRoundTripAndRejections(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{TenantID: "t-a", Epoch: 100, Tests: []Test{
		{ID: "x", Type: "icmp", Target: "10.0.0.1", IntervalSeconds: 30, TimeoutSeconds: 5},
	}}
	signed, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Valid: verifies, epoch newer than current.
	got, err := Verify(signed, pub, 50)
	if err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if got.TenantID != "t-a" || len(got.Tests) != 1 || got.Tests[0].Target != "10.0.0.1" {
		t.Fatalf("bundle content wrong: %+v", got)
	}

	// Replay/rollback: same or older epoch is refused even though signed.
	if _, err := Verify(signed, pub, 100); err == nil {
		t.Fatal("a non-newer epoch must be refused (rollback/replay)")
	}

	// Tamper: flip a byte in the signed blob → signature fails.
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)/2] ^= 0xff
	if _, err := Verify(tampered, pub, 50); err == nil {
		t.Fatal("tampered bundle must fail verification")
	}

	// Wrong key: a different public key must not verify.
	_, otherPub, _ := crypto.GenerateEd25519KeyPEM()
	if _, err := Verify(signed, otherPub, 50); err != ErrBadSignature {
		t.Fatalf("wrong key: err = %v, want ErrBadSignature", err)
	}
}
