package crypto

import (
	"crypto/fips140"
	"encoding/hex"
	"testing"
)

// TestPowerOnSelfTest is the named POST test: the power-on self-test passes in
// this build. (In the FIPS artifact this additionally asserts the validated
// module is active; in the standard build it runs the same KATs without that
// requirement.)
func TestPowerOnSelfTest(t *testing.T) {
	if err := PowerOnSelfTest(); err != nil {
		t.Fatalf("power-on self-test failed: %v", err)
	}
}

// TestTransparentSwap is the named transparency test: the S3 interface
// produces identical, standardized outputs regardless of whether FIPS is
// compiled in. These golden vectors run in BOTH builds, so if the FIPS module
// ever changed an output the test would fail in that build — proving the swap
// is transparent. (Published vectors: FIPS 180-4 SHA-256, RFC 4231 HMAC,
// SP 800-132 PBKDF2.)
func TestTransparentSwap(t *testing.T) {
	p := Default
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"sha256", p.Hash([]byte("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"hmac-sha256", p.Sign([]byte("Jefe"), []byte("what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{"pbkdf2-sha256", pbkdf2Key([]byte("password"), []byte("salt"), 1, 32), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.got); got != c.want {
			t.Errorf("%s: standardized output changed (FIPS swap not transparent): got %s want %s", c.name, got, c.want)
		}
	}

	// AES-GCM and Ed25519 are nonce/key-randomized, so transparency is proven
	// by cross-consistency: ciphertext from Encrypt decrypts back, and a
	// signature verifies — the formats and semantics are identical in both
	// builds (a FIPS swap that broke them would fail here).
	key := make([]byte, KeySize)
	ct, err := p.Encrypt(key, []byte("swap"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Decrypt(key, ct, nil); err != nil || string(got) != "swap" {
		t.Fatalf("AES-GCM cross-consistency: %q %v", got, err)
	}
	priv, pub, err := GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignEd25519(priv, []byte("swap"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyEd25519(pub, []byte("swap"), sig); err != nil || !ok {
		t.Fatalf("Ed25519 cross-consistency: %v", err)
	}
}

// TestStatusReflectsBuild: Status() reports the build tag and the live module
// state coherently (BuildTag follows the compile tag; ModuleActive follows
// crypto/fips140; a version appears only when active).
func TestStatusReflectsBuild(t *testing.T) {
	st := Status()
	if st.BuildTag != fipsBuildTag {
		t.Errorf("BuildTag = %v, want %v", st.BuildTag, fipsBuildTag)
	}
	if st.ModuleActive != fips140.Enabled() {
		t.Errorf("ModuleActive = %v, want %v", st.ModuleActive, fips140.Enabled())
	}
	if !st.ModuleActive && st.ModuleVersion != "" {
		t.Errorf("ModuleVersion must be empty when the module is inactive: %q", st.ModuleVersion)
	}
	if st.ModuleActive && st.ModuleVersion == "" {
		t.Error("ModuleVersion must be reported when the module is active")
	}
}

// TestPOSTDetectsTamper proves the POST actually exercises the negative paths:
// a deliberately-wrong expectation makes a KAT fail. (Guards against a POST
// that only ever returns nil.)
func TestPOSTDetectsTamper(t *testing.T) {
	orig := katSHA256Expect
	t.Cleanup(func() { katSHA256Expect = orig })
	katSHA256Expect = mustHex("0000000000000000000000000000000000000000000000000000000000000000")
	if err := PowerOnSelfTest(); err == nil {
		t.Fatal("POST must fail when a KAT vector does not match")
	}
}
