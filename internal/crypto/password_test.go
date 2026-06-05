package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	rec, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec, "pbkdf2$sha256$600000$") {
		t.Fatalf("record format: %s", rec)
	}
	if !VerifyPassword(rec, "correct horse battery staple") {
		t.Fatal("correct password must verify")
	}
	if VerifyPassword(rec, "wrong") || VerifyPassword(rec, "") {
		t.Fatal("wrong/empty password must not verify")
	}
	// Two hashes of the same password differ (fresh salt).
	rec2, _ := HashPassword("correct horse battery staple")
	if rec == rec2 {
		t.Fatal("salts must be unique")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	for _, rec := range []string{
		"", "plaintext", "pbkdf2$sha256$abc$x$y",
		"pbkdf2$sha256$600000$!!!$AAAA",
		"pbkdf2$sha256$600000$AAAA$!!!",
		"pbkdf2$md5$600000$AAAA$AAAA",
		"pbkdf2$sha256$99999999999$AAAA$AAAA", // iteration bomb rejected
	} {
		if VerifyPassword(rec, "x") {
			t.Fatalf("malformed record %q must verify false", rec)
		}
	}
}

func TestTOTPRoundTrip(t *testing.T) {
	b32, raw, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 20 || b32 == "" {
		t.Fatalf("secret shape: %d bytes, %q", len(raw), b32)
	}
	now := time.Unix(1_750_000_000, 0)
	code := TOTPNow(raw, now)
	if len(code) != 6 {
		t.Fatalf("code = %q", code)
	}
	if !VerifyTOTP(raw, code, now) {
		t.Fatal("current code must verify")
	}
	// ±1 step of skew is accepted; ±2 is not.
	if !VerifyTOTP(raw, code, now.Add(30*time.Second)) || !VerifyTOTP(raw, code, now.Add(-30*time.Second)) {
		t.Fatal("one step of skew must verify")
	}
	if VerifyTOTP(raw, code, now.Add(90*time.Second)) {
		t.Fatal("three steps away must not verify")
	}
	if VerifyTOTP(raw, "000000", now) && VerifyTOTP(raw, "999999", now) {
		t.Fatal("two fixed guesses both verifying is implausible")
	}
	if VerifyTOTP(nil, code, now) || VerifyTOTP(raw, "12345", now) {
		t.Fatal("empty secret / short code must not verify")
	}
}

// TestTOTPRFC6238Vector pins the implementation to the RFC 6238 Appendix B
// SHA-1 test vectors (secret "12345678901234567890").
func TestTOTPRFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{
		59:          "287082", // RFC value 94287082, truncated to 6 digits
		1111111109:  "081804",
		1234567890:  "005924",
		20000000000: "353130",
	}
	for unix, want := range cases {
		if got := TOTPNow(secret, time.Unix(unix, 0)); got != want {
			t.Fatalf("TOTP(%d) = %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("probectl provider", "ops@msp.example", "ABC234")
	for _, want := range []string{"otpauth://totp/", "secret=ABC234", "issuer=probectl+provider"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}
