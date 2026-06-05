package crypto

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 interop: HMAC-SHA-1 (not bare SHA-1) — FIPS-permitted in HMAC mode.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP (RFC 6238, S-T1): the provider plane's mandatory operator MFA.
// HMAC-SHA-1 with a 30-second step and 6 digits is used for authenticator-app
// interoperability (the de-facto otpauth defaults; several major apps ignore
// the algorithm parameter, so SHA-256 would lock operators out). HMAC-SHA-1
// remains FIPS-approved in HMAC mode; this is not a bare SHA-1 digest.

const (
	totpStep   = 30 * time.Second
	totpDigits = 1_000_000 // 6 digits
	totpSecret = 20        // RFC 4226 §4 recommended secret length
)

// GenerateTOTPSecret returns a new shared secret as base32 (the form
// authenticator apps accept) plus the raw bytes for sealed storage.
func GenerateTOTPSecret() (b32 string, raw []byte, err error) {
	raw, err = Random(totpSecret)
	if err != nil {
		return "", nil, err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), raw, nil
}

// TOTPURI renders the otpauth:// provisioning URI an authenticator app scans.
func TOTPURI(issuer, account, b32Secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
		url.PathEscape(issuer), url.PathEscape(account), b32Secret, url.QueryEscape(issuer))
}

// totpCode computes the RFC 6238 code for one time-step counter.
func totpCode(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%totpDigits)
}

// VerifyTOTP reports whether code is valid for the secret at time t, accepting
// ±1 step of clock skew. Comparison is constant-time per candidate.
func VerifyTOTP(secret []byte, code string, t time.Time) bool {
	if len(secret) == 0 || len(code) != 6 {
		return false
	}
	counter := uint64(t.Unix()) / uint64(totpStep/time.Second)
	for _, c := range []uint64{counter, counter - 1, counter + 1} {
		if ConstantTimeEqual([]byte(totpCode(secret, c)), []byte(code)) {
			return true
		}
	}
	return false
}

// TOTPNow returns the current code (used by tests and the enrollment check).
func TOTPNow(secret []byte, t time.Time) string {
	return totpCode(secret, uint64(t.Unix())/uint64(totpStep/time.Second))
}
