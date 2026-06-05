package license

import "encoding/base64"

// builtinPubKeysB64 carries the build-time-baked trusted license public keys
// (PEM, base64-encoded; comma-separated to support rotation), injected at
// release time via:
//
//	go build -ldflags "-X github.com/imfeelingtheagi/probectl/internal/license.builtinPubKeysB64=$(base64 -w0 license-signing.pub)"
//
// A development build bakes NO keys: any configured license file then fails
// verification loudly ("no trusted license keys are baked into this build"),
// and an unconfigured build is simply Community. The trust anchor is a
// build-time decision, never an environment variable — an operator-supplied
// public key would let anyone sign their own licenses.
var builtinPubKeysB64 string

// TrustedKeys returns the baked-in trusted public keys (PEM), decoding the
// ldflags payload. Invalid entries are skipped (a malformed bake surfaces as
// verification failure, which is loud).
func TrustedKeys() [][]byte {
	if builtinPubKeysB64 == "" {
		return nil
	}
	var out [][]byte
	start := 0
	s := builtinPubKeysB64
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if pem, err := base64.StdEncoding.DecodeString(s[start:i]); err == nil && len(pem) > 0 {
				out = append(out, pem)
			}
			start = i + 1
		}
	}
	return out
}
