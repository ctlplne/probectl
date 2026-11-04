// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/redactpat"
)

func TestSnapshotCursorEncodingSurvivesMandatoryRedaction(t *testing.T) {
	payload := cursorPayload{Version: 1, ID: "00000000-0000-4000-8000-000000000001",
		Offset: 5000, PageSize: 5000, QueryHash: strings.Repeat("a", 64), Expires: 2000000000000000}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic MAC bytes exercise encoding, not a live signing key or a
	// forged authorization proof. Construct the credential-like shape only
	// at runtime so there is no key-shaped dummy in the source tree.
	shape := strings.Join([]string{"s", "k", "-", strings.Repeat("a", 39), "A"}, "")
	mac, err := base64.RawURLEncoding.DecodeString(shape)
	if err != nil || len(mac) != 32 {
		t.Fatal("invalid synthetic MAC fixture")
	}
	legacy := base64.RawURLEncoding.EncodeToString(body) + "." + shape

	if redactCursorFixture(legacy) == legacy {
		t.Fatal("legacy cursor collision control did not exercise mandatory secret masking")
	}
	cursor := encodeCursor(body, mac)
	if redactCursorFixture(cursor) != cursor {
		t.Fatal("opaque continuation changed under mandatory redaction")
	}
	if len(cursor) > 2048 {
		t.Fatal("redaction-safe cursor exceeded unchanged byte limit")
	}
	got, decoded, signature, err := parseCursor(cursor)
	if err != nil || got != payload || !bytes.Equal(decoded, body) || !bytes.Equal(signature, mac) {
		t.Fatal("cursor encoding changed canonical payload or MAC bytes")
	}
}

func TestSnapshotCursorEncodingKeepsLegacyAndRealMACValidation(t *testing.T) {
	m := manifest{ID: "00000000-0000-4000-8000-000000000001", PageSize: 5000,
		QueryHash: strings.Repeat("b", 64), ExpiresAt: time.UnixMicro(2000000000000000)}
	key := crypto.Hash([]byte("deterministic cursor codec regression"))
	cursor, err := makeCursor(m, key, 5000)
	if err != nil || !strings.HasPrefix(cursor, cursorEncodingPrefix) {
		t.Fatal("new cursor encoding was not emitted")
	}
	payload, body, mac, err := parseCursor(cursor)
	if err != nil || !crypto.Verify(key, body, mac) {
		t.Fatal("new encoding lost the real MAC")
	}
	legacy := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(mac)
	oldPayload, oldBody, oldMAC, err := parseCursor(legacy)
	if err != nil || oldPayload != payload || !bytes.Equal(oldBody, body) || !bytes.Equal(oldMAC, mac) || !crypto.Verify(key, oldBody, oldMAC) {
		t.Fatal("intact legacy continuation changed or failed real MAC validation")
	}
	last := cursor[len(cursor)-1]
	replacement := byte('a')
	if last == replacement {
		replacement = 'b'
	}
	tampered := cursor[:len(cursor)-1] + string(replacement)
	_, changedBody, changedMAC, err := parseCursor(tampered)
	if err != nil || crypto.Verify(key, changedBody, changedMAC) {
		t.Fatal("changed cursor MAC was accepted")
	}
	for _, malformed := range []string{
		"", "fc3~aa~aa", cursorEncodingPrefix + "a~" + encodeCursorPart(mac),
		cursorEncodingPrefix + "qq~" + encodeCursorPart(mac), cursorEncodingPrefix + encodeCursorPart(body) + "~AA",
		cursor + "~", strings.Repeat("a", 2049),
	} {
		if _, _, _, err := parseCursor(malformed); err != ErrCursor {
			t.Fatal("malformed cursor encoding was accepted")
		}
	}
	// Prove a real signed control message collides, using only throwaway
	// keys derived through the crypto door. Inspect only the fixed-size MAC
	// prefix while searching; full parsing/redaction runs once after a match.
	foundSignedCollision := false
	for sequence := 1; sequence <= 1<<22; sequence++ {
		candidateKey := crypto.Hash([]byte(fmt.Sprintf("cursor redaction fixture %d", sequence)))
		signature := crypto.Sign(candidateKey, body)
		signatureText := base64.RawURLEncoding.EncodeToString(signature)
		if !strings.EqualFold(signatureText[:3], "sk-") {
			continue
		}
		if !redactpat.ProviderToken.MatchString(signatureText) {
			t.Fatal("signed collision fixture did not match the actual secret rule")
		}
		legacy := base64.RawURLEncoding.EncodeToString(body) + "." + signatureText
		_, legacyControl, legacyMAC, err := parseCursor(legacy)
		if err != nil || !bytes.Equal(body, legacyControl) || !crypto.Verify(candidateKey, legacyControl, legacyMAC) {
			t.Fatal("signed legacy fixture was not a valid continuation")
		}
		if redactCursorFixture(legacy) == legacy {
			t.Fatal("valid signed legacy fixture bypassed mandatory secret redaction")
		}
		foundSignedCollision = true
		signed, err := makeCursor(m, candidateKey, 5000)
		if err != nil {
			t.Fatal(err)
		}
		_, unchanged, unchangedMAC, err := parseCursor(redactCursorFixture(signed))
		if err != nil || !bytes.Equal(unchanged, body) || !bytes.Equal(unchangedMAC, signature) || !crypto.Verify(candidateKey, unchanged, unchangedMAC) {
			t.Fatal("valid signed continuation changed under built-in redaction")
		}
		break
	}
	if !foundSignedCollision {
		t.Fatal("deterministic actual-MAC legacy collision fixture did not exercise built-in redaction")
	}
	// Canonical JSON and the supported payload version remain mandatory.
	for _, invalid := range [][]byte{append([]byte(" "), body...), bytes.Replace(body, []byte(`"v":1`), []byte(`"v":2`), 1)} {
		if _, _, _, err := parseCursor(encodeCursor(invalid, mac)); err != ErrCursor {
			t.Fatal("noncanonical or unknown cursor payload was accepted")
		}
	}
}

// Same immutable built-in recognition floor as the native result boundary.
func redactCursorFixture(value string) string {
	value = redactpat.MaskSecrets(value, func(redactpat.SecretShape, string) string { return "[secret:fixture]" })
	value = redactpat.MaskPAN(value, func(string) string { return "[pan:fixture]" })
	value = redactpat.SSN.ReplaceAllString(value, "[ssn:fixture]")
	value = redactpat.Email.ReplaceAllString(value, "[email:fixture]")
	value = redactpat.MAC.ReplaceAllString(value, "[mac:fixture]")
	value = redactpat.MaskIPv4(value, func(string) string { return "[ip:fixture]" })
	value = redactpat.MaskIPv6(value, func(string) string { return "[ip:fixture]" })
	return redactpat.Hostname.ReplaceAllString(value, "[host:fixture]")
}
