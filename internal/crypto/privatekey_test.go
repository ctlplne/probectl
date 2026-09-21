// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestPrivateKeyToPKCS8PEM(t *testing.T) {
	t.Parallel()

	ca, err := GenerateCA("pkcs8-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, sec1, err := ca.IssueServerCert("kafka", []string{"kafka"}, time.Hour-time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := PrivateKeyToPKCS8PEM(sec1)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatalf("unexpected PKCS#8 PEM block: block=%v trailing=%d", block, len(rest))
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("parsed key type = %T, want *ecdsa.PrivateKey", parsed)
	}
}

func TestPrivateKeyToPKCS8PEMRejectsNonSEC1AndTrailingData(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{
		nil,
		[]byte("not pem"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")}),
		append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not-a-key")}), 'x'),
	} {
		if _, err := PrivateKeyToPKCS8PEM(input); err == nil {
			t.Fatalf("PrivateKeyToPKCS8PEM(%q) succeeded", input)
		}
	}
}
