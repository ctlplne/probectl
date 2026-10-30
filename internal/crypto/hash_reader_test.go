// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

type hashOnlyProvider struct{ Provider }
type failingDigestReader struct{ err error }

func (r failingDigestReader) Read([]byte) (int, error) { return 0, r.err }

func TestHashReaderVectorsAndFailureNeverReturnPartialDigest(t *testing.T) {
	for _, data := range []string{"", "abc", strings.Repeat("probectl", 100000)} {
		digest, err := HashReader(strings.NewReader(data))
		if err != nil || !bytes.Equal(digest, Hash([]byte(data))) {
			t.Fatalf("stream differs from SHA-256: %v", err)
		}
		if data == "abc" && hex.EncodeToString(digest) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Fatal("SHA-256 known-answer mismatch")
		}
	}
	fault := errors.New("injected digest read failure")
	if digest, err := HashReader(io.MultiReader(strings.NewReader("prefix"), failingDigestReader{fault})); !errors.Is(err, fault) || digest != nil {
		t.Fatalf("partial hash returned: %x %v", digest, err)
	}
}

func TestHashReaderRespectsConfiguredProvider(t *testing.T) {
	previous := Default
	Default = hashOnlyProvider{previous}
	t.Cleanup(func() { Default = previous })
	if digest, err := HashReader(strings.NewReader("secret")); !errors.Is(err, ErrStreamingHashUnavailable) || digest != nil {
		t.Fatal("streaming silently bypassed configured provider")
	}
}
