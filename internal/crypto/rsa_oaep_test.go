// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRSAOAEPWrapOnlyProvider(t *testing.T) {
	privatePEM, publicPEM, err := GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	writer, err := NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	investigator, err := NewRSAOAEPKeyProviderPEM(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if writer.KeyID() != investigator.KeyID() {
		t.Fatalf("public/private key ids differ: %q != %q", writer.KeyID(), investigator.KeyID())
	}

	dek := bytes.Repeat([]byte{0x5a}, KeySize)
	wrapped, err := writer.WrapKey(context.Background(), dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.UnwrapKey(context.Background(), writer.KeyID(), wrapped); !errors.Is(err, ErrUnwrapUnavailable) {
		t.Fatalf("public-only unwrap error = %v, want ErrUnwrapUnavailable", err)
	}
	opened, err := investigator.UnwrapKey(context.Background(), investigator.KeyID(), wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, dek) {
		t.Fatal("unwrapped DEK differs")
	}
	if _, err := investigator.UnwrapKey(context.Background(), "foreign", wrapped); err == nil {
		t.Fatal("foreign key id was accepted")
	}
	investigator.Destroy()
	if _, err := investigator.UnwrapKey(
		context.Background(),
		writer.KeyID(),
		wrapped,
	); !errors.Is(err, ErrUnwrapUnavailable) {
		t.Fatalf("destroyed opener remained usable: %v", err)
	}
}
