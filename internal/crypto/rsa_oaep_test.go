// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
