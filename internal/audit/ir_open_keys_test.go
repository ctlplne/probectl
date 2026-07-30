// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const (
	irOpenTenantA = "00000000-0000-0000-0000-0000000000a1"
	irOpenTenantB = "00000000-0000-0000-0000-0000000000b2"
)

func TestLocalIRPrivateKeyResolverOpensEncryptedTenantArtifact(t *testing.T) {
	ctx := context.Background()
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zeroize(privatePEM)
	unlock, err := crypto.NewStaticKeyProvider(
		"ir-artifact-unlock",
		bytes.Repeat([]byte{0x42}, crypto.KeySize),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifact, keyID, err := SealIRPrivateKeyArtifact(
		ctx,
		unlock,
		irOpenTenantA,
		privatePEM,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zeroize(artifact)
	if bytes.Contains(artifact, []byte("PRIVATE KEY")) ||
		bytes.Contains(artifact, privatePEM) {
		t.Fatal("encrypted IR artifact contains plaintext private-key material")
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	filename, err := IRPrivateKeyArtifactFilename(irOpenTenantA, keyID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, filename)
	if err := os.WriteFile(path, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewLocalIRPrivateKeyResolver(directory, unlock)
	if err != nil {
		t.Fatal(err)
	}
	opener, cleanup, err := resolver.OpenProviderForTenant(
		ctx,
		irOpenTenantA,
		keyID,
	)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	const plaintext = "bounded-investigation-canary"
	sealed, err := crypto.NewEnvelope(writer).Seal(
		ctx,
		[]byte(plaintext),
		[]byte("tenant-bound-test"),
	)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	opened, err := crypto.NewEnvelope(opener).Open(
		ctx,
		sealed,
		[]byte("tenant-bound-test"),
	)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if string(opened) != plaintext {
		crypto.Zeroize(opened)
		cleanup()
		t.Fatalf("opened plaintext = %q", opened)
	}
	crypto.Zeroize(opened)
	cleanup()
	if _, err := opener.UnwrapKey(
		ctx,
		sealed.KeyID,
		sealed.WrappedDEK,
	); !errors.Is(err, crypto.ErrUnwrapUnavailable) {
		t.Fatalf("cleaned-up opener remained usable: %v", err)
	}
}

func TestLocalIRPrivateKeyArtifactRejectsTenantTransplant(t *testing.T) {
	ctx := context.Background()
	privatePEM, _, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zeroize(privatePEM)
	unlock, err := crypto.NewStaticKeyProvider(
		"ir-artifact-unlock",
		bytes.Repeat([]byte{0x24}, crypto.KeySize),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifact, keyID, err := SealIRPrivateKeyArtifact(
		ctx,
		unlock,
		irOpenTenantA,
		privatePEM,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Zeroize(artifact)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(
			directory,
			mustIRPrivateKeyArtifactFilename(t, irOpenTenantB, keyID),
		),
		artifact,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewLocalIRPrivateKeyResolver(directory, unlock)
	if err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := resolver.OpenProviderForTenant(
		ctx,
		irOpenTenantB,
		keyID,
	); err == nil {
		cleanup()
		t.Fatal("tenant-B AAD opened tenant-A private-key artifact")
	}
}

func TestLocalIRPrivateKeyResolverRetainsHistoricalKeyVersions(t *testing.T) {
	ctx := context.Background()
	unlock, err := crypto.NewStaticKeyProvider(
		"ir-artifact-unlock",
		bytes.Repeat([]byte{0x63}, crypto.KeySize),
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	var keyIDs []string
	for range 2 {
		privatePEM, _, err := crypto.GenerateRSAOAEPKeyPEM()
		if err != nil {
			t.Fatal(err)
		}
		artifact, keyID, err := SealIRPrivateKeyArtifact(
			ctx,
			unlock,
			irOpenTenantA,
			privatePEM,
		)
		crypto.Zeroize(privatePEM)
		if err != nil {
			t.Fatal(err)
		}
		filename := mustIRPrivateKeyArtifactFilename(
			t,
			irOpenTenantA,
			keyID,
		)
		if err := os.WriteFile(
			filepath.Join(directory, filename),
			artifact,
			0o600,
		); err != nil {
			crypto.Zeroize(artifact)
			t.Fatal(err)
		}
		crypto.Zeroize(artifact)
		keyIDs = append(keyIDs, keyID)
	}
	resolver, err := NewLocalIRPrivateKeyResolver(directory, unlock)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range keyIDs {
		provider, cleanup, err := resolver.OpenProviderForTenant(
			ctx,
			irOpenTenantA,
			keyID,
		)
		if err != nil {
			t.Fatalf("open retained key %s: %v", keyID, err)
		}
		if provider.KeyID() != keyID {
			cleanup()
			t.Fatalf("opened key ID = %q, want %q", provider.KeyID(), keyID)
		}
		cleanup()
	}
}

func mustIRPrivateKeyArtifactFilename(
	t *testing.T,
	tenantID, keyID string,
) string {
	t.Helper()
	filename, err := IRPrivateKeyArtifactFilename(tenantID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestIRRevealPathHasNoNetworkOrDirectCryptoPrimitiveImports(t *testing.T) {
	for _, path := range []string{"ir_open_keys.go", "ir_reveal.go"} {
		file, err := parser.ParseFile(
			token.NewFileSet(),
			path,
			nil,
			parser.ImportsOnly,
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if importPath == "net" || strings.HasPrefix(importPath, "net/") {
				t.Fatalf("%s imports network package %q", path, importPath)
			}
			if importPath == "crypto" || strings.HasPrefix(importPath, "crypto/") {
				t.Fatalf("%s bypasses internal/crypto with %q", path, importPath)
			}
		}
	}
}
