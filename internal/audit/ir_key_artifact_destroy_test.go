// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func TestIRKeyDestroyLocalArtifactInventoryDestroyAndRetry(t *testing.T) {
	t.Parallel()

	destroyer, publicDirectory, privateDirectory := newIRArtifactDestroyer(t)
	tenantA := "11111111-1111-4111-8111-111111111111"
	tenantB := "22222222-2222-4222-8222-222222222222"
	keyA := "rsa-oaep-sha256:key-a"
	keyZ := "rsa-oaep-sha256:key-z"

	publicA := filepath.Join(publicDirectory, tenantA+".pem")
	publicB := filepath.Join(publicDirectory, tenantB+".pem")
	legacyA := filepath.Join(privateDirectory, tenantA+".pem.enc")
	versionA, err := IRPrivateKeyArtifactFilename(tenantA, keyA)
	if err != nil {
		t.Fatal(err)
	}
	versionZ, err := IRPrivateKeyArtifactFilename(tenantA, keyZ)
	if err != nil {
		t.Fatal(err)
	}
	versionB, err := IRPrivateKeyArtifactFilename(tenantB, "tenant-b-key")
	if err != nil {
		t.Fatal(err)
	}
	writeIRArtifactTestFile(t, publicA, []byte("tenant-a-public"), 0o644)
	writeIRArtifactTestFile(t, publicB, []byte("tenant-b-public"), 0o644)
	writeIRArtifactTestFile(t, legacyA, []byte("tenant-a-legacy-ciphertext"), 0o600)
	writeIRArtifactTestFile(
		t,
		filepath.Join(privateDirectory, versionA),
		[]byte("tenant-a-version-a-ciphertext"),
		0o600,
	)
	writeIRArtifactTestFile(
		t,
		filepath.Join(privateDirectory, versionZ),
		[]byte("tenant-a-version-z-ciphertext"),
		0o600,
	)
	privateB := filepath.Join(privateDirectory, versionB)
	writeIRArtifactTestFile(t, privateB, []byte("tenant-b-ciphertext"), 0o600)
	unrelated := filepath.Join(privateDirectory, "operator-readme.txt")
	writeIRArtifactTestFile(t, unrelated, []byte("keep"), 0o600)

	manifest, err := destroyer.Inventory(
		context.Background(),
		tenantA,
		[]string{keyZ, keyA, keyZ},
	)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if want := []string{keyA, keyZ}; !reflect.DeepEqual(manifest.KeyIDs, want) {
		t.Fatalf("canonical key ids = %#v, want %#v", manifest.KeyIDs, want)
	}
	if got, want := len(manifest.Artifacts), 4; got != want {
		t.Fatalf("artifact count = %d, want %d", got, want)
	}
	for _, artifact := range manifest.Artifacts {
		if strings.Contains(artifact.ID, publicDirectory) ||
			strings.Contains(artifact.ID, privateDirectory) ||
			filepath.IsAbs(artifact.ID) {
			t.Fatalf("artifact id exposes a filesystem path: %q", artifact.ID)
		}
	}
	again, err := destroyer.Inventory(
		context.Background(),
		tenantA,
		[]string{keyA, keyZ},
	)
	if err != nil {
		t.Fatalf("second inventory: %v", err)
	}
	if !reflect.DeepEqual(manifest, again) {
		t.Fatalf("inventory is not deterministic:\nfirst=%#v\nagain=%#v", manifest, again)
	}
	if err := destroyer.VerifyDestroyed(context.Background(), manifest); err == nil {
		t.Fatal("VerifyDestroyed succeeded while artifacts remained")
	}

	manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := destroyer.Destroy(context.Background(), manifest)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if receipt.ManifestHash != manifestHash {
		t.Fatalf("receipt manifest hash = %q, want %q", receipt.ManifestHash, manifestHash)
	}
	if receipt.Destroyed != len(manifest.Artifacts) {
		t.Fatalf(
			"receipt destroyed = %d, want planned count %d",
			receipt.Destroyed,
			len(manifest.Artifacts),
		)
	}
	for _, path := range []string{
		publicA,
		legacyA,
		filepath.Join(privateDirectory, versionA),
		filepath.Join(privateDirectory, versionZ),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("destroyed artifact %q still exists or cannot be checked: %v", path, err)
		}
	}
	for _, path := range []string{publicB, privateB, unrelated} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unrelated artifact %q was changed: %v", path, err)
		}
	}
	if err := destroyer.VerifyDestroyed(context.Background(), manifest); err != nil {
		t.Fatalf("verify destroyed: %v", err)
	}

	retryReceipt, err := destroyer.Destroy(context.Background(), manifest)
	if err != nil {
		t.Fatalf("idempotent destroy retry: %v", err)
	}
	if !reflect.DeepEqual(retryReceipt, receipt) {
		t.Fatalf("retry receipt = %#v, want %#v", retryReceipt, receipt)
	}
}

func TestLocalIRKeyArtifactDestroyerInventoryIsPagedBoundedAndCancelable(
	t *testing.T,
) {
	t.Parallel()

	page := make([]os.DirEntry, irArtifactInventoryPageSize)
	for index := range page {
		page[index] = irArtifactTestDirEntry("unrelated")
	}

	t.Run("exact aggregate ceiling", func(t *testing.T) {
		t.Parallel()

		remaining := maxIRArtifactInventoryEntries
		requests := make([]int, 0)
		entries, err := readBoundedIRPrivateDirectory(
			context.Background(),
			func(size int) ([]os.DirEntry, error) {
				requests = append(requests, size)
				if size <= 0 {
					size = len(page)
				}
				if remaining == 0 {
					return nil, io.EOF
				}
				count := min(size, remaining)
				remaining -= count
				return page[:count], nil
			},
		)
		if err != nil {
			t.Fatalf("exact-ceiling scan: %v", err)
		}
		if len(entries) != maxIRArtifactInventoryEntries {
			t.Fatalf(
				"exact-ceiling visits = %d, want %d",
				len(entries),
				maxIRArtifactInventoryEntries,
			)
		}
		for _, size := range requests {
			if size != irArtifactInventoryPageSize {
				t.Fatalf(
					"ReadDir request = %d, want fixed page size %d",
					size,
					irArtifactInventoryPageSize,
				)
			}
		}
	})

	t.Run("one past aggregate ceiling", func(t *testing.T) {
		t.Parallel()

		remaining := maxIRArtifactInventoryEntries + 1
		entries, err := readBoundedIRPrivateDirectory(
			context.Background(),
			func(size int) ([]os.DirEntry, error) {
				if size <= 0 {
					size = len(page)
				}
				count := min(size, remaining)
				remaining -= count
				if remaining == 0 {
					return page[:count], io.EOF
				}
				return page[:count], nil
			},
		)
		if err == nil ||
			!strings.Contains(err.Error(), "private-key directory exceeds 65536 entries") {
			t.Fatalf("one-past-ceiling error = %v, want aggregate bound refusal", err)
		}
		if len(entries) != 0 {
			t.Fatalf(
				"one-past-ceiling visits = %d, want zero before overflow refusal",
				len(entries),
			)
		}
	})

	t.Run("cancellation after page read", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		requests := 0
		entries, err := readBoundedIRPrivateDirectory(
			ctx,
			func(size int) ([]os.DirEntry, error) {
				requests++
				cancel()
				if size <= 0 {
					size = len(page)
				}
				return page[:min(size, len(page))], nil
			},
		)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled scan error = %v, want context.Canceled", err)
		}
		if requests != 1 || len(entries) != 0 {
			t.Fatalf(
				"canceled scan requests/visits = %d/%d, want 1/0",
				requests,
				len(entries),
			)
		}
	})

	t.Run("empty page cannot spin", func(t *testing.T) {
		t.Parallel()

		requests := 0
		entries, err := readBoundedIRPrivateDirectory(
			context.Background(),
			func(int) ([]os.DirEntry, error) {
				requests++
				return nil, nil
			},
		)
		if !errors.Is(err, io.ErrNoProgress) {
			t.Fatalf("empty-page error = %v, want io.ErrNoProgress", err)
		}
		if requests != 1 || len(entries) != 0 {
			t.Fatalf(
				"empty-page requests/entries = %d/%d, want 1/0",
				requests,
				len(entries),
			)
		}
	})
}

func TestIRKeyDestroyRejectsUnsafeLocalArtifacts(t *testing.T) {
	t.Parallel()

	tenant := "33333333-3333-4333-8333-333333333333"
	keyID := "rsa-oaep-sha256:unsafe"
	filename, err := IRPrivateKeyArtifactFilename(tenant, keyID)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "wrong private mode",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
		},
		{
			name: "non-regular",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard-linked",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Link(path, path+".alias"); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			destroyer, _, privateDirectory := newIRArtifactDestroyer(t)
			path := filepath.Join(privateDirectory, filename)
			writeIRArtifactTestFile(t, path, []byte("encrypted-private-key"), 0o600)
			test.mutate(t, path)
			if _, err := destroyer.Inventory(
				context.Background(),
				tenant,
				[]string{keyID},
			); err == nil {
				t.Fatal("Inventory accepted an unsafe private artifact")
			}
		})
	}
}

func TestIRKeyDestroyRejectsUnsafeDomainAndUnboundedPlan(t *testing.T) {
	t.Parallel()

	t.Run("writable public directory", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		publicDirectory := filepath.Join(root, "public")
		privateDirectory := filepath.Join(root, "private")
		if err := os.Mkdir(publicDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(publicDirectory, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(privateDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewLocalIRKeyArtifactDestroyer(
			publicDirectory,
			privateDirectory,
		); err == nil {
			t.Fatal("constructor accepted a group/world-writable public key directory")
		}
	})

	t.Run("oversized key id", func(t *testing.T) {
		t.Parallel()

		destroyer, _, _ := newIRArtifactDestroyer(t)
		if _, err := destroyer.Inventory(
			context.Background(),
			"77777777-7777-4777-8777-777777777777",
			[]string{strings.Repeat("k", maxIRArtifactKeyIDBytes+1)},
		); err == nil {
			t.Fatal("Inventory accepted an oversized key id")
		}
	})

	t.Run("too many key ids", func(t *testing.T) {
		t.Parallel()

		destroyer, _, _ := newIRArtifactDestroyer(t)
		keyIDs := make([]string, maxIRArtifactKeyIDs+1)
		for index := range keyIDs {
			keyIDs[index] = "key"
		}
		if _, err := destroyer.Inventory(
			context.Background(),
			"88888888-8888-4888-8888-888888888888",
			keyIDs,
		); err == nil {
			t.Fatal("Inventory accepted too many key ids")
		}
	})
}

func TestIRKeyDestroyFailsClosedAndResumesTombstone(t *testing.T) {
	t.Parallel()

	t.Run("changed live artifact", func(t *testing.T) {
		t.Parallel()

		destroyer, _, privateDirectory := newIRArtifactDestroyer(t)
		tenant := "44444444-4444-4444-8444-444444444444"
		keyID := "rsa-oaep-sha256:changed"
		filename, err := IRPrivateKeyArtifactFilename(tenant, keyID)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(privateDirectory, filename)
		writeIRArtifactTestFile(t, path, []byte("original-ciphertext"), 0o600)
		manifest, err := destroyer.Inventory(
			context.Background(),
			tenant,
			[]string{keyID},
		)
		if err != nil {
			t.Fatal(err)
		}
		writeIRArtifactTestFile(t, path, []byte("replaced-ciphertext"), 0o600)
		if _, err := destroyer.Destroy(context.Background(), manifest); !errors.Is(
			err,
			crypto.ErrKeyArtifactManifestChanged,
		) {
			t.Fatalf("Destroy changed-artifact error = %v", err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("changed live artifact was removed: %v", err)
		}
	})

	t.Run("unexpected version", func(t *testing.T) {
		t.Parallel()

		destroyer, _, privateDirectory := newIRArtifactDestroyer(t)
		tenant := "55555555-5555-4555-8555-555555555555"
		expectedID := "rsa-oaep-sha256:expected"
		extraFilename, err := IRPrivateKeyArtifactFilename(
			tenant,
			"rsa-oaep-sha256:extra",
		)
		if err != nil {
			t.Fatal(err)
		}
		writeIRArtifactTestFile(
			t,
			filepath.Join(privateDirectory, extraFilename),
			[]byte("extra-ciphertext"),
			0o600,
		)
		if _, err := destroyer.Inventory(
			context.Background(),
			tenant,
			[]string{expectedID},
		); !errors.Is(err, crypto.ErrKeyArtifactManifestChanged) {
			t.Fatalf("Inventory unexpected-version error = %v", err)
		}
	})

	t.Run("interrupted overwrite", func(t *testing.T) {
		t.Parallel()

		destroyer, _, privateDirectory := newIRArtifactDestroyer(t)
		tenant := "66666666-6666-4666-8666-666666666666"
		keyID := "rsa-oaep-sha256:retry"
		filename, err := IRPrivateKeyArtifactFilename(tenant, keyID)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(privateDirectory, filename)
		original := []byte("encrypted-private-key-for-interrupted-destroy")
		writeIRArtifactTestFile(t, path, original, 0o600)
		manifest, err := destroyer.Inventory(
			context.Background(),
			tenant,
			[]string{keyID},
		)
		if err != nil {
			t.Fatal(err)
		}
		manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		tombstone := filepath.Join(
			privateDirectory,
			irPrivateDestroyTombstoneName(filename, manifestHash),
		)
		if err := os.Rename(path, tombstone); err != nil {
			t.Fatal(err)
		}
		overwritten := make([]byte, len(original))
		for index := range overwritten {
			overwritten[index] = byte(index + 1)
		}
		writeIRArtifactTestFile(t, tombstone, overwritten, 0o600)

		receipt, err := destroyer.Destroy(context.Background(), manifest)
		if err != nil {
			t.Fatalf("resume interrupted destroy: %v", err)
		}
		if receipt.Destroyed != len(manifest.Artifacts) {
			t.Fatalf(
				"resumed receipt destroyed = %d, want %d",
				receipt.Destroyed,
				len(manifest.Artifacts),
			)
		}
		if _, err := os.Lstat(tombstone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("in-progress tombstone remains: %v", err)
		}
	})
}

func TestIRKeyDestroyRejectsKeyDomainPathSubstitution(t *testing.T) {
	t.Parallel()

	destroyer, publicDirectory, privateDirectory := newIRArtifactDestroyer(t)
	tenant := "99999999-9999-4999-8999-999999999999"
	keyID := "rsa-oaep-sha256:anchored"
	privateName, err := IRPrivateKeyArtifactFilename(tenant, keyID)
	if err != nil {
		t.Fatal(err)
	}
	writeIRArtifactTestFile(
		t,
		filepath.Join(publicDirectory, tenant+".pem"),
		[]byte("anchored-public"),
		0o644,
	)
	writeIRArtifactTestFile(
		t,
		filepath.Join(privateDirectory, privateName),
		[]byte("anchored-private-ciphertext"),
		0o600,
	)
	manifest, err := destroyer.Inventory(
		context.Background(),
		tenant,
		[]string{keyID},
	)
	if err != nil {
		t.Fatal(err)
	}

	movedPublic := publicDirectory + ".moved"
	movedPrivate := privateDirectory + ".moved"
	if err := os.Rename(publicDirectory, movedPublic); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(privateDirectory, movedPrivate); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := destroyer.Destroy(
		context.Background(),
		manifest,
	); !errors.Is(err, crypto.ErrKeyArtifactManifestChanged) {
		t.Fatalf("path-substituted destroy error = %v", err)
	}
	for _, path := range []string{
		filepath.Join(movedPublic, tenant+".pem"),
		filepath.Join(movedPrivate, privateName),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("path-substituted destroy changed anchored artifact %q: %v", path, err)
		}
	}
	for _, directory := range []string{publicDirectory, privateDirectory} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("replacement directory %q was mutated: %#v", directory, entries)
		}
	}
}

func newIRArtifactDestroyer(
	t *testing.T,
) (*LocalIRKeyArtifactDestroyer, string, string) {
	t.Helper()

	root := t.TempDir()
	publicDirectory := filepath.Join(root, "public")
	privateDirectory := filepath.Join(root, "private")
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	destroyer, err := NewLocalIRKeyArtifactDestroyer(
		publicDirectory,
		privateDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := destroyer.Close(); err != nil {
			t.Errorf("close IR artifact destroyer: %v", err)
		}
	})
	return destroyer, publicDirectory, privateDirectory
}

func writeIRArtifactTestFile(
	t *testing.T,
	path string,
	raw []byte,
	mode os.FileMode,
) {
	t.Helper()

	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

type irArtifactTestDirEntry string

func (e irArtifactTestDirEntry) Name() string             { return string(e) }
func (irArtifactTestDirEntry) IsDir() bool                { return false }
func (irArtifactTestDirEntry) Type() os.FileMode          { return 0 }
func (irArtifactTestDirEntry) Info() (os.FileInfo, error) { return nil, nil }
