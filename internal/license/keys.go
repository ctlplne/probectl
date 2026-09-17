// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package license

import (
	"bytes"
	"embed"
	"encoding/base64"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// builtinPubKeysB64 carries link-time trusted license public keys (PEM,
// base64-encoded; comma-separated to support rotation):
//
//	go build -ldflags "-X github.com/ctlplne/probectl/internal/license.builtinPubKeysB64=$(base64 -w0 license-signing.pub)"
//
// The Makefile (PROBECTL_LICENSE_PUBKEYS_B64), the Docker build-arg
// LICENSE_PUBKEYS_B64, and scripts/build-release-binaries.sh all feed it. It
// exists for vendor pipelines that keep keys out of the tree and for lab
// builds that mint their own throwaway licenses. Production trust normally
// comes from the committed trusted_keys/*.pub files below, so a plain source
// build is licensable with no build-time plumbing at all (DPR-001).
var builtinPubKeysB64 string

// trustedKeyFS embeds everything under trusted_keys/. Only *.pub entries are
// trust anchors; README.md documents the directory. The directory is embedded
// (rather than a *.pub glob) so an intentionally keyless tree still compiles:
// it then runs Community-only and refuses every license file, loudly.
//
//go:embed trusted_keys
var trustedKeyFS embed.FS

// TrustedKeys returns the trust anchors this build verifies license files
// against: the committed trusted_keys/*.pub files (sorted by name) followed
// by any link-time keys. Invalid entries are skipped (a malformed anchor
// surfaces as verification failure, which is loud). The anchor set is a
// build-time decision — never an environment variable, config key, or
// runtime file — because an operator-supplied public key would let anyone
// sign their own licenses.
func TrustedKeys() [][]byte {
	return trustedKeysFrom(trustedKeyFS, builtinPubKeysB64)
}

// TrustAnchorCount reports how many trust anchors the build carries. Zero
// means a keyless build: Community works, every license file is refused.
func TrustAnchorCount() int { return len(TrustedKeys()) }

func trustedKeysFrom(fsys fs.FS, ldflagsB64 string) [][]byte {
	var out [][]byte
	out = append(out, embeddedKeys(fsys)...)
	out = append(out, ldflagsKeys(ldflagsB64)...)
	return out
}

// embeddedKeys collects every *.pub file in fsys that looks like a PEM public
// key, in name order so rotation stays deterministic.
func embeddedKeys(fsys fs.FS) [][]byte {
	if fsys == nil {
		return nil
	}
	var names []string
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path.Base(p), ".pub") {
			names = append(names, p)
		}
		return nil
	})
	sort.Strings(names)
	var out [][]byte
	for _, n := range names {
		pem, err := fs.ReadFile(fsys, n)
		if err != nil {
			continue
		}
		pem = bytes.TrimSpace(pem)
		if len(pem) == 0 || !bytes.Contains(pem, []byte("BEGIN PUBLIC KEY")) {
			continue
		}
		out = append(out, pem)
	}
	return out
}

// ldflagsKeys decodes the comma-separated base64 PEM payload from -X.
func ldflagsKeys(s string) [][]byte {
	if s == "" {
		return nil
	}
	var out [][]byte
	for _, part := range strings.Split(s, ",") {
		if pem, err := base64.StdEncoding.DecodeString(part); err == nil && len(pem) > 0 {
			out = append(out, pem)
		}
	}
	return out
}
