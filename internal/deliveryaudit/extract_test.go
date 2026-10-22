// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"archive/tar"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	hdr  tar.Header
	body string
}

func tarFile(name, body string) tarEntry {
	return tarEntry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(body))}, body: body}
}

func tarStream(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("write header %q: %v", hdr.Name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("write body %q: %v", hdr.Name, err)
		}
	}
	// Close fails only for the size-cap entry, which declares a body it never
	// writes; its stream then ends after that header, which is all it needs.
	_ = tw.Close()
	return buf.Bytes()
}

// TestExtractTarRefusesEscapesAndLinks (CodeQL #38) pins the containment of
// the immutable source tree the delivery audit lints: an archive entry that
// names a path outside root, or that is a symlink or hard link, is refused
// before anything is written, so a hostile archive cannot plant or link a file
// outside root. A plain directory and file extract, git's pax global header is
// skipped, a repeated name is refused by O_EXCL, and the size cap holds.
func TestExtractTarRefusesEscapesAndLinks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []tarEntry
		wantErr string // "" = the stream extracts
	}{
		{name: "parent escape", entries: []tarEntry{tarFile("../x", "escaped")}, wantErr: "unsafe path"},
		{name: "absolute name", entries: []tarEntry{tarFile("/abs", "escaped")}, wantErr: "unsafe path"},
		{name: "escape through a directory", entries: []tarEntry{tarFile("a/../../x", "escaped")}, wantErr: "unsafe path"},
		{name: "archive root", entries: []tarEntry{{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "./", Mode: 0o755}}}, wantErr: "unsafe path"},
		{name: "symlink", entries: []tarEntry{{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "../x"}}}, wantErr: "unsupported Git archive entry type"},
		{name: "hard link", entries: []tarEntry{tarFile("victim", "kept"), {hdr: tar.Header{Typeflag: tar.TypeLink, Name: "hard", Linkname: "../x"}}}, wantErr: "unsupported Git archive entry type"},
		{name: "repeated name", entries: []tarEntry{tarFile("dup", "first"), tarFile("dup", "second")}, wantErr: "file exists"},
		{name: "over the size cap", entries: []tarEntry{{hdr: tar.Header{Typeflag: tar.TypeReg, Name: "huge", Mode: 0o644, Size: 2<<30 + 1}}}, wantErr: "exceeds bounded size"},
		{name: "directory and file", entries: []tarEntry{
			{hdr: tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "f6e3bff"}}},
			{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "dir/", Mode: 0o755}},
			tarFile("dir/file.txt", "payload"),
			tarFile("top.txt", "top"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "root")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			err := extractTar(bytes.NewReader(tarStream(t, tc.entries)), root)

			// Whatever the outcome, nothing may appear beside root.
			if siblings, rerr := os.ReadDir(parent); rerr != nil || len(siblings) != 1 || siblings[0].Name() != "root" {
				t.Fatalf("extraction wrote outside root: %v %v", siblings, rerr)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("extractTar = %v, want an error containing %q", err, tc.wantErr)
				}
				for _, name := range []string{"link", "hard"} {
					if _, lerr := os.Lstat(filepath.Join(root, name)); !errors.Is(lerr, fs.ErrNotExist) {
						t.Fatalf("link entry %q was materialized (%v)", name, lerr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("extractTar: %v", err)
			}
			for name, want := range map[string]string{"dir/file.txt": "payload", "top.txt": "top"} {
				got, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
				if rerr != nil || string(got) != want {
					t.Fatalf("%s = %q (%v), want %q", name, got, rerr, want)
				}
			}
			if info, serr := os.Stat(filepath.Join(root, "dir")); serr != nil || !info.IsDir() {
				t.Fatalf("dir/ not extracted as a directory: %v", serr)
			}
			if _, lerr := os.Lstat(filepath.Join(root, "pax_global_header")); !errors.Is(lerr, fs.ErrNotExist) {
				t.Fatalf("pax global header was materialized (%v)", lerr)
			}
		})
	}
}
