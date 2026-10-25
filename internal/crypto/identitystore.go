// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// On-disk identity units (R3). An agent's certificate and key must change
// together: a rotation that renames the key and then the certificate, with no
// fsync, can be torn by a kill, a power loss or a full disk and leave a valid
// certificate beside a key that is not its own (or an empty one) — an identity
// the TLS stack refuses to load.
//
// InstallIdentity therefore writes every file of the unit into a fresh version
// directory, fsyncs the files and the directory, and only then swaps ONE
// symlink, "current", to it with an atomic rename (and fsyncs the parent). The
// configured paths (cert.pem, key.pem, …) are fixed symlinks to
// current/<name>, so a reader sees the old unit or the new one, never half of
// each. The previous version is kept until the next install.
//
//	<dir>/cert.pem -> current/cert.pem
//	<dir>/key.pem  -> current/key.pem
//	<dir>/current  -> v-<n>
//	<dir>/v-<n>/{cert.pem,key.pem,...}

const identityCurrent = "current"

// identityFault, when set (tests only), is consulted at every step of an
// install; an error stops the install there, as a crash would.
var identityFault func(step string) error

func faultAt(step string) error {
	if identityFault != nil {
		return identityFault(step)
	}
	return nil
}

// VerifyIdentityPair reports whether the certificate and key files load as one
// TLS identity (the key is the certificate's).
func VerifyIdentityPair(certFile, keyFile string) error {
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("crypto: identity pair does not load: %w", err)
	}
	return nil
}

// InstallIdentity atomically and durably replaces the identity unit at
// certFile/keyFile (same directory) with certPEM/keyPEM plus extra files
// (basename → content, e.g. "ca.pem"). The pair must load as one identity or
// nothing is written.
func InstallIdentity(certFile, keyFile string, certPEM, keyPEM []byte, extra map[string][]byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("crypto: refusing to install an identity whose key is not its certificate's: %w", err)
	}
	dir := filepath.Dir(certFile)
	if filepath.Dir(keyFile) != dir || filepath.Base(certFile) == filepath.Base(keyFile) {
		return errors.New("crypto: an identity's certificate and key must be distinct files in one directory")
	}
	files := map[string][]byte{filepath.Base(certFile): certPEM, filepath.Base(keyFile): keyPEM}
	for name, data := range extra {
		if name != filepath.Base(name) || name == identityCurrent || strings.HasPrefix(name, "v-") || files[name] != nil {
			return fmt.Errorf("crypto: invalid identity file name %q", name)
		}
		files[name] = data
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := adoptIdentityLayout(dir, certFile, keyFile, files); err != nil {
		return err
	}
	prev, _ := os.Readlink(filepath.Join(dir, identityCurrent))
	version, err := writeIdentityVersion(dir, files)
	if err != nil {
		return err
	}
	if err := faultAt("before-swap"); err != nil {
		return err
	}
	if err := swapIdentityCurrent(dir, version); err != nil {
		return err
	}
	if err := faultAt("after-swap"); err != nil {
		return err
	}
	if err := linkIdentityNames(dir, files); err != nil {
		return err
	}
	pruneIdentityVersions(dir, version, prev)
	return nil
}

// adoptIdentityLayout converts a directory of plain files (the layout before
// R3) into the versioned one WITHOUT a torn moment: the existing pair is copied
// into a version, "current" points at it, and only then are the plain names
// replaced by symlinks to identical content. An existing pair that does not
// load is not worth preserving; the new install replaces it.
func adoptIdentityLayout(dir, certFile, keyFile string, files map[string][]byte) error {
	if linked(dir, filepath.Base(certFile)) && linked(dir, filepath.Base(keyFile)) {
		return nil
	}
	if VerifyIdentityPair(certFile, keyFile) != nil {
		return nil
	}
	existing := map[string][]byte{}
	for name := range files {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			existing[name] = b
		}
	}
	version, err := writeIdentityVersion(dir, existing)
	if err != nil {
		return err
	}
	if err := swapIdentityCurrent(dir, version); err != nil {
		return err
	}
	if err := faultAt("adopt-before-link"); err != nil {
		return err
	}
	return linkIdentityNames(dir, existing)
}

// linked reports whether dir/name is the fixed symlink into current.
func linked(dir, name string) bool {
	t, err := os.Readlink(filepath.Join(dir, name))
	return err == nil && t == filepath.Join(identityCurrent, name)
}

// writeIdentityVersion writes files into a new version directory, each file
// and the directory fsynced, and returns the version's name.
func writeIdentityVersion(dir string, files map[string][]byte) (string, error) {
	var name, vdir string
	for i := 0; ; i++ {
		name = "v-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(i)
		vdir = filepath.Join(dir, name)
		err := os.Mkdir(vdir, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || i >= 8 {
			return "", err
		}
	}
	names := make([]string, 0, len(files))
	for fname := range files {
		names = append(names, fname)
	}
	sort.Strings(names)
	for _, fname := range names {
		if err := writeSynced(filepath.Join(vdir, fname), files[fname]); err != nil {
			return "", err
		}
		if err := faultAt("wrote:" + fname); err != nil {
			return "", err
		}
	}
	return name, syncDir(vdir)
}

// swapIdentityCurrent points "current" at version with one atomic rename.
func swapIdentityCurrent(dir, version string) error {
	tmp := filepath.Join(dir, "."+identityCurrent+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(version, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, identityCurrent)); err != nil {
		return err
	}
	return syncDir(dir)
}

// linkIdentityNames makes each configured name the fixed symlink into current.
// Each rename replaces a name with a link to the SAME content the previous
// layout held (adoption) or to the unit "current" already names, so no step
// pairs a certificate with another unit's key.
func linkIdentityNames(dir string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if linked(dir, name) {
			continue
		}
		tmp := filepath.Join(dir, "."+name+".link")
		_ = os.Remove(tmp)
		if err := os.Symlink(filepath.Join(identityCurrent, name), tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			return err
		}
		if err := faultAt("linked:" + name); err != nil {
			return err
		}
	}
	return syncDir(dir)
}

// pruneIdentityVersions removes every version but the current and the
// previous one. Best effort: a leftover version is only disk space.
func pruneIdentityVersions(dir, current, prev string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if n := e.Name(); e.IsDir() && strings.HasPrefix(n, "v-") && n != current && n != prev {
			_ = os.RemoveAll(filepath.Join(dir, n))
		}
	}
}

// WriteFileDurable replaces path with data (owner-only): a same-directory
// temporary file, fsynced, renamed over path, and the directory fsynced — a
// crash leaves the old content or the new, never an empty or partial file.
func WriteFileDurable(path string, data []byte) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return serr
	}
	return cerr
}
