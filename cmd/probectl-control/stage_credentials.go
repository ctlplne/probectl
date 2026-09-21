// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxStagedCredentialBytes bounds one staged file; credential files are tiny
// (a JSON username/password, a PEM key) and anything larger is a mistake.
const maxStagedCredentialBytes = 64 * 1024

// stageCredentials copies operator credential files into a private staging
// directory as regular, owner-only (0600) files owned by the running user —
// the shape the strict credential readers (PROBECTL_TSDB_BASIC_AUTH_FILE,
// PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE, broker mTLS keys) insist on. A
// Kubernetes Secret volume cannot provide that shape: its entries are symlinks
// into a ..data/ directory and fsGroup makes them group-readable. Distroless
// images have no shell or cp, so the Helm chart runs this as an init container
// (DPR-030):
//
//	probectl-control stage-credentials <source-dir> <destination-dir>
func stageCredentials(args []string) error {
	if len(args) != 2 || strings.TrimSpace(args[0]) == "" || strings.TrimSpace(args[1]) == "" {
		return fmt.Errorf("usage: probectl-control stage-credentials <source-dir> <destination-dir>")
	}
	return stageCredentialDir(args[0], args[1])
}

func stageCredentialDir(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read credential source directory: %w", err)
	}
	// The destination is usually a volume mount point the pod already owns
	// (root-owned, private to the pod), which a non-root process may write
	// but not chmod; only a directory this helper creates gets 0700. The
	// files themselves are always 0600, which is what the readers check.
	if info, err := os.Stat(destination); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("credential staging destination %s is not a directory", destination)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(destination, 0o700); err != nil {
			return fmt.Errorf("create credential staging directory %s: %w", destination, err)
		}
	} else {
		return fmt.Errorf("inspect credential staging directory %s: %w", destination, err)
	}
	staged := 0
	for _, entry := range entries {
		name := entry.Name()
		// Projected volumes keep their data under ..data/ and ..<timestamp>/
		// with the visible entries symlinked to them; only the visible names
		// are credentials.
		if strings.HasPrefix(name, ".") {
			continue
		}
		src := filepath.Join(source, name)
		info, err := os.Stat(src) // follows the projected symlink on purpose
		if err != nil {
			return fmt.Errorf("inspect credential %s: %w", name, err)
		}
		if info.IsDir() {
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("credential %s is not a regular file", name)
		}
		if info.Size() > maxStagedCredentialBytes {
			return fmt.Errorf("credential %s exceeds %d bytes", name, maxStagedCredentialBytes)
		}
		if err := stageCredentialFile(src, filepath.Join(destination, name)); err != nil {
			return err
		}
		staged++
	}
	if staged == 0 {
		return errors.New("no credential files found to stage")
	}
	return nil
}

// stageCredentialFile lands one file atomically as a regular 0600 file owned
// by the current user; a partial write never replaces a complete credential.
func stageCredentialFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open credential %s: %w", filepath.Base(source), err)
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".probectl-credential-*")
	if err != nil {
		return fmt.Errorf("create staged credential: %w", err)
	}
	tempPath := output.Name()
	closed := false
	defer func() {
		if !closed {
			_ = output.Close()
		}
		_ = os.Remove(tempPath)
	}()
	if _, err := io.Copy(output, io.LimitReader(input, maxStagedCredentialBytes+1)); err != nil {
		return fmt.Errorf("copy credential %s: %w", filepath.Base(source), err)
	}
	if err := output.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict staged credential: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync staged credential: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close staged credential: %w", err)
	}
	closed = true
	if err := os.Rename(tempPath, destination); err != nil {
		return fmt.Errorf("install staged credential at %s: %w", destination, err)
	}
	return nil
}
