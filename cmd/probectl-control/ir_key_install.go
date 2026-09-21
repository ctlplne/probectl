// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
)

// irKeyInstall (DPR-036) installs one tenant's IR public key into the
// operator-owned keyring the break-glass sealer reads
// (PROBECTL_IR_PUBLIC_KEY_DIR/<tenant-uuid>.pem). It reads the PEM from stdin
// so it works through `kubectl exec -i` / `docker compose exec -T` against
// the shell-less distroless image, validates the key exactly as the runtime
// would (RSA-OAEP wrap provider), writes it atomically, and refuses to
// overwrite an existing key unless -replace (rotation) is given.
//
//	probectl-control ir-key-install <tenant-id> [-dir DIR] [-replace] < <tenant-id>.pem
func irKeyInstall(args []string, stdin io.Reader, getenv func(string) string, stdout io.Writer) error {
	fs := flag.NewFlagSet("ir-key-install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "keyring directory (default PROBECTL_IR_PUBLIC_KEY_DIR)")
	replace := fs.Bool("replace", false, "replace an existing key for this tenant (rotation)")
	usage := errors.New("usage: probectl-control ir-key-install <tenant-id> [-dir DIR] [-replace] < <tenant-id>.pem")
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return usage
	}
	tenantID := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return usage
	}
	if fs.NArg() != 0 {
		return usage
	}
	filename, err := audit.IRPublicKeyFilename(tenantID)
	if err != nil {
		return fmt.Errorf("ir-key-install: %w", err)
	}
	directory := strings.TrimSpace(*dir)
	if directory == "" {
		directory = strings.TrimSpace(getenv("PROBECTL_IR_PUBLIC_KEY_DIR"))
	}
	if directory == "" {
		return errors.New("ir-key-install: no keyring directory: pass -dir or set PROBECTL_IR_PUBLIC_KEY_DIR")
	}
	directory = filepath.Clean(directory)
	if !filepath.IsAbs(directory) {
		return fmt.Errorf("ir-key-install: keyring directory must be absolute, got %q", directory)
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, audit.MaxIRPublicKeyBytes+1))
	if err != nil {
		return fmt.Errorf("ir-key-install: read public key from stdin: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("ir-key-install: stdin is empty; pipe the tenant's public key PEM (probectl audit ir-keygen)")
	}
	if len(raw) > audit.MaxIRPublicKeyBytes {
		return fmt.Errorf("ir-key-install: public key exceeds %d bytes", audit.MaxIRPublicKeyBytes)
	}
	provider, err := crypto.NewRSAOAEPWrapProviderPEM(raw)
	if err != nil {
		return fmt.Errorf("ir-key-install: stdin is not a usable IR public key (want the RSA-3072 PUBLIC KEY PEM from `probectl audit ir-keygen`): %w", err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("ir-key-install: create keyring directory: %w", err)
	}
	target := filepath.Join(directory, filename)
	previous := ""
	if existing, err := os.ReadFile(target); err == nil {
		if !*replace {
			return fmt.Errorf("ir-key-install: %s already holds a key for tenant %s; pass -replace to rotate it (keep the old private artifact so historical records stay revealable)", target, tenantID)
		}
		if old, err := crypto.NewRSAOAEPWrapProviderPEM(existing); err == nil {
			previous = old.KeyID()
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("ir-key-install: inspect %s: %w", target, err)
	}
	if err := writeIRPublicKeyAtomically(target, raw); err != nil {
		return fmt.Errorf("ir-key-install: %w", err)
	}
	if previous != "" {
		fmt.Fprintf(stdout, "path=%s key_id=%s tenant=%s replaced_key_id=%s\n", target, provider.KeyID(), tenantID, previous)
		return nil
	}
	fmt.Fprintf(stdout, "path=%s key_id=%s tenant=%s\n", target, provider.KeyID(), tenantID)
	return nil
}

// writeIRPublicKeyAtomically stages the PEM next to its final name and renames
// it into place, so a replica that lists the keyring mid-install never sees a
// partial file. Public material is world-readable (0644): the runtime user
// (uid 65532 in the shipped image) must be able to read a key an operator
// installed, and nothing secret is in it.
func writeIRPublicKeyAtomically(target string, raw []byte) error {
	// §7.3: primitives come from internal/crypto so a FIPS module can be
	// compiled in — including the randomness that names a staging file.
	nonce, err := crypto.Random(8)
	if err != nil {
		return fmt.Errorf("stage temp name: %w", err)
	}
	tmp := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".tmp-"+hex.EncodeToString(nonce))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("stage %s: %w", tmp, err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", target, err)
	}
	return nil
}
