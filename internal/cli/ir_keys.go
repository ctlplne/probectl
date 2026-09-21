// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"context"
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

const (
	maxCLIIRPrivateKeyBytes = 64 << 10
	maxCLIIRUnlockKeyBytes  = 1024
)

func cmdSealIRPrivateKey(
	args []string,
	stdout, stderr io.Writer,
) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "audit seal-private-key: missing <tenant-id>")
		return 2
	}
	tenantID := args[0]
	fs := flag.NewFlagSet("audit seal-private-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	privateKeyFile := fs.String(
		"private-key-file",
		"",
		"owner-only RSA private PEM file",
	)
	unlockKeyFile := fs.String(
		"unlock-key-file",
		"",
		"owner-only file containing the base64 32-byte artifact KEK",
	)
	unlockKeyID := fs.String(
		"unlock-key-id",
		"",
		"non-secret artifact KEK identity",
	)
	outputDir := fs.String(
		"output-dir",
		"",
		"owner-only absolute directory for the encrypted artifact",
	)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(
			stderr,
			"audit seal-private-key: unexpected args: %s\n",
			strings.Join(fs.Args(), " "),
		)
		return 2
	}
	for name, value := range map[string]string{
		"--private-key-file": *privateKeyFile,
		"--unlock-key-file":  *unlockKeyFile,
		"--unlock-key-id":    *unlockKeyID,
		"--output-dir":       *outputDir,
	} {
		if strings.TrimSpace(value) == "" {
			fmt.Fprintf(stderr, "audit seal-private-key: %s is required\n", name)
			return 2
		}
	}
	directory, err := ownerOnlyCLIDir(*outputDir)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: output directory "+err.Error())
		return 2
	}
	privatePEM, err := readOwnerOnlyCLIFile(
		*privateKeyFile,
		maxCLIIRPrivateKeyBytes,
	)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: read private key: "+err.Error())
		return 2
	}
	defer crypto.Zeroize(privatePEM)
	unlockRaw, err := readOwnerOnlyCLIFile(
		*unlockKeyFile,
		maxCLIIRUnlockKeyBytes,
	)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: read unlock key: "+err.Error())
		return 2
	}
	defer crypto.Zeroize(unlockRaw)
	unlock, err := crypto.NewStaticKeyProviderFromBase64(
		strings.TrimSpace(*unlockKeyID),
		strings.TrimSpace(string(unlockRaw)),
	)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: invalid unlock key")
		return 2
	}
	artifact, keyID, err := audit.SealIRPrivateKeyArtifact(
		context.Background(),
		unlock,
		tenantID,
		privatePEM,
	)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: "+err.Error())
		return 1
	}
	defer crypto.Zeroize(artifact)
	filename, err := audit.IRPrivateKeyArtifactFilename(tenantID, keyID)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: "+err.Error())
		return 1
	}
	path := filepath.Join(directory, filename)
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: create artifact: "+err.Error())
		return 1
	}
	writeErr := writeAndSyncIRArtifact(file, artifact)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		fmt.Fprintln(stderr, "audit seal-private-key: persist artifact failed")
		return 1
	}
	fmt.Fprintf(stdout, "path=%s key_id=%s\n", path, keyID)
	return 0
}

func writeAndSyncIRArtifact(file *os.File, artifact []byte) error {
	if _, err := file.Write(artifact); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	return file.Sync()
}

// ownerOnlyCLIDir cleans path and requires it to be an absolute, real
// (non-symlink) directory that denies group/other access — the posture every
// private IR artifact location shares.
func ownerOnlyCLIDir(path string) (string, error) {
	directory := filepath.Clean(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect: %w", err)
	}
	if !filepath.IsAbs(directory) ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("must be absolute, real, and owner-only")
	}
	return directory, nil
}

// cmdIRKeygen (DPR-036) mints one tenant's IR wrapping-key pair offline:
//
//	probectl audit ir-keygen <tenant-id> --public-key-dir DIR --private-key-file FILE
//
// The public half is written as DIR/<tenant-id>.pem — the exact keyring entry
// `probectl-control ir-key-install` places under PROBECTL_IR_PUBLIC_KEY_DIR,
// which is what lets the break-glass transaction seal attribution for that
// tenant. The private half is written owner-only to FILE as the escrow input
// for `audit seal-private-key`; it never touches the control plane. Nothing
// here talks to the network or the API.
func cmdIRKeygen(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "audit ir-keygen: missing <tenant-id>")
		return 2
	}
	tenantID := args[0]
	fs := flag.NewFlagSet("audit ir-keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	publicDir := fs.String(
		"public-key-dir",
		"",
		"absolute directory that receives <tenant-id>.pem (install it with probectl-control ir-key-install)",
	)
	privateFile := fs.String(
		"private-key-file",
		"",
		"owner-only absolute path for the new RSA private key PEM (escrow input for audit seal-private-key)",
	)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(stderr, "audit ir-keygen: unexpected args: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	for name, value := range map[string]string{
		"--public-key-dir":   *publicDir,
		"--private-key-file": *privateFile,
	} {
		if strings.TrimSpace(value) == "" {
			fmt.Fprintf(stderr, "audit ir-keygen: %s is required\n", name)
			return 2
		}
	}
	filename, err := audit.IRPublicKeyFilename(tenantID)
	if err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: <tenant-id> must be the tenant's canonical UUID")
		return 2
	}
	directory := filepath.Clean(*publicDir)
	info, err := os.Lstat(directory)
	if err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: inspect --public-key-dir: "+err.Error())
		return 2
	}
	if !filepath.IsAbs(directory) || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		fmt.Fprintln(stderr, "audit ir-keygen: --public-key-dir must be an absolute, real directory")
		return 2
	}
	privatePath := filepath.Clean(*privateFile)
	if !filepath.IsAbs(privatePath) {
		fmt.Fprintln(stderr, "audit ir-keygen: --private-key-file must be an absolute path")
		return 2
	}
	if _, err := ownerOnlyCLIDir(filepath.Dir(privatePath)); err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: --private-key-file directory "+err.Error())
		return 2
	}
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: generate key pair: "+err.Error())
		return 1
	}
	defer crypto.Zeroize(privatePEM)
	writer, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: verify generated public key: "+err.Error())
		return 1
	}
	if err := writeExclusiveCLIFile(privatePath, privatePEM, 0o600); err != nil {
		fmt.Fprintln(stderr, "audit ir-keygen: write private key: "+err.Error())
		return 1
	}
	publicPath := filepath.Join(directory, filename)
	if err := writeExclusiveCLIFile(publicPath, publicPEM, 0o644); err != nil {
		_ = os.Remove(privatePath)
		fmt.Fprintln(stderr, "audit ir-keygen: write public key: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "public=%s private=%s key_id=%s\n", publicPath, privatePath, writer.KeyID())
	fmt.Fprintf(
		stderr,
		"next: install the public key on the control plane with `probectl-control ir-key-install %s < %s`, "+
			"then seal the private key offline with `probectl audit seal-private-key %s --private-key-file %s ...` (docs/audit.md)\n",
		tenantID, publicPath, tenantID, privatePath,
	)
	return 0
}

// writeExclusiveCLIFile creates path with mode (refusing to overwrite), writes
// body, and fsyncs it; a failed write leaves no partial file behind.
func writeExclusiveCLIFile(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
