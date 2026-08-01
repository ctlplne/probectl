// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"context"
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
	directory := filepath.Clean(*outputDir)
	info, err := os.Lstat(directory)
	if err != nil {
		fmt.Fprintln(stderr, "audit seal-private-key: inspect output directory: "+err.Error())
		return 2
	}
	if !filepath.IsAbs(directory) ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintln(
			stderr,
			"audit seal-private-key: output directory must be absolute, real, and owner-only",
		)
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
