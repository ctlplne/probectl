// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/deliveryaudit"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "seal":
		return runSeal(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "certs":
		return runCerts(args[1:], stdout, stderr)
	case "selftest":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "selftest accepts no arguments")
			return 2
		}
		if err := deliveryaudit.SelfTest(); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		writeJSON(stdout, map[string]any{"diagnostic": "fixture-only", "status": "PASS"})
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func runSeal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	draftPath := fs.String("draft", "", "strict unsigned receipt JSON")
	artifactRoot := fs.String("artifacts", "", "root containing every declared artifact")
	sourceRoot := fs.String("source-root", "", "exact archived source tree used to resolve static reachability")
	keyPath := fs.String("key", "", "Ed25519 signing-key PEM (created 0600 if absent)")
	outPath := fs.String("out", "", "new immutable signed-envelope path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *draftPath == "" || *artifactRoot == "" || *keyPath == "" || *outPath == "" {
		fmt.Fprintln(stderr, "seal requires --draft, --artifacts, --key, and --out")
		return 2
	}
	receipt, err := deliveryaudit.DecodeReceiptFile(*draftPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if receipt.Status == deliveryaudit.OutcomeVerified {
		if *sourceRoot == "" {
			fmt.Fprintln(stderr, "seal requires --source-root for a VERIFIED receipt")
			return 2
		}
		if diagnostics := deliveryaudit.LintWithArtifactsAtSource(receipt, *artifactRoot, *sourceRoot); len(diagnostics) != 0 {
			writeJSON(stdout, map[string]any{"diagnostics": diagnostics, "promotion_status": deliveryaudit.StatusNonPromotable})
			return 1
		}
	}
	privatePEM, generated, err := deliveryaudit.LoadOrCreateSigningKey(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer probcrypto.Zeroize(privatePEM)
	envelope, err := deliveryaudit.SealWithSource(receipt, *artifactRoot, *sourceRoot, privatePEM)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	verified, err := deliveryaudit.Verify(envelope, *artifactRoot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if receipt.Status == deliveryaudit.OutcomeVerified {
		if diagnostics := deliveryaudit.LintVerifiedAtSource(verified, *sourceRoot); len(diagnostics) != 0 {
			writeJSON(stdout, map[string]any{"diagnostics": diagnostics, "promotion_status": deliveryaudit.StatusNonPromotable})
			return 1
		}
	}
	if err := deliveryaudit.WriteEnvelope(*outPath, envelope); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	writeJSON(stdout, map[string]any{
		"receipt":               *outPath,
		"signer_fingerprint":    verified.Envelope.Signing.Fingerprint,
		"signing_key_generated": generated,
		"status":                receipt.Status,
	})
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	receiptPath := fs.String("receipt", "", "signed receipt envelope")
	artifactRoot := fs.String("artifacts", "", "artifact root (defaults to receipt directory)")
	repo := fs.String("repo", ".", "Git checkout used for exact current-SHA verification")
	requireCurrent := fs.Bool("require-current", false, "require trusted signer, semantic eligibility, clean checkout, and exact current SHA")
	trustedKey := fs.String("trusted-public-key", "", "out-of-band trusted Ed25519 public-key PEM")
	trustedFingerprint := fs.String("trusted-fingerprint", "", "out-of-band trusted sha256 public-key fingerprint")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *receiptPath == "" {
		fmt.Fprintln(stderr, "verify requires --receipt")
		return 2
	}
	if *artifactRoot == "" {
		*artifactRoot = filepath.Dir(*receiptPath)
	}
	trust, err := loadTrust(*trustedKey, *trustedFingerprint)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	verified, err := deliveryaudit.VerifyFileWithArtifacts(*receiptPath, *artifactRoot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *requireCurrent {
		status, diagnostics, statusErr := deliveryaudit.CurrentStatus(verified, *repo, trust)
		if statusErr != nil {
			fmt.Fprintln(stderr, statusErr)
			return 1
		}
		cryptographicStatus := "SIGNATURE_VALID_TRUSTED"
		if trustErr := deliveryaudit.VerifySignerTrust(verified, trust); trustErr != nil {
			cryptographicStatus = string(deliveryaudit.StatusSignatureValidUntrusted)
		}
		writeJSON(stdout, map[string]any{
			"cryptographic_status": cryptographicStatus,
			"diagnostics":          diagnostics,
			"promotion_status":     status,
			"receipt_status":       verified.Receipt.Status,
			"signer_fingerprint":   verified.Envelope.Signing.Fingerprint,
		})
		if status == deliveryaudit.StatusVerifiedCurrent {
			return 0
		}
		return 1
	}

	cryptographicStatus := string(deliveryaudit.StatusSignatureValidUntrusted)
	if err := deliveryaudit.VerifySignerTrust(verified, trust); err == nil {
		cryptographicStatus = "SIGNATURE_VALID_TRUSTED"
	} else if !errors.Is(err, deliveryaudit.ErrTrustRequired) {
		diagnostic := "receipt signer does not match the out-of-band trust input"
		if !errors.Is(err, deliveryaudit.ErrUntrustedSigner) {
			diagnostic = err.Error()
		}
		writeJSON(stdout, map[string]any{
			"cryptographic_status": "SIGNATURE_VALID_UNTRUSTED",
			"diagnostics":          []deliveryaudit.Diagnostic{{Code: "untrusted-signer", Problem: diagnostic}},
			"receipt_status":       verified.Receipt.Status,
			"signer_fingerprint":   verified.Envelope.Signing.Fingerprint,
		})
		return 1
	}
	writeJSON(stdout, map[string]any{
		"cryptographic_status": cryptographicStatus,
		"receipt_status":       verified.Receipt.Status,
		"signer_fingerprint":   verified.Envelope.Signing.Fingerprint,
	})
	return 0
}

func runLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	receiptPath := fs.String("receipt", "", "signed receipt envelope")
	artifactRoot := fs.String("artifacts", "", "artifact root (defaults to receipt directory)")
	sourceRoot := fs.String("source-root", "", "exact source tree used to resolve static reachability")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *receiptPath == "" {
		fmt.Fprintln(stderr, "lint requires --receipt")
		return 2
	}
	if *artifactRoot == "" {
		*artifactRoot = filepath.Dir(*receiptPath)
	}
	verified, err := deliveryaudit.VerifyFileWithArtifacts(*receiptPath, *artifactRoot)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	diagnostics := deliveryaudit.LintVerifiedAtSource(verified, *sourceRoot)
	writeJSON(stdout, map[string]any{
		"cryptographic_status": deliveryaudit.StatusSignatureValidUntrusted,
		"diagnostics":          diagnostics,
		"receipt_status":       verified.Receipt.Status,
		"signer_fingerprint":   verified.Envelope.Signing.Fingerprint,
	})
	if len(diagnostics) != 0 {
		return 1
	}
	return 0
}

func runCerts(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("certs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outDir := fs.String("out", "", "new private certificate directory")
	ttl := fs.Duration("ttl", deliveryaudit.MaxDisposableCATTL, "disposable CA lifetime (maximum 6h)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *outDir == "" {
		fmt.Fprintln(stderr, "certs requires --out")
		return 2
	}
	manifest, err := deliveryaudit.GenerateDisposableCertificates(*outDir, *ttl)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	writeJSON(stdout, manifest)
	return 0
}

func loadTrust(publicKeyPath, fingerprint string) (deliveryaudit.TrustPolicy, error) {
	trust := deliveryaudit.TrustPolicy{Fingerprint: strings.TrimSpace(fingerprint)}
	if publicKeyPath == "" {
		return trust, nil
	}
	info, err := os.Lstat(publicKeyPath)
	if err != nil {
		return deliveryaudit.TrustPolicy{}, fmt.Errorf("inspect trusted public key: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return deliveryaudit.TrustPolicy{}, errors.New("trusted public key must be a regular non-symlink file no larger than 64 KiB")
	}
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return deliveryaudit.TrustPolicy{}, fmt.Errorf("read trusted public key: %w", err)
	}
	trust.PublicKeyPEM = data
	return trust, nil
}

func writeJSON(w io.Writer, value any) {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `probectl-delivery-audit proves delivery independently of unit tests.

Commands:
  certs   --out DIR [--ttl 6h]
  seal    --draft FILE --artifacts DIR --source-root DIR --key FILE --out FILE
  verify  --receipt FILE [--artifacts DIR] [--trusted-public-key FILE | --trusted-fingerprint PIN]
          [--require-current --repo DIR]
  lint    --receipt FILE [--artifacts DIR] [--source-root DIR]
  selftest

Only verify --require-current with out-of-band signer trust can authorize a
VERIFIED_CURRENT result. An envelope's embedded key proves integrity only.`)
}
