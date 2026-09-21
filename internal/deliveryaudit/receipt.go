// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

const maxReceiptBytes = 4 << 20

// VerifiedEnvelope is returned only after schema, signature, and every
// external artifact hash have verified.
type VerifiedEnvelope struct {
	Envelope Envelope
	Receipt  Receipt

	artifactRoot string
	artifacts    map[string]semanticArtifactResult
}

// PromotionStatus distinguishes cryptographic validity from promotability.
// In particular, a signed FAILED receipt is valid evidence of failure.
type PromotionStatus string

const (
	StatusVerifiedCurrent         PromotionStatus = "VERIFIED_CURRENT"
	StatusFailed                  PromotionStatus = "FAILED"
	StatusNonPromotable           PromotionStatus = "NON_PROMOTABLE"
	StatusStaleSHA                PromotionStatus = "STALE_SHA"
	StatusCurrentCheckoutDirty    PromotionStatus = "CURRENT_CHECKOUT_DIRTY"
	StatusSignatureValidUntrusted PromotionStatus = "SIGNATURE_VALID_UNTRUSTED"
)

var (
	// ErrTrustRequired means signature integrity succeeded, but the caller did
	// not provide an out-of-band signer authority.
	ErrTrustRequired = errors.New("delivery audit: trusted signer is required")
	// ErrUntrustedSigner means the receipt was signed by a different key than
	// the public key or fingerprint pinned out of band.
	ErrUntrustedSigner = errors.New("delivery audit: receipt signer is not trusted")
	// ErrAuditorMismatch means the trusted key is authorized for a different
	// auditor identity than the one attested in the signed receipt.
	ErrAuditorMismatch = errors.New("delivery audit: receipt auditor is not authorized by trust policy")
)

// TrustPolicy is supplied out of band by the auditor/verifier. The public key
// embedded in a self-contained envelope proves only integrity; accepting that
// same embedded key as authority would let anyone mint their own VERIFIED
// receipt. At least one of PublicKeyPEM or Fingerprint is required to promote.
type TrustPolicy struct {
	PublicKeyPEM    []byte
	Fingerprint     string
	ExpectedAuditor string
}

func (p TrustPolicy) empty() bool {
	return len(p.PublicKeyPEM) == 0 && strings.TrimSpace(p.Fingerprint) == ""
}

// Seal binds the declared artifact files and signs the exact compact JSON
// receipt bytes with the supplied private key. A claimed VERIFIED receipt is
// semantically checked against its artifact bytes before signing; FAILED
// receipts remain signable evidence of an unsuccessful audit.
func Seal(receipt Receipt, artifactRoot string, privatePEM []byte) ([]byte, error) {
	return SealWithSource(receipt, artifactRoot, "", privatePEM)
}

// SealWithSource binds artifacts and resolves static reachability against an
// exact archived source tree before signing a VERIFIED receipt.
func SealWithSource(receipt Receipt, artifactRoot, sourceRoot string, privatePEM []byte) ([]byte, error) {
	if err := validateStructural(receipt); err != nil {
		return nil, err
	}
	bound, snapshot, err := bindArtifactSnapshot(receipt, artifactRoot)
	if err != nil {
		return nil, err
	}
	if bound.Status == OutcomeVerified {
		if diagnostics := lintWithArtifactSnapshot(bound, snapshot, sourceRoot); len(diagnostics) != 0 {
			return nil, fmt.Errorf("delivery audit: VERIFIED evidence is not promotable: %s", summarizeDiagnostics(diagnostics))
		}
	}
	return sealBoundReceipt(bound, privatePEM)
}

func sealBoundReceipt(bound Receipt, privatePEM []byte) ([]byte, error) {
	raw, err := json.Marshal(bound)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: encode receipt: %w", err)
	}
	signature, err := probcrypto.SignEd25519(privatePEM, raw)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: sign receipt: %w", err)
	}
	publicPEM, err := probcrypto.PublicPEMFromPrivate(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: derive public key: %w", err)
	}
	envelope := Envelope{
		Schema:  EnvelopeSchema,
		Receipt: raw,
		Signing: Signing{
			Algorithm:   SignatureAlgorithm,
			PublicKey:   string(publicPEM),
			Fingerprint: digestBytes(publicPEM),
			Signature:   signature,
		},
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: encode envelope: %w", err)
	}
	return append(encoded, '\n'), nil
}

// DecodeReceipt strictly decodes an unsigned receipt draft. Unknown fields and
// trailing JSON are rejected so a misspelled security assertion cannot be
// silently ignored.
func DecodeReceipt(raw []byte) (Receipt, error) {
	var receipt Receipt
	if err := decodeStrict(raw, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("delivery audit: decode receipt: %w", err)
	}
	if err := validateStructural(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// DecodeReceiptFile performs the same strict decoding for a bounded,
// non-symlinked draft file.
func DecodeReceiptFile(path string) (Receipt, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Receipt{}, fmt.Errorf("delivery audit: inspect receipt draft: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Receipt{}, errors.New("delivery audit: receipt draft must be a regular file, not a symlink")
	}
	raw, _, err := readBoundedRegular(path, maxReceiptBytes)
	if err != nil {
		return Receipt{}, fmt.Errorf("delivery audit: read receipt draft: %w", err)
	}
	return DecodeReceipt(raw)
}

// Verify checks an envelope signature and every artifact under artifactRoot.
func Verify(raw []byte, artifactRoot string) (*VerifiedEnvelope, error) {
	if len(raw) > maxReceiptBytes {
		return nil, fmt.Errorf("delivery audit: receipt exceeds %d-byte limit", maxReceiptBytes)
	}
	var envelope Envelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return nil, fmt.Errorf("delivery audit: decode envelope: %w", err)
	}
	if envelope.Schema != EnvelopeSchema {
		return nil, fmt.Errorf("delivery audit: unsupported envelope schema %q", envelope.Schema)
	}
	if envelope.Signing.Algorithm != SignatureAlgorithm {
		return nil, fmt.Errorf("delivery audit: unsupported signature algorithm %q", envelope.Signing.Algorithm)
	}
	if len(envelope.Signing.Signature) != probcrypto.Ed25519SignatureSize {
		return nil, errors.New("delivery audit: invalid signature length")
	}
	if envelope.Signing.PublicKey == "" || envelope.Signing.Fingerprint != digestBytes([]byte(envelope.Signing.PublicKey)) {
		return nil, errors.New("delivery audit: signing-key fingerprint mismatch")
	}
	ok, err := probcrypto.VerifyEd25519(
		[]byte(envelope.Signing.PublicKey), envelope.Receipt, envelope.Signing.Signature,
	)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: verify public key: %w", err)
	}
	if !ok {
		return nil, errors.New("delivery audit: receipt signature does not verify")
	}
	receipt, err := DecodeReceipt(envelope.Receipt)
	if err != nil {
		return nil, err
	}
	snapshot, err := verifyArtifacts(receipt, artifactRoot)
	if err != nil {
		return nil, err
	}
	return &VerifiedEnvelope{
		Envelope: envelope, Receipt: receipt, artifactRoot: artifactRoot, artifacts: snapshot,
	}, nil
}

// VerifyFileWithArtifacts verifies a receipt file while resolving its signed
// attachment paths beneath the explicitly supplied artifact root.
func VerifyFileWithArtifacts(path, artifactRoot string) (*VerifiedEnvelope, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: inspect receipt: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("delivery audit: receipt must be a regular file, not a symlink")
	}
	data, _, err := readBoundedRegular(path, maxReceiptBytes)
	if err != nil {
		return nil, fmt.Errorf("delivery audit: read receipt: %w", err)
	}
	return Verify(data, artifactRoot)
}

// WriteEnvelope creates an immutable receipt path. Existing files and symlink
// targets are never overwritten.
func WriteEnvelope(path string, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxReceiptBytes {
		return errors.New("delivery audit: invalid envelope size")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("delivery audit: create receipt directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("delivery audit: create immutable receipt: %w", err)
	}
	written := false
	defer func() {
		_ = f.Close()
		if !written {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("delivery audit: write receipt: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("delivery audit: sync receipt: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("delivery audit: close receipt: %w", err)
	}
	written = true
	return nil
}

// LoadOrCreateSigningKey uses the repository crypto abstraction and refuses a
// symlinked or group/world-accessible private key.
func LoadOrCreateSigningKey(path string) ([]byte, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, errors.New("delivery audit: signing key path is required")
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, false, errors.New("delivery audit: signing key must be a regular file, not a symlink")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, false, fmt.Errorf("delivery audit: signing key permissions %04o expose private material; require 0600", info.Mode().Perm())
		}
		privatePEM, _, readErr := readBoundedRegular(path, 64<<10)
		if readErr != nil {
			return nil, false, fmt.Errorf("delivery audit: read signing key: %w", readErr)
		}
		if _, parseErr := probcrypto.PublicPEMFromPrivate(privatePEM); parseErr != nil {
			probcrypto.Zeroize(privatePEM)
			return nil, false, fmt.Errorf("delivery audit: invalid signing key: %w", parseErr)
		}
		return privatePEM, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("delivery audit: inspect signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("delivery audit: create signing key directory: %w", err)
	}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		return nil, false, err
	}
	if err := writeNewFile(path, privatePEM, 0o600); err != nil {
		probcrypto.Zeroize(privatePEM)
		return nil, false, err
	}
	return privatePEM, true, nil
}

func validateStructural(receipt Receipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("delivery audit: encode receipt structure: %w", err)
	}
	if len(encoded) > maxReceiptBytes/2 {
		return fmt.Errorf("delivery audit: unsigned receipt exceeds %d-byte limit", maxReceiptBytes/2)
	}
	if receipt.Schema != ReceiptSchema {
		return fmt.Errorf("delivery audit: unsupported receipt schema %q", receipt.Schema)
	}
	if strings.TrimSpace(receipt.ReceiptID) == "" || strings.TrimSpace(receipt.Item) == "" || strings.TrimSpace(receipt.CapabilityID) == "" {
		return errors.New("delivery audit: receipt_id, item, and capability_id are required")
	}
	if receipt.Status != OutcomeVerified && receipt.Status != OutcomeFailed {
		return fmt.Errorf("delivery audit: unsupported outcome %q", receipt.Status)
	}
	if receipt.StartedAt.IsZero() || receipt.CompletedAt.IsZero() || receipt.CompletedAt.Before(receipt.StartedAt) {
		return errors.New("delivery audit: valid started_at and completed_at are required")
	}
	if receipt.Status == OutcomeFailed && len(receipt.FailureReasons) == 0 {
		return errors.New("delivery audit: FAILED receipt requires failure_reasons")
	}
	if len(receipt.Artifacts) == 0 {
		return errors.New("delivery audit: artifacts are required")
	}
	if len(receipt.Artifacts) > maxArtifactCount || len(receipt.CLI.Commands) > 128 ||
		len(receipt.UI.Routes) > 128 || len(receipt.UI.Screenshots) > 128 ||
		len(receipt.BrowserNetwork.Requests) > 256 ||
		len(receipt.Activation.BuildTags) > 32 || len(receipt.FailureReasons) > 64 {
		return errors.New("delivery audit: evidence collection exceeds a bounded entry limit")
	}
	return nil
}

func decodeStrict(raw []byte, target any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = true
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

type repositoryState struct {
	GitSHA  string
	TreeSHA string
	Dirty   bool
}

func readRepositoryState(repo string) (repositoryState, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return repositoryState{}, err
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", abs}, args...)...)
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	gitSHA, err := run("rev-parse", "HEAD")
	if err != nil {
		return repositoryState{}, err
	}
	treeSHA, err := run("rev-parse", "HEAD^{tree}")
	if err != nil {
		return repositoryState{}, err
	}
	status, err := run("status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return repositoryState{}, err
	}
	return repositoryState{GitSHA: gitSHA, TreeSHA: treeSHA, Dirty: status != ""}, nil
}

// VerifySignerTrust authorizes an already verified envelope against a public
// key and/or fingerprint supplied outside the envelope. The embedded key alone
// proves integrity but can never authorize VERIFIED promotion.
func VerifySignerTrust(verified *VerifiedEnvelope, trust TrustPolicy) error {
	if verified == nil {
		return errors.New("delivery audit: verified envelope is nil")
	}
	if trust.empty() {
		return ErrTrustRequired
	}
	if len(trust.PublicKeyPEM) > 0 {
		ok, err := probcrypto.VerifyEd25519(
			trust.PublicKeyPEM,
			verified.Envelope.Receipt,
			verified.Envelope.Signing.Signature,
		)
		if err != nil {
			return fmt.Errorf("delivery audit: parse trusted public key: %w", err)
		}
		if !ok {
			return ErrUntrustedSigner
		}
	}
	if pin := strings.TrimSpace(trust.Fingerprint); pin != "" && pin != verified.Envelope.Signing.Fingerprint {
		return ErrUntrustedSigner
	}
	if expected := strings.TrimSpace(trust.ExpectedAuditor); expected != "" && expected != strings.TrimSpace(verified.Receipt.Auditor.Agent) {
		return ErrAuditorMismatch
	}
	return nil
}

// CurrentStatus combines signed-envelope validity, semantic lint, and current
// checkout state. Call Verify or VerifyFileWithArtifacts first; this function
// assumes artifact and signature verification has already succeeded.
func CurrentStatus(verified *VerifiedEnvelope, repo string, trust TrustPolicy) (PromotionStatus, []Diagnostic, error) {
	if verified == nil {
		return StatusNonPromotable, nil, errors.New("delivery audit: verified envelope is nil")
	}
	if verified.Receipt.Status == OutcomeFailed {
		return StatusFailed, []Diagnostic{{Code: "status-failed", Problem: "signed receipt records a FAILED audit and cannot promote the item"}}, nil
	}
	trustErr := VerifySignerTrust(verified, trust)
	switch {
	case errors.Is(trustErr, ErrTrustRequired):
		return StatusSignatureValidUntrusted, []Diagnostic{{Code: "untrusted-signer", Problem: "receipt signature is valid but no out-of-band trusted public key or fingerprint was supplied"}}, nil
	case errors.Is(trustErr, ErrUntrustedSigner):
		return StatusNonPromotable, []Diagnostic{{Code: "untrusted-signer", Problem: "receipt signer does not match the out-of-band trusted public key or fingerprint"}}, nil
	case errors.Is(trustErr, ErrAuditorMismatch):
		return StatusNonPromotable, []Diagnostic{{Code: "untrusted-auditor", Problem: "receipt auditor does not match the identity authorized for the out-of-band trusted signer"}}, nil
	case trustErr != nil:
		return StatusNonPromotable, nil, trustErr
	}
	state, err := readRepositoryState(repo)
	if err != nil {
		return StatusNonPromotable, nil, err
	}
	if state.Dirty {
		return StatusCurrentCheckoutDirty, []Diagnostic{{Code: "current-checkout-dirty", Problem: "current repository checkout is dirty"}}, nil
	}
	if state.GitSHA != verified.Receipt.Source.GitSHA || state.TreeSHA != verified.Receipt.Source.TreeSHA {
		return StatusStaleSHA, []Diagnostic{{Code: "stale-sha", Problem: "receipt source SHA/tree does not match the current checkout"}}, nil
	}
	// Evaluate source semantics from a fresh immutable Git archive, never from
	// mutable worktree bytes. This closes status/lint races and Git index flags
	// such as assume-unchanged or skip-worktree.
	sourceRoot, cleanup, err := materializeRepositoryTree(repo, verified.Receipt.Source.GitSHA)
	if err != nil {
		return StatusNonPromotable, nil, err
	}
	defer cleanup()
	diagnostics := LintVerifiedAtSource(verified, sourceRoot)
	if len(diagnostics) > 0 {
		return StatusNonPromotable, diagnostics, nil
	}
	return StatusVerifiedCurrent, nil, nil
}

func materializeRepositoryTree(repo, gitSHA string) (string, func(), error) {
	root, err := os.MkdirTemp("", "probectl-delivery-audit-source-")
	if err != nil {
		return "", func() {}, fmt.Errorf("delivery audit: create immutable source root: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	command := exec.Command("git", "-C", repo, "archive", "--format=tar", gitSHA)
	stdout, err := command.StdoutPipe()
	if err != nil {
		cleanup()
		return "", func() {}, err
	}
	if err := command.Start(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	reader := tar.NewReader(stdout)
	var total int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			cleanup()
			return "", func() {}, fmt.Errorf("delivery audit: read source archive: %w", nextErr)
		}
		clean := filepath.Clean(header.Name)
		if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			cleanup()
			return "", func() {}, errors.New("delivery audit: Git archive contains unsafe path")
		}
		target := filepath.Join(root, clean)
		switch header.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			// archive/tar applies PAX metadata to the following entry. Git emits
			// a global header for archive provenance; it is metadata, not a
			// filesystem object, so there is nothing to materialize here.
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				cleanup()
				return "", func() {}, err
			}
		case tar.TypeReg, 0: // NUL is the legacy regular-file type emitted by old tar writers.
			total += header.Size
			if header.Size < 0 || total > 2<<30 {
				cleanup()
				return "", func() {}, errors.New("delivery audit: Git archive exceeds bounded size")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				cleanup()
				return "", func() {}, err
			}
			file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				cleanup()
				return "", func() {}, err
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				cleanup()
				return "", func() {}, errors.New("delivery audit: incomplete Git archive entry")
			}
		default:
			cleanup()
			return "", func() {}, fmt.Errorf("delivery audit: unsupported Git archive entry type %d", header.Typeflag)
		}
	}
	if err := command.Wait(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("delivery audit: materialize source archive: %w", err)
	}
	return root, cleanup, nil
}

func summarizeDiagnostics(diagnostics []Diagnostic) string {
	var summary strings.Builder
	for i, diagnostic := range diagnostics {
		if i > 0 {
			summary.WriteString("; ")
		}
		summary.WriteString(diagnostic.Code)
		if diagnostic.Field != "" {
			summary.WriteString("[")
			summary.WriteString(diagnostic.Field)
			summary.WriteString("]")
		}
	}
	return summary.String()
}
