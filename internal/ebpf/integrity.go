package ebpf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// BPF object integrity (U-014): the compiled BPF objects are embedded into
// the agent at `make ebpf-agent` time, and so is a SHA-256 manifest of them
// (bpf_digests_ebpf.go, written by internal/ebpf/gendigests right after
// bpf2go). Before anything is handed to the kernel, the embedded bytes must
// match the manifest — a swapped or corrupted object REFUSES to load (the
// kernel never sees it) and the failure is loud (error + the agent's
// attach-failure metric). An empty manifest entry also refuses: integrity is
// never silently skipped for a known program.

// ErrObjectTampered wraps every integrity failure so callers/tests can
// identify the class.
type errObjectTampered struct{ msg string }

func (e errObjectTampered) Error() string { return e.msg }

// IsTampered reports whether err is a BPF-object integrity failure.
func IsTampered(err error) bool {
	_, ok := err.(errObjectTampered)
	return ok
}

// ObjectDigest returns the lowercase hex SHA-256 of a BPF object.
func ObjectDigest(obj []byte) string {
	sum := sha256.Sum256(obj)
	return hex.EncodeToString(sum[:])
}

// VerifyObjectDigest checks obj against the build-time manifest digest for
// name. It fails closed: a missing/empty expected digest is a refusal, not a
// skip — the manifest must cover every program the build embeds.
func VerifyObjectDigest(name string, obj []byte, wantHex string) error {
	if wantHex == "" {
		return errObjectTampered{fmt.Sprintf(
			"ebpf: no build-time digest for BPF object %q — refusing to load (regenerate with `make ebpf-agent`; U-014)", name)}
	}
	if got := ObjectDigest(obj); got != wantHex {
		return errObjectTampered{fmt.Sprintf(
			"ebpf: BPF object %q digest mismatch (got %s, manifest %s) — object tampered or stale; refusing kernel load (U-014)",
			name, got, wantHex)}
	}
	return nil
}
