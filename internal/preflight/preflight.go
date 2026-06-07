// Package preflight is the operator-facing deployment self-check (Sprint 8,
// SEC-002/COMPLY-004). probectl encrypts what it manages (sealed tenant
// values, TLS in transit); the BULK telemetry stores (Postgres, ClickHouse,
// object-store volumes) are encrypted at rest by the OPERATOR's storage
// layer — dm-crypt/LUKS, ZFS native encryption, or cloud-volume encryption.
// That duty is documented in docs/hardening.md; this check makes it visible:
// it inspects the mounts backing the data paths and WARNS when a backing
// device is not detectably encrypted (FATAL with --strict, for regulated
// profiles and CI).
//
// Detection is necessarily heuristic from inside a container: dm-crypt/LUKS
// presents as /dev/mapper/*, ZFS/eCryptFS by filesystem type; cloud-volume
// encryption (EBS, PD-CMEK, ...) is INVISIBLE here. Operators using such
// volumes attest via PROBECTL_STORAGE_ENCRYPTION_ATTESTED=true, which
// downgrades the finding to informational — the attestation is logged.
package preflight

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Severity grades one finding.
type Severity string

const (
	OK   Severity = "ok"
	Info Severity = "info"
	Warn Severity = "warn"
)

// Finding is one preflight observation.
type Finding struct {
	Check    string
	Severity Severity
	Detail   string
}

// encryptedFstypes are filesystems that imply (or natively support) at-rest
// encryption when used as the backing store.
var encryptedFstypes = map[string]bool{"zfs": true, "ecryptfs": true, "gocryptfs": true}

// mount is one parsed /proc/self/mounts row.
type mount struct{ source, target, fstype string }

// parseMounts parses /proc/self/mounts content (fields: source target fstype ...).
func parseMounts(content string) []mount {
	var out []mount
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		out = append(out, mount{source: f[0], target: f[1], fstype: f[2]})
	}
	return out
}

// backing returns the most specific mount containing path.
func backing(mounts []mount, path string) (mount, bool) {
	best, found := mount{}, false
	for _, m := range mounts {
		if path == m.target || strings.HasPrefix(path, strings.TrimRight(m.target, "/")+"/") || m.target == "/" {
			if !found || len(m.target) > len(best.target) {
				best, found = m, true
			}
		}
	}
	return best, found
}

// deviceLooksEncrypted applies the heuristics this check CAN see.
func deviceLooksEncrypted(m mount) bool {
	if strings.HasPrefix(m.source, "/dev/mapper/") { // dm-crypt/LUKS (or LVM — stated in the finding)
		return true
	}
	return encryptedFstypes[m.fstype]
}

// CheckStorageEncryption evaluates the mounts backing each data path.
// mountsContent is the raw /proc/self/mounts text (injectable for tests).
func CheckStorageEncryption(mountsContent string, paths []string, attested bool) []Finding {
	mounts := parseMounts(mountsContent)
	var out []Finding
	sort.Strings(paths)
	for _, p := range paths {
		m, ok := backing(mounts, p)
		if !ok {
			out = append(out, Finding{Check: "storage-encryption " + p, Severity: Warn,
				Detail: "no mount found backing this path — cannot assess at-rest encryption"})
			continue
		}
		switch {
		case deviceLooksEncrypted(m):
			out = append(out, Finding{Check: "storage-encryption " + p, Severity: OK,
				Detail: fmt.Sprintf("backed by %s (%s) — device-mapper/encrypted filesystem detected (note: /dev/mapper also matches plain LVM; confirm dm-crypt/LUKS)", m.source, m.fstype)})
		case attested:
			out = append(out, Finding{Check: "storage-encryption " + p, Severity: Info,
				Detail: fmt.Sprintf("backed by %s (%s) — not detectably encrypted from here, but PROBECTL_STORAGE_ENCRYPTION_ATTESTED=true (operator attests cloud-volume/external encryption; logged)", m.source, m.fstype)})
		default:
			out = append(out, Finding{Check: "storage-encryption " + p, Severity: Warn,
				Detail: fmt.Sprintf("backed by %s (%s) — NOT detectably encrypted. Bulk telemetry at rest is the operator's duty (docs/hardening.md): use dm-crypt/LUKS, ZFS encryption, or encrypted cloud volumes; if already encrypted below this layer, set PROBECTL_STORAGE_ENCRYPTION_ATTESTED=true", m.source, m.fstype)})
		}
	}
	return out
}

// CheckEnvelopeKey reports whether probectl's OWN at-rest sealing has a key.
func CheckEnvelopeKey(keyConfigured bool, required bool) Finding {
	switch {
	case keyConfigured:
		return Finding{Check: "envelope-key", Severity: OK, Detail: "at-rest envelope key configured (sealed tenant values encrypt)"}
	case required:
		return Finding{Check: "envelope-key", Severity: Warn, Detail: "PROBECTL_REQUIRE_AT_REST_ENCRYPTION is set but no key resolves — the control plane will REFUSE to start (TENANT-106 fail-closed)"}
	default:
		return Finding{Check: "envelope-key", Severity: Warn, Detail: "no envelope key — sealed values fall back to keyless passthrough (dev only; set PROBECTL_ENVELOPE_KEY[_FILE], see docs/hardening.md)"}
	}
}

// ReadSelfMounts loads /proc/self/mounts ("" with an error elsewhere — the
// caller degrades to a warning, never a crash).
func ReadSelfMounts() (string, error) {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Strict reports whether findings demand a non-zero exit under --strict.
func Strict(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == Warn {
			return true
		}
	}
	return false
}
