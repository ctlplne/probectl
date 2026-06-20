// SPDX-License-Identifier: LicenseRef-probectl-TBD

package preflight

import (
	"strings"
	"testing"
)

// The unencrypted fixture from the sprint verify: a plain block device must
// WARN (and trip --strict); dm-crypt and ZFS must pass; attestation downgrades.
const fixtureMounts = `/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /var/lib/postgresql ext4 rw 0 0
/dev/mapper/luks-data /var/lib/clickhouse ext4 rw 0 0
tank/probectl /var/lib/probectl zfs rw 0 0
`

func TestCheckStorageEncryptionAtRest(t *testing.T) {
	fs := CheckStorageEncryption(fixtureMounts,
		[]string{"/var/lib/postgresql/data", "/var/lib/clickhouse", "/var/lib/probectl"}, false)
	got := map[string]Severity{}
	for _, f := range fs {
		got[f.Check] = f.Severity
	}
	if got["storage-encryption /var/lib/postgresql/data"] != Warn {
		t.Fatalf("plain ext4 on /dev/sda2 must WARN: %+v", fs)
	}
	if got["storage-encryption /var/lib/clickhouse"] != OK {
		t.Fatalf("dm-crypt (/dev/mapper) must pass: %+v", fs)
	}
	if got["storage-encryption /var/lib/probectl"] != OK {
		t.Fatalf("zfs must pass: %+v", fs)
	}
	if !Strict(fs) {
		t.Fatal("strict mode must fail on the unencrypted fixture")
	}

	// Operator attestation (cloud-volume encryption invisible from a container)
	// downgrades to Info and unblocks strict — and says so in the detail.
	att := CheckStorageEncryption(fixtureMounts, []string{"/var/lib/postgresql/data"}, true)
	if len(att) != 1 || att[0].Severity != Info || !strings.Contains(att[0].Detail, "ATTESTED") {
		t.Fatalf("attested finding wrong: %+v", att)
	}
	if Strict(att) {
		t.Fatal("attested deployment must pass strict")
	}
}

func TestCheckStorageEncryptionUnknownPath(t *testing.T) {
	fs := CheckStorageEncryption("/dev/sda1 /other ext4 rw 0 0\n", []string{"/data"}, false)
	if len(fs) != 1 || fs[0].Severity != Warn {
		t.Fatalf("unbacked path must warn: %+v", fs)
	}
}

func TestCheckEnvelopeKeyAtRest(t *testing.T) {
	if f := CheckEnvelopeKey(true, true, false); f.Severity != OK {
		t.Fatalf("configured key must be OK: %+v", f)
	}
	if f := CheckEnvelopeKey(false, false, true); f.Severity != Warn || !strings.Contains(f.Detail, "ALLOW_KEYLESS_DEV") || !strings.Contains(f.Detail, "passthrough") {
		t.Fatalf("explicit keyless dev must warn about passthrough: %+v", f)
	}
	if f := CheckEnvelopeKey(false, true, false); f.Severity != Warn || !strings.Contains(f.Detail, "REFUSE") {
		t.Fatalf("required-but-keyless must state the fail-closed refusal: %+v", f)
	}
	if f := CheckEnvelopeKey(false, false, false); f.Severity != Warn || !strings.Contains(f.Detail, "ALLOW_KEYLESS_DEV") || !strings.Contains(f.Detail, "REFUSE") {
		t.Fatalf("implicit keyless must state the dev escape hatch and refusal: %+v", f)
	}
}
