// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/govern"
)

func TestDataRetentionMatrixCoversPrivacyGovernanceRows(t *testing.T) {
	b, err := os.ReadFile("data-retention.md")
	if err != nil {
		t.Fatalf("read data-retention.md: %v", err)
	}
	doc := string(b)
	flatDoc := strings.Join(strings.Fields(doc), " ")

	required := []string{
		"DNS answers",
		"Topology labels",
		"User directory attributes",
		"Object artifacts",
		"Audit entries",
		"AI prompts and answers",
		"SIEM-exported copies",
		"PROBECTL_FLOW_RETENTION_DAYS",
		"PROBECTL_EBPF_RETENTION_DAYS",
		"PROBECTL_PATH_RETENTION_DAYS",
		"PROBECTL_OTEL_RETENTION_DAYS",
		"PROBECTL_AUDIT_RETENTION",
		"audit-retention runner wakes hourly",
		"audit.retention_prune",
		"subject-erasure markers",
		"PROBECTL_AI_ANSWER_RETENTION",
		"PROBECTL_BACKUP_RETENTION_DAYS",
		"flow_retention_days is the only tenant-scoped age-retention override today",
		"No object-store age TTL is enforced by FSStore",
		"SIEM retention is owned by the destination SIEM",
	}
	for _, want := range required {
		if !strings.Contains(flatDoc, want) {
			t.Fatalf("data-retention.md missing required privacy retention term %q", want)
		}
	}
	for _, id := range govern.RequiredDataInventoryIDs() {
		if !strings.Contains(flatDoc, "`"+id+"`") {
			t.Fatalf("data-retention.md missing maintained data inventory id %q", id)
		}
	}
}

func TestGovernanceDocsLinkToDataRetentionMatrix(t *testing.T) {
	for _, path := range []string{"governance.md", "configuration.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(b), "data-retention.md") {
			t.Fatalf("%s must link to data-retention.md so retention governance is discoverable", path)
		}
	}
}
