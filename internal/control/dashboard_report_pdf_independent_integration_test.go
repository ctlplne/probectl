// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// Inspect actual rendered source-table PDF through approved CI-only Poppler,
// independently of the renderer's PDF object/ActualText implementation.
func verifyIndependentSourcePDF(t *testing.T, proof *reportDownloadProof, capture *reportFlowCapture) {
	t.Helper()
	binary, err := exec.LookPath("pdftotext")
	if err != nil {
		testsupport.SkipOrFatal(t, "CI Poppler pdftotext is required for independent source PDF proof")
	}
	directory := t.TempDir()
	input, output := filepath.Join(directory, "source.pdf"), filepath.Join(directory, "source.txt")
	if err := os.WriteFile(input, proof.expected, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-layout", "-enc", "UTF-8", input, output)
	if err := command.Run(); err != nil {
		t.Fatal("independent source PDF extraction failed", err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() > 8<<20 {
		t.Fatal("independent PDF text exceeded verification budget", err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	compact := strings.Join(strings.Fields(text), "")
	if !strings.Contains(compact, "OWN-"+proof.tenant) {
		t.Fatal("independent PDF lost the actual owned source tag")
	}
	addresses := map[string]bool{}
	for _, match := range regexp.MustCompile(`\b198\.18\.[0-9]{1,3}\.[0-9]{1,3}\b`).FindAllString(text, -1) {
		address, err := netip.ParseAddr(match)
		if err != nil || !address.Is4() {
			t.Fatal("independent source PDF contains malformed address")
		}
		addresses[address.String()] = true
	}
	var rows int64
	for _, table := range capture.Tables {
		if !strings.HasSuffix(table.ID, "/detail") {
			continue
		}
		sourceAddress, metric := -1, -1
		for i, column := range table.Columns {
			if column.Name == "src_addr" {
				sourceAddress = i
			}
			if column.Name == "bytes:total" {
				metric = i
			}
		}
		if sourceAddress < 0 || metric < 0 {
			t.Fatal("independent PDF source schema is unavailable")
		}
		if err := table.WalkRows(ctx, func(row []string) error {
			if row[0] != "detail" {
				return nil
			}
			if !addresses[row[sourceAddress]] {
				t.Fatal("independent PDF omitted an actual selected source row", row[sourceAddress])
			}
			if !strings.Contains(compact, row[metric]) {
				t.Fatal("independent PDF changed an exact source integer")
			}
			rows++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if rows != 4000 || len(addresses) != 4000 {
		t.Fatal("independent PDF source completeness disagrees", rows, len(addresses))
	}
	t.Log(fmt.Sprintf("independent source PDF selected_rows=%d unique_addresses=%d extracted_bytes=%d complete_actual_source_values=true", rows, len(addresses), len(raw)))
}
