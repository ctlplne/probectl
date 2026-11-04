// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the actual shipping handlers against the same inventory operation
// check as the capability gate, including deliberate current-caller and bound
// omissions. A handler's name or a stale comment is insufficient evidence.
func TestReportingCLIClaimsRequireCurrentRequestAndBoundedInput(t *testing.T) {
	source, err := os.ReadFile("../cli/commands.go")
	if err != nil {
		t.Fatal(err)
	}
	handlers := map[string]string{"dashboard": "cmdDashboard", "dashboard-report": "cmdDashboardReport"}
	commands := []string{"probectl dashboard export", "probectl dashboard import", "probectl dashboard-report download"}
	cases := []struct{ name, old, replacement, group, operation string }{
		{name: "shipping handlers"},
		{"export loses current configuration", customCLIHandlerSpines["dashboardExport"], strings.Replace(customCLIHandlerSpines["dashboardExport"], "newClient(cfg)", "newClient(Config{})", 1), "dashboard", "export"},
		{"import loses current configuration", customCLIHandlerSpines["dashboardImport"], strings.Replace(customCLIHandlerSpines["dashboardImport"], "newClient(cfg)", "newClient(Config{})", 1), "dashboard", "import"},
		{"download changes resource path", customCLIHandlerSpines["dashboardReportDownload"], strings.Replace(customCLIHandlerSpines["dashboardReportDownload"], "/v1/dashboard-report-artifacts/", "/v1/unrelated/", 1), "dashboard-report", "download"},
		{"export changes argument selection", "return dashboardExport(cfg, args[1:], stdout, stderr)", "return dashboardExport(cfg, args, stdout, stderr)", "dashboard", "export"},
		{"import loses caller input", "return dashboardImport(cfg, args[1:], stdin, stdout, stderr)", "return dashboardImport(cfg, args[1:], bytes.NewReader(nil), stdout, stderr)", "dashboard", "import"},
		{"download becomes no-op", customCLIHandlerSpines["dashboardReportDownload"], "{ return 0 }", "dashboard-report", "download"},
		{"manifest input bound is enlarged", "const maxDashboardManifestInput = 64 << 10", "const maxDashboardManifestInput = 64 << 30", "dashboard", "import"},
		{"manifest reader loses byte bound", "io.ReadAll(io.LimitReader(reader, maxDashboardManifestInput+1))", "io.ReadAll(reader)", "dashboard", "import"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := string(source)
			if tc.old != "" {
				// AST-normalized bodies omit blank lines and comments. Normalize the
				// shipping text likewise for an exact body mutation, preserving tokens.
				text = stripReportingCLICommentsAndBlankLines(text)
				if strings.Count(text, tc.old) != 1 {
					t.Fatal("original reporting mutation seam missing or ambiguous")
				}
				text = strings.Replace(text, tc.old, tc.replacement, 1)
			}
			root := t.TempDir()
			dir := filepath.Join(root, "internal", "cli")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "commands.go"), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			validator := &Validator{root: root}
			inventory, err := validator.loadExplicitCLIOperations(handlers, commands)
			if err != nil {
				t.Fatal(err)
			}
			if tc.old == "" {
				for _, item := range []struct{ group, operation string }{{"dashboard", "export"}, {"dashboard", "import"}, {"dashboard-report", "download"}} {
					if !inventory[item.group][item.operation] {
						t.Fatalf("shipping %s %s was not reachable", item.group, item.operation)
					}
				}
			} else if inventory[tc.group][tc.operation] {
				t.Fatal("reporting claim survived removal of its actual authenticated bounded request")
			}
		})
	}
}

func stripReportingCLICommentsAndBlankLines(source string) string {
	lines := strings.Split(source, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Only the reader's close-error explanation occurs inside the sealed
		// helper. Preserve every executable token and all other source lines.
		if index := strings.Index(line, " //nolint:errcheck"); index >= 0 {
			line = line[:index]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
