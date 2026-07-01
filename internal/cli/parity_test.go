// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

type openAPIDoc struct {
	Paths map[string]map[string]any `json:"paths"`
}

func TestCLIOpenAPIParity(t *testing.T) {
	raw, err := os.ReadFile("../control/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	covered := map[string]cliCoverage{}
	for _, cov := range cliImplementedCoverage() {
		covered[opKey(cov.Method, cov.Path)] = cov
	}
	for _, cov := range cliCoverageExceptions {
		if cov.Reason == "" {
			t.Fatalf("%s %s: none-by-design exception must explain why", cov.Method, cov.Path)
		}
		covered[opKey(cov.Method, cov.Path)] = cov
	}

	var missing []string
	for path, methods := range doc.Paths {
		if !strings.HasPrefix(path, "/v1/") {
			continue
		}
		for method := range methods {
			if method == "parameters" {
				continue
			}
			key := opKey(method, path)
			if _, ok := covered[key]; !ok {
				missing = append(missing, key)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("OpenAPI operations without CLI command or explicit exception:\n%s", strings.Join(missing, "\n"))
	}
}

func TestCLIHelpListsExpandedSurfaceGroups(t *testing.T) {
	var out, errs bytes.Buffer
	code := Run([]string{"help"}, func(string) string { return "" }, &out, &errs)
	if code != 0 {
		t.Fatalf("help exit = %d, stderr=%s", code, errs.String())
	}
	for _, want := range []string{
		"incident|alert|flow",
		"provider|tenant|billing",
		"topology",
		"slo",
		"compliance",
		"rollout create",
		"api <method> <path>",
		"Examples:",
		"probectl --url https://control.example --tenant 00000000-0000-0000-0000-000000000001 test create --name checkout-http --type http --target https://checkout.example/health --interval 60",
		`probectl --tenant 00000000-0000-0000-0000-000000000001 agent enroll-token --body '{"name":"edge-canary-1","ttl_seconds":3600}'`,
		"probectl --tenant 00000000-0000-0000-0000-000000000001 audit verify",
		`probectl --tenant 00000000-0000-0000-0000-000000000001 lifecycle subject-erase --subject user:ada@example.com --confirm user:ada@example.com --reason "requested deletion"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q:\n%s", want, out.String())
		}
	}
}

func opKey(method, path string) string { return strings.ToUpper(method) + " " + path }
