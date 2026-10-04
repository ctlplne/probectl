// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fencedBlockRE matches a fenced Markdown code block, capturing its body.
var fencedBlockRE = regexp.MustCompile("(?s)```[a-zA-Z0-9]*\\n(.*?)\\n```")

// curlDataRE captures the single-quoted payload of a curl `-d '...'` argument.
// The quickstart's JSON uses only double quotes inside, so stopping at the next
// single quote recovers the whole body.
var curlDataRE = regexp.MustCompile(`-d '([^']*)'`)

// TestAIQuickstartAskExampleDecodes keeps docs/ai-quickstart.md's first
// copy-paste `/v1/ai/ask` example honest against the shipped request decoder.
// It lifts the JSON body straight out of the doc's fenced code block and runs it
// through decodeJSON -> askRequest, the exact call handleAIAsk makes. askRequest's
// Subject is map[string]string (an OBJECT); a documented string subject would
// fail to decode with a JSON type error (AI-12). Reading the doc at test time
// keeps this coupled to the published example, not a copy of it.
func TestAIQuickstartAskExampleDecodes(t *testing.T) {
	root := findRepoRoot(t)
	docPath := filepath.Join(root, "docs", "ai-quickstart.md")
	content, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	body := extractQuickstartAskBody(t, string(content))

	// decodeJSON is the real request-decode seam: handleAIAsk calls it with the
	// same askRequest type and the same application/json content-type.
	req := httptest.NewRequest(http.MethodPost, "/v1/ai/ask", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	var ask askRequest
	if err := decodeJSON(req, &ask); err != nil {
		t.Fatalf("docs/ai-quickstart.md first /v1/ai/ask example does not decode through askRequest: %v\nbody: %s\n"+
			"subject must be a JSON object (map[string]string), consistent with docs/ai-rca.md and the shipped decoder", err, body)
	}
	// Couple the assertion to the corrected shape: a bare string subject cannot
	// produce a populated object, so a non-empty subject map proves the example
	// now matches askRequest.Subject's type.
	if len(ask.Subject) == 0 {
		t.Fatalf("quickstart /v1/ai/ask example decoded an empty subject; want a focusing object like {\"target\": ...}\nbody: %s", body)
	}
}

// extractQuickstartAskBody pulls the JSON request body out of the first fenced
// code block in the quickstart that posts to /v1/ai/ask. It fails the test (not
// silently returns empty) if the doc's structure drifts, so the coupling holds.
func extractQuickstartAskBody(t *testing.T, doc string) string {
	t.Helper()
	for _, m := range fencedBlockRE.FindAllStringSubmatch(doc, -1) {
		block := m[1]
		if !strings.Contains(block, "/v1/ai/ask") {
			continue
		}
		d := curlDataRE.FindStringSubmatch(block)
		if d == nil {
			t.Fatalf("found the /v1/ai/ask quickstart block but no curl -d '...' payload in it:\n%s", block)
		}
		return d[1]
	}
	t.Fatal("no fenced code block posting to /v1/ai/ask found in docs/ai-quickstart.md")
	return ""
}
