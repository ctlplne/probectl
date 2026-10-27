// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import "testing"

func TestOpenAPIChangeWebhookContract(t *testing.T) {
	spec := decodeOpenAPISpec(t)
	op, ok := specOperation(spec, "POST", "/ingest/changes/{provider}/{id}")
	if !ok {
		t.Fatal("registered change webhook is absent from served OpenAPI")
	}
	sec, explicit := effectiveSecurity(spec, op)
	if !explicit || len(sec) != 3 {
		t.Fatal("webhook must declare provider signature OR token authentication, not inherit session auth")
	}
	schemes := spec["components"].(map[string]any)["securitySchemes"].(map[string]any)
	expected := map[string]string{"changeGenericSignature": "X-Probectl-Signature", "changeGitHubSignature": "X-Hub-Signature-256", "changeGitLabToken": "X-Gitlab-Token"}
	for _, raw := range sec {
		requirement := raw.(map[string]any)
		if len(requirement) != 1 {
			t.Fatal("each alternative must require one webhook credential")
		}
		for name := range requirement {
			header, exists := expected[name]
			if !exists {
				t.Fatalf("unexpected webhook authentication %q", name)
			}
			scheme := schemes[name].(map[string]any)
			if scheme["type"] != "apiKey" || scheme["in"] != "header" || scheme["name"] != header {
				t.Fatalf("%s must be header-only", name)
			}
			delete(expected, name)
		}
	}
	if len(expected) != 0 {
		t.Fatal("webhook authentication alternative missing")
	}
	params := op["parameters"].([]any)
	for _, name := range []string{"provider", "id"} {
		found := false
		for _, raw := range params {
			p := raw.(map[string]any)
			if p["name"] == name && p["in"] == "path" && p["required"] == true {
				found = true
			}
		}
		if !found {
			t.Fatalf("required path parameter %s missing", name)
		}
	}
	responses := op["responses"].(map[string]any)
	for _, status := range []string{"202", "400", "401", "403", "413", "429", "500"} {
		if _, ok := responses[status]; !ok {
			t.Errorf("missing response %s", status)
		}
	}
	request := op["requestBody"].(map[string]any)
	if request["required"] != true {
		t.Fatal("webhook body must be required")
	}
	schema := request["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	if len(schema["anyOf"].([]any)) != 5 {
		t.Fatal("generic payload, GitHub push/deployment and GitLab push/deployment shapes must be documented")
	}
}
