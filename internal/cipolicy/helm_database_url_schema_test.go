// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"encoding/json"
	"testing"
)

// RTO-10: values.schema.json must require database.url ONLY when no managed
// secret supplies the DSN. The Terraform module and the Argo CD/Flux GitOps
// manifests install with secrets.existingSecret carrying the DSN and NO
// database.url in values (so the DSN never lands in Git/Terraform state); an
// unconditional `required: ["url"]` + `minLength: 1` on the database block
// rejected every such install before templates/secret.yaml could run.
//
// The behavioral proof is the helm-gate CI job (it actually `helm template`s
// the secret-managed path). This test is the container-runnable anchor: it
// pins the schema SHAPE that makes that render possible, so the unconditional
// requirement cannot creep back without failing here first.
func TestHelmSchemaMakesDatabaseURLConditionalOnExistingSecret(t *testing.T) {
	t.Parallel()

	raw := readRepoFile(t, "deploy", "helm", "probectl", "values.schema.json")
	var schema map[string]any
	if err := json.Unmarshal([]byte(raw), &schema); err != nil {
		t.Fatalf("values.schema.json is not valid JSON: %v", err)
	}

	// 1. The standalone database block must NOT unconditionally demand url.
	props, _ := schema["properties"].(map[string]any)
	db, _ := props["database"].(map[string]any)
	if db == nil {
		t.Fatal("schema has no properties.database block (RTO-10)")
	}
	if req, ok := db["required"].([]any); ok {
		for _, r := range req {
			if r == "url" {
				t.Error("properties.database still unconditionally requires url; it must be required only when secrets.existingSecret is unset (RTO-10)")
			}
		}
	}
	if dbProps, ok := db["properties"].(map[string]any); ok {
		if url, ok := dbProps["url"].(map[string]any); ok {
			if _, has := url["minLength"]; has {
				t.Error("properties.database.url still carries an unconditional minLength; a secret-managed install supplies no url here (RTO-10)")
			}
		}
	}

	// 2. A root allOf branch must require database.url precisely when
	//    secrets.existingSecret is absent (if:{not:{… existingSecret …}} then
	//    database.url required).
	allOf, _ := schema["allOf"].([]any)
	if len(allOf) == 0 {
		t.Fatal("schema has no root allOf; the conditional database.url requirement is missing (RTO-10)")
	}
	found := false
	for _, entry := range allOf {
		e, _ := entry.(map[string]any)
		ifBlock, _ := e["if"].(map[string]any)
		not, _ := ifBlock["not"].(map[string]any)
		if not == nil {
			continue
		}
		if !mentionsExistingSecret(not) {
			continue
		}
		if thenRequiresDatabaseURL(e["then"]) {
			found = true
			break
		}
	}
	if !found {
		t.Error("no root allOf branch requires database.url under `not(secrets.existingSecret)`; the conditional DSN requirement is gone (RTO-10)")
	}
}

func mentionsExistingSecret(not map[string]any) bool {
	props, _ := not["properties"].(map[string]any)
	secrets, _ := props["secrets"].(map[string]any)
	if secrets == nil {
		return false
	}
	sprops, _ := secrets["properties"].(map[string]any)
	_, ok := sprops["existingSecret"]
	return ok
}

func thenRequiresDatabaseURL(thenBlock any) bool {
	then, _ := thenBlock.(map[string]any)
	props, _ := then["properties"].(map[string]any)
	db, _ := props["database"].(map[string]any)
	if db == nil {
		return false
	}
	req, _ := db["required"].([]any)
	for _, r := range req {
		if r == "url" {
			return true
		}
	}
	return false
}
