// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/govern"
)

// The caller validates the complete original document under the existing
// subject-scan byte/token/depth/work budget before allocating this projection.
// Only declared reference values change, and only for UUID-shaped references.
// Portable rows are always exported from the original database row.
func projectSavedQuerySubject(ctx context.Context, table string, raw []byte) ([]byte, bool, error) {
	if table != "flow_query_filters" && table != "flow_query_views" && table != "change_events" {
		return nil, false, nil
	}
	var documents []any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber() // Never narrow exact stored counter or revision values.
	if err := decoder.Decode(&documents); err != nil {
		return nil, false, err
	}
	columns := subjectPostgresTablePolicies[table].contains
	if len(documents) != len(columns) {
		return nil, false, govern.ErrSubjectDocument
	}
	changed := false
	for i, column := range columns {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		document, ok := documents[i].(map[string]any)
		if !ok {
			continue // Unknown/invalid values remain subject-bearing.
		}
		switch column {
		case "routing_source":
			changed = projectRoutingChangeSubjectReferences(document) || changed
		case "expression":
			updated, err := projectSubjectFilterReferences(ctx, document)
			if err != nil {
				return nil, false, err
			}
			changed = changed || updated
		case "definition":
			if bindings, ok := document["tag_ids"].(map[string]any); ok {
				for key, value := range bindings {
					if err := ctx.Err(); err != nil {
						return nil, false, err
					}
					if strings.HasPrefix(key, "tag.") && len(key) > 4 && subjectReferenceUUID(value) {
						bindings[key], changed = nil, true // Keep personal keys.
					}
				}
			}
			if plan, ok := document["plan"].(map[string]any); ok {
				filter, _ := plan["filter"].(map[string]any)
				updated, err := projectSubjectFilterReferences(ctx, filter)
				if err != nil {
					return nil, false, err
				}
				changed = changed || updated
			}
		}
	}
	if !changed {
		return nil, false, nil
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(documents); err != nil {
		return nil, false, err
	}
	return body.Bytes(), true, ctx.Err()
}

// Routing source identifiers can contain personal text. Only recognized UUID
// references in the original version1 envelope are structural; unknown fields,
// malformed references and collector/source identifiers remain matchable.
func projectRoutingChangeSubjectReferences(document map[string]any) bool {
	if document["version"] != json.Number("1") {
		return false
	}
	changed := projectSubjectUUIDFields(document, "view_id", "generation")
	if source, ok := document["source"].(map[string]any); ok {
		changed = projectSubjectUUIDFields(source, "tenant_id", "context_id", "RouterID") || changed
	}
	if selection, ok := document["selection"].(map[string]any); ok {
		changed = projectSubjectUUIDFields(selection, "base_context_id", "base_router_id", "context_id", "router_id", "epoch", "binding_id") || changed
		if binding, ok := selection["binding"].(map[string]any); ok {
			changed = projectSubjectUUIDFields(binding, "id", "context_id", "router_id") || changed
		}
	}
	return changed
}

func projectSubjectUUIDFields(document map[string]any, fields ...string) bool {
	changed := false
	for _, field := range fields {
		if subjectReferenceUUID(document[field]) {
			document[field], changed = nil, true
		}
	}
	return changed
}

func projectSubjectFilterReferences(ctx context.Context, group map[string]any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	changed := false
	if saved, ok := group["saved"].([]any); ok {
		for _, value := range saved {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if reference, ok := value.(map[string]any); ok && subjectReferenceUUID(reference["id"]) {
				reference["id"], changed = nil, true
			}
		}
	}
	if children, ok := group["groups"].([]any); ok {
		for _, child := range children {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if childGroup, ok := child.(map[string]any); ok {
				updated, err := projectSubjectFilterReferences(ctx, childGroup)
				if err != nil {
					return false, err
				}
				changed = changed || updated
			}
		}
	}
	return changed, nil
}

func subjectReferenceUUID(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	id, err := gouuid.Parse(text)
	return err == nil && strings.EqualFold(id.String(), text)
}
