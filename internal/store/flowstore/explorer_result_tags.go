// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"maps"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

// OutputVocabulary reconstructs the original field identities of an already
// authorized result. It is never query-admission authority. The authenticated
// tenant must match the materialized result, including after a definition is
// renamed or removed. Native fields need no tag metadata.
func (r PlanResult) OutputVocabulary(tenant string) (flow.QueryVocabulary, error) {
	if r.TagRevision == 0 && r.TagTenantID == "" && len(r.TagIDs) == 0 {
		if resultHasTagFields(r) {
			return flow.QueryVocabulary{}, ErrTagQueryScope
		}
		return flow.QueryVocabulary{}, nil
	}
	if r.TagRevision < 1 || tenant == "" || r.TagTenantID != tenant {
		return flow.QueryVocabulary{}, ErrTagQueryScope
	}
	byKey := make(map[string]string)
	for name, id := range r.TagIDs {
		key, ok := resultTagDefinitionKey(name)
		if !ok {
			return flow.QueryVocabulary{}, ErrTagQueryScope
		}
		if previous, exists := byKey[key]; exists && previous != id {
			return flow.QueryVocabulary{}, ErrTagQueryScope
		}
		byKey[key] = id
	}
	definitions := make([]tags.Definition, 0, len(byKey))
	for key, id := range byKey {
		definitions = append(definitions, tags.Definition{TenantID: tenant, ID: id, Key: key})
	}
	vocabulary, err := flow.NewTagQueryVocabulary(tenant, definitions)
	if err != nil {
		return flow.QueryVocabulary{}, ErrTagQueryScope
	}
	expected, err := resultTagIDs(r, vocabulary)
	if err != nil || !maps.Equal(expected, r.TagIDs) {
		return flow.QueryVocabulary{}, ErrTagQueryScope
	}
	return vocabulary, nil
}

func resultHasTagFields(result PlanResult) bool {
	fields := [][]string{result.Query.GroupBy, result.Query.MatrixWith, flow.QueryFilterFields(result.Query.Filter)}
	if result.Coverage != nil {
		fields = append(fields, result.Coverage.Fields)
	}
	for _, names := range fields {
		for _, name := range names {
			if strings.HasPrefix(name, "tag.") {
				return true
			}
		}
	}
	return false
}

func resultTagDefinitionKey(name string) (string, bool) {
	key, ok := strings.CutPrefix(name, "tag.")
	if !ok {
		return "", false
	}
	if subject, tail, qualified := strings.Cut(key, "."); qualified {
		switch subject {
		case "device", "agent", "in_interface", "out_interface", "src_prefix", "dst_prefix":
			key = tail
		default:
			return "", false
		}
	}
	return key, tags.ValidateKey(key) == nil
}

func resultTagIDs(result PlanResult, vocabulary flow.QueryVocabulary) (map[string]string, error) {
	ids, err := flow.QueryViewTagIDs(result.Query, vocabulary)
	if err != nil {
		return nil, err
	}
	if result.Coverage != nil {
		for _, name := range result.Coverage.Fields {
			if !strings.HasPrefix(name, "tag.") {
				continue
			}
			field, ok := vocabulary.Lookup(name)
			if !ok || field.Derived != "tenant_tag" || field.TagID == "" {
				return nil, ErrTagQueryScope
			}
			ids[name] = field.TagID
		}
	}
	return ids, nil
}

func captureResultTagIdentity(result *PlanResult, query PlanQuery, vocabulary flow.QueryVocabulary) error {
	if query.Tags == nil {
		return nil
	}
	revision, err := query.Tags.Revision(query.TenantID)
	if err != nil {
		return err
	}
	ids, err := resultTagIDs(*result, vocabulary)
	if err != nil {
		return err
	}
	result.TagTenantID, result.TagRevision, result.TagIDs = query.TenantID, revision, ids
	return nil
}
