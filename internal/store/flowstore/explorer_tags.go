// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"net/netip"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

var ErrTagQueryScope = errors.New("flow tag lookup is not bound to this tenant")

// TagQueryData is an immutable, revision-pinned lookup from one tenant's
// uniquely owned exporter addresses. A raw row's claimed agent ID is absent
// from the API and cannot choose an overlapping routing context.
type TagQueryData struct {
	tenantID   string
	revision   int64
	vocabulary flow.QueryVocabulary
	exporters  map[string]map[string]string
}

func NewTagQueryData(tenantID string, revision int64, definitions []tags.Definition,
	projections []tags.ExporterProjection, maxBytes int64) (*TagQueryData, error) {
	if revision <= 0 || maxBytes <= 0 {
		return nil, ErrTagQueryScope
	}
	vocabulary, err := flow.NewTagQueryVocabulary(tenantID, definitions)
	if err != nil {
		return nil, err
	}
	if int64(len(projections)) > maxBytes/256 {
		return nil, ErrExplorerBudget
	}
	result := &TagQueryData{tenantID: tenantID, revision: revision,
		vocabulary: vocabulary, exporters: make(map[string]map[string]string, len(projections))}
	used := int64(0)
	for _, projection := range projections {
		address, err := netip.ParseAddr(projection.Exporter)
		if err != nil || address.Zone() != "" || address.Unmap().String() != projection.Exporter {
			return nil, ErrTagQueryScope
		}
		if _, exists := result.exporters[projection.Exporter]; exists {
			return nil, ErrTagQueryScope
		}
		used += 256 + int64(len(projection.Exporter))
		if used > maxBytes {
			return nil, ErrExplorerBudget
		}
		values := make(map[string]string, len(projection.Values))
		for key, value := range projection.Values {
			field, ok := vocabulary.Lookup("tag." + key)
			if !ok || field.TagKey != key || value == "" || len(value) > 128 {
				return nil, ErrTagQueryScope
			}
			used += 128 + int64(len(key)+len(value))
			if used > maxBytes {
				return nil, ErrExplorerBudget
			}
			values[key] = value
		}
		result.exporters[projection.Exporter] = values
	}
	return result, nil
}

func (d *TagQueryData) Revision(tenantID string) (int64, error) {
	if d == nil || d.tenantID == "" || d.tenantID != tenantID || d.revision <= 0 {
		return 0, ErrTagQueryScope
	}
	return d.revision, nil
}

func (d *TagQueryData) Vocabulary(tenantID string) (flow.QueryVocabulary, error) {
	if _, err := d.Revision(tenantID); err != nil {
		return flow.QueryVocabulary{}, err
	}
	return d.vocabulary, nil
}

// Value returns the explicit unmatched empty value for an address/key with
// no valid tenant binding or assignment. Callers present it as "Unmatched".
func (d *TagQueryData) Value(tenantID, exporter, key string) (string, error) {
	if _, err := d.Revision(tenantID); err != nil {
		return "", err
	}
	field, ok := d.vocabulary.Lookup("tag." + key)
	if !ok || field.TagKey != key {
		return "", ErrTagQueryScope
	}
	return d.valueTrusted(exporter, key), nil
}

func (d *TagQueryData) valueTrusted(exporter, key string) string {
	address, err := netip.ParseAddr(exporter)
	if err != nil || address.Zone() != "" {
		return ""
	}
	return d.exporters[address.Unmap().String()][key]
}
