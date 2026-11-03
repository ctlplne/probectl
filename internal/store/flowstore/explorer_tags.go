// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

var ErrTagQueryScope = errors.New("flow tag lookup is not bound to this tenant")

// TagQueryData is an immutable, revision-pinned lookup from one tenant's
// uniquely owned exporter addresses. A raw row's claimed agent ID is absent
// from the API and cannot choose an overlapping routing context.
type TagQueryData struct {
	tenantID             string
	revision             int64
	vocabulary           flow.QueryVocabulary
	exporters            map[string]map[string]string
	contextAuthorization string
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
			if !ok || field.TagKey != key || tags.ValidateValue(value) != nil {
				return nil, ErrTagQueryScope
			}
			used += 128 + int64(len(key)+len(value))
			if used > maxBytes {
				return nil, ErrExplorerBudget
			}
			values[key] = value
		}
		for index, entries := range projection.Interfaces {
			used += 128
			if used > maxBytes {
				return nil, ErrExplorerBudget
			}
			if index == 0 {
				return nil, ErrTagQueryScope
			}
			for key, value := range entries {
				field, ok := vocabulary.Lookup("tag.in_interface." + key)
				if !ok || field.TagKey != "in_interface."+key || tags.ValidateValue(value) != nil {
					return nil, ErrTagQueryScope
				}
				lookup := "interface." + strconv.FormatUint(uint64(index), 10) + "." + key
				used += 128 + int64(len(lookup)+len(value))
				if used > maxBytes {
					return nil, ErrExplorerBudget
				}
				values[lookup] = value
			}
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

// WithContextAuthorization returns an immutable copy bound to the server's
// context-policy decision digest. It accepts no public query grammar.
func (d *TagQueryData) WithContextAuthorization(tenantID, digest string) (*TagQueryData, error) {
	if _, err := d.Revision(tenantID); err != nil {
		return nil, err
	}
	if len(digest) != 64 {
		return nil, ErrTagQueryScope
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return nil, ErrTagQueryScope
	}
	cloned := *d
	cloned.contextAuthorization = digest
	return &cloned, nil
}

func (d *TagQueryData) ContextAuthorization(tenantID string) (string, error) {
	if _, err := d.Revision(tenantID); err != nil || d.contextAuthorization == "" {
		return "", ErrTagQueryScope
	}
	return d.contextAuthorization, nil
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

// An index is meaningful only beneath this tenant's owned exporter lookup.
// The raw sender ID is deliberately absent from the selection operation.
func (d *TagQueryData) valueForRow(row Row, key string) (string, error) {
	if _, err := d.Revision(row.TenantID); err != nil {
		return "", err
	}
	subject, name, qualified := strings.Cut(key, ".")
	if !qualified || (subject != "in_interface" && subject != "out_interface") {
		return d.Value(row.TenantID, row.Exporter, key)
	}
	field, ok := d.vocabulary.Lookup("tag." + key)
	if !ok || field.TagKey != key {
		return "", ErrTagQueryScope
	}
	index := row.InIf
	if subject == "out_interface" {
		index = row.OutIf
	}
	if index == 0 {
		return "", nil
	}
	return d.valueTrusted(row.Exporter, "interface."+strconv.FormatUint(uint64(index), 10)+"."+name), nil
}

func (d *TagQueryData) valueTrusted(exporter, key string) string {
	address, err := netip.ParseAddr(exporter)
	if err != nil || address.Zone() != "" {
		return ""
	}
	return d.exporters[address.Unmap().String()][key]
}

// ExternalRows is the fixed-schema JSONEachRow body for one request-local
// ClickHouse external table. All literals stay in the HTTPS multipart body;
// the query joins on both lookup_tenant and lookup_exporter.
func (d *TagQueryData) ExternalRows(tenantID string, maxBytes int64) ([]byte, error) {
	if _, err := d.Revision(tenantID); err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		return nil, ErrExplorerBudget
	}
	addresses := make([]string, 0, len(d.exporters))
	for address := range d.exporters {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	var body bytes.Buffer
	for _, address := range addresses {
		row, err := json.Marshal(struct {
			Tenant   string            `json:"lookup_tenant"`
			Exporter string            `json:"lookup_exporter"`
			Values   map[string]string `json:"tag_values"`
		}{Tenant: tenantID, Exporter: address, Values: d.exporters[address]})
		if err != nil {
			return nil, err
		}
		if int64(body.Len()+len(row)+1) > maxBytes {
			return nil, ErrExplorerBudget
		}
		body.Write(row)
		body.WriteByte('\n')
	}
	return body.Bytes(), nil
}
