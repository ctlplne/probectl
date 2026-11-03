// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

// QueryVocabulary is the immutable, request-local field registry for one
// tenant tag revision. The native registry remains process-wide and cannot
// be changed by a tenant's definitions.
type QueryVocabulary struct {
	tenantID string
	byName   map[string]QueryField
	tagIDs   map[string]bool
}

type queryVocabularyContextKey struct{}

// WithQueryVocabulary binds a tenant-validated field registry to a single
// saved-configuration operation. Storage can revalidate fields under its own
// transaction without trusting a client-supplied key or process-global state.
func WithQueryVocabulary(ctx context.Context, tenant string, vocabulary QueryVocabulary) (context.Context, error) {
	if tenant == "" || vocabulary.tenantID != tenant {
		return nil, tags.ErrScopeMismatch
	}
	return context.WithValue(ctx, queryVocabularyContextKey{}, vocabulary), nil
}

// QueryVocabularyFromContext refuses a registry from a different tenant.
func QueryVocabularyFromContext(ctx context.Context, tenant string) (QueryVocabulary, bool, error) {
	vocabulary, ok := ctx.Value(queryVocabularyContextKey{}).(QueryVocabulary)
	if !ok {
		return QueryVocabulary{}, false, nil
	}
	if tenant == "" || vocabulary.tenantID != tenant {
		return QueryVocabulary{}, false, tags.ErrScopeMismatch
	}
	return vocabulary, true, nil
}

// NewTagQueryVocabulary accepts definitions only from a tenant-scoped read
// snapshot. It still checks every key, ID and tenant before making a field
// available to normalization or SQL compilation.
func NewTagQueryVocabulary(tenantID string, definitions []tags.Definition) (QueryVocabulary, error) {
	if id, err := uuid.Parse(tenantID); err != nil || id == uuid.Nil || id.String() != tenantID {
		return QueryVocabulary{}, tags.ErrScopeMismatch
	}
	if len(definitions) > tags.MaxDefinitions {
		return QueryVocabulary{}, tags.ErrInvalid
	}
	vocab := QueryVocabulary{tenantID: tenantID,
		byName: make(map[string]QueryField, len(definitions)),
		tagIDs: make(map[string]bool, len(definitions))}
	for _, def := range definitions {
		id, err := uuid.Parse(def.ID)
		if def.TenantID != tenantID || err != nil || id == uuid.Nil || id.String() != def.ID {
			return QueryVocabulary{}, tags.ErrScopeMismatch
		}
		if err := tags.ValidateKey(def.Key); err != nil {
			return QueryVocabulary{}, err
		}
		if _, exists := vocab.byName["tag."+def.Key]; exists || vocab.tagIDs[def.ID] {
			return QueryVocabulary{}, tags.ErrConflict
		}
		for _, subject := range []struct{ qualifier, permission, column string }{
			{"", "tags.read", ""}, {"device.", "metrics.read", ""}, {"agent.", "agent.read", ""},
			{"in_interface.", "metrics.read", "in_if"}, {"out_interface.", "metrics.read", "out_if"},
			{"src_prefix.", "entities.read", "src_addr"}, {"dst_prefix.", "entities.read", "dst_addr"},
		} {
			key := subject.qualifier + def.Key
			field := queryField("tag."+key, subject.column, QueryText, false, 0)
			field.Derived = "tenant_tag"
			field.TagID, field.TagKey = def.ID, key
			field.Permission = subject.permission
			vocab.byName[field.Name] = field
		}
		vocab.tagIDs[def.ID] = true
	}
	return vocab, nil
}

// Lookup resolves a native field or one of this tenant's exact tag keys.
// An unknown key cannot become SQL structure or select another tenant's tag.
func (v QueryVocabulary) Lookup(name string) (QueryField, bool) {
	if native, ok := LookupQueryField(name); ok {
		return native, true
	}
	if v.tenantID == "" {
		return QueryField{}, false
	}
	field, ok := v.byName[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return QueryField{}, false
	}
	field.Operators = append([]QueryOperator(nil), field.Operators...)
	return field, true
}

// QueryViewTagIDs records the immutable definitions used by a fully expanded
// saved query. A reference to a filter must be expanded before calling this.
func QueryViewTagIDs(plan QueryPlan, vocabulary QueryVocabulary) (map[string]string, error) {
	if vocabulary.tenantID == "" {
		return nil, tags.ErrScopeMismatch
	}
	names := append(append([]string{}, plan.GroupBy...), plan.MatrixWith...)
	names = append(names, QueryFilterFields(plan.Filter)...)
	ids := map[string]string{}
	for _, name := range names {
		if !strings.HasPrefix(name, "tag.") {
			continue
		}
		field, ok := vocabulary.Lookup(name)
		if !ok || field.Derived != "tenant_tag" || field.TagID == "" {
			return nil, ErrQueryViewStaleTag
		}
		ids[name] = field.TagID
	}
	return ids, nil
}

// VerifyQueryViewTagIDs rejects a rename, deletion, replacement or newly
// introduced tag predicate in a referenced saved filter.
func VerifyQueryViewTagIDs(saved map[string]string, plan QueryPlan, vocabulary QueryVocabulary) error {
	current, err := QueryViewTagIDs(plan, vocabulary)
	if err != nil {
		return err
	}
	if len(current) != len(saved) {
		return ErrQueryViewStaleTag
	}
	for name, id := range current {
		if saved[name] != id {
			return ErrQueryViewStaleTag
		}
	}
	return nil
}

// Fields is safe for an authorized tenant schema response. Callers must check
// tags.read before exposing the dynamic subset.
func (v QueryVocabulary) Fields() ([]QueryField, error) {
	if v.tenantID == "" {
		return nil, errors.New("tag query vocabulary is unbound")
	}
	fields := QueryFields()
	keys := make([]string, 0, len(v.byName))
	for key := range v.byName {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		field := v.byName[key]
		field.Operators = append([]QueryOperator(nil), field.Operators...)
		fields = append(fields, field)
	}
	return fields, nil
}
