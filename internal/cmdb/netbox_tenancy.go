// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ErrTenantBinding never discloses a source tenant or candidate CI.
var ErrTenantBinding = errors.New("cmdb: source tenant binding is unavailable or inconsistent")

// ParseNetBoxTenantMap reads deployment-owned tenant UUID to NetBox tenant ID
// configuration. Duplicate keys or source IDs are rejected instead of choosing
// one owner. A tenant cannot configure this map through a telemetry/API body.
func ParseNetBoxTenantMap(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > 1<<20 {
		return nil, ErrTenantBinding
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrTenantBinding
	}
	bindings := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, ErrTenantBinding
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrTenantBinding
		}
		if _, exists := bindings[key]; exists {
			return nil, ErrTenantBinding
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrTenantBinding
		}
		bindings[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrTenantBinding
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrTenantBinding
	}
	return validatedNetBoxTenantMap(bindings)
}

func validatedNetBoxTenantMap(bindings map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(bindings))
	sources := make(map[string]bool, len(bindings))
	for tenant, source := range bindings {
		id, err := uuid.Parse(tenant)
		if err != nil || id == uuid.Nil || id.String() != tenant {
			return nil, ErrTenantBinding
		}
		number, err := strconv.ParseInt(source, 10, 64)
		if err != nil || number <= 0 || strconv.FormatInt(number, 10) != source || sources[source] {
			return nil, ErrTenantBinding
		}
		sources[source] = true
		out[tenant] = source
	}
	return out, nil
}

func (n *NetBox) sourceTenant(ctx context.Context) (string, string, error) {
	if n == nil || n.bindingErr != nil {
		return "", "", ErrTenantBinding
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || n.tenants[tenant.String()] == "" {
		return "", "", ErrTenantBinding
	}
	return tenant.String(), n.tenants[tenant.String()], nil
}

// cacheScope prevents even a stale enrichment hit crossing a tenant mapping.
// It is resolved before the resolver reads its cache or calls the provider.
func (n *NetBox) cacheScope(ctx context.Context) (string, error) {
	tenant, source, err := n.sourceTenant(ctx)
	if err != nil {
		return "", err
	}
	return tenant + "\x00" + source, nil
}

type netBoxTenant struct {
	ID int64 `json:"id"`
}

func (t *netBoxTenant) matches(source string) bool {
	return t != nil && t.ID > 0 && strconv.FormatInt(t.ID, 10) == source
}

// NetBox is untrusted input. Reject duplicate/case-aliased ownership fields
// before encoding/json can silently select their last occurrence.
func validateNetBoxJSON(body []byte) error {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrTenantBinding
	}
	if err := scanNetBoxContainer(decoder, '{', 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrTenantBinding
	}
	return nil
}

func scanNetBoxContainer(decoder *json.Decoder, kind json.Delim, depth int) error {
	if depth > 64 {
		return ErrTenantBinding
	}
	seen := map[string]bool{}
	for decoder.More() {
		if kind == '{' {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[strings.ToLower(key)] {
				return ErrTenantBinding
			}
			seen[strings.ToLower(key)] = true
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrTenantBinding
		}
		if nested, ok := token.(json.Delim); ok {
			if nested != '{' && nested != '[' {
				return ErrTenantBinding
			}
			if err := scanNetBoxContainer(decoder, nested, depth+1); err != nil {
				return err
			}
		}
	}
	want := json.Delim('}')
	if kind == '[' {
		want = ']'
	}
	if token, err := decoder.Token(); err != nil || token != want {
		return ErrTenantBinding
	}
	return nil
}
