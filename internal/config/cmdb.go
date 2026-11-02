// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"errors"
	"net/url"
	"strings"

	"github.com/ctlplne/probectl/internal/cmdb"
)

func (l *loader) netBoxTenantMap() map[string]string {
	const key = "PROBECTL_CMDB_NETBOX_TENANT_MAP"
	bindings, err := cmdb.ParseNetBoxTenantMap(l.str("PROBECTL_CMDB_NETBOX_TENANT_MAP", ""))
	if err != nil {
		l.errf("%s must map canonical tenant UUIDs to distinct positive NetBox tenant ID strings", key)
	}
	return bindings
}

// Credentials travel only in CMDBSecret, never in URLs or startup logs
// (docs/guardrails.md G7-6).
func validateCMDBEndpoint(raw string) error {
	const name = "PROBECTL_CMDB_URL"
	if err := validateHTTPSOrLoopbackHTTP(raw, name); err != nil {
		return err
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(raw, "#") {
		return errors.New("PROBECTL_CMDB_URL must not contain credentials, query parameters or fragments; use PROBECTL_CMDB_SECRET")
	}
	return nil
}
