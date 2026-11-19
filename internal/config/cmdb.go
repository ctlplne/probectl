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

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ServiceNowCMDBTenant binds the deployment-wide credential to one tenant.
// Older single-profile installs default to the established seeded tenant.
func (c *Config) ServiceNowCMDBTenant() tenancy.ID {
	if c.CMDBServiceNowTenantID == "" && (c.DeploymentProfile == "single" || c.DeploymentProfile == "") {
		return tenancy.DefaultTenantID
	}
	return tenancy.ID(c.CMDBServiceNowTenantID)
}

func validateServiceNowTenant(l *loader, cfg *Config) {
	if cfg.CMDBProvider != "servicenow" && cfg.CMDBServiceNowTenantID == "" {
		return
	}
	const key = "PROBECTL_CMDB_SERVICENOW_TENANT_ID"
	owner := cfg.ServiceNowCMDBTenant().String()
	id, err := uuid.Parse(owner)
	if err != nil || id == uuid.Nil || id.String() != owner {
		l.errf("%s must be a canonical nonzero tenant UUID; ServiceNow in multi-tenant and regulated profiles requires an explicit owner", key)
	}
}

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
