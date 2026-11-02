// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

func TestCMDBNetBoxTenantMapConfiguration(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const key = "PROBECTL_CMDB_NETBOX_TENANT_MAP"
	cfg, err := Load(envFunc(map[string]string{key: `{"` + tenant + `":"7"}`}))
	if err != nil || cfg.CMDBNetBoxTenantMap[tenant] != "7" {
		t.Fatalf("valid NetBox mapping was not loaded: %v", err)
	}
	for _, raw := range []string{`null`, `{"tenant":"7"}`, `{"` + tenant + `":"7","` + tenant + `":"8"}`} {
		if _, err := Load(envFunc(map[string]string{key: raw})); err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("unsafe NetBox mapping accepted: %s: %v", raw, err)
		}
	}
}
