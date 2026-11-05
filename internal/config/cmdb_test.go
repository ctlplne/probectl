// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
	"time"
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

func TestCMDBCompleteLookupCapacityProfiles(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil || cfg.CMDBLookupTimeout != 15*time.Second || cfg.CMDBResponseBytes != 4<<20 || cfg.CMDBMemoryBytes != 512<<20 {
		t.Fatal("complete lookup default profile drifted", err)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_CMDB_LOOKUP_TIMEOUT": "25h", "PROBECTL_CMDB_MAX_RESPONSE_BYTES": "67108864", "PROBECTL_CMDB_MEMORY_BYTES": "4294967296"}))
	if err != nil || cfg.CMDBLookupTimeout != 25*time.Hour || cfg.CMDBResponseBytes != 64<<20 || cfg.CMDBMemoryBytes != 4<<30 {
		t.Fatal("larger finite complete lookup profile refused", err)
	}
	for _, key := range []string{"PROBECTL_CMDB_LOOKUP_TIMEOUT", "PROBECTL_CMDB_MAX_RESPONSE_BYTES", "PROBECTL_CMDB_MEMORY_BYTES"} {
		for _, value := range []string{"0", "-1"} {
			if _, err := Load(envFunc(map[string]string{key: value})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("nonpositive operation admission accepted: %s=%s err=%v", key, value, err)
			}
		}
	}
}

func TestCMDBEndpointRefusesURLCredentialsAndSecretCarriers(t *testing.T) {
	for _, provider := range []string{"netbox", "servicenow"} {
		for _, endpoint := range []string{
			"https://user:private-pass@cmdb.example",
			"https://cmdb.example?token=private-token",
			"https://cmdb.example?", "https://cmdb.example#private-token",
			"https://", "http://cmdb.example",
		} {
			_, err := Load(envFunc(map[string]string{"PROBECTL_CMDB_PROVIDER": provider,
				"PROBECTL_CMDB_URL": endpoint, "PROBECTL_CMDB_SECRET": "test-token"}))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_CMDB_URL") ||
				strings.Contains(err.Error(), "private-pass") || strings.Contains(err.Error(), "private-token") {
				t.Fatal("unsafe CMDB endpoint was accepted or its credential reached a validation error")
			}
		}
	}
	for _, endpoint := range []string{"https://cmdb.example/netbox", "http://127.0.0.1:18443"} {
		if _, err := Load(envFunc(map[string]string{"PROBECTL_CMDB_PROVIDER": "netbox",
			"PROBECTL_CMDB_URL": endpoint, "PROBECTL_CMDB_SECRET": "test-token"})); err != nil {
			t.Fatalf("safe CMDB endpoint rejected: %v", err)
		}
	}
}
