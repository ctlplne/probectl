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

func TestNMSImportDeploymentPolicyFailsClosed(t *testing.T) {
	defaultConfig, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultConfig.NMSImportApprovedCIDRs) != 0 || defaultConfig.NMSImportRefPrefix != "" {
		t.Fatal("live NMS import gained default egress or a secret namespace")
	}
	valid := map[string]string{
		"PROBECTL_NMS_IMPORT_APPROVED_CIDRS": "10.42.0.0/16,127.0.0.0/8",
		"PROBECTL_NMS_IMPORT_REF_PREFIX":     "vault:probectl/nms/{tenant}/",
		"PROBECTL_NMS_IMPORT_TIMEOUT":        "12s",
	}
	cfg, err := Load(envFunc(valid))
	if err != nil || len(cfg.NMSImportApprovedCIDRs) != 2 || cfg.NMSImportTimeout != 12*time.Second {
		t.Fatalf("approved import policy: cfg=%+v err=%v", cfg, err)
	}
	for _, item := range []struct {
		name  string
		patch map[string]string
		want  string
	}{
		{"missing namespace", map[string]string{"PROBECTL_NMS_IMPORT_REF_PREFIX": ""}, "PROBECTL_NMS_IMPORT_REF_PREFIX"},
		{"missing CIDRs", map[string]string{"PROBECTL_NMS_IMPORT_APPROVED_CIDRS": ""}, "PROBECTL_NMS_IMPORT_APPROVED_CIDRS"},
		{"invalid CIDR", map[string]string{"PROBECTL_NMS_IMPORT_APPROVED_CIDRS": "not-a-prefix"}, "PROBECTL_NMS_IMPORT_APPROVED_CIDRS"},
		{"environment secret", map[string]string{"PROBECTL_NMS_IMPORT_REF_PREFIX": "env:{tenant}/"}, "PROBECTL_NMS_IMPORT_REF_PREFIX"},
		{"unbounded timeout", map[string]string{"PROBECTL_NMS_IMPORT_TIMEOUT": "31s"}, "PROBECTL_NMS_IMPORT_TIMEOUT"},
		{"unreadable CA", map[string]string{"PROBECTL_NMS_IMPORT_CA_FILE": "/missing/nms-import-ca.pem"}, "PROBECTL_NMS_IMPORT_CA_FILE"},
	} {
		t.Run(item.name, func(t *testing.T) {
			env := make(map[string]string, len(valid))
			for key, value := range valid {
				env[key] = value
			}
			for key, value := range item.patch {
				env[key] = value
			}
			if _, err := Load(envFunc(env)); err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("invalid policy was accepted or misreported: %v", err)
			}
		})
	}
}
