// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestE2EStoresRunTheProductionTLSShape pins beta gate G6's store half of
// TQ-03: the black-box e2e runs the release image against its bus and
// telemetry stores the way production does (docs/guardrails.md G7-12), not on
// the dev stack's plaintext shortcuts. Before this gate the e2e published to a
// plaintext Kafka listener under PROBECTL_BUS_ALLOW_PLAINTEXT and
// PROBECTL_EBPF_BUS_ALLOW_PLAINTEXT and had no ClickHouse at all, so neither
// the broker TLS path nor the DPR-285 reader login ever ran in CI against the
// shipped image.
//
// It fails when test/e2e regains a plaintext bus flag or listener, or loses any
// part of the TLS wiring: the broker's SASL_SSL/SSL listener map, the control
// plane's and the collectors' TLS + CA settings, the certgen SANs those
// listeners are verified against, and ClickHouse over HTTPS on every telemetry
// plane with tenant scoping, the reader login, both credential files, the
// shipped TLS-only server config and login provisioning, and the restart that
// re-runs the reader self-check over non-empty tables.
func TestE2EStoresRunTheProductionTLSShape(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "test", "e2e")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Any spelling of a plaintext bus: the agents' and control plane's dev-only
	// flag, a PLAINTEXT or SASL_PLAINTEXT listener or client protocol, or a
	// plaintext ClickHouse endpoint.
	forbidden := regexp.MustCompile(`ALLOW_PLAINTEXT|PLAINTEXT|http://clickhouse|:8123\b|STORE_MODE":\s+"memory"`)
	var all strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		for _, loc := range forbidden.FindAllStringIndex(body, -1) {
			line := strings.Count(body[:loc[0]], "\n") + 1
			t.Errorf("G6/TQ-03: test/e2e/%s:%d uses a plaintext store path (%q); the e2e must reach the bus and ClickHouse over TLS as production does",
				e.Name(), line, body[loc[0]:loc[1]])
		}
		all.WriteString(body)
		all.WriteString("\n")
	}
	e2e := all.String()

	for _, want := range []struct{ pattern, why string }{
		// Kafka: every listener is TLS, client listeners authenticated.
		{`KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:SSL,EXTERNAL:SASL_SSL,INTERNAL:SASL_SSL\n`, "the broker serves SASL_SSL on its client listeners and SSL on its controller listener"},
		{`KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM: https\n`, "the broker verifies the controller hop's hostname"},
		{`ssl.endpoint.identification.algorithm=https`, "the admin tools verify the broker's hostname"},
		{`PROBECTL_CERT_HOSTS=localhost,127.0.0.1,postgres,kafka,clickhouse"`, "certgen issues the kafka and clickhouse SANs every hop is verified against"},
		// The control plane's bus.
		{`"PROBECTL_BUS_TLS_ENABLED":\s+"true"`, "the control plane dials the broker over TLS"},
		{`"PROBECTL_BUS_TLS_CA_FILE":\s+ctl\.path\(t, serverCA\)`, "the control plane verifies the broker against the run's CA"},
		{`"PROBECTL_BUS_SASL_MECHANISM":\s+"plain"`, "the control plane authenticates to the broker"},
		// The collectors' bus.
		{`prefix \+ "_BUS_TLS_ENABLED=true"`, "the fixture collectors dial the broker over TLS"},
		{`prefix \+ "_BUS_TLS_CA_FILE=" \+ caFile`, "the fixture collectors verify the broker against the run's CA"},
		{`collectorBusEnv\("PROBECTL_EBPF", serverCA, secrets\)`, "the eBPF fixture agents get the TLS bus settings"},
		// ClickHouse over HTTPS with the reader login on every plane.
		{`clickhouseURL = "https://clickhouse:8443"`, "every ClickHouse lane is HTTPS"},
		{`clickhousePlanes = \[\]string\{"pathstore", "flowstore", "otelstore", "ebpfstore", "endpointstore"\}`, "all five telemetry planes run on ClickHouse"},
		{`env\[key\+"_MODE"\] = "clickhouse"`, "each plane's store mode is clickhouse"},
		{`env\[key\+"_URL"\] = clickhouseURL`, "each plane's store URL is the HTTPS endpoint"},
		{`env\[key\+"_TENANT_SCOPING"\] = "true"`, "each plane is tenant-scoped at the database"},
		{`env\[key\+"_READER_USER"\] = clickhouseReaderUser`, "each plane's row policy binds the reader login"},
		{`"PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE":\s+ctl\.path`, "the control login's credential is a file"},
		{`"PROBECTL_CLICKHOUSE_READER_BASIC_AUTH_FILE":\s+ctl\.path`, "the reader login's credential is a file (DPR-285)"},
		{`"SSL_CERT_FILE":\s+ctl\.path\(t, serverCA\)`, "the HTTPS ClickHouse hop is verified against the run's CA"},
		{`\./prod/clickhouse/tls\.xml:/etc/clickhouse-server/config\.d/`, "ClickHouse runs the shipped TLS-only server config"},
		{`\./prod/clickhouse/users\.xml:/etc/clickhouse-server/users\.d/`, "ClickHouse runs the shipped fail-closed tenant-setting default"},
		{`\./prod/clickhouse-init\.sh:/prod/clickhouse-init\.sh`, "the shipped clickhouse-init.sh provisions the control and reader logins"},
		{`\n\tprovisionClickHouseLogins\(t, root, stack\)\n`, "TestE2E runs the login provisioning"},
		// The reads and the boot self-check over non-empty tables.
		{`\n\tassertClickHouseReads\(t, a, b\)\n\trestartAndReverify\(t, ctl, anon, controlRunning\)\n\tassertClickHouseReads\(t, a, b\)\n`, "TestE2E proves the per-tenant ClickHouse reads, then restarts so the reader self-check runs over rows"},
		{`ClickHouse tenant reads run as the policy-bound reader login`, "the restart must see every plane's reader self-check pass"},
	} {
		if !regexp.MustCompile(want.pattern).MatchString(e2e) {
			t.Errorf("G6/TQ-03: test/e2e lost its production store wiring: %s (pattern %q not found)", want.why, want.pattern)
		}
	}
}
