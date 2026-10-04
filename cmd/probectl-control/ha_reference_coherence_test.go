// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// PLAT-02 (supersedes the RESIL-004 doc-string match): the medium production
// reference runs multiple control-plane replicas, which is read-coherent ONLY
// on shared durable backends — a real broker for the per-replica bus fan-in,
// plus a shared TSDB and ClickHouse stores. On the in-memory defaults each
// replica answers /v1/results/latest, topology, TLS and endpoint from its own
// slice of the stream, so the same query changes pod to pod. This test asserts
// over the ACTUALLY-RENDERED manifests (not prose): the chart refuses the HA
// profile on memory stores and accepts it once durable endpoints are supplied.

// haDurableBackend is one durable-backend requirement of the HA profile: a
// human name and the single --set-string pair that satisfies it. The guard
// must require EVERY one of these — a shared bus (mode + brokers), a shared TSDB
// (mode + url) and a shared ClickHouse store (mode + url) for each telemetry
// plane — because any single in-memory backend makes a multi-replica read
// diverge pod-to-pod (PLAT-02).
type haDurableBackend struct {
	name string
	flag [2]string
}

var haDurableBackends = []haDurableBackend{
	{"bus mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_BUS_MODE=kafka"}},
	{"bus brokers", [2]string{"--set-string", "control.extraEnv.PROBECTL_BUS_BROKERS=kafka.probectl.svc:9093"}},
	{"tsdb mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_TSDB_MODE=prometheus"}},
	{"tsdb url", [2]string{"--set-string", "control.extraEnv.PROBECTL_TSDB_URL=https://prometheus.probectl.svc:9090"}},
	{"pathstore mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_PATHSTORE_MODE=clickhouse"}},
	{"pathstore url", [2]string{"--set-string", "control.extraEnv.PROBECTL_PATHSTORE_URL=https://clickhouse.probectl.svc:8443"}},
	{"flowstore mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_FLOWSTORE_MODE=clickhouse"}},
	{"flowstore url", [2]string{"--set-string", "control.extraEnv.PROBECTL_FLOWSTORE_URL=https://clickhouse.probectl.svc:8443"}},
	{"otelstore mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_OTELSTORE_MODE=clickhouse"}},
	{"otelstore url", [2]string{"--set-string", "control.extraEnv.PROBECTL_OTELSTORE_URL=https://clickhouse.probectl.svc:8443"}},
	{"ebpfstore mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_EBPFSTORE_MODE=clickhouse"}},
	{"ebpfstore url", [2]string{"--set-string", "control.extraEnv.PROBECTL_EBPFSTORE_URL=https://clickhouse.probectl.svc:8443"}},
	{"endpointstore mode", [2]string{"--set-string", "control.extraEnv.PROBECTL_ENDPOINTSTORE_MODE=clickhouse"}},
	{"endpointstore url", [2]string{"--set-string", "control.extraEnv.PROBECTL_ENDPOINTSTORE_URL=https://clickhouse.probectl.svc:8443"}},
}

// haDurableSets supplies a complete durable backend set for the HA profile. It
// omits the backend named by skip (empty string omits nothing), so a caller can
// prove the chart refuses the profile when any single durable backend is
// missing, not only when all are.
func haDurableSets(skip string) []string {
	var out []string
	for _, backend := range haDurableBackends {
		if backend.name == skip {
			continue
		}
		out = append(out, backend.flag[0], backend.flag[1])
	}
	return out
}

// renderMediumConfigMap renders values-medium.yaml's ConfigMap. trustedProxies
// is set explicitly so the only variable under test is the PLAT-02 HA-durable
// guard (the AUTHZ-04 ingress guard is satisfied regardless of helm version).
func renderMediumConfigMap(t *testing.T, extra ...string) ([]byte, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"-f", "deploy/helm/probectl/values-medium.yaml",
		"--show-only", "templates/configmap.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "control.trustedProxies={10.244.0.0/16}",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.existingSecret=probectl-secrets",
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	return cmd.CombinedOutput()
}

func TestMediumHAReferenceRequiresDurableBackends(t *testing.T) {
	requireOrSkipHelm(t)
	values := readArtifact(t, "deploy/helm/probectl/values-medium.yaml")

	// The reference must actually declare >1 replica (else there is no HA to make
	// coherent), with a PDB that does not exceed it.
	replicas := topLevelInt(t, values, "replicaCount")
	if replicas < 2 {
		t.Fatalf("values-medium.yaml replicaCount must be >= 2, got %d", replicas)
	}
	if minAvail, ok := nestedInt(values, "podDisruptionBudget", "minAvailable"); ok && minAvail > replicas {
		t.Errorf("podDisruptionBudget.minAvailable=%d exceeds replicaCount=%d — voluntary disruptions/upgrades would be blocked (OPS-010)", minAvail, replicas)
	}

	// On the in-memory defaults the multi-replica render MUST be refused.
	out, err := renderMediumConfigMap(t)
	if err == nil {
		t.Fatalf("multi-replica values-medium.yaml rendered on in-memory stores — reads would diverge pod to pod (PLAT-02)")
	}
	if !strings.Contains(string(out), "multi-replica HA") {
		t.Fatalf("the refusal must explain the multi-replica durability requirement; got:\n%s", out)
	}

	// With a shared durable bus + TSDB + stores, it renders, and the rendered
	// ConfigMap carries exactly those durable modes.
	out, err = renderMediumConfigMap(t, haDurableSets("")...)
	if err != nil {
		t.Fatalf("values-medium.yaml with durable backends must render; got %v\n%s", err, out)
	}
	cm := string(out)
	for _, want := range []string{
		`PROBECTL_BUS_MODE: "kafka"`,
		`PROBECTL_TSDB_MODE: "prometheus"`,
		`PROBECTL_FLOWSTORE_MODE: "clickhouse"`,
		`PROBECTL_OTELSTORE_MODE: "clickhouse"`,
		`PROBECTL_EBPFSTORE_MODE: "clickhouse"`,
		`PROBECTL_ENDPOINTSTORE_MODE: "clickhouse"`,
		`PROBECTL_PATHSTORE_MODE: "clickhouse"`,
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("rendered medium HA ConfigMap is missing durable mode %q:\n%s", want, cm)
		}
	}
}

// TestMediumHARefusesEachMissingDurableBackend is the PLAT-11 strengthening of
// the all-or-nothing check above. The previous test proved only that a render
// with ZERO durable backends is refused and a render with ALL of them succeeds;
// a stub guard that inspected just one backend (say, the bus) would pass it
// while still letting an in-memory ClickHouse store through — reads would then
// diverge pod-to-pod on that plane. This test supplies every durable backend
// but one, for each backend in turn, and requires the chart to REFUSE every
// such incomplete profile, naming the HA-durability guard — so the guard must
// require the complete shared-backend set, not a convenient subset.
func TestMediumHARefusesEachMissingDurableBackend(t *testing.T) {
	requireOrSkipHelm(t)
	for _, backend := range haDurableBackends {
		t.Run(backend.name, func(t *testing.T) {
			out, err := renderMediumConfigMap(t, haDurableSets(backend.name)...)
			if err == nil {
				t.Fatalf("values-medium.yaml rendered while missing the durable %s — a multi-replica read on that backend would diverge pod to pod (PLAT-02); rendered:\n%s", backend.name, out)
			}
			// The refusal must come from the PLAT-02 HA-durability guard, not an
			// unrelated chart error, so the gate actually proves the durability
			// requirement rather than any failure to render.
			if !strings.Contains(string(out), "multi-replica HA") {
				t.Fatalf("omitting the durable %s was refused for the wrong reason; the HA-durability guard must fire. got:\n%s", backend.name, out)
			}
		})
	}
}

// topLevelInt reads a `key: <int>` at column 0 of a YAML doc.
func topLevelInt(t *testing.T, doc, key string) int {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:\s*(\d+)\s*$`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("could not find top-level %q in values", key)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// nestedInt reads `parent:\n  child: <int>` (one level of nesting).
func nestedInt(doc, parent, child string) (int, bool) {
	re := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(parent) + `:.*?^\s+` + regexp.QuoteMeta(child) + `:\s*(\d+)`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}
