// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

func TestArtifactAwareLintAcceptsCompleteReceipt(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	if diagnostics := LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)); len(diagnostics) != 0 {
		t.Fatalf("artifact-aware diagnostics = %v, want none", diagnostics)
	}
}

func TestStoreProofsAreNonVacuousAndHonest(t *testing.T) {
	zero := int64(0)
	one := int64(1)
	tests := []struct {
		name   string
		mutate func(*Receipt)
		code   string
	}{
		{name: "postgres empty seed", mutate: func(r *Receipt) { r.Stores.Postgres.SeededTenantARows = &zero }, code: "store-probe-failed"},
		{name: "postgres A visible to B", mutate: func(r *Receipt) { r.Stores.Postgres.TenantAToBVisibleRows = &one }, code: "store-probe-failed"},
		{name: "clickhouse missing release reader", mutate: func(r *Receipt) { r.Stores.ClickHouse.ReaderUser = "" }, code: "store-probe-failed"},
		{name: "clickhouse wrong proof kind", mutate: func(r *Receipt) { r.Stores.ClickHouse.ProofKind = PostgresProofKind }, code: "store-proof-kind-invalid"},
		{name: "kafka false product claim", mutate: func(r *Receipt) {
			yes := true
			r.Stores.Kafka.ProductMessagesObserved = &yes
			r.Stores.Kafka.ObservedProductMessages = &zero
		}, code: "store-probe-failed"},
		{name: "kafka reader isolation overclaim", mutate: func(r *Receipt) {
			yes := true
			r.Stores.Kafka.ReaderIsolationClaimed = &yes
		}, code: "store-proof-overclaim"},
		{name: "prometheus empty labels", mutate: func(r *Receipt) { r.Stores.Prometheus.ObservedTenantASeries = &zero }, code: "store-probe-failed"},
		{name: "prometheus isolation overclaim", mutate: func(r *Receipt) {
			yes := true
			r.Stores.Prometheus.IsolationClaimed = &yes
		}, code: "store-proof-overclaim"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := mustSelfTestReceipt(t, t.TempDir())
			test.mutate(&receipt)
			if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, test.code) {
				t.Fatalf("codes = %v, want %q", codes, test.code)
			}
		})
	}
}

func TestTLSRequiresEveryDirectionalListenerProbe(t *testing.T) {
	receipt := mustSelfTestReceipt(t, t.TempDir())
	delete(receipt.TLS.Listeners, "dex")
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-missing") {
		t.Fatalf("codes = %v, want tls-listener-missing", codes)
	}
	probe := receipt.TLS.Listeners["control"]
	no := false
	probe.PlaintextRejected = &no
	receipt.TLS.Listeners["control"] = probe
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-failed") {
		t.Fatalf("codes = %v, want tls-listener-failed", codes)
	}
	receipt = mustSelfTestReceipt(t, t.TempDir())
	otlp := receipt.TLS.Listeners["otlp_http"]
	no = false
	otlp.InvalidAuthenticationRejected = &no
	receipt.TLS.Listeners["otlp_http"] = otlp
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-failed") {
		t.Fatalf("OTLP invalid-auth codes = %v, want tls-listener-failed", codes)
	}
	receipt = mustSelfTestReceipt(t, t.TempDir())
	otlp = receipt.TLS.Listeners["otlp_http"]
	otlp.CertificateService = "otlp_http"
	receipt.TLS.Listeners["otlp_http"] = otlp
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-failed") {
		t.Fatalf("OTLP certificate-service codes = %v, want tls-listener-failed", codes)
	}
	receipt = mustSelfTestReceipt(t, t.TempDir())
	control := receipt.TLS.Listeners["control"]
	control.PeerCertificateSHA256 = ""
	receipt.TLS.Listeners["control"] = control
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-failed") {
		t.Fatalf("missing peer certificate fingerprint codes = %v, want tls-listener-failed", codes)
	}
	receipt = mustSelfTestReceipt(t, t.TempDir())
	control = receipt.TLS.Listeners["control"]
	control.PeerCertificateSHA256 = "sha256:" + strings.Repeat("A", 64)
	receipt.TLS.Listeners["control"] = control
	if codes := diagnosticCodes(Lint(receipt)); !slices.Contains(codes, "tls-listener-failed") {
		t.Fatalf("uppercase peer certificate fingerprint codes = %v, want tls-listener-failed", codes)
	}
}

func TestTLSListenerPeerFingerprintRejectsDeclaredLeafSplices(t *testing.T) {
	for _, listener := range requiredTLSListeners {
		t.Run(listener, func(t *testing.T) {
			root := t.TempDir()
			receipt := mustSelfTestReceipt(t, root)
			other := "dex"
			if listener == "dex" {
				other = "control"
			}
			probe := receipt.TLS.Listeners[listener]
			probe.PeerCertificateSHA256 = receipt.TLS.Listeners[other].PeerCertificateSHA256
			receipt.TLS.Listeners[listener] = probe
			writeTestJSON(t, filepath.Join(root, receipt.TLS.Artifact), tlsTrustArtifact(receipt.TLS))
			diagnostics := LintWithArtifactsAtSource(receipt, root, testSourceRoot(t))
			codes := diagnosticCodes(diagnostics)
			if !slices.Contains(codes, "tls-certificate-invalid") {
				t.Fatalf("codes = %v, want tls-certificate-invalid", codes)
			}
			if slices.Contains(codes, "artifact-summary-mismatch") {
				t.Fatalf("splice was rejected only as a summary mismatch: %v", diagnostics)
			}
		})
	}
}

func TestActivationAllowsEmptyDefaultTagsAndRejectsSyntheticOrTestTags(t *testing.T) {
	receipt := mustSelfTestReceipt(t, t.TempDir())
	receipt.Activation.BuildTags = []string{}
	if codes := diagnosticCodes(Lint(receipt)); slices.Contains(codes, "activation-unproven") {
		t.Fatalf("empty default build tags rejected: %v", codes)
	}
	for _, tag := range []string{"default", "dev", "test", "probectl-dev", "integration-test"} {
		t.Run(tag, func(t *testing.T) {
			candidate := receipt
			candidate.Activation.BuildTags = []string{tag}
			if codes := diagnosticCodes(Lint(candidate)); !slices.Contains(codes, "activation-unproven") {
				t.Fatalf("tag %q codes = %v, want activation-unproven", tag, codes)
			}
		})
	}
}

func TestCompletenessAuditActivationBindsCanonicalDocsPath(t *testing.T) {
	script, err := os.ReadFile(filepath.Join(testSourceRoot(t), "scripts", "run_completeness_audit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const binding = `docs_path:.docs_path`
	if !strings.Contains(string(script), `$activation + {schema:"probectl.delivery-audit-activation/v1",`+binding) {
		t.Fatalf("activation.json construction must bind %s from the hashed capability manifest", binding)
	}
}

func TestArtifactSummaryMismatchCannotBeSealed(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	two := int64(2)
	receipt.Stores.Postgres.SeededTenantARows = &two
	diagnostics := LintWithArtifactsAtSource(receipt, root, testSourceRoot(t))
	if codes := diagnosticCodes(diagnostics); !slices.Contains(codes, "artifact-summary-mismatch") {
		t.Fatalf("codes = %v, want artifact-summary-mismatch", codes)
	}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealWithSource(receipt, root, testSourceRoot(t), privatePEM); err == nil || !strings.Contains(err.Error(), "artifact-summary-mismatch") {
		t.Fatalf("SealWithSource error = %v, want artifact-summary-mismatch", err)
	}
}

func TestLiteralSelftestArtifactCannotPass(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	if err := os.WriteFile(filepath.Join(root, "stores.json"), []byte("selftest:stores\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	codes := diagnosticCodes(LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)))
	for _, want := range []string{"artifact-invalid", "fixture-only"} {
		if !slices.Contains(codes, want) {
			t.Fatalf("codes = %v, want %q", codes, want)
		}
	}
}

func TestScreenshotMustBeRealBoundPNG(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	if err := os.WriteFile(filepath.Join(root, "ui-a.png"), []byte(strings.Repeat("not-a-png", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if codes := diagnosticCodes(LintWithArtifactsAtSource(receipt, root, testSourceRoot(t))); !slices.Contains(codes, "ui-screenshot-invalid") {
		t.Fatalf("codes = %v, want ui-screenshot-invalid", codes)
	}
}

func TestStackInventoryRejectsMissingServiceAndFalseCredentialOwner(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	var stack StackInventoryArtifact
	readTestJSON(t, filepath.Join(root, "stack.json"), &stack)
	delete(stack.Services, "dex")
	kafka := stack.Runtime.TLSPrivateKeyFiles["kafka"]
	kafka.Path = "/audit/pki/kafka/tls.key"
	kafka.UID = 0
	kafka.GID = 0
	stack.Runtime.TLSPrivateKeyFiles["kafka"] = kafka
	rewriteTestJSON(t, filepath.Join(root, "stack.json"), stack)
	codes := diagnosticCodes(LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)))
	for _, want := range []string{"stack-service-missing", "stack-service-invalid"} {
		if !slices.Contains(codes, want) {
			t.Fatalf("codes = %v, want %q", codes, want)
		}
	}
}

func TestInventedReachabilityFailsExactSourceAnalyzer(t *testing.T) {
	root := t.TempDir()
	receipt := mustSelfTestReceipt(t, root)
	receipt.Reachability.BinaryEntrypoint = "cmd/probectl-control/invented.go#func Invented"
	receipt.Reachability.API = APIReachability{OperationID: "inventedOperation", Method: "GET", Path: "/v1/invented-audit"}
	receipt.Reachability.CLIOperation = "probectl isolation invented"
	receipt.Reachability.UIRoute = "/invented-audit"
	receipt.Reachability.DocsPath = "docs/invented-audit.md#Invented"
	receipt.CLI.Commands = []string{receipt.Reachability.CLIOperation}
	receipt.UI.Routes = []string{receipt.Reachability.UIRoute}

	var cli CLITranscriptArtifact
	readTestJSON(t, filepath.Join(root, "cli.json"), &cli)
	for i := range cli.Observations {
		cli.Observations[i].Command = receipt.Reachability.CLIOperation
		cli.Observations[i].Method = receipt.Reachability.API.Method
		cli.Observations[i].Path = receipt.Reachability.API.Path
	}
	rewriteTestJSON(t, filepath.Join(root, "cli.json"), cli)

	var browser BrowserNetworkArtifact
	readTestJSON(t, filepath.Join(root, "network.json"), &browser)
	for i := range browser.Sessions {
		browser.Sessions[i].Route = receipt.Reachability.UIRoute
	}
	rewriteTestJSON(t, filepath.Join(root, "network.json"), browser)

	registry, err := readSourceFile(testSourceRoot(t), reachabilityRegistryPath, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	rewriteTestJSON(t, filepath.Join(root, "reachability.json"), reachabilityArtifact(receipt, digestBytes(registry)))
	codes := diagnosticCodes(LintWithArtifactsAtSource(receipt, root, testSourceRoot(t)))
	for _, want := range []string{"binary-unreachable", "api-unreachable", "cli-unreachable", "ui-unreachable", "docs-unreachable"} {
		if !slices.Contains(codes, want) {
			t.Fatalf("codes = %v, want %q", codes, want)
		}
	}
}

func mustSelfTestReceipt(t *testing.T, root string) Receipt {
	t.Helper()
	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func readTestJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrict(data, target); err != nil {
		t.Fatal(err)
	}
}

func rewriteTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
