// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	probcrypto "github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/otelstore"
)

// SelfTest plants a test-only marker in an actual evidence artifact inside an
// otherwise complete receipt, then proves that the exact signed object verifies
// cryptographically while artifact-aware promotion fails closed.
func SelfTest() error {
	root, err := os.MkdirTemp("", "probectl-delivery-audit-selftest-")
	if err != nil {
		return fmt.Errorf("delivery audit selftest: create workspace: %w", err)
	}
	defer os.RemoveAll(root)

	receipt, err := newSelfTestReceipt(root)
	if err != nil {
		return err
	}
	receipt.Status = OutcomeFailed
	receipt.FailureReasons = []string{"planted negative control"}
	if err := os.WriteFile(
		filepath.Join(root, receipt.CLI.Transcript),
		[]byte("probectl isolation status\nfixture-only: planted negative control\n"),
		0o600,
	); err != nil {
		return fmt.Errorf("delivery audit selftest: plant artifact marker: %w", err)
	}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		return fmt.Errorf("delivery audit selftest: generate signer: %w", err)
	}
	defer probcrypto.Zeroize(privatePEM)
	// A FAILED receipt remains signable so the negative vector proves the
	// linter, rather than the signature parser, rejected its artifact marker.
	envelope, err := Seal(receipt, root, privatePEM)
	if err != nil {
		return fmt.Errorf("delivery audit selftest: seal planted receipt: %w", err)
	}
	verified, err := Verify(envelope, root)
	if err != nil {
		return fmt.Errorf("delivery audit selftest: verify planted receipt: %w", err)
	}
	diagnostics := LintWithArtifacts(verified.Receipt, root)
	fixtureDetected, failedDetected := false, false
	for _, diagnostic := range diagnostics {
		fixtureDetected = fixtureDetected || diagnostic.Code == "fixture-only"
		failedDetected = failedDetected || diagnostic.Code == "status-failed"
	}
	if !fixtureDetected || !failedDetected {
		return fmt.Errorf("delivery audit selftest: planted fixture diagnostics = %v, want fixture-only and status-failed", diagnostics)
	}
	return nil
}

func newSelfTestReceipt(root string) (Receipt, error) {
	artifacts := []Artifact{
		{Path: "cli.json", Kind: ArtifactCLITranscript},
		{Path: "ui-a.png", Kind: ArtifactUIScreenshot},
		{Path: "ui-b.png", Kind: ArtifactUIScreenshot},
		{Path: "network.json", Kind: ArtifactBrowserNetwork},
		{Path: "stores.json", Kind: ArtifactStoreProbes},
		{Path: "product-pipeline.json", Kind: ArtifactProductPipeline},
		{Path: "product/counters-before.prom", Kind: ArtifactPipelineCounters},
		{Path: "product/counters-after.prom", Kind: ArtifactPipelineCounters},
		{Path: "tls.json", Kind: ArtifactTLSTrust},
		{Path: "stack.json", Kind: ArtifactStackInventory},
		{Path: "reachability.json", Kind: ArtifactReachability},
		{Path: "activation.json", Kind: ArtifactActivation},
		{Path: "cli/status-a.out", Kind: ArtifactCLIOutput},
		{Path: "cli/status-a-response.json", Kind: ArtifactAPIObservation},
		{Path: "cli/status-b.out", Kind: ArtifactCLIOutput},
		{Path: "cli/status-b-response.json", Kind: ArtifactAPIObservation},
		{Path: "cli/deny-a-to-b.out", Kind: ArtifactCLIOutput},
		{Path: "cli/deny-a-to-b-response.json", Kind: ArtifactAPIObservation},
		{Path: "cli/deny-b-to-a.out", Kind: ArtifactCLIOutput},
		{Path: "cli/deny-b-to-a-response.json", Kind: ArtifactAPIObservation},
		{Path: "negative/linter-output.json", Kind: ArtifactLinterOutput},
		{Path: "negative/failed-envelope.json", Kind: ArtifactNegativeReceipt},
		{Path: "negative/planted.txt", Kind: ArtifactNegativeFixture},
	}
	no := false
	yes := true
	one := int64(1)
	zero := int64(0)
	started := time.Now().UTC().Truncate(time.Second)
	sha := strings.Repeat("a", 40)
	certificateRoot := filepath.Join(root, "pki")
	certificateManifest, err := GenerateDisposableCertificates(certificateRoot, 4*time.Hour)
	if err != nil {
		return Receipt{}, err
	}
	caPEM, err := os.ReadFile(filepath.Join(certificateRoot, "ca.crt"))
	if err != nil {
		return Receipt{}, err
	}
	caPin, err := probcrypto.CertificatePinPEM(caPEM)
	if err != nil {
		return Receipt{}, err
	}
	artifacts = append(artifacts,
		Artifact{Path: "pki/manifest.json", Kind: ArtifactCertManifest},
		Artifact{Path: "pki/ca.crt", Kind: ArtifactPublicCert},
	)
	serviceCertificates := make(map[string]string, len(certificateManifest.Services))
	serviceFingerprints := make(map[string]string, len(certificateManifest.Services))
	for _, service := range certificateManifest.Services {
		artifactPath := filepath.ToSlash(filepath.Join("pki", service.Certificate.Path))
		artifacts = append(artifacts, Artifact{Path: artifactPath, Kind: ArtifactPublicCert})
		serviceCertificates[service.Name] = artifactPath
		leafPEM, readErr := os.ReadFile(filepath.Join(certificateRoot, filepath.FromSlash(service.Certificate.Path)))
		if readErr != nil {
			return Receipt{}, readErr
		}
		leaf, inspectErr := probcrypto.InspectPublicCertificatePEM(leafPEM)
		if inspectErr != nil {
			return Receipt{}, inspectErr
		}
		serviceFingerprints[service.Name] = "sha256:" + leaf.FingerprintSHA256
	}
	protectedListener := func(service string) TLSListenerProbe {
		return TLSListenerProbe{
			AuthModel: TLSAuthModelProtected, CertificateService: service, PeerCertificateSHA256: serviceFingerprints[service],
			TrustedTLS: &yes, PlaintextRejected: &yes, UnauthenticatedRejected: &yes,
		}
	}
	dexListener := TLSListenerProbe{
		AuthModel: TLSAuthModelPublicOIDC, CertificateService: "dex", PeerCertificateSHA256: serviceFingerprints["dex"], TrustedTLS: &yes, PlaintextRejected: &yes,
		MetadataPublic: &yes, MalformedAuthorizationRejected: &yes, RealCredentialedLoginSucceeded: &yes,
	}
	receipt := Receipt{
		Schema:       ReceiptSchema,
		ReceiptID:    "cl002-audit-receipt-0001",
		Item:         "CL-002",
		CapabilityID: "F50",
		Status:       OutcomeVerified,
		StartedAt:    started,
		CompletedAt:  started.Add(time.Minute),
		Source:       Source{GitSHA: sha, TreeSHA: strings.Repeat("b", 40), Dirty: &no},
		Build: BuildEvidence{
			ControlCommit: sha, CLICommit: sha,
			ControlImageID: "sha256:" + strings.Repeat("c", 64),
			CLISHA256:      "sha256:" + strings.Repeat("d", 64),
			DevAuth:        &no, PlaceholderUI: &no,
		},
		Auditor: AuditorEvidence{
			Agent: "independent-selftest-auditor", ImplementationOwner: "selftest-implementer",
			IndependentFromImplementation: &yes,
		},
		HarnessScope: HarnessScopeEvidence{
			Mode: HarnessModeTenantPlane, BrowserAuthMode: HarnessAuthTenantOIDC, CLIAuthMode: HarnessAuthTenantMCPBearer,
			ProviderCompatibilityValidated: &no,
			CapabilityDriver:               HarnessDriverEvidence{Kind: HarnessDriverBuiltin, RuntimePath: "scripts/run_completeness_audit.sh#run_f50_capability"},
			BrowserDriver:                  HarnessDriverEvidence{Kind: HarnessDriverBuiltin, RuntimePath: "scripts/completeness_audit_browser.mjs"},
		},
		HumanPath: HumanPathEvidence{
			ID: "f50-tenant-oidc-isolation", PathClass: HumanPathClassExecutableEndUser,
			Coverage: HumanPathCoverageGovernedPath, Reproduced: &yes,
			Summary: "inspected tenant isolation through the release CLI and rendered UI",
		},
		CLI: CLIEvidence{Transcript: "cli.json", Commands: []string{"probectl isolation status"}},
		UI:  UIEvidence{Screenshots: []string{"ui-a.png", "ui-b.png"}, Routes: []string{"/admin"}},
		BrowserNetwork: BrowserNetworkEvidence{
			Artifact: "network.json", LiveHTTPS: &yes, RequestInterception: &no,
			Requests: []BrowserRequest{{Method: "GET", URL: "https://localhost:8443/v1/lifecycle/retention", Status: 200}},
		},
		Reachability: ReachabilityEvidence{
			Artifact: "reachability.json", BinaryEntrypoint: "cmd/probectl-control/builders.go#func verifyServePosture",
			DefaultBuildCommand: "go build ./cmd/probectl-control", DefaultBuildReachable: &yes,
			API:          APIReachability{OperationID: "getIsolationStatus", Method: "GET", Path: "/v1/isolation/status"},
			CLIOperation: "probectl isolation status", UIRoute: "/admin", DocsPath: "docs/isolation.md#Tenant isolation models",
		},
		Activation: ActivationEvidence{
			Artifact: "activation.json", EnabledByDefault: &yes, RuntimeActive: &yes,
			DocsPath: "docs/isolation.md#Tenant isolation models", LicenseTier: "core", LicenseState: "not_applicable", BuildTags: []string{},
		},
		Stores: StoreEvidence{
			Artifact: "stores.json", ProductPipelineArtifact: "product-pipeline.json",
			Postgres: PostgresIsolationProbe{
				ProofKind: PostgresProofKind, TenantA: "tenant-a", TenantB: "tenant-b",
				SeededTenantARows: &one, SeededTenantBRows: &one,
				TenantAOwnVisibleRows: &one, TenantBOwnVisibleRows: &one,
				TenantAToBVisibleRows: &zero, TenantBToAVisibleRows: &zero,
				Detail: "RLS-scoped queries run as both tenants",
			},
			ClickHouse: ClickHouseIsolationProbe{
				ProofKind: ClickHouseProofKind, ProductPathConfigured: &yes, ControlRoundTripObserved: &yes,
				Database: "default", Table: "probectl_otel_spans", ReaderUser: "probectl",
				TenantSetting: "SQL_probectl_tenant", ReaderPolicyObserved: &yes,
				TenantA: "tenant-a", TenantB: "tenant-b",
				SeededTenantARows: &one, SeededTenantBRows: &one,
				TenantAOwnVisibleRows: &one, TenantBOwnVisibleRows: &one,
				TenantAToBVisibleRows: &zero, TenantBToAVisibleRows: &zero, UnsetVisibleRows: &zero,
				Detail: "actual product table queried as release reader with tenant A/B settings and no setting",
			},
			Kafka: KafkaIntegrityProbe{
				ProofKind: KafkaProofKind, SecurityProtocol: "SASL_SSL", AuthenticationMechanism: "SCRAM-SHA-512",
				ControlConfiguredForBroker: &yes, ControlConnectivityProven: &yes,
				AuthenticatedManualTagProbe: &yes, TLSVerified: &yes, SASLAuthenticated: &yes,
				TenantA: "tenant-a", TenantB: "tenant-b",
				ObservedTenantAMessages: &one, ObservedTenantBMessages: &one,
				MissingTenantTagMessages: &zero, MismatchedTenantTagMessages: &zero,
				ProductMessagesObserved: &yes, ObservedProductMessages: int64Pointer(4),
				ReaderIsolationClaimed: &no, Detail: "four correlated product-emitted OTLP messages observed and committed by release consumers",
			},
			Prometheus: PrometheusIntegrityProbe{
				ProofKind: PrometheusProofKind, ProductPathConfigured: &yes, ControlRoundTripObserved: &yes,
				DirectQuery: &yes, UnfilteredSeriesQuery: &yes, TLSVerified: &yes, Authenticated: &yes,
				TenantA: "tenant-a", TenantB: "tenant-b",
				ObservedTenantASeries: &one, ObservedTenantBSeries: &one,
				TotalObservedSeries: int64Pointer(2), ExpectedTenantLabeledSeries: int64Pointer(2),
				MissingTenantLabelSeries: &zero, MismatchedTenantLabelSeries: &zero,
				IsolationClaimed: &no, Detail: "direct authenticated query verifies tenant labels, not query isolation",
			},
		},
		TLS: TLSEvidence{
			Artifact: "tls.json", CAFingerprint: "sha256:" + caPin,
			CANotBefore: certificateManifest.ValidFrom, CANotAfter: certificateManifest.ExpiresAt, BrowserRejectedWithoutCA: &yes,
			BrowserTrustedWithCA: &yes, IgnoreHTTPSErrors: &no,
			BrowserPretrustFailure: BrowserPretrustFailure{Browser: "webkit", URL: "https://control:8443/ui/admin", ErrorClass: "unknown_authority", SanitizedMessage: "TLS certificate signed by unknown authority", Rejected: &yes},
			Listeners: map[string]TLSListenerProbe{
				"control": protectedListener("control"), "dex": dexListener, "postgres": protectedListener("postgres"),
				"kafka": protectedListener("kafka"), "clickhouse": protectedListener("clickhouse"), "prometheus": protectedListener("prometheus"),
				"otlp_http": {
					AuthModel: TLSAuthModelProtected, CertificateService: "control", PeerCertificateSHA256: serviceFingerprints["control"],
					TrustedTLS: &yes, PlaintextRejected: &yes, UnauthenticatedRejected: &yes, InvalidAuthenticationRejected: &yes,
				},
			},
			CertificateManifest: "pki/manifest.json", CACertificate: "pki/ca.crt", ServiceCertificates: serviceCertificates,
		},
		EvidenceSources: EvidenceSources{Fixture: &no, Mock: &no, TestData: &no},
		Artifacts:       artifacts,
	}
	return writeSelfTestReceiptArtifacts(root, receipt)
}

func writeSelfTestReceiptArtifacts(root string, receipt Receipt) (Receipt, error) {
	no := false
	yes := true
	if err := os.MkdirAll(filepath.Join(root, "cli"), 0o700); err != nil {
		return Receipt{}, err
	}
	statusA, err := writeSelfTestCLIObservation(root, "status-a", CLICommandObservation{
		AuthMode: HarnessAuthTenantMCPBearer, Tenant: "tenant-a", Command: "probectl isolation status", Method: "GET",
		Path: "/v1/isolation/status", Expected: CLIExpectedSuccess, CLIExitStatus: 0,
		StatusProvenance: CLIStatusFromCLIResponse, Status: 200, Success: &yes, ExpectationMet: &yes,
	}, json.RawMessage(`{"isolation":"pooled"}`), "")
	if err != nil {
		return Receipt{}, err
	}
	statusB, err := writeSelfTestCLIObservation(root, "status-b", CLICommandObservation{
		AuthMode: HarnessAuthTenantMCPBearer, Tenant: "tenant-b", Command: "probectl isolation status", Method: "GET",
		Path: "/v1/isolation/status", Expected: CLIExpectedSuccess, CLIExitStatus: 0,
		StatusProvenance: CLIStatusFromCLIResponse, Status: 200, Success: &yes, ExpectationMet: &yes,
	}, json.RawMessage(`{"isolation":"pooled"}`), "")
	if err != nil {
		return Receipt{}, err
	}
	denyAToB, err := writeSelfTestCLIObservation(root, "deny-a-to-b", CLICommandObservation{
		AuthMode: HarnessAuthTenantMCPBearer, Tenant: "tenant-a", TargetTenant: "tenant-b", Command: "probectl tests get foreign-b",
		Method: "GET", Path: "/v1/tests/foreign-b", Expected: CLIExpectedRejected, CLIExitStatus: 1,
		StatusProvenance: CLIStatusFromSameAuthHTTPS, Status: 404, Success: &no, ExpectationMet: &yes,
	}, json.RawMessage(`{"error":"not_found"}`), "not_found")
	if err != nil {
		return Receipt{}, err
	}
	denyBToA, err := writeSelfTestCLIObservation(root, "deny-b-to-a", CLICommandObservation{
		AuthMode: HarnessAuthTenantMCPBearer, Tenant: "tenant-b", TargetTenant: "tenant-a", Command: "probectl tests get foreign-a",
		Method: "GET", Path: "/v1/tests/foreign-a", Expected: CLIExpectedRejected, CLIExitStatus: 1,
		StatusProvenance: CLIStatusFromSameAuthHTTPS, Status: 404, Success: &no, ExpectationMet: &yes,
	}, json.RawMessage(`{"error":"not_found"}`), "not_found")
	if err != nil {
		return Receipt{}, err
	}
	productObservations, productArtifacts, err := writeSelfTestProductPipeline(root, receipt)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Artifacts = append(receipt.Artifacts, productArtifacts...)
	if err := writeSelfTestJSON(root, "cli.json", CLITranscriptArtifact{
		Schema: CLITranscriptArtifactSchema, Redacted: &yes,
		Observations: append([]CLICommandObservation{statusA, statusB, denyAToB, denyBToA}, productObservations...),
	}); err != nil {
		return Receipt{}, err
	}
	uiPNG, err := selfTestPNG()
	if err != nil {
		return Receipt{}, err
	}
	if err := writeNewFile(filepath.Join(root, "ui-a.png"), uiPNG, 0o600); err != nil {
		return Receipt{}, fmt.Errorf("delivery audit selftest: %w", err)
	}
	if err := writeNewFile(filepath.Join(root, "ui-b.png"), uiPNG, 0o600); err != nil {
		return Receipt{}, fmt.Errorf("delivery audit selftest: %w", err)
	}
	if err := writeSelfTestJSON(root, "network.json", BrowserNetworkArtifact{
		Schema: BrowserNetworkArtifactSchema, Browser: "webkit",
		LiveHTTPS:           receipt.BrowserNetwork.LiveHTTPS,
		RequestInterception: receipt.BrowserNetwork.RequestInterception,
		IgnoreHTTPSErrors:   receipt.TLS.IgnoreHTTPSErrors,
		Requests:            receipt.BrowserNetwork.Requests,
		Sessions: []BrowserSession{{
			AuthMode: HarnessAuthTenantOIDC, Tenant: "tenant-a", Route: "/admin", Screenshot: "ui-a.png", Rendered: &yes,
			CredentialedLogin: &yes, TenantIndicatorVisible: &yes,
			ExpectedEvidenceVisible: &yes, ForeignEvidenceAbsent: &yes,
		}, {
			AuthMode: HarnessAuthTenantOIDC, Tenant: "tenant-b", Route: "/admin", Screenshot: "ui-b.png", Rendered: &yes,
			CredentialedLogin: &yes, TenantIndicatorVisible: &yes,
			ExpectedEvidenceVisible: &yes, ForeignEvidenceAbsent: &yes,
		}},
	}); err != nil {
		return Receipt{}, err
	}
	if err := writeSelfTestJSON(root, "stores.json", StoreProbesArtifact{
		Schema: StoreProbesArtifactSchema, ProductPipelineArtifact: receipt.Stores.ProductPipelineArtifact, Postgres: receipt.Stores.Postgres,
		ClickHouse: receipt.Stores.ClickHouse, Kafka: receipt.Stores.Kafka,
		Prometheus: receipt.Stores.Prometheus,
	}); err != nil {
		return Receipt{}, err
	}
	if err := writeSelfTestJSON(root, "tls.json", tlsTrustArtifact(receipt.TLS)); err != nil {
		return Receipt{}, err
	}
	zeroInt := 0
	service := func(version string) StackServiceInventory {
		return StackServiceInventory{
			Version: version, Running: &yes, RealService: &yes,
			TLSConfigured: &yes, AuthenticationConfigured: &yes,
		}
	}
	if err := writeSelfTestJSON(root, "stack.json", StackInventoryArtifact{
		Schema: StackInventoryArtifactSchema,
		Source: receipt.Source,
		Release: StackReleaseInventory{
			Control: StackControlInventory{
				Image: "probectl-control:audit", ImageID: receipt.Build.ControlImageID,
				BuildTags: []string{}, DevAuth: &no, EmbeddedViteUI: &yes,
			},
			CLI: StackCLIInventory{
				Image: "probectl-cli:audit", ImageID: "sha256:" + strings.Repeat("f", 64),
				SHA256: receipt.Build.CLISHA256, BuildTags: []string{}, DevAuth: &no,
			},
			Browser: StackBrowserInventory{
				Image: "probectl-browser:audit", ImageID: "sha256:" + strings.Repeat("9", 64),
				Engine: "webkit", Version: "1",
			},
		},
		Services: map[string]StackServiceInventory{
			"control": service(receipt.Source.GitSHA), "dex": service("2.45.1"), "postgres": service("16"),
			"kafka": service("3.9.0"), "clickhouse": service("24.8"), "prometheus": service("3.1.0"),
		},
		Network: StackNetworkInventory{Internal: &yes, PublishedPorts: &zeroInt},
		CredentialTransport: map[string]string{
			"database": "owner-only file", "kafka": "SASL credential file",
			"clickhouse": "authorization header", "prometheus": "authorization header",
		},
		Runtime: StackRuntimeInventory{
			TLSPrivateKeyFiles: map[string]RuntimeCredentialFile{
				"control":    {Path: "/audit/pki/control/tls.key", UID: 65532, GID: 65532, Mode: "0600", ConsumedBy: "control", Purpose: "server_tls_private_key"},
				"dex":        {Path: "/audit/pki/dex/tls.key", UID: 65532, GID: 65532, Mode: "0600", ConsumedBy: "dex", Purpose: "server_tls_private_key"},
				"postgres":   {Path: "/audit/pki/postgres/tls.key", UID: 999, GID: 999, Mode: "0600", ConsumedBy: "postgres", Purpose: "server_tls_private_key"},
				"kafka":      {Path: "/etc/kafka/secrets/kafka.keystore.p12", UID: 1000, GID: 1000, Mode: "0600", ConsumedBy: "kafka", Purpose: "server_tls_private_key"},
				"clickhouse": {Path: "/audit/pki/clickhouse/tls.key", UID: 101, GID: 101, Mode: "0600", ConsumedBy: "clickhouse", Purpose: "server_tls_private_key"},
				"prometheus": {Path: "/audit/pki/prometheus/tls.key", UID: 65534, GID: 65534, Mode: "0600", ConsumedBy: "prometheus", Purpose: "server_tls_private_key"},
			},
		},
		Harness:     receipt.HarnessScope,
		Limitations: []string{},
	}); err != nil {
		return Receipt{}, err
	}
	sourceRoot, err := findSelfTestSourceRoot()
	if err != nil {
		return Receipt{}, err
	}
	registry, err := readSourceFile(sourceRoot, reachabilityRegistryPath, 4<<20)
	if err != nil {
		return Receipt{}, err
	}
	if err := writeSelfTestJSON(root, "reachability.json", reachabilityArtifact(receipt, digestBytes(registry))); err != nil {
		return Receipt{}, err
	}
	if err := writeSelfTestJSON(root, "activation.json", activationArtifact(receipt)); err != nil {
		return Receipt{}, err
	}
	if err := writeSelfTestNegativeControl(root, receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

type selfTestProductSpec struct {
	tenant            string
	metricCorrelation string
	traceCorrelation  string
	spanID            string
	value             float64
}

func writeSelfTestProductPipeline(root string, receipt Receipt) ([]CLICommandObservation, []Artifact, error) {
	specs := []selfTestProductSpec{
		{tenant: "tenant-a", metricCorrelation: strings.Repeat("1", 32), traceCorrelation: strings.Repeat("2", 32), spanID: strings.Repeat("a", 16), value: 101},
		{tenant: "tenant-b", metricCorrelation: strings.Repeat("3", 32), traceCorrelation: strings.Repeat("4", 32), spanID: strings.Repeat("b", 16), value: 202},
	}
	productStarted := receipt.StartedAt.Add(2 * time.Second)
	productCompleted := receipt.CompletedAt.Add(-2 * time.Second)
	manifest := ProductPipelineArtifact{
		Schema: ProductPipelineArtifactSchema, ReceiptID: receipt.ReceiptID,
		SourceGitSHA: receipt.Source.GitSHA, SourceTreeSHA: receipt.Source.TreeSHA,
		ControlImageID: receipt.Build.ControlImageID, CLISHA256: receipt.Build.CLISHA256,
		StartedAt: productStarted, CompletedAt: productCompleted,
	}
	var observations []CLICommandObservation
	var artifacts []Artifact
	yes := true

	for i, spec := range specs {
		metricTime := productStarted.Add(time.Duration(5+i*5) * time.Second)
		metricFlow := ProductMetricPipelineFlow{
			CorrelationID: spec.metricCorrelation, ServiceName: "completeness-" + spec.metricCorrelation,
			MetricName: productMetricName, StoredMetricName: productStoredMetric, Value: spec.value, TimeUnixNano: uint64(metricTime.UnixNano()),
		}
		metricRequest := &colmetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: selfTestProductResource(spec.tenant, metricFlow.ServiceName),
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: metricFlow.MetricName,
				Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
					TimeUnixNano: metricFlow.TimeUnixNano,
					Attributes:   []*commonpb.KeyValue{selfTestStringAttribute("marker", metricFlow.CorrelationID)},
					Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: metricFlow.Value},
				}}}},
			}}}},
		}}}
		metricBytes, err := proto.Marshal(metricRequest)
		if err != nil {
			return nil, nil, err
		}
		prefix := filepath.ToSlash(filepath.Join("product", spec.tenant))
		metricRequestRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/metrics-ingest-request.pb", ArtifactOTLPRequest, metricBytes)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		metricResponseRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/metrics-ingest-response.pb", ArtifactOTLPResponse, nil)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		metricKeyRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/metrics-kafka-key.bin", ArtifactKafkaKey, bus.TenantKey(spec.tenant, "service.name="+metricFlow.ServiceName))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		metricPayloadRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/metrics-kafka-payload.pb", ArtifactKafkaPayload, metricBytes)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		metricGroupRef, groupArtifacts, err := writeSelfTestKafkaGroupOffset(root, prefix+"/metrics", productMetricsTopic, int32(i), productMetricsGroup, int64(11+i), metricTime.Add(100*time.Millisecond))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, groupArtifacts...)
		metricFlow.Ingest = ProductIngestExchange{
			ObservedAt: metricTime.Add(10 * time.Millisecond), URL: "https://control:4318/v1/metrics", AuthMode: productOTLPAuthMode, Method: "POST", Status: 200,
			Request: metricRequestRef, Response: metricResponseRef,
		}
		metricFlow.Kafka = ProductKafkaObservation{
			Topic: productMetricsTopic, Partition: int32(i), Offset: int64(10 + i),
			Key: metricKeyRef, Payload: metricPayloadRef, GroupOffset: metricGroupRef,
		}
		metricControlObservedAt := metricTime.Add(200 * time.Millisecond)
		metricDirectObservedAt := metricTime.Add(300 * time.Millisecond)
		metricBody, err := selfTestPrometheusBody(spec.tenant, metricFlow, metricControlObservedAt, false)
		if err != nil {
			return nil, nil, err
		}
		metricSelector := metricFlow.StoredMetricName + `{marker="` + metricFlow.CorrelationID + `"}`
		metricPath := "/v1/grafana/api/v1/query?query=" + url.QueryEscape(metricSelector)
		metricCommand := "probectl metric query --query query=" + metricSelector
		metricObservation, err := writeSelfTestCLIObservation(root, "product-"+spec.tenant+"-metric-own", CLICommandObservation{
			AuthMode: HarnessAuthTenantMCPBearer, Tenant: spec.tenant, Command: metricCommand, Method: "GET", Path: metricPath,
			Expected: CLIExpectedSuccess, CLIExitStatus: 0, StatusProvenance: CLIStatusFromCLIResponse,
			Status: 200, Success: &yes, ExpectationMet: &yes,
		}, metricBody, "")
		if err != nil {
			return nil, nil, err
		}
		observations = append(observations, metricObservation)
		artifacts = append(artifacts, selfTestCLIArtifacts(metricObservation)...)
		metricFlow.ControlQuery = ProductControlQuery{
			ObservedAt: metricControlObservedAt, Command: metricCommand, Method: "GET", Path: metricPath,
			APIObservation: ProductArtifactRef{Path: metricObservation.ResponseArtifact, SHA256: metricObservation.ResponseSHA256},
		}
		metricDirectBody, err := selfTestPrometheusBody(spec.tenant, metricFlow, metricDirectObservedAt, false)
		if err != nil {
			return nil, nil, err
		}
		metricDirectRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/prometheus-direct-response.json", ArtifactStoreObservation, append(metricDirectBody, '\n'))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		directSelector := metricFlow.StoredMetricName + `{marker="` + metricFlow.CorrelationID + `",tenant_id="` + spec.tenant + `"}`
		metricFlow.PrometheusDirect = ProductPrometheusDirectQuery{
			ObservedAt: metricDirectObservedAt, User: "audit", Query: directSelector,
			URL: "https://prometheus:9090/api/v1/query?query=" + url.QueryEscape(directSelector), Response: metricDirectRef,
		}

		traceStart := metricTime.Add(time.Second)
		traceEnd := traceStart.Add(time.Millisecond)
		traceFlow := ProductTracePipelineFlow{
			CorrelationID: spec.traceCorrelation, TraceID: spec.traceCorrelation, SpanID: spec.spanID,
			ServiceName: "completeness-" + spec.traceCorrelation, SpanName: productSpanName,
			StartTimeUnixNano: uint64(traceStart.UnixNano()), EndTimeUnixNano: uint64(traceEnd.UnixNano()),
		}
		traceID, _ := hex.DecodeString(traceFlow.TraceID)
		spanID, _ := hex.DecodeString(traceFlow.SpanID)
		traceRequest := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: selfTestProductResource(spec.tenant, traceFlow.ServiceName),
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
				TraceId: traceID, SpanId: spanID, Name: traceFlow.SpanName, Kind: tracepb.Span_SPAN_KIND_SERVER,
				StartTimeUnixNano: traceFlow.StartTimeUnixNano,
				EndTimeUnixNano:   traceFlow.EndTimeUnixNano,
			}}}},
		}}}
		traceBytes, err := proto.Marshal(traceRequest)
		if err != nil {
			return nil, nil, err
		}
		traceRequestRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/traces-ingest-request.pb", ArtifactOTLPRequest, traceBytes)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		traceResponseRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/traces-ingest-response.pb", ArtifactOTLPResponse, nil)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		traceKeyRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/traces-kafka-key.bin", ArtifactKafkaKey, bus.TenantKey(spec.tenant, "service.name="+traceFlow.ServiceName))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		tracePayloadRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/traces-kafka-payload.pb", ArtifactKafkaPayload, traceBytes)
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		traceGroupRef, groupArtifacts, err := writeSelfTestKafkaGroupOffset(root, prefix+"/traces", productTracesTopic, int32(i), productTracesGroup, int64(21+i), traceEnd.Add(100*time.Millisecond))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, groupArtifacts...)
		traceFlow.Ingest = ProductIngestExchange{
			ObservedAt: traceEnd.Add(10 * time.Millisecond), URL: "https://control:4318/v1/traces", AuthMode: productOTLPAuthMode, Method: "POST", Status: 200,
			Request: traceRequestRef, Response: traceResponseRef,
		}
		traceFlow.Kafka = ProductKafkaObservation{
			Topic: productTracesTopic, Partition: int32(i), Offset: int64(20 + i),
			Key: traceKeyRef, Payload: tracePayloadRef, GroupOffset: traceGroupRef,
		}
		row := otelstore.Span{
			TenantID: spec.tenant, TraceID: traceFlow.TraceID, SpanID: traceFlow.SpanID, Name: traceFlow.SpanName,
			Kind: "server", Service: traceFlow.ServiceName, Start: traceStart, Duration: time.Millisecond, StatusCode: "unset",
			Attrs: map[string]string{"service.name": traceFlow.ServiceName},
		}
		traceBody, err := json.Marshal(map[string]any{"spans": []otelstore.Span{row}})
		if err != nil {
			return nil, nil, err
		}
		tracePath := "/v1/otlp/traces?trace_id=" + traceFlow.TraceID
		traceCommand := "probectl otlp traces --query trace_id=" + traceFlow.TraceID
		traceObservation, err := writeSelfTestCLIObservation(root, "product-"+spec.tenant+"-trace-own", CLICommandObservation{
			AuthMode: HarnessAuthTenantMCPBearer, Tenant: spec.tenant, Command: traceCommand, Method: "GET", Path: tracePath,
			Expected: CLIExpectedSuccess, CLIExitStatus: 0, StatusProvenance: CLIStatusFromCLIResponse,
			Status: 200, Success: &yes, ExpectationMet: &yes,
		}, traceBody, "")
		if err != nil {
			return nil, nil, err
		}
		observations = append(observations, traceObservation)
		artifacts = append(artifacts, selfTestCLIArtifacts(traceObservation)...)
		traceFlow.ControlQuery = ProductControlQuery{
			ObservedAt: traceEnd.Add(200 * time.Millisecond), Command: traceCommand, Method: "GET", Path: tracePath,
			APIObservation: ProductArtifactRef{Path: traceObservation.ResponseArtifact, SHA256: traceObservation.ResponseSHA256},
		}
		directTrace, err := json.Marshal(productClickHouseRow{
			TenantID: spec.tenant, TraceID: traceFlow.TraceID, SpanID: traceFlow.SpanID,
			Name: traceFlow.SpanName, Service: traceFlow.ServiceName, StartTimeUnixNano: traceFlow.StartTimeUnixNano,
		})
		if err != nil {
			return nil, nil, err
		}
		traceDirectRef, artifact, err := writeSelfTestProductBytes(root, prefix+"/clickhouse-direct-response.json", ArtifactStoreObservation, append(directTrace, '\n'))
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, artifact)
		traceFlow.ClickHouseDirect = ProductClickHouseDirectQuery{
			ObservedAt: traceEnd.Add(300 * time.Millisecond), User: "probectl", Database: "default", Table: "probectl_otel_spans",
			TenantSetting: "SQL_probectl_tenant", TenantSettingValue: spec.tenant,
			SQL: productClickHouseSQL, Parameters: map[string]string{"trace": traceFlow.TraceID}, Response: traceDirectRef,
		}
		manifest.Tenants = append(manifest.Tenants, ProductTenantPipeline{Tenant: spec.tenant, Metrics: metricFlow, Traces: traceFlow})
	}

	foreignObservations, foreignArtifacts, err := writeSelfTestForeignQueries(root, &manifest, specs, productStarted)
	if err != nil {
		return nil, nil, err
	}
	observations = append(observations, foreignObservations...)
	artifacts = append(artifacts, foreignArtifacts...)

	isolationRef, isolationArtifacts, err := writeSelfTestClickHouseIsolation(root, manifest, productStarted.Add(35*time.Second))
	if err != nil {
		return nil, nil, err
	}
	manifest.ClickHouseIsolation = isolationRef
	artifacts = append(artifacts, isolationArtifacts...)

	before := selfTestProductCounters(false)
	after := selfTestProductCounters(true)
	beforeRef := ProductArtifactRef{Path: "product/counters-before.prom", SHA256: digestBytes(before)}
	afterRef := ProductArtifactRef{Path: "product/counters-after.prom", SHA256: digestBytes(after)}
	if err := writeNewFile(filepath.Join(root, filepath.FromSlash(beforeRef.Path)), before, 0o600); err != nil {
		return nil, nil, err
	}
	if err := writeNewFile(filepath.Join(root, filepath.FromSlash(afterRef.Path)), after, 0o600); err != nil {
		return nil, nil, err
	}
	manifest.Integrity = ProductPipelineIntegrity{
		BeforeObservedAt: productStarted.Add(time.Millisecond), AfterObservedAt: productCompleted.Add(-time.Millisecond),
		Before: beforeRef, After: afterRef,
	}
	if err := writeSelfTestJSON(root, receipt.Stores.ProductPipelineArtifact, manifest); err != nil {
		return nil, nil, err
	}
	return observations, artifacts, nil
}

func writeSelfTestForeignQueries(root string, manifest *ProductPipelineArtifact, specs []selfTestProductSpec, productStarted time.Time) ([]CLICommandObservation, []Artifact, error) {
	yes := true
	var observations []CLICommandObservation
	var artifacts []Artifact
	for i, spec := range specs {
		other := manifest.Tenants[1-i]
		foreignObservedAt := productStarted.Add(time.Duration(25+i) * time.Second)
		emptyMetricBody, err := selfTestPrometheusBody("", other.Metrics, foreignObservedAt, true)
		if err != nil {
			return nil, nil, err
		}
		selector := other.Metrics.StoredMetricName + `{marker="` + other.Metrics.CorrelationID + `"}`
		metricPath := "/v1/grafana/api/v1/query?query=" + url.QueryEscape(selector)
		metricCommand := "probectl metric query --query query=" + selector
		metricObservation, err := writeSelfTestCLIObservation(root, "product-"+spec.tenant+"-metric-foreign", CLICommandObservation{
			AuthMode: HarnessAuthTenantMCPBearer, Tenant: spec.tenant, Command: metricCommand, Method: "GET", Path: metricPath,
			Expected: CLIExpectedSuccess, CLIExitStatus: 0, StatusProvenance: CLIStatusFromCLIResponse,
			Status: 200, Success: &yes, ExpectationMet: &yes,
		}, emptyMetricBody, "")
		if err != nil {
			return nil, nil, err
		}
		emptyTraceBody := json.RawMessage(`{"spans":[]}`)
		tracePath := "/v1/otlp/traces?trace_id=" + other.Traces.TraceID
		traceCommand := "probectl otlp traces --query trace_id=" + other.Traces.TraceID
		traceObservation, err := writeSelfTestCLIObservation(root, "product-"+spec.tenant+"-trace-foreign", CLICommandObservation{
			AuthMode: HarnessAuthTenantMCPBearer, Tenant: spec.tenant, Command: traceCommand, Method: "GET", Path: tracePath,
			Expected: CLIExpectedSuccess, CLIExitStatus: 0, StatusProvenance: CLIStatusFromCLIResponse,
			Status: 200, Success: &yes, ExpectationMet: &yes,
		}, emptyTraceBody, "")
		if err != nil {
			return nil, nil, err
		}
		observations = append(observations, metricObservation, traceObservation)
		artifacts = append(artifacts, selfTestCLIArtifacts(metricObservation)...)
		artifacts = append(artifacts, selfTestCLIArtifacts(traceObservation)...)
		manifest.Tenants[i].ForeignQueries = ProductForeignQueries{
			Metrics: ProductControlQuery{ObservedAt: foreignObservedAt, Command: metricCommand, Method: "GET", Path: metricPath, APIObservation: ProductArtifactRef{Path: metricObservation.ResponseArtifact, SHA256: metricObservation.ResponseSHA256}},
			Traces:  ProductControlQuery{ObservedAt: foreignObservedAt.Add(time.Second), Command: traceCommand, Method: "GET", Path: tracePath, APIObservation: ProductArtifactRef{Path: traceObservation.ResponseArtifact, SHA256: traceObservation.ResponseSHA256}},
		}
	}
	return observations, artifacts, nil
}

func writeSelfTestClickHouseIsolation(root string, manifest ProductPipelineArtifact, observedAt time.Time) (ProductArtifactRef, []Artifact, error) {
	if len(manifest.Tenants) != 2 {
		return ProductArtifactRef{}, nil, fmt.Errorf("delivery audit selftest: ClickHouse isolation needs two tenants")
	}
	rows := make([][]byte, 2)
	for i, tenant := range manifest.Tenants {
		flow := tenant.Traces
		row := productClickHouseRow{
			TenantID: tenant.Tenant, TraceID: flow.TraceID, SpanID: flow.SpanID, Name: flow.SpanName,
			Service: flow.ServiceName, StartTimeUnixNano: flow.StartTimeUnixNano,
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return ProductArtifactRef{}, nil, err
		}
		rows[i] = append(encoded, '\n')
	}
	aRef, aArtifact, err := writeSelfTestProductBytes(root, "product/clickhouse-isolation-tenant-a.jsonl", ArtifactClickHouseIsolationRaw, rows[0])
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	bRef, bArtifact, err := writeSelfTestProductBytes(root, "product/clickhouse-isolation-tenant-b.jsonl", ArtifactClickHouseIsolationRaw, rows[1])
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	unsetRef, unsetArtifact, err := writeSelfTestProductBytes(root, "product/clickhouse-isolation-unset.jsonl", ArtifactClickHouseIsolationRaw, nil)
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	proof := ClickHouseIsolationArtifact{
		Schema: ClickHouseIsolationArtifactSchema, User: "probectl", Database: "default", Table: "probectl_otel_spans",
		TenantSetting: "SQL_probectl_tenant", SQL: productClickHouseIsolationSQL,
		Parameters: map[string]string{"trace_a": manifest.Tenants[0].Traces.TraceID, "trace_b": manifest.Tenants[1].Traces.TraceID},
		TenantA:    manifest.Tenants[0].Tenant, TenantB: manifest.Tenants[1].Tenant,
		TenantAObservedAt: observedAt, TenantBObservedAt: observedAt.Add(time.Second), UnsetObservedAt: observedAt.Add(2 * time.Second),
		TenantAResponse: aRef, TenantBResponse: bRef, UnsetResponse: unsetRef,
	}
	encoded, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	encoded = append(encoded, '\n')
	proofRef, proofArtifact, err := writeSelfTestProductBytes(root, "product/clickhouse-isolation.json", ArtifactClickHouseIsolation, encoded)
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	return proofRef, []Artifact{aArtifact, bArtifact, unsetArtifact, proofArtifact}, nil
}

func selfTestProductResource(tenant, service string) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
		selfTestStringAttribute(otel.AttrTenantID, tenant), selfTestStringAttribute("service.name", service),
	}}
}

func selfTestStringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}}
}

func selfTestPrometheusBody(tenant string, flow ProductMetricPipelineFlow, observedAt time.Time, empty bool) (json.RawMessage, error) {
	result := []any{}
	if !empty {
		result = append(result, map[string]any{
			"metric": map[string]string{
				"__name__": flow.StoredMetricName, "tenant_id": tenant, "marker": flow.CorrelationID, "service_name": flow.ServiceName,
			},
			"value": []any{float64(observedAt.UnixNano()) / float64(time.Second), strconv.FormatFloat(flow.Value, 'f', -1, 64)},
		})
	}
	return json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": result}})
}

func writeSelfTestProductBytes(root, relative string, kind ArtifactKind, data []byte) (ProductArtifactRef, Artifact, error) {
	full := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return ProductArtifactRef{}, Artifact{}, err
	}
	if err := writeNewFile(full, data, 0o600); err != nil {
		return ProductArtifactRef{}, Artifact{}, err
	}
	return ProductArtifactRef{Path: relative, SHA256: digestBytes(data)}, Artifact{Path: relative, Kind: kind}, nil
}

func writeSelfTestKafkaGroupOffset(root, prefix, topic string, partition int32, group string, committed int64, observedAt time.Time) (ProductArtifactRef, []Artifact, error) {
	raw := []byte(fmt.Sprintf(
		"GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID\n%s %s %d %d %d 0 - - -\n",
		group, topic, partition, committed, committed,
	))
	rawRef, rawArtifact, err := writeSelfTestProductBytes(root, prefix+"-group-offset.txt", ArtifactKafkaGroupRaw, raw)
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	yes := true
	proof := KafkaGroupOffsetArtifact{
		Schema: KafkaGroupOffsetArtifactSchema, BrokerAuthority: "kafka:9093", Source: "kafka_consumer_groups_describe",
		SecurityProtocol: "SASL_SSL", TLSVerified: &yes, SASLAuthenticated: &yes,
		ObservedAt: observedAt, Topic: topic, Partition: partition, ConsumerGroup: group, CommittedOffset: committed, RawObservation: rawRef,
	}
	data, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	data = append(data, '\n')
	proofRef, proofArtifact, err := writeSelfTestProductBytes(root, prefix+"-group-offset.json", ArtifactKafkaGroupOffset, data)
	if err != nil {
		return ProductArtifactRef{}, nil, err
	}
	return proofRef, []Artifact{rawArtifact, proofArtifact}, nil
}

func selfTestCLIArtifacts(observation CLICommandObservation) []Artifact {
	return []Artifact{{Path: observation.CLIOutputArtifact, Kind: ArtifactCLIOutput}, {Path: observation.ResponseArtifact, Kind: ArtifactAPIObservation}}
}

func selfTestProductCounters(after bool) []byte {
	var output strings.Builder
	for _, signal := range []string{"otlp_metrics", "otlp_traces"} {
		for _, suffix := range []string{"received_total", "stored_total", "malformed_total", "tenant_rejected_total", "fairness_shed_total", "cardinality_dropped_total", "label_truncated_total", "unsupported_total", "dead_lettered_total", "dropped_total"} {
			value := 10
			if after && (suffix == "received_total" || suffix == "stored_total") {
				value = 12
			}
			fmt.Fprintf(&output, "probectl_pipeline_%s_%s %d\n", signal, suffix, value)
		}
	}
	return []byte(output.String())
}

func writeSelfTestNegativeControl(root string, receipt Receipt) error {
	negativeDir := filepath.Join(root, "negative")
	if err := os.MkdirAll(negativeDir, 0o700); err != nil {
		return err
	}
	plantedPath := "negative/planted.txt"
	planted := []byte("fixture-only: planted negative control\n")
	if err := writeNewFile(filepath.Join(root, plantedPath), planted, 0o600); err != nil {
		return err
	}
	failed := receipt
	failed.Status = OutcomeFailed
	failed.FailureReasons = []string{"planted negative control"}
	failed.Artifacts = []Artifact{{Path: plantedPath, Kind: ArtifactOther}}
	privatePEM, _, err := probcrypto.GenerateEd25519KeyPEM()
	if err != nil {
		return err
	}
	defer probcrypto.Zeroize(privatePEM)
	failedEnvelope, err := Seal(failed, root, privatePEM)
	if err != nil {
		return err
	}
	failedEnvelopePath := "negative/failed-envelope.json"
	if err := writeNewFile(filepath.Join(root, failedEnvelopePath), failedEnvelope, 0o600); err != nil {
		return err
	}
	diagnostics := LintWithArtifacts(failed, root)
	report := LinterOutputArtifact{
		Schema: LinterOutputArtifactSchema, Rejected: boolPointer(true),
		FailedEnvelopePath: failedEnvelopePath, FailedEnvelopeSHA256: digestBytes(failedEnvelope),
		PlantedArtifactPath: plantedPath, PlantedArtifactSHA256: digestBytes(planted), Diagnostics: diagnostics,
	}
	return writeSelfTestJSON(root, "negative/linter-output.json", report)
}

func writeSelfTestCLIObservation(root, name string, observation CLICommandObservation, body json.RawMessage, errorCode string) (CLICommandObservation, error) {
	outputPath := filepath.ToSlash(filepath.Join("cli", name+".out"))
	responsePath := filepath.ToSlash(filepath.Join("cli", name+"-response.json"))
	cliOutput := append(append([]byte(nil), body...), '\n')
	if observation.Expected == CLIExpectedRejected {
		cliOutput = []byte("probectl: request rejected\n")
	}
	if err := writeNewFile(filepath.Join(root, filepath.FromSlash(outputPath)), cliOutput, 0o600); err != nil {
		return CLICommandObservation{}, err
	}
	api := APIObservationArtifact{
		Schema: APIObservationArtifactSchema, Redacted: boolPointer(true), AuthMode: observation.AuthMode,
		Tenant: observation.Tenant, TargetTenant: observation.TargetTenant, ProviderActor: observation.ProviderActor,
		Command: observation.Command, Method: observation.Method, Path: observation.Path, Status: observation.Status,
		ErrorCode: errorCode, Body: body,
	}
	if err := writeSelfTestJSON(root, responsePath, api); err != nil {
		return CLICommandObservation{}, err
	}
	response, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(responsePath)))
	if err != nil {
		return CLICommandObservation{}, err
	}
	observation.CLIOutputArtifact = outputPath
	observation.CLIOutputSHA256 = digestBytes(cliOutput)
	observation.ResponseArtifact = responsePath
	observation.ResponseSHA256 = digestBytes(response)
	if observation.StatusProvenance == CLIStatusFromSameAuthHTTPS {
		observation.CompanionRequestArtifact = responsePath
		observation.CompanionRequestSHA256 = observation.ResponseSHA256
	}
	return observation, nil
}

func findSelfTestSourceRoot() (string, error) {
	candidate, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("delivery audit selftest: working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(candidate, reachabilityRegistryPath)); err == nil {
				return candidate, nil
			}
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", fmt.Errorf("delivery audit selftest: repository root not found")
		}
		candidate = parent
	}
}

func selfTestPNG() ([]byte, error) {
	canvas := image.NewRGBA(image.Rect(0, 0, 640, 480))
	for y := 0; y < 480; y++ {
		for x := 0; x < 640; x++ {
			canvas.SetRGBA(x, y, color.RGBA{R: uint8(x % 251), G: uint8(y % 241), B: 48, A: 255})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, canvas); err != nil {
		return nil, fmt.Errorf("delivery audit selftest: encode PNG: %w", err)
	}
	return output.Bytes(), nil
}

func writeSelfTestJSON(root, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("delivery audit selftest: encode %s: %w", name, err)
	}
	data = append(data, '\n')
	if err := writeNewFile(filepath.Join(root, name), data, 0o600); err != nil {
		return fmt.Errorf("delivery audit selftest: %w", err)
	}
	return nil
}
