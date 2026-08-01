// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"strings"
	"testing"
)

func TestHelmMetricsTransportMatchesRenderedControlListener(t *testing.T) {
	helpers := readArtifact(t, "deploy/helm/probectl/templates/_helpers.tpl")
	service := readArtifact(t, "deploy/helm/probectl/templates/service.yaml")
	deployment := readArtifact(t, "deploy/helm/probectl/templates/deployment.yaml")
	configMap := readArtifact(t, "deploy/helm/probectl/templates/configmap.yaml")
	ingress := readArtifact(t, "deploy/helm/probectl/templates/ingress.yaml")
	serviceMonitor := readArtifact(t, "deploy/helm/probectl/templates/servicemonitor.yaml")
	values := readArtifact(t, "deploy/helm/probectl/values.yaml")
	strictValues := readArtifact(t, "deploy/helm/probectl/values-strict.yaml")
	schema := readArtifact(t, "deploy/helm/probectl/values.schema.json")
	hardening := readArtifact(t, "scripts/check_helm_hardening.sh")

	for name, body := range map[string]string{
		"values.yaml":        values,
		"values-strict.yaml": strictValues,
		"ServiceMonitor":     serviceMonitor,
	} {
		if strings.Contains(body, "metrics sidecar") || strings.Contains(body, "TLS sidecar") {
			t.Fatalf("%s still documents a metrics TLS sidecar that the chart does not render", name)
		}
	}

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "helpers",
			body: helpers,
			want: []string{
				`define "probectl.servicePortName"`,
				`define "probectl.probeScheme"`,
				`define "probectl.serviceScheme"`,
				`.Values.control.tls.enabled`,
			},
		},
		{
			name: "Service template",
			body: service,
			want: []string{
				`name: {{ include "probectl.servicePortName" . }}`,
				`targetPort: {{ include "probectl.servicePortName" . }}`,
			},
		},
		{
			name: "Deployment template",
			body: deployment,
			want: []string{
				`name: {{ include "probectl.servicePortName" . }}`,
				`port: {{ include "probectl.servicePortName" . }}`,
				`scheme: {{ include "probectl.probeScheme" . }}`,
				`required "control.tls.existingSecret is required when control.tls.enabled=true"`,
				`name: control-tls`,
			},
		},
		{
			name: "ConfigMap template",
			body: configMap,
			want: []string{
				`PROBECTL_ALLOW_PLAINTEXT_HTTP: {{ and (not .Values.control.tls.enabled) .Values.allowPlaintextHTTP | quote }}`,
				`PROBECTL_TLS_CERT_FILE`,
				`PROBECTL_TLS_KEY_FILE`,
			},
		},
		{
			name: "Ingress template",
			body: ingress,
			want: []string{
				`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`,
				`nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`,
				`nginx.ingress.kubernetes.io/proxy-ssl-secret:`,
				`nginx.ingress.kubernetes.io/proxy-ssl-server-name: "on"`,
				`nginx.ingress.kubernetes.io/proxy-ssl-name:`,
				`name: {{ include "probectl.servicePortName" . }}`,
			},
		},
		{
			name: "ServiceMonitor template",
			body: serviceMonitor,
			want: []string{
				`metrics.serviceMonitor.scheme must match the rendered control listener transport`,
				`metrics.serviceMonitor.tlsConfig requires metrics.serviceMonitor.scheme=https`,
				`port: {{ include "probectl.servicePortName" . }}`,
				`scheme: {{ .Values.metrics.serviceMonitor.scheme }}`,
			},
		},
		{
			name: "values.yaml",
			body: values,
			want: []string{
				"tls:\n    enabled: true",
				"existingSecret: \"\"",
				"mountPath: /etc/probectl/http-tls",
				"allowPlaintextHTTP: false",
				"scheme: https",
				"backendTLS:",
				"trustSecret: \"\"",
				"serverName: \"\"",
			},
		},
		{
			name: "values-strict.yaml",
			body: strictValues,
			want: []string{
				"allowPlaintextHTTP: false",
				"scheme: https",
				"tls:\n    enabled: true",
				"existingSecret: probectl-metrics-tls",
			},
		},
		{
			name: "values.schema.json",
			body: schema,
			want: []string{
				`"tls"`,
				`"existingSecret"`,
				`"certKey"`,
				`"keyKey"`,
				`"mountPath"`,
				`"backendTLS"`,
				`"trustSecret"`,
				`"serverName"`,
			},
		},
		{
			name: "helm hardening gate",
			body: hardening,
			want: []string{
				"RUNOPS-004",
				"CONFIG-aa08042e",
				"base_svc",
				"base_dep",
				"strict_svc",
				"strict_sm",
				`PROBECTL_ALLOW_PLAINTEXT_HTTP: \"false\"`,
				"chart rendered without control.tls.existingSecret",
				"chart rendered an HTTPS backend without ingress.backendTLS trust/name",
				"chart rendered an HTTPS backend without a CA Secret",
				"chart rendered an HTTPS backend without an expected certificate name",
				`nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`,
				"strict ServiceMonitor rendered an HTTPS scrape without an HTTPS control listener",
				"chart rendered an HTTP ServiceMonitor against the default HTTPS listener",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				if !strings.Contains(tc.body, want) {
					t.Errorf("%s missing %q", tc.name, want)
				}
			}
		})
	}
}

func TestHelmDefaultHasNoPlaintextListener(t *testing.T) {
	values := readArtifact(t, "deploy/helm/probectl/values.yaml")
	schema := readArtifact(t, "deploy/helm/probectl/values.schema.json")
	hardening := readArtifact(t, "scripts/check_helm_hardening.sh")

	for _, forbidden := range []string{
		"tls:\n    enabled: false",
		"allowPlaintextHTTP: true",
		"scheme: http\n",
	} {
		if strings.Contains(values, forbidden) {
			t.Errorf("values.yaml retains plaintext default %q", forbidden)
		}
	}

	for _, want := range []string{
		`"existingSecret": { "type": "string", "minLength": 1 }`,
		`"required": ["enabled", "existingSecret", "certKey", "keyKey", "mountPath"]`,
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("values schema missing fail-closed TLS contract %q", want)
		}
	}
	for _, want := range []string{
		`need "name: https" "$base_svc"`,
		`need "scheme: HTTPS" "$base_dep"`,
		`PROBECTL_ALLOW_PLAINTEXT_HTTP: \"false\"`,
		`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`,
		"default ingress does not use the backend CA Secret",
		"default ingress does not verify the expected backend name",
		`chart rendered without control.tls.existingSecret`,
		`chart rendered an HTTPS backend without ingress.backendTLS trust/name`,
		`chart rendered an HTTPS backend without a CA Secret`,
		`chart rendered an HTTPS backend without an expected certificate name`,
		`default ServiceMonitor must scrape the HTTPS control listener`,
	} {
		if !strings.Contains(hardening, want) {
			t.Errorf("Helm hardening gate missing default-listener assertion %q", want)
		}
	}
}

func TestHelmControlImageRequiresImmutableDigest(t *testing.T) {
	helper := readArtifact(t, "deploy/helm/probectl/templates/_helpers.tpl")
	values := readArtifact(t, "deploy/helm/probectl/values.yaml")
	schema := readArtifact(t, "deploy/helm/probectl/values.schema.json")
	hardening := readArtifact(t, "scripts/check_helm_hardening.sh")
	supply := readArtifact(t, "scripts/check_supply_pins.sh")
	helmREADME := readArtifact(t, "deploy/helm/README.md")

	for _, want := range []string{
		`required "image.digest is required`,
		`.Values.image.digest`,
		`printf "%s@%s"`,
		`^sha256:[0-9a-f]{64}$`,
	} {
		if !strings.Contains(helper, want) {
			t.Errorf("primary image helper missing immutable-reference contract %q", want)
		}
	}
	if strings.Contains(helper, ".Values.image.tag") {
		t.Error("primary image helper still accepts mutable image.tag")
	}
	if !strings.Contains(values, "image:\n  repository: ghcr.io/ctlplne/probectl-control\n") ||
		!strings.Contains(values, "  digest: \"\" # sha256:<64 lowercase hex>\n") {
		t.Error("primary image values do not expose the required digest field")
	}
	valuesPullSecrets := strings.Index(values, "imagePullSecrets:")
	if valuesPullSecrets < 0 {
		t.Fatal("primary image values missing the imagePullSecrets anchor")
	}
	if strings.Contains(values[:valuesPullSecrets], "tag:") {
		t.Error("primary image values still expose a mutable tag")
	}
	schemaPullSecrets := strings.Index(schema, `"imagePullSecrets"`)
	if schemaPullSecrets < 0 {
		t.Fatal("primary image schema missing the imagePullSecrets anchor")
	}
	for _, want := range []string{
		`"digest": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" }`,
		`"required": ["repository", "digest", "pullPolicy"]`,
	} {
		if !strings.Contains(schema[:schemaPullSecrets], want) {
			t.Errorf("primary image schema missing %q", want)
		}
	}
	for _, want := range []string{
		"SUPPLY-deb3c967",
		"need_digest_pinned_control_images",
		"chart rendered a tag-only primary control image",
		"chart accepted obsolete image.tag alongside image.digest",
		"chart rendered a malformed primary control image digest",
	} {
		if !strings.Contains(hardening, want) {
			t.Errorf("Helm hardening gate missing immutable-image assertion %q", want)
		}
	}
	for _, want := range []string{
		"helm_control_image_contract_is_mutable",
		"tag-only primary Helm image accepted",
		"MUTABLE primary Helm control image contract",
	} {
		if !strings.Contains(supply, want) {
			t.Errorf("supply gate missing templated-image assertion %q", want)
		}
	}
	for _, want := range []string{
		"do not use `--reuse-values`",
		"helm upgrade --reset-values",
		"still supplies `image.tag` fails closed",
	} {
		if !strings.Contains(helmREADME, want) {
			t.Errorf("Helm upgrade guide missing immutable-image migration guidance %q", want)
		}
	}
}

func TestHelmDatastoreTLSContracts(t *testing.T) {
	configMap := readArtifact(t, "deploy/helm/probectl/templates/configmap.yaml")
	hardening := readArtifact(t, "scripts/check_helm_hardening.sh")
	strictValues := readArtifact(t, "deploy/helm/probectl/values-strict.yaml")

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "ConfigMap datastore TLS validators",
			body: configMap,
			want: []string{
				"WIRE-001",
				`PROBECTL_DEPLOYMENT_PROFILE`,
				`sslmode=(require|verify-ca|verify-full)`,
				`PROBECTL_DATABASE_READ_URL`,
				`PROBECTL_PATHSTORE_URL`,
				`PROBECTL_FLOWSTORE_URL`,
				`PROBECTL_OTELSTORE_URL`,
				`PROBECTL_EBPFSTORE_URL`,
				`PROBECTL_DATAPLANES`,
				`https:// ClickHouse endpoint`,
			},
		},
		{
			name: "helm hardening datastore TLS coverage",
			body: hardening,
			want: []string{
				"WIRE-001",
				"plaintext multi-tenant database.url",
				"plaintext multi-tenant PROBECTL_DATABASE_READ_URL",
				"plaintext multi-tenant PROBECTL_FLOWSTORE_URL",
				"plaintext multi-tenant PROBECTL_DATAPLANES",
				"strict profile still permits plaintext datastore/broker egress port",
			},
		},
		{
			name: "strict profile TLS egress ports",
			body: strictValues,
			want: []string{
				"port: 5432",
				"port: 8443",
				"port: 9440",
				"port: 9093",
				"Prometheus/VictoriaMetrics HTTPS remote-write",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.want {
				if !strings.Contains(tc.body, want) {
					t.Errorf("%s missing %q", tc.name, want)
				}
			}
			if tc.name == "strict profile TLS egress ports" {
				for _, banned := range []string{"port: 8123", "port: 9000", "port: 9092", "port: 9009"} {
					if strings.Contains(tc.body, banned) {
						t.Errorf("%s still includes plaintext egress %q", tc.name, banned)
					}
				}
			}
		})
	}
}
