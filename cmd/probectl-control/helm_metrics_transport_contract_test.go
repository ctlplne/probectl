// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
				"tls:\n    enabled: false",
				"existingSecret: \"\"",
				"mountPath: /etc/probectl/http-tls",
				"scheme: http",
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
			},
		},
		{
			name: "helm hardening gate",
			body: hardening,
			want: []string{
				"RUNOPS-004",
				"strict_svc",
				"strict_sm",
				`PROBECTL_ALLOW_PLAINTEXT_HTTP: \"false\"`,
				"strict ServiceMonitor rendered an HTTPS scrape without an HTTPS control listener",
				"chart rendered https ServiceMonitor scheme while control.tls.enabled=false",
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
