// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBGPAnalyzerDeployContract(t *testing.T) {
	repo := filepath.Join("..", "..")
	checks := map[string][]string{
		"deploy/compose/eval.yml": {
			`profiles: ["bgp-analyzer"]`,
			"Dockerfile.bgp-analyzer",
			"PROBECTL_BGP_ANALYZER_SOURCE_FILE",
		},
		"deploy/helm/probectl/values.yaml": {
			"bgpAnalyzer:",
			"enabled: false",
			"PROBECTL_BUS_TLS_ENABLED",
		},
		"deploy/helm/probectl/templates/bgp-analyzer.yaml": {
			"bgpAnalyzer.image.digest is required",
			"bgpAnalyzer.source is required",
			"bgpAnalyzer.sourceFile is required for mrt/replay sources",
			"automountServiceAccountToken: false",
			"PROBECTL_BGP_ANALYZER_CONFIG",
		},
		"deploy/helm/probectl/templates/bgp-analyzer-networkpolicy.yaml": {
			"ingress: []",
			"egressTo must be non-empty",
		},
		"deploy/docker/Dockerfile.bgp-analyzer": {
			"python:${PYTHON_VERSION}-slim-bookworm@sha256:",
			"pip install --no-cache-dir --require-hashes",
			"chmod -R a+rX /opt/probectl/analyzer",
			`python -c "import probectl_analyzer"`,
			`ENTRYPOINT ["/usr/local/bin/probectl-control", "bgp-analyzer"]`,
		},
	}
	for name, wants := range checks {
		body, err := os.ReadFile(filepath.Join(repo, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, want := range wants {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s missing %q", name, want)
			}
		}
	}
}
