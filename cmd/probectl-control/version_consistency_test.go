// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// OPS-008: the shipped artifacts used to disagree on version (compose v0.4.0,
// chart appVersion 0.1.0, binary 0.0.0-dev). The repo-root VERSION file is now
// the single source of truth; the Makefile stamps the binary from it, and this
// gate asserts the Compose image pin, Helm Chart appVersion, and OpenAPI
// info.version all equal it. A release tag overrides the binary version, and
// release.yml already asserts the tag equals the chart appVersion — so every
// shipped version surface converges.
func TestShippedVersionsAgree(t *testing.T) {
	truth := strings.TrimSpace(readArtifact(t, "VERSION"))
	if truth == "" {
		t.Fatal("VERSION file is empty — it is the single source of version truth (OPS-008)")
	}
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(truth) {
		t.Fatalf("VERSION %q is not a semver (OPS-008)", truth)
	}

	// Chart appVersion must equal VERSION.
	chart := readArtifact(t, "deploy/helm/probectl/Chart.yaml")
	appv := ""
	for _, ln := range strings.Split(chart, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "appVersion:") {
			appv = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "appVersion:")), `"`)
			break
		}
	}
	if appv != truth {
		t.Errorf("Chart appVersion %q != VERSION %q (OPS-008)", appv, truth)
	}

	// Compose image pin tag must equal VERSION.
	compose := readArtifact(t, "deploy/compose/probectl.yml")
	m := regexp.MustCompile(`probectl-control:v?(\d+\.\d+\.\d+)`).FindStringSubmatch(compose)
	if m == nil {
		t.Fatal("could not find a probectl-control image pin in deploy/compose/probectl.yml (OPS-008)")
	}
	if m[1] != truth {
		t.Errorf("compose image tag %q != VERSION %q (OPS-008)", m[1], truth)
	}

	// OpenAPI info.version identifies the product release that emitted the
	// schema; /v1 in each path independently carries the API major.
	var spec struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(readArtifact(t, "internal/control/openapi.json")), &spec); err != nil {
		t.Fatalf("parse core OpenAPI: %v", err)
	}
	if spec.Info.Version != truth {
		t.Errorf("OpenAPI info.version %q != VERSION %q (OPS-008)", spec.Info.Version, truth)
	}
}
