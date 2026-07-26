// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package webui

import (
	"os"
	"strings"
	"testing"
)

// TestDockerWebStageCarriesPrebuildInputs keeps the real image build aligned
// with web/package.json. The web stage has an isolated filesystem: copying
// web/ alone is insufficient when npm's prebuild reaches back into repository
// scripts and that script validates a repository OpenAPI document.
func TestDockerWebStageCarriesPrebuildInputs(t *testing.T) {
	pkg, err := os.ReadFile("../../web/package.json")
	if err != nil {
		t.Fatalf("read web/package.json: %v", err)
	}
	if !strings.Contains(string(pkg), `"prebuild": "node ../scripts/web_rendered_a11y.mjs --selftest"`) {
		t.Fatal("web prebuild contract changed; update the Docker web-stage input test")
	}

	dockerfile, err := os.ReadFile("../../deploy/docker/Dockerfile")
	if err != nil {
		t.Fatalf("read deploy/docker/Dockerfile: %v", err)
	}
	for _, want := range []string{
		"COPY scripts/web_rendered_a11y.mjs /scripts/web_rendered_a11y.mjs",
		"COPY internal/control/openapi.json /internal/control/openapi.json",
		"RUN npm run build",
	} {
		if !strings.Contains(string(dockerfile), want) {
			t.Fatalf("Docker web stage is missing prebuild contract %q", want)
		}
	}
}

// TestDockerRuntimeSeedsNonRootCertDirectory prevents the shipped named-volume
// quickstart from regressing to a root-owned /certs mount. Both certgen and
// control intentionally run as distroless nonroot, so seeding the image path is
// what lets certgen create a 0600 key that control can subsequently read.
func TestDockerRuntimeSeedsNonRootCertDirectory(t *testing.T) {
	dockerfile, err := os.ReadFile("../../deploy/docker/Dockerfile")
	if err != nil {
		t.Fatalf("read deploy/docker/Dockerfile: %v", err)
	}
	text := string(dockerfile)
	for _, want := range []string{
		"RUN install -d -m 0700 -o 65532 -g 65532 /out/certs",
		"COPY --from=build --chown=nonroot:nonroot /out/certs/ /certs/",
		"USER nonroot:nonroot",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Docker runtime is missing non-root certificate-volume contract %q", want)
		}
	}
}
