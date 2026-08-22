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

// TestDockerRuntimeSeedsNonRootWritableDirectories prevents the shipped named-
// volume quickstart from regressing to root-owned /certs or /var/lib/probectl
// mounts. Certgen, control, and the real-Dex overlay intentionally run as
// distroless nonroot, so both writable volume roots must inherit UID/GID 65532.
func TestDockerRuntimeSeedsNonRootWritableDirectories(t *testing.T) {
	dockerfile, err := os.ReadFile("../../deploy/docker/Dockerfile")
	if err != nil {
		t.Fatalf("read deploy/docker/Dockerfile: %v", err)
	}
	text := string(dockerfile)
	for _, want := range []string{
		"RUN install -d -m 0700 -o 65532 -g 65532 /out/certs /out/probectl",
		"COPY --from=build --chown=nonroot:nonroot /out/certs/ /certs/",
		"COPY --from=build --chown=nonroot:nonroot /out/probectl/ /var/lib/probectl/",
		"USER nonroot:nonroot",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Docker runtime is missing non-root writable-volume contract %q", want)
		}
	}
}

// TestEvalSyntheticUsesSeededNonRootStateRoot protects the real first-data
// path, not just the control-plane quickstart. Docker creates a fresh named
// volume mounted at an otherwise absent /identity as root:root; the shipped
// distroless agent runs as UID/GID 65532 and then consumes its one-time token
// before failing to write key.pem. Mounting the volume at the image-seeded
// /var/lib/probectl root makes enrollment durable without running as root.
func TestEvalSyntheticUsesSeededNonRootStateRoot(t *testing.T) {
	files := map[string][]string{
		"../../deploy/compose/eval-synthetic.yml": {
			"identity:/var/lib/probectl",
			"browser-state:/var/lib/probectl",
		},
		"../../deploy/compose/eval-agent.yml": {
			"cert_file: /var/lib/probectl/identity/cert.pem",
			"key_file: /var/lib/probectl/identity/key.pem",
			"dir: /var/lib/probectl/buffer",
		},
		"../../deploy/compose/eval-browser-agent.yml": {
			"cert_file: /var/lib/probectl/identity/cert.pem",
			"key_file: /var/lib/probectl/identity/key.pem",
			"dir: /var/lib/probectl/buffer",
		},
	}
	for path, wants := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(data)
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s is missing non-root agent state contract %q", path, want)
			}
		}
		for _, forbidden := range []string{"cert_file: /identity/cert.pem", "key_file: /identity/key.pem", ":/identity", ":/var/lib/probectl-agent"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s retains root-owned agent state path %q", path, forbidden)
			}
		}
	}
}
