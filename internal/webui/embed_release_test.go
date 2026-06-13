// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build release

package webui

import "testing"

// UX-002: in a RELEASE build the web UI MUST be bundled — a shipped binary that
// serves the "not bundled" stub is a defect, not an acceptable degrade. The
// docker/release path runs `npm run build` and overlays the bundle into
// internal/webui/dist before compiling (see deploy/docker/Dockerfile, web
// stage), so Built() is true. Run with `-tags release` to enforce it; CI's
// release/image build exercises this. Local from-source builds (no tag) get the
// honest placeholder and TestBuiltIsHonestAboutTheBundle instead.
func TestRealBundleRequiredInReleaseBuild(t *testing.T) {
	if !Built() {
		t.Fatal("UX-002: release build embeds the placeholder, not the real UI — " +
			"the web bundle was not built into internal/webui/dist. " +
			"Build it with `npm --prefix web ci && npm --prefix web run build` and copy " +
			"web/dist/* into internal/webui/dist (the docker `web` stage does this).")
	}
}
