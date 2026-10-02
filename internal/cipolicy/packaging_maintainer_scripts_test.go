// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// SUP-05: the packaged agents' maintainer scripts must touch ONLY their own
// systemd unit, and preremove must act only on a REAL removal — never on the
// remove half of an upgrade. The old shared preremove looped over every agent
// unit on every remove/upgrade and ran `systemctl disable --now`, so upgrading
// one agent stopped and un-enabled the whole fleet.
//
// These tests render the real shipped scripts the way release.yml /
// packaging-smoke.sh do (baking ${AGENT} in per package) and run them against a
// recording fake `systemctl`, under the exact argv dpkg/rpm pass their
// maintainer scripts. This is the "fake-systemctl harness" SUP-05 calls for.

const (
	sup05Target = "flow-agent" // the package under test
	sup05Own    = "probectl-flow-agent"
)

// otherAgentUnits are the units a probectl-flow-agent operation must never touch.
var sup05OtherUnits = []string{
	"probectl-ebpf-agent",
	"probectl-device-agent",
	"probectl-endpoint",
	// NB: "probectl-agent" (the base agent) is intentionally NOT substring-checked
	// here — "probectl-flow-agent" contains no such substring, but the postinstall
	// hint text legitimately names the `probectl-agent` binary, so the behavioral
	// (fake-systemctl) assertions below are what guard the base agent.
}

// renderMaintainerScript reads deploy/packaging/scripts/<name>.sh and bakes in
// ${AGENT} exactly as the build's `envsubst '${AGENT}'` step does.
func renderMaintainerScript(t *testing.T, name, agent string) string {
	t.Helper()
	raw := readRepoFile(t, "deploy", "packaging", "scripts", name+".sh")
	return strings.ReplaceAll(raw, "${AGENT}", agent)
}

// runMaintainerScript writes the rendered script and a recording fake systemctl,
// runs the script under /bin/sh with the given maintainer-script argv, and
// returns every line the fake systemctl recorded (one per invocation, args
// space-joined).
func runMaintainerScript(t *testing.T, body string, args ...string) []string {
	t.Helper()
	dir := t.TempDir()

	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "systemctl.log")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SYSTEMCTL_LOG\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/sh", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SYSTEMCTL_LOG="+logPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("maintainer script %v failed: %v\noutput:\n%s", args, err, out)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // systemctl was never called
		}
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func joinLines(lines []string) string { return strings.Join(lines, "\n") }

// assertTouchesOnlyOwn fails if any recorded systemctl invocation names a
// probectl agent unit other than this package's own.
func assertTouchesOnlyOwn(t *testing.T, lines []string) {
	t.Helper()
	log := joinLines(lines)
	for _, other := range sup05OtherUnits {
		if strings.Contains(log, other) {
			t.Errorf("maintainer script touched a foreign unit %q — a package must only act on its own unit (SUP-05)\nrecorded systemctl calls:\n%s", other, log)
		}
	}
}

func hasCall(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// usesSubcommand reports whether any recorded invocation's FIRST token (the
// systemctl subcommand) equals sub. A substring test would be wrong here:
// "try-restart" contains "start", "restart" contains "start ", etc.
func usesSubcommand(lines []string, sub string) bool {
	for _, l := range lines {
		if fields := strings.Fields(l); len(fields) > 0 && fields[0] == sub {
			return true
		}
	}
	return false
}

func TestPreremoveDisablesOnlyOwnUnitAndOnlyOnRealRemoval(t *testing.T) {
	t.Parallel()
	body := renderMaintainerScript(t, "preremove", sup05Target)

	// Static backstop: the fleet-wide loop is gone — a flow-agent prerm must not
	// even mention another agent's unit name.
	assertTouchesOnlyOwn(t, []string{body})

	cases := []struct {
		name        string
		args        []string
		wantDisable bool // expect `disable --now probectl-flow-agent`
	}{
		{"deb-removal", []string{"remove"}, true},
		{"deb-upgrade", []string{"upgrade", "0.9.9"}, false},
		{"deb-deconfigure", []string{"deconfigure", "0.9.9"}, false},
		{"deb-failed-upgrade", []string{"failed-upgrade", "0.9.9"}, false},
		{"rpm-removal", []string{"0"}, true},
		{"rpm-upgrade", []string{"1"}, false},
		{"rpm-upgrade-multi", []string{"2"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := runMaintainerScript(t, body, tc.args...)
			assertTouchesOnlyOwn(t, lines)
			gotDisable := hasCall(lines, "disable --now "+sup05Own)
			if gotDisable != tc.wantDisable {
				t.Errorf("args %v: disable own unit = %v, want %v\nrecorded systemctl calls:\n%s",
					tc.args, gotDisable, tc.wantDisable, joinLines(lines))
			}
			// On an upgrade nothing at all may be disabled.
			if !tc.wantDisable && hasCall(lines, "disable") {
				t.Errorf("args %v: preremove disabled a unit during an upgrade — must be a no-op\nrecorded systemctl calls:\n%s",
					tc.args, joinLines(lines))
			}
		})
	}
}

func TestPostinstallRestartsOwnUnitOnlyOnUpgrade(t *testing.T) {
	t.Parallel()
	body := renderMaintainerScript(t, "postinstall", sup05Target)

	cases := []struct {
		name        string
		args        []string
		wantRestart bool // expect `try-restart probectl-flow-agent`
	}{
		{"deb-fresh-install", []string{"configure", ""}, false},
		{"deb-fresh-install-no-arg", []string{"configure"}, false},
		{"deb-upgrade", []string{"configure", "0.9.9"}, true},
		{"rpm-fresh-install", []string{"1"}, false},
		{"rpm-upgrade", []string{"2"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines := runMaintainerScript(t, body, tc.args...)
			assertTouchesOnlyOwn(t, lines)
			gotRestart := hasCall(lines, "try-restart "+sup05Own)
			if gotRestart != tc.wantRestart {
				t.Errorf("args %v: try-restart own unit = %v, want %v\nrecorded systemctl calls:\n%s",
					tc.args, gotRestart, tc.wantRestart, joinLines(lines))
			}
			// postinstall must NEVER start/enable a fresh install and must never
			// disable/stop anything — only daemon-reload, plus try-restart on upgrade.
			for _, forbidden := range []string{"start", "enable", "disable", "stop"} {
				if usesSubcommand(lines, forbidden) {
					t.Errorf("args %v: postinstall issued `systemctl %s` — it may only daemon-reload (+ try-restart on upgrade)\nrecorded systemctl calls:\n%s",
						tc.args, forbidden, joinLines(lines))
				}
			}
		})
	}
}

// TestMaintainerScriptsBakeInTheAgent guards the rendering contract: nfpm points
// at ${PROBECTL_SCRIPTS}/*.sh, and both build paths render the per-agent scripts
// into that dir. If the scripts stopped using ${AGENT}, every package would
// target the same hard-coded unit again.
func TestMaintainerScriptsBakeInTheAgent(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"preremove", "postinstall"} {
		raw := readRepoFile(t, "deploy", "packaging", "scripts", name+".sh")
		if !strings.Contains(raw, "${AGENT}") {
			t.Errorf("%s.sh no longer bakes in ${AGENT}; packages would share one hard-coded unit (SUP-05)", name)
		}
	}
	nfpm := readRepoFile(t, "deploy", "packaging", "nfpm.yaml")
	for _, want := range []string{
		"${PROBECTL_SCRIPTS}/preremove.sh",
		"${PROBECTL_SCRIPTS}/postinstall.sh",
	} {
		if !strings.Contains(nfpm, want) {
			t.Errorf("nfpm.yaml must point at the rendered script %q (SUP-05)", want)
		}
	}
	// Both build paths must render the scripts, or a package ships a literal ${AGENT}.
	for _, f := range [][]string{
		{"scripts", "packaging-smoke.sh"},
		{".github", "workflows", "release.yml"},
	} {
		body := readRepoFile(t, f...)
		if !strings.Contains(body, "PROBECTL_SCRIPTS") || !strings.Contains(body, "deploy/packaging/scripts/") {
			t.Errorf("%s must render the per-agent maintainer scripts into PROBECTL_SCRIPTS (SUP-05)", filepath.Join(f...))
		}
	}
}
