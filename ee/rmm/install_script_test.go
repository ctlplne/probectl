// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build !windows

package rmm

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxInstallerRetriesManagedIdentityLayout(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("the Linux installer requires Bash")
	}
	raw, err := os.ReadFile("install-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Run only the file preflight. The test must not install packages, enroll
	// against a server, or access the host's systemd and agent configuration.
	const start = `[[ -f "$ca_file"`
	_, tail, found := strings.Cut(string(raw), start)
	preflight, _, ended := strings.Cut(tail, "# Package repositories and their signing keys")
	if !found || !ended {
		t.Fatal("cannot locate the installer's managed identity preflight")
	}
	setup := `set -eu
fail() { printf '%s\n' "$1" >&2; exit 1; }
systemctl() { return 1; }
`
	if runtime.GOOS == "darwin" {
		setup += "stat() { command stat -f '%Lp' \"$4\"; }\n"
	}
	for _, tt := range []struct {
		name     string
		managed  bool
		layout   string
		token    bool
		writable string
		refusal  string
	}{
		{name: "managed versioned identity", managed: true, layout: "versioned"},
		{name: "managed legacy identity", managed: true, layout: "regular"},
		{name: "unmanaged identity", layout: "versioned", refusal: "unmanaged agent"},
		{name: "foreign identity directory", managed: true, layout: "foreign", refusal: "unexpected link"},
		{name: "broken identity link", managed: true, layout: "dangling", refusal: "unexpected link"},
		{name: "missing version with token", managed: true, layout: "missing-version", token: true, refusal: "unexpected link"},
		{name: "missing certificate with token", managed: true, layout: "missing-cert", token: true, refusal: "unexpected link"},
		{name: "missing identity", managed: true, refusal: "set the protected join token"},
		{name: "group writable trust directory", token: true, writable: "directory", refusal: "writable only by root"},
		{name: "group writable trust bundle", token: true, writable: "bundle", refusal: "writable only by root"},
		{name: "group writable existing policy", managed: true, token: true, writable: "policy", refusal: "writable only by root"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			identity := filepath.Join(root, "identity")
			if err := os.Mkdir(identity, 0o700); err != nil {
				t.Fatal(err)
			}
			if tt.layout != "" {
				stagePreflightCertificate(t, identity, tt.layout)
			}
			config, ca := filepath.Join(root, "agent.yaml"), filepath.Join(root, "ca.pem")
			if tt.managed {
				writePreflightFixture(t, config)
			}
			writePreflightFixture(t, ca)
			switch tt.writable {
			case "directory":
				if err := os.Chmod(root, 0o770); err != nil {
					t.Fatal(err)
				}
			case "bundle":
				if err := os.Chmod(ca, 0o660); err != nil {
					t.Fatal(err)
				}
			case "policy":
				if err := os.Chmod(config, 0o660); err != nil {
					t.Fatal(err)
				}
			}
			joinSecret := ""
			if tt.token {
				joinSecret = "pjt_" + strings.Repeat("a", 64)
			}
			cmd := exec.CommandContext(t.Context(), bash, "-s")
			cmd.Stdin = strings.NewReader(setup + start + preflight)
			cmd.Env = []string{
				"PATH=" + os.Getenv("PATH"), "identity=" + identity, "ca_file=" + ca,
				"config_dir=" + root, "config=" + config, "join_secret=" + joinSecret, "unit=probectl-agent.service",
				"unit_dir=" + filepath.Join(root, "service.d"), "drop_in=" + filepath.Join(root, "service.d", "agent.conf"),
			}
			out, err := cmd.CombinedOutput()
			if tt.refusal == "" && err != nil {
				t.Fatalf("managed identity did not reach enrollment verification: %v %s", err, out)
			}
			if tt.refusal != "" && (err == nil || !strings.Contains(string(out), tt.refusal)) {
				t.Fatalf("expected refusal %q: %v %s", tt.refusal, err, out)
			}
		})
	}
}

func stagePreflightCertificate(t *testing.T, identity, layout string) {
	t.Helper()
	link := func(target, path string) {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	cert := filepath.Join(identity, "cert.pem")
	if layout == "regular" {
		writePreflightFixture(t, cert)
		return
	}
	link("current/cert.pem", cert)
	if layout == "dangling" {
		return
	}
	version := "v-example-0"
	if layout == "foreign" {
		version = "../foreign"
	}
	link(version, filepath.Join(identity, "current"))
	if layout == "missing-version" {
		return
	}
	material := filepath.Join(identity, version)
	if err := os.Mkdir(material, 0o700); err != nil {
		t.Fatal(err)
	}
	if layout != "missing-cert" {
		writePreflightFixture(t, filepath.Join(material, "cert.pem"))
	}
}

func writePreflightFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("preflight fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
