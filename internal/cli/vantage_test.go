// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVantageDeployKeepsPlanAndCredentialsScoped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this subprocess fixture uses a POSIX shell")
	}
	bin := t.TempDir()
	root := filepath.Join(t.TempDir(), "owned region")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
if [ -n "$PROBECTL_API_TOKEN$PROBECTL_AGENT_JOIN_TOKEN$PROBECTL_RMM_JOIN_TOKEN$PROBECTL_SESSION_COOKIE_FILE" ]; then
    echo 'probectl credentials reached Terraform' >&2
    exit 1
fi
if [ "$AWS_PROFILE" != "owned-vantage-fixture" ]; then
    echo 'the operator cloud profile did not reach Terraform' >&2
    exit 1
fi
printf '%s\n' "$1" "$2" "$3"
`
	if err := os.WriteFile(filepath.Join(bin, "terraform"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("PROBECTL_API_TOKEN", "test-api-credential")
	t.Setenv("PROBECTL_AGENT_JOIN_TOKEN", "test-agent-credential")
	t.Setenv("PROBECTL_RMM_JOIN_TOKEN", "test-rmm-credential")
	t.Setenv("PROBECTL_SESSION_COOKIE_FILE", "test-session-file")
	t.Setenv("AWS_PROFILE", "owned-vantage-fixture")
	for _, entry := range []struct {
		name, want, input string
		extra             []string
	}{
		{name: "plan", want: "plan", input: "-input=false"},
		{name: "apply", want: "apply", input: "-input=true", extra: []string{"--apply"}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append([]string{"vantage", "deploy", "--dir", root}, entry.extra...)
			code := RunWithStdin(args, os.Getenv, strings.NewReader(""), &out, &errOut)
			want := strings.Join([]string{"-chdir=" + root, "init", "-input=false", "-chdir=" + root, entry.want, entry.input, ""}, "\n")
			if code != 0 || out.String() != want || errOut.Len() != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q, want %q", code, out.String(), errOut.String(), want)
			}
		})
	}
}
