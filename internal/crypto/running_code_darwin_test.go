// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build darwin && cgo

package crypto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunningCodeIdentityRemainsBoundToTheLaunchedMachO(t *testing.T) {
	const child = "PROBECTL_TEST_RUNNING_CODE_CHILD"
	if os.Getenv(child) == "1" {
		fmt.Println("ready")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		hash, eligible, err := readRunningCodeDirectory()
		if err != nil || eligible {
			t.Fatalf("ad-hoc test image must have a kernel identity and be ineligible: %v, %v", err, eligible)
		}
		if measured, err := RunningCodeIdentity(); measured != "" || !errors.Is(err, ErrRunningCodeIdentityUnavailable) {
			t.Fatalf("ad-hoc code escaped the release gate: %q, %v", measured, err)
		}
		fmt.Println(hash)
		return
	}

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	installed := filepath.Join(directory, "endpoint")
	next := filepath.Join(directory, "next")
	expected := signRunningCodeFixture(t, ctx, installed, "com.probectl.test.first", image)
	replacement := signRunningCodeFixture(t, ctx, next, "com.probectl.test.second", image)
	if expected == replacement {
		t.Fatal("fixture signatures must identify different executables")
	}

	command := exec.CommandContext(ctx, installed, "-test.run=^TestRunningCodeIdentityRemainsBoundToTheLaunchedMachO$")
	command.Env = append(os.Environ(), child+"=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatalf("signed fixture did not start: %q (%v)", lines.Text(), lines.Err())
	}
	if err := os.Rename(next, installed); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stdin, "measure"); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != expected {
		t.Fatalf("running image measured %q after replacement, want %q (%v)", lines.Text(), expected, lines.Err())
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("running-image probe: %v: %s", err, stderr.String())
	}
}

func signRunningCodeFixture(t *testing.T, ctx context.Context, path, identifier string, image []byte) string {
	t.Helper()
	if err := os.WriteFile(path, image, 0o700); err != nil {
		t.Fatal(err)
	}
	signed, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime", "--identifier", identifier, path).CombinedOutput()
	if err != nil {
		t.Fatalf("signing local fixture: %v: %s", err, signed)
	}
	metadata, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--display", "--verbose=4", path).CombinedOutput()
	if err != nil {
		t.Fatalf("reading local fixture signature: %v: %s", err, metadata)
	}
	for _, line := range strings.Split(string(metadata), "\n") {
		hash, ok := strings.CutPrefix(line, "CDHash=")
		if ok && len(hash) == 40 {
			return "cdhash:" + hash
		}
	}
	t.Fatal("codesign returned no code-directory hash")
	return ""
}
