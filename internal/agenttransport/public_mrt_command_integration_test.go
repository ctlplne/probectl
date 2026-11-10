// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/store"
)

// Builds and executes the shipped command; actual issued evidence mTLS and
// TLS app-role Postgres validate the result. Input MRT remains synthetic.
func TestPublicMRTNativeCommandPublishesWholeFileAndRejectsCorruptCompression(t *testing.T) {
	buildCtx, stopBuild := context.WithTimeout(t.Context(), 4*time.Minute)
	defer stopBuild()
	bin := filepath.Join(t.TempDir(), "probectl-agent")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("native MRT command requires the pinned Go tool on PATH", err)
	}
	env := append(os.Environ(), "GOTOOLCHAIN=local")
	version := exec.CommandContext(buildCtx, goBinary, "version")
	version.Env = env
	if output, err := version.CombinedOutput(); err != nil || !bytes.Contains(output, []byte(" "+runtime.Version()+" ")) {
		t.Fatal("native MRT command requires the same Go patch as its test binary", err, string(output))
	}
	build := exec.CommandContext(buildCtx, goBinary, "build", "-p=2", "-o", bin, "../../cmd/probectl-agent")
	build.Env = env
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatal("native MRT command did not build", err, string(output))
	}
	f := newPublicWireFixture(t)
	a, b := &f.lanes[0], &f.lanes[1]
	dir := t.TempDir()
	for name, original := range map[string]string{agent.IdentityCertFile: a.certFile, agent.IdentityKeyFile: a.keyFile, agent.IdentityServerCAFile: f.server.caFile} {
		raw, err := os.ReadFile(original)
		if err != nil {
			t.Fatal(err)
		}
		writeTemp(t, dir, name, raw)
	}
	original := bytes.Clone(a.source.SourceRecord)
	clock := binary.BigEndian.Uint32(original[:4])
	original = append(original, publicRIBWire(1, a.tail, clock)...)
	original = append(original, publicRIBWire(2, a.tail, clock)...)
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	invoke := func(t *testing.T, raw []byte) (string, error) {
		t.Helper()
		input := writeTemp(t, t.TempDir(), "original.input", raw)
		command := exec.CommandContext(f.ctx, bin, "import-mrt", "--file", input, "--source", a.source.ConfiguredRef, "--control-addr", f.server.addr, "--identity-dir", dir, "--server-name", "localhost")
		command.Env = append(os.Environ(), "PROBECTL_AGENT_LOG_FORMAT=json", "PROBECTL_AGENT_LOG_LEVEL=info")
		output, err := command.CombinedOutput()
		return string(output), err
	}
	output, err := invoke(t, compressed.Bytes())
	if err != nil {
		t.Fatal("native MRT command refused complete compressed original input", err, output)
	}
	var snapshot string
	for _, line := range bytes.Split([]byte(output), []byte{'\n'}) {
		var receipt struct {
			Message    string `json:"msg"`
			SnapshotID string `json:"snapshot_id"`
			Records    int64  `json:"records"`
			Bytes      int64  `json:"bytes"`
		}
		if err := json.Unmarshal(line, &receipt); err != nil || receipt.Message != "public routing source imported" {
			continue
		}
		if snapshot != "" || receipt.SnapshotID == "" || receipt.Records != 3 || receipt.Bytes != int64(len(original)) {
			t.Fatal("native MRT command lost its complete original receipt", output)
		}
		snapshot = receipt.SnapshotID
	}
	if snapshot == "" {
		t.Fatal("native MRT command omitted its complete-source receipt", output)
	}
	a.source.ObservationId = snapshot
	f.assertCurrent(t, a)
	f.assertCurrent(t, b)
	output, err = invoke(t, compressed.Bytes()[:compressed.Len()-1])
	if err == nil || bytes.Contains([]byte(output), []byte("public routing source imported")) {
		t.Fatal("native MRT command published corrupt compression", err, output)
	}
	if got, err := f.read(a, "192.0.2.9"); !errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("failed native MRT replacement left former source current", got, err)
	}
	f.assertCurrent(t, b)
}
