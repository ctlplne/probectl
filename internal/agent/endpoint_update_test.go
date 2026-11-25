// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestEndpointInstallerPublishesOnlyACompleteVerifiedStream(t *testing.T) {
	const platform = "darwin/arm64"
	const body = "signed installer fixture"
	digest := "sha256:" + hex.EncodeToString(crypto.Hash([]byte(body)))
	metadata := func(size int64, target string) *agentv1.DownloadEndpointPackageResponse {
		return &agentv1.DownloadEndpointPackageResponse{Frame: &agentv1.DownloadEndpointPackageResponse_Metadata{
			Metadata: &agentv1.EndpointPackageMetadata{Version: "v0.2.0", Platform: target,
				PackageDigest: digest, ExecutableIdentity: "cdhash:" + strings.Repeat("a", 40), SizeBytes: size},
		}}
	}
	chunk := func(body string) *agentv1.DownloadEndpointPackageResponse {
		return &agentv1.DownloadEndpointPackageResponse{Frame: &agentv1.DownloadEndpointPackageResponse_Chunk{Chunk: []byte(body)}}
	}
	opening := metadata(int64(len(body)), platform)
	for _, tc := range []struct {
		name       string
		frames     []*agentv1.DownloadEndpointPackageResponse
		lastErr    error
		exists     bool
		wantStaged bool
	}{
		{name: "complete", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body[:8]), chunk(body[8:])}, wantStaged: true},
		{name: "missing header", frames: []*agentv1.DownloadEndpointPackageResponse{chunk(body)}},
		{name: "wrong platform", frames: []*agentv1.DownloadEndpointPackageResponse{metadata(int64(len(body)), "darwin/amd64"), chunk(body)}},
		{name: "over transfer limit", frames: []*agentv1.DownloadEndpointPackageResponse{metadata(wire.EndpointPackageLimit+1, platform)}},
		{name: "over chunk limit", frames: []*agentv1.DownloadEndpointPackageResponse{metadata(wire.EndpointPackageChunk+1, platform), chunk(strings.Repeat("x", wire.EndpointPackageChunk+1))}},
		{name: "duplicate header", frames: []*agentv1.DownloadEndpointPackageResponse{opening, opening, chunk(body)}},
		{name: "truncated", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body[:8])}},
		{name: "trailing frame", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body), chunk("extra")}},
		{name: "terminal RPC failure", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body)}, lastErr: status.Error(codes.Aborted, "fixture stopped")},
		{name: "tampered", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(strings.Repeat("x", len(body)))}},
		{name: "destination collision", frames: []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body)}, exists: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "update.pkg")
			if tc.exists {
				if err := os.WriteFile(out, []byte("previous installer"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			i := 0
			recv := func() (*agentv1.DownloadEndpointPackageResponse, error) {
				if i < len(tc.frames) {
					frame := tc.frames[i]
					i++
					return frame, nil
				}
				if tc.lastErr != nil {
					return nil, tc.lastErr
				}
				return nil, io.EOF
			}
			got, err := receiveEndpointPackage(t.Context(), recv, platform, out)
			if (err == nil) != tc.wantStaged || (got != nil) != tc.wantStaged {
				t.Fatalf("staging result = %v, %v", got, err)
			}
			installed, readErr := os.ReadFile(out)
			switch {
			case tc.wantStaged && (readErr != nil || string(installed) != body):
				t.Fatal("verified installer bytes were not staged", readErr)
			case tc.exists && (readErr != nil || string(installed) != "previous installer"):
				t.Fatal("destination collision changed the earlier installer", readErr)
			case !tc.wantStaged && !tc.exists && !os.IsNotExist(readErr):
				t.Fatal("invalid installer left a destination file", readErr)
			}
			if staged, err := filepath.Glob(filepath.Join(dir, ".probectl-endpoint-package-*")); err != nil || len(staged) != 0 {
				t.Fatal("private staging files were not removed", staged, err)
			}
		})
	}
	t.Run("output directory is replaced", func(t *testing.T) {
		parent := t.TempDir()
		directory := filepath.Join(parent, "output")
		moved := filepath.Join(parent, "renamed")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		frames := []*agentv1.DownloadEndpointPackageResponse{opening, chunk(body)}
		recv := func() (*agentv1.DownloadEndpointPackageResponse, error) {
			if len(frames) != 0 {
				frame := frames[0]
				frames = frames[1:]
				return frame, nil
			}
			if err := os.Rename(directory, moved); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("Windows filesystem pins the open output directory: %v", err)
				}
				t.Fatal(err)
			}
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			return nil, io.EOF
		}
		metadata, err := receiveEndpointPackage(t.Context(), recv, platform, filepath.Join(directory, "update.pkg"))
		if metadata != nil || err == nil {
			t.Fatalf("accepted a replaced output directory: %v, %v", metadata, err)
		}
		for _, path := range []string{moved, directory} {
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unexpected installer files after directory replacement in %s: %v, %v", path, entries, err)
			}
		}
	})
}
