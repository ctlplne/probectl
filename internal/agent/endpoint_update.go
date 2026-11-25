// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// DownloadEndpointPackage stages a released native installer from the device's
// enrolled control plane. A new destination appears only after the whole
// stream and the approved digest have been verified. OS tooling installs it.
func (c *Client) DownloadEndpointPackage(ctx context.Context, rolloutID, platform, destination string) (*agentv1.EndpointPackageMetadata, error) {
	if rolloutID == "" || len(rolloutID) > 64 || !wire.IsManagedPlatform(platform) || destination == "" {
		return nil, errors.New("endpoint update: rollout, native platform and local output path required")
	}
	ctx, cancel := context.WithTimeout(ctx, wire.EndpointPackageDeadline-5*time.Second)
	defer cancel()
	stream, err := agentv1.NewEndpointUpdateServiceClient(c.conn).DownloadEndpointPackage(ctx,
		&agentv1.DownloadEndpointPackageRequest{RolloutId: rolloutID, Platform: platform},
		grpc.MaxCallRecvMsgSize(wire.EndpointPackageChunk+1024))
	if err != nil {
		return nil, err
	}
	return receiveEndpointPackage(ctx, stream.Recv, platform, destination)
}

func receiveEndpointPackage(ctx context.Context, recv func() (*agentv1.DownloadEndpointPackageResponse, error),
	platform, destination string) (*agentv1.EndpointPackageMetadata, error) {
	opening, err := recv()
	if err != nil {
		return nil, fmt.Errorf("endpoint update: read installer metadata: %w", err)
	}
	metadata := opening.GetMetadata()
	remaining := metadata.GetSizeBytes()
	if remaining <= 0 || remaining > wire.EndpointPackageLimit || metadata.GetVersion() == "" ||
		metadata.GetPlatform() != platform || !digestRE.MatchString(metadata.GetPackageDigest()) ||
		!wire.ValidExecutableIdentity(platform, metadata.GetExecutableIdentity()) || metadata.GetExecutableIdentity() == metadata.GetPackageDigest() {
		return nil, errors.New("endpoint update: invalid installer metadata")
	}
	directory := filepath.Dir(destination)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	suffix, err := crypto.UUIDv4()
	if err != nil {
		return nil, err
	}
	stageName := ".probectl-endpoint-package-" + suffix
	stage, err := root.OpenFile(stageName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Remove(stageName) }()
	defer stage.Close()
	for remaining > 0 {
		frame, err := recv()
		if err != nil {
			return nil, fmt.Errorf("endpoint update: incomplete installer body: %w", err)
		}
		chunk := frame.GetChunk()
		if size := int64(len(chunk)); size == 0 || size > wire.EndpointPackageChunk || size > remaining {
			return nil, errors.New("endpoint update: invalid installer chunk")
		}
		if _, err := stage.Write(chunk); err != nil {
			return nil, err
		}
		remaining -= int64(len(chunk))
	}
	if _, err := recv(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("endpoint update: download did not complete: %w", err)
		}
		return nil, errors.New("endpoint update: unexpected data after installer body")
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	digest, err := crypto.HashReader(stage)
	if err != nil {
		return nil, err
	}
	if "sha256:"+hex.EncodeToString(digest) != metadata.GetPackageDigest() {
		return nil, errors.New("endpoint update: installer differs from the approved digest")
	}
	if err := stage.Sync(); err != nil {
		return nil, err
	}
	verified, err := stage.Stat()
	if err != nil {
		return nil, err
	}
	if err := stage.Close(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := publishEndpointInstaller(root, directory, stageName, filepath.Base(destination), verified); err != nil {
		return nil, err
	}
	return metadata, nil
}

func publishEndpointInstaller(root *os.Root, directory, stageName, destination string, verified os.FileInfo) error {
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	sameDirectory := func() bool {
		named, err := os.Stat(directory)
		return err == nil && os.SameFile(opened, named)
	}
	if !sameDirectory() {
		return errors.New("endpoint update: installer output directory changed")
	}
	staged, err := root.Lstat(stageName)
	if err != nil || !os.SameFile(verified, staged) {
		return errors.New("endpoint update: staged installer changed")
	}
	// Publish within the opened directory. Linking is atomic and preserves an
	// existing destination. No name lookup can jump to a replacement directory.
	if err := root.Link(stageName, destination); err != nil {
		return err
	}
	published, err := root.Lstat(destination)
	if err != nil || !os.SameFile(verified, published) {
		return errors.New("endpoint update: published installer changed")
	}
	if !sameDirectory() {
		return errors.Join(errors.New("endpoint update: installer output directory changed"), root.Remove(destination))
	}
	return nil
}
