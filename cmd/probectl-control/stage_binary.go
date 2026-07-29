// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stageBinary copies the running static control binary into a shared volume.
// Distroless images deliberately contain no shell or cp utility, so Helm backup
// and restore init containers use this narrow app-native helper.
func stageBinary(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return fmt.Errorf("usage: probectl-control stage-binary <destination>")
	}
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	return stageBinaryFile(source, args[0])
}

func stageBinaryFile(source, destination string) error {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("inspect source executable: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("source executable %s is not a regular file", source)
	}
	if destinationInfo, err := os.Stat(destination); err == nil {
		if os.SameFile(sourceInfo, destinationInfo) {
			return fmt.Errorf("source executable and destination are the same file: %s", destination)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect staging destination: %w", err)
	}

	destinationDir := filepath.Dir(destination)
	if err := os.MkdirAll(destinationDir, 0o755); err != nil {
		return fmt.Errorf("create staging directory %s: %w", destinationDir, err)
	}

	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source executable: %w", err)
	}
	defer input.Close()

	output, err := os.CreateTemp(destinationDir, ".probectl-stage-*")
	if err != nil {
		return fmt.Errorf("create staged executable: %w", err)
	}
	tempPath := output.Name()
	closed := false
	defer func() {
		if !closed {
			_ = output.Close()
		}
		_ = os.Remove(tempPath)
	}()

	written, err := io.Copy(output, input)
	if err != nil {
		return fmt.Errorf("copy executable into staging volume: %w", err)
	}
	if written != sourceInfo.Size() {
		return fmt.Errorf("copy executable into staging volume: wrote %d bytes, want %d", written, sourceInfo.Size())
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync staged executable: %w", err)
	}
	if err := output.Chmod(0o555); err != nil {
		return fmt.Errorf("make staged executable runnable: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close staged executable: %w", err)
	}
	closed = true
	if err := os.Rename(tempPath, destination); err != nil {
		return fmt.Errorf("install staged executable at %s: %w", destination, err)
	}
	return nil
}
