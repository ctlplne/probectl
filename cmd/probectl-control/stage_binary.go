// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stageBinary copies the running static control binary into a shared volume.
// Distroless images deliberately contain no shell or cp utility, so Helm backup
// and restore init containers use this narrow app-native helper.
//
//	probectl-control stage-binary <destination>
//
// Arguments are parsed through a flag.FlagSet so that `-h`/`--help` print usage
// and exit cleanly instead of being taken as a destination path. Before this
// guard, `stage-binary -h` sailed past the len==1 check and copied the ~50MB
// binary to a file literally named "-h"; a destination that begins with '-' is
// now rejected (it is almost always a mistyped flag) before anything is staged.
func stageBinary(args []string) error {
	fs := flag.NewFlagSet("stage-binary", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: probectl-control stage-binary <destination>")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h/--help: usage already printed to stderr; not an error and
			// nothing is staged.
			return nil
		}
		// An unknown flag (e.g. -x). flag already printed the specifics + usage.
		return fmt.Errorf("usage: probectl-control stage-binary <destination>")
	}
	rest := fs.Args()
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		fs.Usage()
		return fmt.Errorf("usage: probectl-control stage-binary <destination>")
	}
	destination := rest[0]
	// Defense in depth for a destination that slipped through as a positional
	// (e.g. after `--`): a '-'-prefixed path is refused before staging so no
	// file is ever written under a flag-shaped name.
	if strings.HasPrefix(destination, "-") {
		fs.Usage()
		return fmt.Errorf("usage: probectl-control stage-binary <destination> (destination must not begin with '-')")
	}
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate running executable: %w", err)
	}
	return stageBinaryFile(source, destination)
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
