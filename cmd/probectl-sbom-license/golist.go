// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// build is what a binary's embedded build information says about how it was
// compiled: enough to ask `go list` for exactly the files it links.
type build struct {
	mainPackage string // e.g. github.com/ctlplne/probectl/cmd/probectl-agent
	mainModule  string
	tags        string // the -tags build setting, comma-separated
	goos        string
	goarch      string
	cgo         string
	revision    string // vcs.revision, when the build recorded one
}

// readBuild reads the Go build information embedded in a binary.
func readBuild(path string) (build, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return build{}, fmt.Errorf("%s: no Go build information: %w", path, err)
	}
	b := build{mainPackage: info.Path, mainModule: info.Main.Path}
	for _, s := range info.Settings {
		switch s.Key {
		case "-tags":
			b.tags = s.Value
		case "GOOS":
			b.goos = s.Value
		case "GOARCH":
			b.goarch = s.Value
		case "CGO_ENABLED":
			b.cgo = s.Value
		case "vcs.revision":
			b.revision = s.Value
		}
	}
	if b.mainPackage == "" || b.goos == "" || b.goarch == "" {
		return build{}, fmt.Errorf("%s: build information lacks the main package, GOOS or GOARCH", path)
	}
	return b, nil
}

// linkedFile is one first-party file compiled or embedded into a binary.
type linkedFile struct {
	rel string // repository-relative, slash-separated
}

type goListPackage struct {
	ImportPath string
	Dir        string
	Standard   bool
	Module     *struct {
		Path string
		Main bool
	}
	GoFiles    []string
	CgoFiles   []string
	SFiles     []string
	EmbedFiles []string
	Error      *struct{ Err string }
}

// listFiles returns the first-party files `go list -deps` says the build
// links: every Go, cgo and assembly source file and every embedded file of
// each main-module package the main package depends on.
func listFiles(ctx context.Context, src *sourceTree, b build, warn io.Writer) ([]linkedFile, error) {
	if b.mainModule != src.module {
		return nil, fmt.Errorf("binary main module %q is not this checkout's module %q", b.mainModule, src.module)
	}
	if b.revision != "" {
		if head, err := gitHead(ctx, src.root); err == nil && head != b.revision {
			return nil, fmt.Errorf("binary was built from commit %s but the checkout is at %s", b.revision, head)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	args := []string{"list", "-e", "-deps", "-json=ImportPath,Dir,Standard,Module,GoFiles,CgoFiles,SFiles,EmbedFiles,Error"}
	if b.tags != "" {
		args = append(args, "-tags="+b.tags)
	}
	args = append(args, b.mainPackage)
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // fixed go binary; the arguments come from the binary's own build information
	cmd.Dir = src.root
	cmd.Env = append(os.Environ(), "GOOS="+b.goos, "GOARCH="+b.goarch, "GOWORK=off", "GOFLAGS=")
	if b.cgo != "" {
		cmd.Env = append(cmd.Env, "CGO_ENABLED="+b.cgo)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return decodeGoList(&stdout, src, b.mainPackage, warn)
}

func decodeGoList(r io.Reader, src *sourceTree, mainPackage string, warn io.Writer) ([]linkedFile, error) {
	dec := json.NewDecoder(r)
	var files []linkedFile
	sawMain := false
	for {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		if p.Standard || p.Module == nil || p.Module.Path != src.module {
			continue
		}
		if p.ImportPath == mainPackage {
			sawMain = true
			if p.Error != nil {
				return nil, fmt.Errorf("go list %s: %s", mainPackage, p.Error.Err)
			}
		} else if p.Error != nil {
			// Typically a go:embed pattern whose generated files only exist
			// inside the image build (e.g. compiled BPF objects); the package's
			// checked-in files are still listed.
			fmt.Fprintf(warn, "note: go list %s: %s\n", p.ImportPath, p.Error.Err)
		}
		for _, group := range [][]string{p.GoFiles, p.CgoFiles, p.SFiles, p.EmbedFiles} {
			for _, name := range group {
				rel, err := filepath.Rel(src.root, filepath.Join(p.Dir, name))
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return nil, fmt.Errorf("package %s file %s is outside the checkout %s", p.ImportPath, name, src.root)
				}
				files = append(files, linkedFile{rel: filepath.ToSlash(rel)})
			}
		}
	}
	if !sawMain {
		return nil, fmt.Errorf("go list did not report the main package %s", mainPackage)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("go list reported no first-party files for %s", mainPackage)
	}
	return files, nil
}

func gitHead(ctx context.Context, root string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// binaryResolver finds the binary behind an SBOM package (syft's sourceInfo
// path, relative to the scanned directory) and lists what it links.
type binaryResolver struct {
	dir string
	src *sourceTree
}

func (r binaryResolver) files(ctx context.Context, artifact string, warn io.Writer) ([]linkedFile, error) {
	clean := filepath.Clean("/" + filepath.FromSlash(artifact))
	path := filepath.Join(r.dir, clean)
	b, err := readBuild(path)
	if err != nil {
		return nil, err
	}
	return listFiles(ctx, r.src, b, warn)
}
