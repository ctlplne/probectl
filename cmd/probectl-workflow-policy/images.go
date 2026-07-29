// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var literalDigestImagePattern = regexp.MustCompile(`^[^@[:space:]]+@sha256:[0-9a-fA-F]{64}$`)

type imageFinding struct {
	line   int
	key    string
	value  string
	reason string
}

func runImages(paths []string, stdout, stderr io.Writer) int {
	files, err := workflowFiles(paths)
	if err != nil {
		fmt.Fprintf(stderr, "workflow-policy: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintln(stderr, "workflow-policy: no .yml or .yaml workflows found")
		return 1
	}

	failed := false
	for _, path := range files {
		root, err := loadWorkflow(path)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %v\n", err)
			failed = true
			continue
		}
		findings, err := workflowImageFindings(root)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %s: %v\n", path, err)
			failed = true
			continue
		}
		for _, finding := range findings {
			fmt.Fprintln(stdout, "MUTABLE workflow container/service/matrix image (use a literal @sha256 digest; SUPPLY-002):")
			fmt.Fprintf(stdout, "  %s:%d:%s: %q (%s)\n", path, finding.line, finding.key, finding.value, finding.reason)
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

func workflowFiles(paths []string) ([]string, error) {
	seen := make(map[string]struct{})
	var files []string
	addFile := func(path string) error {
		if _, ok := seen[path]; ok {
			return nil
		}
		if len(files) >= maxWorkflowFiles {
			return fmt.Errorf("workflow file count exceeds %d-file limit", maxWorkflowFiles)
		}
		seen[path] = struct{}{}
		files = append(files, path)
		return nil
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s: workflow path must not be a symlink", path)
		}
		if !info.IsDir() {
			if !isWorkflowYAML(path) {
				return nil, fmt.Errorf("%s: workflow path must end in .yml or .yaml", path)
			}
			if err := addFile(path); err != nil {
				return nil, err
			}
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !isWorkflowYAML(candidate) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("%s: workflow must be a regular file", candidate)
			}
			return addFile(candidate)
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", path, err)
		}
	}
	sort.Strings(files)
	return files, nil
}

func isWorkflowYAML(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yml" || extension == ".yaml"
}

func workflowImageFindings(root *yaml.Node) ([]imageFinding, error) {
	jobs, ok := mappingValue(root, "jobs")
	if !ok {
		return nil, fmt.Errorf("$.jobs: required mapping is missing")
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("$.jobs: must be a mapping")
	}

	var findings []imageFinding
	walkWorkflowImages(jobs, &findings)
	return findings, nil
}

func walkWorkflowImages(node *yaml.Node, findings *[]imageFinding) {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			switch key.Value {
			case "container":
				if value.Kind == yaml.MappingNode {
					if _, ok := mappingValue(value, "image"); !ok {
						*findings = append(*findings, imageFinding{
							line:   value.Line,
							key:    key.Value,
							value:  nodeDescription(value),
							reason: "container mapping has no direct literal image",
						})
					}
					walkWorkflowImages(value, findings)
					continue
				}
				if finding := inspectImageValue(key.Value, value); finding != nil {
					*findings = append(*findings, *finding)
				}
			case "image":
				if finding := inspectImageValue(key.Value, value); finding != nil {
					*findings = append(*findings, *finding)
				}
			default:
				walkWorkflowImages(value, findings)
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkWorkflowImages(child, findings)
		}
	}
}

func inspectImageValue(key string, node *yaml.Node) *imageFinding {
	finding := &imageFinding{
		line:  node.Line,
		key:   key,
		value: nodeDescription(node),
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		finding.reason = "image value must be a string"
		return finding
	}
	finding.value = node.Value
	if node.Style == yaml.LiteralStyle || node.Style == yaml.FoldedStyle || strings.ContainsAny(node.Value, "\r\n") {
		finding.reason = "multiline image values are not allowed"
		return finding
	}
	if strings.Contains(node.Value, "${{") {
		finding.reason = "GitHub expression is unresolved"
		return finding
	}
	if !literalDigestImagePattern.MatchString(node.Value) {
		finding.reason = "image is not a literal digest reference"
		return finding
	}
	return nil
}

func nodeDescription(node *yaml.Node) string {
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	switch node.Kind {
	case yaml.MappingNode:
		return "<mapping>"
	case yaml.SequenceNode:
		return "<sequence>"
	case yaml.AliasNode:
		return "<alias>"
	default:
		return "<non-string>"
	}
}
