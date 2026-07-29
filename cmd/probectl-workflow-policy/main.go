// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// probectl-workflow-policy exposes the semantic YAML facts used by the
// repository's workflow security gates. Keeping YAML interpretation here
// prevents harmless quoting and flow style from changing what the gates see.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type permissionRecord struct {
	scope string
	job   string
	write bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "permissions" {
		fmt.Fprintln(stderr, "usage: probectl-workflow-policy permissions WORKFLOW")
		return 2
	}

	root, err := loadWorkflow(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "workflow-policy: %v\n", err)
		return 1
	}
	records, err := permissionRecords(root)
	if err != nil {
		fmt.Fprintf(stderr, "workflow-policy: %s: %v\n", args[1], err)
		return 1
	}
	for _, record := range records {
		level := "read"
		if record.write {
			level = "write"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", record.scope, record.job, level)
	}
	return 0
}

func loadWorkflow(path string) (*yaml.Node, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, fmt.Errorf("decode %s: expected one YAML document", path)
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("decode %s: workflow root must be a mapping", path)
	}
	if err := validateSemanticShape(root, "$"); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return root, nil
}

func validateSemanticShape(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("%s: YAML aliases are not allowed in security-policy input", path)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return fmt.Errorf("%s: malformed YAML mapping", path)
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: mapping key at line %d must be a string", path, key.Line)
			}
			if key.Tag == "!!merge" || key.Value == "<<" {
				return fmt.Errorf("%s: YAML merge keys are not allowed in security-policy input", path)
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("%s: duplicate mapping key %q", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			childPath := path + "." + key.Value
			if err := validateSemanticShape(value, childPath); err != nil {
				return err
			}
		}
		return nil
	}
	for index, child := range node.Content {
		if err := validateSemanticShape(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}
	return nil
}

func permissionRecords(root *yaml.Node) ([]permissionRecord, error) {
	workflowWrite := false
	if permissions, ok := mappingValue(root, "permissions"); ok {
		var err error
		workflowWrite, err = permissionsWrite(permissions, "$.permissions")
		if err != nil {
			return nil, err
		}
	}
	records := []permissionRecord{{scope: "workflow", job: "-", write: workflowWrite}}

	jobs, ok := mappingValue(root, "jobs")
	if !ok {
		return nil, fmt.Errorf("$.jobs: required mapping is missing")
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("$.jobs: must be a mapping")
	}
	for i := 0; i < len(jobs.Content); i += 2 {
		key, job := jobs.Content[i], jobs.Content[i+1]
		if !jobIDPattern.MatchString(key.Value) {
			return nil, fmt.Errorf("$.jobs: invalid job identifier %q at line %d", key.Value, key.Line)
		}
		if job.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("$.jobs.%s: job must be a mapping", key.Value)
		}
		write := false
		if permissions, ok := mappingValue(job, "permissions"); ok {
			var err error
			write, err = permissionsWrite(permissions, "$.jobs."+key.Value+".permissions")
			if err != nil {
				return nil, err
			}
		}
		records = append(records, permissionRecord{scope: "job", job: key.Value, write: write})
	}
	return records, nil
}

func permissionsWrite(node *yaml.Node, path string) (bool, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return false, fmt.Errorf("%s: permission scalar at line %d must be a string", path, node.Line)
		}
		switch strings.TrimSpace(node.Value) {
		case "read-all":
			return false, nil
		case "write-all":
			return true, nil
		default:
			return false, fmt.Errorf("%s: unresolved permission scalar %q", path, node.Value)
		}
	case yaml.MappingNode:
		write := false
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return false, fmt.Errorf("%s.%s: permission at line %d must be a string", path, key.Value, value.Line)
			}
			switch strings.TrimSpace(value.Value) {
			case "read", "none":
			case "write":
				write = true
			default:
				return false, fmt.Errorf("%s.%s: unresolved permission %q", path, key.Value, value.Value)
			}
		}
		return write, nil
	default:
		return false, fmt.Errorf("%s: permissions at line %d must be read-all, write-all, or a mapping", path, node.Line)
	}
}

func mappingValue(mapping *yaml.Node, name string) (*yaml.Node, bool) {
	if mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1], true
		}
	}
	return nil, false
}
