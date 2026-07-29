// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	repositoryActionPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	dockerActionPattern     = regexp.MustCompile(`^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$`)
)

type actionRecord struct {
	job    string
	line   int
	ref    string
	reason string
}

func runActions(paths []string, stdout, stderr io.Writer) int {
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
		records, err := workflowActionRecords(root)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %s: %v\n", path, err)
			failed = true
			continue
		}
		for _, record := range records {
			if record.reason == "" {
				continue
			}
			fmt.Fprintln(stdout, "UNPINNED workflow action (use a full action commit SHA or docker sha256 digest):")
			fmt.Fprintf(stdout, "  %s:%d: job %s uses %q (%s)\n", path, record.line, record.job, record.ref, record.reason)
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

func workflowActionRecords(root *yaml.Node) ([]actionRecord, error) {
	jobs, ok := mappingValue(root, "jobs")
	if !ok {
		return nil, fmt.Errorf("$.jobs: required mapping is missing")
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("$.jobs: must be a mapping")
	}

	var records []actionRecord
	for i := 0; i < len(jobs.Content); i += 2 {
		key, job := jobs.Content[i], jobs.Content[i+1]
		if !jobIDPattern.MatchString(key.Value) {
			return nil, fmt.Errorf("$.jobs: invalid job identifier %q at line %d", key.Value, key.Line)
		}
		if job.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("$.jobs.%s: job must be a mapping", key.Value)
		}
		walkWorkflowActions(job, key.Value, &records)
	}
	return records, nil
}

func walkWorkflowActions(node *yaml.Node, job string, records *[]actionRecord) {
	switch node.Kind {
	case yaml.MappingNode:
		for index := 0; index < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Value == "uses" {
				*records = append(*records, inspectActionValue(job, value))
				continue
			}
			walkWorkflowActions(value, job, records)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkWorkflowActions(child, job, records)
		}
	}
}

func inspectActionValue(job string, node *yaml.Node) actionRecord {
	record := actionRecord{
		job:  job,
		line: node.Line,
		ref:  nodeDescription(node),
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		record.reason = "action reference must be one literal string"
		return record
	}

	ref := strings.TrimSpace(node.Value)
	record.ref = ref
	switch {
	case ref == "":
		record.reason = "action reference is empty"
	case strings.Contains(ref, "${{"):
		record.reason = "GitHub expression is unresolved"
	case strings.ContainsAny(ref, " \t\r\n"):
		record.reason = "action reference contains whitespace"
	case strings.HasPrefix(ref, "./"):
		if len(ref) == 2 {
			record.reason = "local action path is empty"
		}
	case strings.HasPrefix(ref, "docker://"):
		if !dockerActionPattern.MatchString(ref) {
			record.reason = "docker action is not pinned to a full sha256 digest"
		}
	case !repositoryActionPattern.MatchString(ref):
		record.reason = "repository action is not pinned to a full 40-hex commit SHA"
	}
	return record
}
