// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// checkoutRecord is one `actions/checkout` step and the SEMANTIC value of its
// `with.persist-credentials` input — parsed as a real YAML mapping value, so a
// commented-out or string-shaped line cannot masquerade as the real setting.
type checkoutRecord struct {
	job     string
	line    int
	persist string // "false", "true", or "unset"
}

// runCheckouts prints one TSV line per actions/checkout step:
//
//	job<TAB>line<TAB>persist   (persist ∈ false|true|unset)
//
// The textual gate that forbids credential persistence reads these facts rather
// than grepping, which is why a `# persist-credentials: false` comment — not a
// mapping node — correctly reports "unset" here (SUP-04 adversarial finding).
func runCheckouts(paths []string, stdout, stderr io.Writer) int {
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
		records, err := workflowCheckoutRecords(root)
		if err != nil {
			fmt.Fprintf(stderr, "workflow-policy: %s: %v\n", path, err)
			failed = true
			continue
		}
		for _, r := range records {
			fmt.Fprintf(stdout, "%s\t%s\t%d\t%s\n", path, r.job, r.line, r.persist)
		}
	}
	if failed {
		return 1
	}
	return 0
}

func workflowCheckoutRecords(root *yaml.Node) ([]checkoutRecord, error) {
	jobs, ok := mappingValue(root, "jobs")
	if !ok {
		return nil, fmt.Errorf("$.jobs: required mapping is missing")
	}
	if jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("$.jobs: must be a mapping")
	}
	var records []checkoutRecord
	for i := 0; i < len(jobs.Content); i += 2 {
		key, job := jobs.Content[i], jobs.Content[i+1]
		if !jobIDPattern.MatchString(key.Value) {
			return nil, fmt.Errorf("$.jobs: invalid job identifier %q at line %d", key.Value, key.Line)
		}
		if job.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("$.jobs.%s: job must be a mapping", key.Value)
		}
		walkWorkflowCheckouts(job, key.Value, &records)
	}
	return records, nil
}

// walkWorkflowCheckouts finds every step mapping that uses actions/checkout and
// records the parsed persist-credentials value of its sibling `with` mapping.
func walkWorkflowCheckouts(node *yaml.Node, job string, records *[]checkoutRecord) {
	switch node.Kind {
	case yaml.MappingNode:
		if uses, ok := mappingValue(node, "uses"); ok && isCheckoutRef(uses) {
			*records = append(*records, checkoutRecord{
				job:     job,
				line:    uses.Line,
				persist: persistCredentialsValue(node),
			})
		}
		for index := 0; index < len(node.Content); index += 2 {
			walkWorkflowCheckouts(node.Content[index+1], job, records)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			walkWorkflowCheckouts(child, job, records)
		}
	}
}

func isCheckoutRef(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	ref := strings.TrimSpace(node.Value)
	return ref == "actions/checkout" || strings.HasPrefix(ref, "actions/checkout@")
}

// persistCredentialsValue reads step.with.persist-credentials as a real mapping
// value. Anything that is not a present scalar reads as "unset" (GitHub's
// default is true — the credential is persisted).
func persistCredentialsValue(step *yaml.Node) string {
	with, ok := mappingValue(step, "with")
	if !ok || with.Kind != yaml.MappingNode {
		return "unset"
	}
	val, ok := mappingValue(with, "persist-credentials")
	if !ok || val.Kind != yaml.ScalarNode {
		return "unset"
	}
	switch strings.ToLower(strings.TrimSpace(val.Value)) {
	case "false":
		return "false"
	case "true":
		return "true"
	default:
		return "unset"
	}
}
