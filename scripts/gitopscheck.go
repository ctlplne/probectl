// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command gitopscheck validates the repository's ArgoCD and Flux manifests
// without requiring a cluster or any network access.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Generators []struct {
			List struct {
				Elements []map[string]any `yaml:"elements"`
			} `yaml:"list"`
		} `yaml:"generators"`
		Template struct {
			Spec struct {
				Source struct {
					Helm struct {
						ValueFiles []string `yaml:"valueFiles"`
						Parameters []struct {
							Name  string `yaml:"name"`
							Value string `yaml:"value"`
						} `yaml:"parameters"`
					} `yaml:"helm"`
				} `yaml:"source"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type parsedManifest struct {
	path string
	raw  []byte
	doc  manifest
}

func main() {
	root := "deploy/gitops"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	checked, files, problems := checkGitOps(root)
	if len(problems) != 0 {
		fmt.Println("gitops gate: FAIL")
		for _, problem := range problems {
			fmt.Println("  " + problem.Error())
		}
		os.Exit(1)
	}
	fmt.Printf("gitops gate: OK (%d document(s) across %d file(s))\n", checked, files)
}

func checkGitOps(root string) (int, int, []error) {
	paths, err := filepath.Glob(filepath.Join(root, "**", "*.yaml"))
	if err != nil {
		return 0, 0, []error{err}
	}
	// filepath.Glob does not recursively expand **. Walk supplies the complete,
	// deterministic set and keeps the gate portable across operating systems.
	paths = paths[:0]
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return 0, 0, []error{err}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return 0, 0, []error{fmt.Errorf("no manifests under %s", root)}
	}

	var parsed []parsedManifest
	var problems []error
	checked := 0
	for _, path := range paths {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			problems = append(problems, fmt.Errorf("%s: %w", path, readErr))
			continue
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
		for {
			var doc manifest
			decodeErr := decoder.Decode(&doc)
			if errors.Is(decodeErr, io.EOF) {
				break
			}
			if decodeErr != nil {
				problems = append(problems, fmt.Errorf("%s: invalid YAML: %w", path, decodeErr))
				break
			}
			if doc.APIVersion == "" && doc.Kind == "" && doc.Metadata.Name == "" {
				continue
			}
			checked++
			parsed = append(parsed, parsedManifest{path: path, raw: raw, doc: doc})
			if doc.APIVersion == "" || doc.Kind == "" {
				problems = append(problems, fmt.Errorf("%s: a document is missing apiVersion/kind", path))
			}
		}
	}

	var multi []parsedManifest
	for _, candidate := range parsed {
		if candidate.doc.Kind == "ApplicationSet" && candidate.doc.Metadata.Name == "probectl-two-region" {
			multi = append(multi, candidate)
		}
	}
	if len(multi) != 1 {
		problems = append(problems, errors.New("expected exactly one ApplicationSet metadata.name=probectl-two-region"))
		return checked, len(paths), problems
	}
	return checked, len(paths), append(problems, checkTwoRegion(multi[0])...)
}

func checkTwoRegion(candidate parsedManifest) []error {
	var problems []error
	doc := candidate.doc
	var elements []map[string]any
	if len(doc.Spec.Generators) == 1 {
		elements = doc.Spec.Generators[0].List.Elements
	}
	regions, servers := map[string]bool{}, map[string]bool{}
	for _, element := range elements {
		region, _ := element["region"].(string)
		server, _ := element["server"].(string)
		regions[region], servers[server] = true, true
	}
	if len(elements) != 2 || len(regions) != 2 || len(servers) != 2 || regions[""] || servers[""] {
		problems = append(problems, fmt.Errorf("%s: list generator must declare exactly two distinct non-empty regions and Kubernetes APIs", candidate.path))
	}

	helm := doc.Spec.Template.Spec.Source.Helm
	if !contains(helm.ValueFiles, "values-multiregion.yaml") {
		problems = append(problems, fmt.Errorf("%s: must apply values-multiregion.yaml", candidate.path))
	}
	params := make(map[string]string, len(helm.Parameters))
	for _, parameter := range helm.Parameters {
		params[parameter.Name] = parameter.Value
	}
	required := map[string]string{
		"control.extraEnv.PROBECTL_REPLICATION_MODE": "sync",
		"control.extraEnv.PROBECTL_RPO_SECONDS":      "0",
		"control.extraEnv.PROBECTL_RTO_SECONDS":      "60",
		"secrets.existingSecret":                     "probectl-secrets",
	}
	for name, want := range required {
		if params[name] != want {
			problems = append(problems, fmt.Errorf("%s: %s must be %q", candidate.path, name, want))
		}
	}
	for _, forbidden := range []string{"postgres://", "PROBECTL_DATABASE_URL", "PROBECTL_DATABASE_READ_URL", "ENVELOPE_KEY", "SESSION_HMAC_KEY"} {
		if strings.Contains(string(candidate.raw), forbidden) {
			problems = append(problems, fmt.Errorf("%s: secret-bearing field %q must not be in GitOps YAML", candidate.path, forbidden))
		}
	}
	return problems
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
