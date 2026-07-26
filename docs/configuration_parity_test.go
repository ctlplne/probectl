// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package docs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var probectlEnvKeyRE = regexp.MustCompile(`PROBECTL_[A-Z0-9_]+`)

var productionConfigGlobs = []string{
	"../cmd/*/*.go",
	"../internal/agent/config.go",
	"../internal/browsercanary/*.go",
	"../internal/cli/cli.go",
	"../internal/config/config.go",
	"../internal/device/config.go",
	"../internal/device/creds.go",
	"../internal/device/secretscreds.go",
	"../internal/ebpf/config.go",
	"../internal/ebpf/source_live_l7_linux.go",
	"../internal/endpoint/config.go",
	"../internal/flow/config.go",
	"../internal/secrets/*.go",
}

var generatedEnvFamilies = map[string][]string{
	"SecurityFromEnv": {
		"_TLS_ENABLED",
		"_TLS_CA_FILE",
		"_TLS_CERT_FILE",
		"_TLS_KEY_FILE",
		"_SASL_MECHANISM",
		"_SASL_USER",
		"_SASL_PASSWORD",
		"_ALLOW_PLAINTEXT",
		"_MAX_BUFFERED",
	},
	"ConfigFromEnv": {
		"_METRICS_ADDR",
		"_METRICS_TLS_CERT_FILE",
		"_METRICS_TLS_KEY_FILE",
	},
}

type documentedEnvFamily struct {
	keyPattern *regexp.Regexp
	marker     string
}

var documentedEnvFamilies = []documentedEnvFamily{
	{
		keyPattern: regexp.MustCompile(`^PROBECTL_(AGENT|FLOW|DEVICE|EBPF|ENDPOINT|BMP)_METRICS_(ADDR|TLS_CERT_FILE|TLS_KEY_FILE)$`),
		marker:     "`<PREFIX>_METRICS_ADDR`",
	},
	{
		keyPattern: regexp.MustCompile(`^PROBECTL_(FLOW|DEVICE|EBPF|ENDPOINT)_BUS_(TLS_ENABLED|TLS_CA_FILE|TLS_CERT_FILE|TLS_KEY_FILE|SASL_MECHANISM|SASL_USER|SASL_PASSWORD|ALLOW_PLAINTEXT|MAX_BUFFERED)$`),
		marker:     "`_BUS_TLS_ENABLED`",
	},
}

func TestProductionEnvKeysAndConfigurationDocsAreBidirectional(t *testing.T) {
	codeKeys := productionEnvKeys(t)
	doc, err := os.ReadFile("configuration.md")
	if err != nil {
		t.Fatalf("read configuration.md: %v", err)
	}

	missing, stale := configurationParityViolations(codeKeys, string(doc))
	if len(missing) != 0 || len(stale) != 0 {
		t.Fatalf(
			"configuration parity failed\nundocumented production keys:\n%s\nstale documented keys:\n%s",
			strings.Join(missing, "\n"),
			strings.Join(stale, "\n"),
		)
	}
}

func TestConfigurationParityRejectsPlantedDrift(t *testing.T) {
	doc := "| Variable | Default | Purpose |\n" +
		"|---|---|---|\n" +
		"| `PROBECTL_REAL_KEY` | (none) | used |\n"

	missing, stale := configurationParityViolations(
		map[string]struct{}{
			"PROBECTL_REAL_KEY":                 {},
			"PROBECTL_PLANTED_UNDOCUMENTED_KEY": {},
		},
		doc,
	)
	if len(missing) != 1 || missing[0] != "PROBECTL_PLANTED_UNDOCUMENTED_KEY" || len(stale) != 0 {
		t.Fatalf("undocumented-key self-check = missing %v stale %v", missing, stale)
	}

	missing, stale = configurationParityViolations(
		map[string]struct{}{"PROBECTL_REAL_KEY": {}},
		doc+"| `PROBECTL_PLANTED_STALE_KEY` | (none) | stale |\n",
	)
	if len(missing) != 0 || len(stale) != 1 || stale[0] != "PROBECTL_PLANTED_STALE_KEY" {
		t.Fatalf("stale-key self-check = missing %v stale %v", missing, stale)
	}
}

func productionEnvKeys(t *testing.T) map[string]struct{} {
	t.Helper()
	keys := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, pattern := range productionConfigGlobs {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("expand production config glob %q: %v", pattern, err)
		}
		if len(paths) == 0 {
			t.Fatalf("production config glob %q matched no files", pattern)
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			collectGoEnvKeys(t, path, keys)
		}
	}

	worker, err := os.ReadFile("../browser-worker/worker.mjs")
	if err != nil {
		t.Fatalf("read browser worker config source: %v", err)
	}
	jsEnvRE := regexp.MustCompile(`process\.env\.([A-Z][A-Z0-9_]*)`)
	for _, match := range jsEnvRE.FindAllSubmatch(worker, -1) {
		key := string(match[1])
		if strings.HasPrefix(key, "PROBECTL_") {
			keys[key] = struct{}{}
		}
	}
	return keys
}

func collectGoEnvKeys(t *testing.T, path string, keys map[string]struct{}) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse production config source %s: %v", path, err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if suffixes, ok := generatedEnvFamilies[calledName(call.Fun)]; ok {
			for _, arg := range call.Args {
				for _, prefix := range stringEnvKeys(arg) {
					for _, suffix := range suffixes {
						keys[prefix+suffix] = struct{}{}
					}
				}
			}
			return true
		}
		for _, arg := range call.Args {
			for _, key := range stringEnvKeys(arg) {
				if !strings.HasSuffix(key, "_") {
					keys[key] = struct{}{}
				}
			}
		}
		return true
	})
}

func calledName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		return value.Sel.Name
	default:
		return ""
	}
}

func stringEnvKeys(expr ast.Expr) []string {
	var keys []string
	ast.Inspect(expr, func(node ast.Node) bool {
		if _, nestedCall := node.(*ast.CallExpr); nestedCall {
			// The file-level walk visits this call separately. Skipping it
			// here prevents an outer helper from treating a nested
			// SecurityFromEnv/ConfigFromEnv prefix as a literal key.
			return false
		}
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		keys = append(keys, probectlEnvKeyRE.FindAllString(value, -1)...)
		return true
	})
	return keys
}

func configurationParityViolations(codeKeys map[string]struct{}, doc string) (missing, stale []string) {
	for key := range codeKeys {
		if configurationDocumentsKey(doc, key) {
			continue
		}
		missing = append(missing, key)
	}

	docKeys := map[string]struct{}{}
	for _, key := range probectlEnvKeyRE.FindAllString(doc, -1) {
		// A trailing underscore is a documented family prefix such as
		// PROBECTL_OIDC_* rather than one literal process variable.
		if !strings.HasSuffix(key, "_") {
			docKeys[key] = struct{}{}
		}
	}
	for key := range docKeys {
		if _, ok := codeKeys[key]; ok {
			continue
		}
		if strings.Contains(doc, "`<PREFIX>_METRICS_ADDR`") {
			if _, ok := codeKeys[key+"_METRICS_ADDR"]; ok {
				// The prose enumerates the six concrete process prefixes,
				// while one family row documents their identical suffixes.
				continue
			}
		}
		stale = append(stale, key)
	}
	sort.Strings(missing)
	sort.Strings(stale)
	return missing, stale
}

func configurationDocumentsKey(doc, key string) bool {
	if strings.Contains(doc, "`"+key+"`") {
		return true
	}
	for _, family := range documentedEnvFamilies {
		if family.keyPattern.MatchString(key) && strings.Contains(doc, family.marker) {
			return true
		}
	}
	return false
}
