// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ctlplne/probectl/internal/completeness"
)

const (
	reachabilityRegistryPath = "capabilities.yaml"
	reachabilityStaticGate   = "internal/completeness.Validator"
)

// lintReachabilitySource reruns the repository's existing completeness static
// analyzer against the exact source tree supplied by the independent runner.
// Receipt strings and a matching JSON echo therefore cannot invent a binary,
// API, CLI operation, UI route, or documentation path.
func lintReachabilitySource(receipt Receipt, artifact ReachabilityArtifact, sourceRoot string) []Diagnostic {
	if strings.TrimSpace(sourceRoot) == "" {
		return []Diagnostic{{
			Code:    "reachability-source-unverified",
			Field:   "reachability",
			Problem: "an exact source root is required to rerun the completeness validator",
		}}
	}
	info, err := os.Lstat(sourceRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return []Diagnostic{{
			Code:    "reachability-source-unverified",
			Field:   "reachability",
			Problem: fmt.Sprintf("source root must be a real directory: %v", err),
		}}
	}

	registryData, err := readSourceFile(sourceRoot, reachabilityRegistryPath, 4<<20)
	if err != nil {
		return []Diagnostic{{Code: "reachability-source-unverified", Field: "reachability", Problem: err.Error()}}
	}
	var out []Diagnostic
	out = append(out, lintExecutableAuthority(receipt, sourceRoot)...)
	out = addDiagnosticIf(out, artifact.RegistryPath != reachabilityRegistryPath || artifact.RegistrySHA256 != digestBytes(registryData),
		"reachability-source-mismatch", "reachability", "static-gate artifact is not bound to this source tree's capabilities.yaml")
	out = addDiagnosticIf(out, artifact.StaticGate != reachabilityStaticGate || artifact.ValidatorPassed == nil || !*artifact.ValidatorPassed,
		"reachability-source-unverified", "reachability", "static artifact must name a successful internal/completeness.Validator run")

	registry, err := completeness.DecodeRegistry(registryData)
	if err != nil {
		return append(out, Diagnostic{Code: "reachability-source-unverified", Field: "reachability", Problem: err.Error()})
	}
	validator, err := completeness.NewValidator(sourceRoot)
	if err != nil {
		return append(out, Diagnostic{Code: "reachability-source-unverified", Field: "reachability", Problem: fmt.Sprintf("initialize completeness validator: %v", err)})
	}
	violations := validator.Validate(registry)

	var capability *completeness.Capability
	for i := range registry.Capabilities {
		if registry.Capabilities[i].ID == receipt.CapabilityID {
			capability = &registry.Capabilities[i]
			break
		}
	}
	if capability == nil {
		return append(out, Diagnostic{
			Code: "reachability-capability-missing", Field: "capability_id",
			Problem: fmt.Sprintf("capability %q is absent from the validated source registry", receipt.CapabilityID),
		})
	}
	out = append(out, lintHarnessSourceBindings(receipt, sourceRoot)...)
	for _, violation := range violations {
		if violation.Capability != "" && violation.Capability != capability.ID {
			continue
		}
		out = append(out, Diagnostic{
			Code:    reachabilityViolationCode(violation.Cell),
			Field:   "reachability." + violation.Cell,
			Problem: fmt.Sprintf("completeness validator %s: %s", violation.Code, violation.Problem),
		})
	}

	out = addDiagnosticIf(out, !cellHasRef(capability.Binary, "file:"+receipt.Reachability.BinaryEntrypoint) ||
		!buildTargetsBinary(receipt.Reachability.DefaultBuildCommand, receipt.Reachability.BinaryEntrypoint),
		"binary-unreachable", "reachability.binary_entrypoint", "binary entrypoint/build command do not match the validated capability registry row")
	apiRef := "api:" + strings.ToUpper(strings.TrimSpace(receipt.Reachability.API.Method)) + " " + receipt.Reachability.API.Path
	out = addDiagnosticIf(out, !cellHasRef(capability.API, apiRef) || !openAPIOperationMatches(sourceRoot, receipt.Reachability.API),
		"api-unreachable", "reachability.api", "API method/path/operationId do not match the validated registry and OpenAPI source")
	out = addDiagnosticIf(out, !cellHasRef(capability.CLI, "cli:"+receipt.Reachability.CLIOperation),
		"cli-unreachable", "reachability.cli_operation", "CLI operation does not match the validated capability registry row")
	out = addDiagnosticIf(out, !capabilityHasUIRoute(*capability, receipt.Reachability.UIRoute),
		"ui-unreachable", "reachability.ui_route", "UI route does not match the validated capability registry row")
	out = addDiagnosticIf(out, !cellHasRef(capability.Docs, "file:"+receipt.Reachability.DocsPath),
		"docs-unreachable", "reachability.docs_path", "documentation path does not match the validated capability registry row")
	return out
}

func lintExecutableAuthority(receipt Receipt, sourceRoot string) []Diagnostic {
	data, err := readSourceFile(sourceRoot, reviewProtocolPath, maxSemanticArtifactBytes)
	if err != nil {
		return []Diagnostic{{Code: "receipt-authority-mismatch", Field: "item", Problem: "checked-in delivery-audit authority registry is unavailable"}}
	}
	var registry deliveryAuditAuthorityRegistry
	if err := decodeStrict(data, &registry); err != nil || registry.Schema != "probectl.delivery-audit-authority/v1" {
		return []Diagnostic{{Code: "receipt-authority-mismatch", Field: "item", Problem: "checked-in delivery-audit authority registry is invalid"}}
	}
	matches := 0
	for _, protocol := range registry.ExecutableProtocols {
		if protocol.Item == receipt.Item && protocol.CapabilityID == receipt.CapabilityID &&
			protocol.HumanPathID == receipt.HumanPath.ID && protocol.Mode == receipt.HarnessScope.Mode {
			matches++
		}
	}
	if matches != 1 {
		return []Diagnostic{{Code: "receipt-authority-mismatch", Field: "item", Problem: "receipt item/capability/human-path/mode has no unique checked-in executable audit protocol"}}
	}
	return nil
}

func lintHarnessSourceBindings(receipt Receipt, sourceRoot string) []Diagnostic {
	var out []Diagnostic
	switch receipt.HarnessScope.Mode {
	case HarnessModeTenantPlane:
		out = addDiagnosticIf(out,
			!strings.HasPrefix(receipt.Reachability.API.Path, "/v1/") || strings.HasPrefix(receipt.Reachability.UIRoute, "/provider"),
			"harness-scope-invalid", "harness_scope", "tenant-plane receipt must select tenant API and UI surfaces")
	case HarnessModeProviderPlane:
		out = addDiagnosticIf(out,
			!strings.HasPrefix(receipt.Reachability.API.Path, "/provider/v1/") || !strings.HasPrefix(receipt.Reachability.UIRoute, "/provider"),
			"harness-scope-invalid", "harness_scope", "provider-plane receipt must select provider API and visually separate provider UI surfaces")
	}
	if receipt.HarnessScope.Mode == HarnessModeTenantPlane && receipt.HarnessScope.CapabilityDriver.Kind == HarnessDriverBuiltin {
		capabilityBytes, err := readTrackedBuiltinSourceFile(sourceRoot, "scripts/run_completeness_audit.sh", maxSemanticArtifactBytes)
		out = addDiagnosticIf(out, err != nil || !bytes.Contains(capabilityBytes, []byte("run_f50_capability()")),
			"driver-source-mismatch", "harness_scope.capability_driver", "built-in F50 capability driver must be the tracked run_f50_capability implementation at the signed source SHA")
		browserBytes, browserErr := readTrackedBuiltinSourceFile(sourceRoot, "scripts/completeness_audit_browser.mjs", maxSemanticArtifactBytes)
		out = addDiagnosticIf(out, browserErr != nil || len(browserBytes) == 0,
			"driver-source-mismatch", "harness_scope.browser_driver", "built-in browser driver must be the tracked completeness_audit_browser.mjs at the signed source SHA")
	}
	for name, driver := range map[string]HarnessDriverEvidence{
		"capability_driver": receipt.HarnessScope.CapabilityDriver,
		"browser_driver":    receipt.HarnessScope.BrowserDriver,
	} {
		if driver.Kind != HarnessDriverSourceBound {
			continue
		}
		data, err := readTrackedSourceFile(sourceRoot, receipt.Source.GitSHA, driver.SourcePath, driver.GitBlobSHA, maxSemanticArtifactBytes)
		out = addDiagnosticIf(out, err != nil || digestBytes(data) != driver.SHA256,
			"driver-source-mismatch", "harness_scope."+name,
			fmt.Sprintf("source-bound %s must match the signed SHA-256 in the exact audited source tree", name))
	}
	return out
}

func readTrackedBuiltinSourceFile(root, relative string, limit int64) ([]byte, error) {
	// CurrentStatus supplies a freshly materialized archive of the signed Git SHA, so any
	// file read there is necessarily tracked at the signed commit. Seal-time
	// source archives may omit .git but are still hashed into the receipt.
	return readSourceFile(root, relative, limit)
}

func readTrackedSourceFile(root, gitSHA, relative, expectedBlobSHA string, limit int64) ([]byte, error) {
	data, err := readSourceFile(root, relative, limit)
	if err != nil {
		return nil, err
	}
	probe := exec.Command("git", "-C", root, "rev-parse", "--git-dir")
	if err := probe.Run(); err != nil {
		// Immutable source archives do not carry .git. The signed blob identity
		// is rechecked when CurrentStatus evaluates an exact Git checkout.
		return data, nil
	}
	object := gitSHA + ":" + relative
	resolved, err := exec.Command("git", "-C", root, "rev-parse", "--verify", object).Output()
	if err != nil || strings.TrimSpace(string(resolved)) != expectedBlobSHA {
		return nil, fmt.Errorf("source path %s is not blob %s in commit %s", relative, expectedBlobSHA, gitSHA)
	}
	command := exec.Command("git", "-C", root, "cat-file", "blob", expectedBlobSHA)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	blob, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil || int64(len(blob)) > limit || !bytes.Equal(blob, data) {
		return nil, fmt.Errorf("source path %s bytes do not match tracked blob %s", relative, expectedBlobSHA)
	}
	return data, nil
}

func readSourceFile(root, relative string, limit int64) ([]byte, error) {
	_, data, _, err := readBoundedWithinRoot(root, relative, limit)
	if err != nil {
		return nil, fmt.Errorf("read source %s: %w", relative, err)
	}
	return data, nil
}

func cellHasRef(cell completeness.Cell, want string) bool {
	for _, ref := range cell.Refs {
		if strings.TrimSpace(ref) == want {
			return true
		}
	}
	return false
}

func capabilityHasUIRoute(capability completeness.Capability, route string) bool {
	for _, ref := range capability.UI.Refs {
		payload := strings.TrimPrefix(strings.TrimSpace(ref), "ui:")
		_, declaredRoute, ok := strings.Cut(payload, "@")
		if ok && declaredRoute == route {
			return true
		}
	}
	return false
}

func buildTargetsBinary(command, entrypoint string) bool {
	file, _, ok := strings.Cut(strings.TrimSpace(entrypoint), "#")
	if !ok {
		return false
	}
	fields := strings.Fields(command)
	return len(fields) == 3 && fields[0] == "go" && fields[1] == "build" &&
		filepath.ToSlash(filepath.Clean(strings.TrimPrefix(fields[2], "./"))) == filepath.ToSlash(filepath.Dir(file))
}

func openAPIOperationMatches(sourceRoot string, api APIReachability) bool {
	for _, relative := range []string{"internal/control/openapi.json", "ee/provider/openapi.json"} {
		data, err := readSourceFile(sourceRoot, relative, 32<<20)
		if err != nil {
			continue
		}
		var document struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(data, &document); err != nil {
			continue
		}
		raw := document.Paths[api.Path][strings.ToLower(strings.TrimSpace(api.Method))]
		if len(raw) == 0 {
			continue
		}
		var operation struct {
			OperationID string `json:"operationId"`
		}
		if json.Unmarshal(raw, &operation) == nil && operation.OperationID == api.OperationID {
			return true
		}
	}
	return false
}

func reachabilityViolationCode(cell string) string {
	switch cell {
	case "binary":
		return "binary-unreachable"
	case "api":
		return "api-unreachable"
	case "cli":
		return "cli-unreachable"
	case "ui":
		return "ui-unreachable"
	case "docs":
		return "docs-unreachable"
	default:
		return "reachability-source-unverified"
	}
}
