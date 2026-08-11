// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/cli"
)

const minimumDispositionReason = 24

var (
	configKeyPattern = regexp.MustCompile(`^PROBECTL_[A-Z0-9_]+$`)
)

// Violation is one deterministic gate failure.
type Violation struct {
	Capability string `json:"capability"`
	Cell       string `json:"cell,omitempty"`
	Code       string `json:"code"`
	Problem    string `json:"problem"`
}

// Validator resolves registry evidence against one repository checkout.
type Validator struct {
	root                 string
	operations           map[string]bool
	commands             map[string]bool
	surfaces             []surfaceDeclaration
	configDoc            string
	proofs               map[string]proofBinding
	reachability         map[string]*packageReachability
	expectedCapabilities map[string]bool
	noneByDesign         map[string]bool
}

type proofBinding struct {
	profile      string
	capabilities map[string]bool
}

// NewValidator loads the offline catalogs used by the gate.
func NewValidator(repoRoot string) (*Validator, error) {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	v := &Validator{root: root, operations: map[string]bool{}, commands: map[string]bool{}, proofs: map[string]proofBinding{}, reachability: map[string]*packageReachability{}}
	if err := v.loadCompletenessPolicies(); err != nil {
		return nil, err
	}
	for _, path := range []string{"internal/control/openapi.json", "ee/provider/openapi.json"} {
		if err := v.loadOpenAPI(path); err != nil {
			return nil, err
		}
	}
	topLevelDispatch, err := v.loadCLIDispatch()
	if err != nil {
		return nil, err
	}
	if err := v.validateGenericCLISpine(); err != nil {
		return nil, err
	}
	commandCatalog := cli.CompletenessCommandCatalog()
	explicitOperations, err := v.loadExplicitCLIOperations(topLevelDispatch.explicit, commandCatalog)
	if err != nil {
		return nil, err
	}
	dispatchCases, err := v.loadSpecialCLIDispatchCases()
	if err != nil {
		return nil, err
	}
	for _, command := range commandCatalog {
		fields := strings.Fields(command)
		if len(fields) < 3 || fields[0] != "probectl" {
			continue
		}
		group := fields[1]
		if cases, special := dispatchCases[group]; special {
			if topLevelDispatch.explicit[group] == "" || !cases[fields[2]] {
				continue
			}
		} else if topLevelDispatch.cases[group] {
			if topLevelDispatch.explicit[group] == "" || !explicitOperations[group][fields[2]] {
				continue
			}
		} else if !topLevelDispatch.generic {
			continue
		}
		v.commands[command] = true
	}
	surfacePath, err := v.resolveWithinRoot("web/src/surfaces.ts")
	if err != nil {
		return nil, fmt.Errorf("read web surface registry: %w", err)
	}
	surfaceData, err := os.ReadFile(surfacePath)
	if err != nil {
		return nil, fmt.Errorf("read web surface registry: %w", err)
	}
	v.surfaces, err = parseSurfaceCatalog(surfaceData)
	if err != nil {
		return nil, fmt.Errorf("read web surface registry: %w", err)
	}
	configPath, err := v.resolveWithinRoot("docs/configuration.md")
	if err != nil {
		return nil, fmt.Errorf("read configuration docs: %w", err)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read configuration docs: %w", err)
	}
	v.configDoc = string(configData)
	if err := v.loadRealStackProofCatalog(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Validator) loadRealStackProofCatalog() error {
	path, err := v.resolveWithinRoot(RealStackProofCatalogPath)
	if err != nil {
		return fmt.Errorf("read real-stack proof catalog: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read real-stack proof catalog: %w", err)
	}
	var catalog struct {
		Schema string `json:"schema"`
		Proofs []struct {
			Ref          string   `json:"ref"`
			Profile      string   `json:"profile"`
			Capabilities []string `json:"capabilities"`
		} `json:"proofs"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return fmt.Errorf("decode real-stack proof catalog: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode real-stack proof catalog: trailing JSON value")
		}
		return fmt.Errorf("decode real-stack proof catalog trailing content: %w", err)
	}
	if catalog.Schema != "probectl.real-stack-proofs/v1" {
		return fmt.Errorf("decode real-stack proof catalog: schema must be %q", "probectl.real-stack-proofs/v1")
	}
	profiles := map[string]bool{}
	for i, proof := range catalog.Proofs {
		ref := strings.TrimSpace(proof.Ref)
		if ref == "" || !strings.HasPrefix(ref, "test:") {
			return fmt.Errorf("decode real-stack proof catalog: proof %d needs an exact test: ref", i)
		}
		if _, duplicate := v.proofs[ref]; duplicate {
			return fmt.Errorf("decode real-stack proof catalog: duplicate ref %q", ref)
		}
		switch proof.Profile {
		case "integration", "e2e", "ebpf-kernel", "device-live":
		default:
			return fmt.Errorf("decode real-stack proof catalog: ref %q has unsupported profile %q", ref, proof.Profile)
		}
		if len(proof.Capabilities) == 0 {
			return fmt.Errorf("decode real-stack proof catalog: ref %q has no capability bindings", ref)
		}
		binding := proofBinding{profile: proof.Profile, capabilities: map[string]bool{}}
		for _, rawID := range proof.Capabilities {
			id := strings.TrimSpace(rawID)
			if id == "" {
				return fmt.Errorf("decode real-stack proof catalog: ref %q has an empty capability binding", ref)
			}
			if binding.capabilities[id] {
				return fmt.Errorf("decode real-stack proof catalog: ref %q repeats capability %q", ref, id)
			}
			binding.capabilities[id] = true
		}
		payload := strings.TrimPrefix(ref, "test:")
		if err := v.validateGoTest(payload); err != nil {
			return fmt.Errorf("decode real-stack proof catalog: ref %q: %w", ref, err)
		}
		if err := v.validateRealStackTestBody(payload); err != nil {
			return fmt.Errorf("decode real-stack proof catalog: ref %q: %w", ref, err)
		}
		if err := v.validateRealStackProfile(payload, proof.Profile); err != nil {
			return fmt.Errorf("decode real-stack proof catalog: ref %q: %w", ref, err)
		}
		v.proofs[ref] = binding
		profiles[proof.Profile] = true
	}
	for profile := range profiles {
		if err := v.validateRealStackRunner(profile); err != nil {
			return fmt.Errorf("decode real-stack proof catalog: profile %q: %w", profile, err)
		}
	}
	return nil
}

func (v *Validator) loadSpecialCLIDispatchCases() (map[string]map[string]bool, error) {
	const relative = "internal/cli/commands.go"
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return nil, fmt.Errorf("read CLI dispatcher: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse CLI dispatcher: %w", err)
	}
	wanted := map[string]string{"cmdTest": "test", "cmdAgent": "agent"}
	out := map[string]map[string]bool{"test": {}, "agent": {}}
	found := map[string]int{}
	trustedCallees := map[string]bool{}
	calleeDefinitions := map[string]int{}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		want, tracked := specialCLICalleeSpines[fn.Name.Name]
		if !tracked {
			continue
		}
		calleeDefinitions[fn.Name.Name]++
		got, canonical := canonicalGoBody(fn.Body)
		trustedCallees[fn.Name.Name] = canonical && got == want
	}
	for name := range specialCLICalleeSpines {
		if calleeDefinitions[name] != 1 || !trustedCallees[name] {
			return nil, fmt.Errorf("parse CLI dispatcher: %s must preserve its exact tenant-scoped request spine", name)
		}
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		group, ok := wanted[fn.Name.Name]
		if !ok {
			continue
		}
		if len(fn.Body.List) != 3 {
			return nil, fmt.Errorf("parse CLI dispatcher: %s must preserve its exact guard/client/switch spine", fn.Name.Name)
		}
		prelude, preludeOK := canonicalGoStatements(fn.Body.List[:2])
		if !preludeOK || prelude != specialCLIPreludeSpines[group] {
			return nil, fmt.Errorf("parse CLI dispatcher: %s must preserve its exact guard/client/switch spine", fn.Name.Name)
		}
		switchStatement, ok := fn.Body.List[2].(*ast.SwitchStmt)
		if !ok || !isIndexedIdentifier(switchStatement.Tag, "args", 0) {
			continue
		}
		found[group]++
		for _, rawClause := range switchStatement.Body.List {
			clause, ok := rawClause.(*ast.CaseClause)
			if !ok {
				continue
			}
			if !specialCLICaseExecutes(clause.Body, trustedCallees) {
				continue
			}
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				name, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr != nil {
					return nil, fmt.Errorf("parse CLI dispatcher %s case: %w", group, unquoteErr)
				}
				out[group][name] = true
			}
		}
	}
	for function, group := range wanted {
		if found[group] != 1 {
			return nil, fmt.Errorf("parse CLI dispatcher: %s needs one direct switch on args[0]", function)
		}
	}
	return out, nil
}

var specialCLIPreludeSpines = map[string]string{
	"test": `{
	if len(args) == 0 {
		fmt.Fprintln(stderr, "test: expected a subcommand (list|get|create|delete|path|path-history)")
		return 2
	}
	c := newClient(cfg)
}`,
	"agent": `{
	if len(args) == 0 {
		fmt.Fprintln(stderr, "agent: expected a subcommand (list|get|delete)")
		return 2
	}
	c := newClient(cfg)
}`,
}

var specialCLICalleeSpines = map[string]string{
	"testCreate": `{
	fs := flag.NewFlagSet("test create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "test name (required)")
	typ := fs.String("type", "", "probe type (required)")
	target := fs.String("target", "", "target (host:port or address)")
	interval := fs.Int("interval", 60, "interval seconds")
	timeout := fs.Int("timeout", 3, "timeout seconds")
	disabled := fs.Bool("disabled", false, "create disabled")
	params := kvFlag{}
	fs.Var(&params, "param", "a k=v parameter (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *typ == "" {
		fmt.Fprintln(stderr, "test create: --name and --type are required")
		return 2
	}
	body := testRequest{Name: *name, Type: *typ, Target: *target, IntervalSeconds: *interval, TimeoutSeconds: *timeout, Params: map[string]string(params), Enabled: !*disabled}
	var t Test
	if err := c.do(http.MethodPost, "/v1/tests", body, &t); err != nil {
		return fail(stderr, err)
	}
	if cfg.JSON {
		return printJSON(stdout, t)
	}
	fmt.Fprintf(stdout, "created test %s (%s)\n", t.ID, t.Name)
	return 0
}`,
}

func specialCLICaseExecutes(statements []ast.Stmt, trustedCallees map[string]bool) bool {
	executes := false
	succeeds := false
	block := &ast.BlockStmt{List: statements}
	excluded := excludedSyntax(block)
	for _, statement := range statements {
		ast.Inspect(statement, func(node ast.Node) bool {
			if node == nil {
				return false
			}
			if syntaxExcluded(node, excluded) {
				return false
			}
			if _, ok := node.(*ast.FuncLit); ok {
				return false
			}
			switch value := node.(type) {
			case *ast.ReturnStmt:
				if len(value.Results) != 1 {
					break
				}
				switch result := value.Results[0].(type) {
				case *ast.BasicLit:
					succeeds = result.Kind == token.INT && result.Value == "0"
				case *ast.CallExpr:
					if called, ok := result.Fun.(*ast.Ident); ok &&
						(called.Name == "runRawOperation" || trustedCallees[called.Name] || called.Name == "printJSON") {
						succeeds = true
					}
				}
			case *ast.CallExpr:
				switch called := value.Fun.(type) {
				case *ast.Ident:
					if called.Name == "runRawOperation" || trustedCallees[called.Name] {
						executes = true
					}
				case *ast.SelectorExpr:
					if called.Sel.Name == "do" {
						executes = true
					}
				}
			}
			return true
		})
	}
	return executes && succeeds
}

func (v *Validator) loadOpenAPI(relative string) error {
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return fmt.Errorf("read %s: %w", relative, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", relative, err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode %s: %w", relative, err)
	}
	for path, item := range document.Paths {
		for method := range item {
			upper := strings.ToUpper(method)
			switch upper {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
				v.operations[upper+" "+path] = true
			}
		}
	}
	return nil
}

// Validate checks registry shape, the independently fixed denominator against
// the canonical release catalog, and every declared evidence reference.
// Returned violations are stably sorted.
func (v *Validator) Validate(registry Registry) []Violation {
	var out []Violation
	if registry.Schema != RegistrySchema {
		out = append(out, Violation{Code: "schema", Problem: fmt.Sprintf("schema must be %q", RegistrySchema)})
	}
	switch {
	case strings.TrimSpace(registry.SourceCatalog) == "":
		out = append(out, Violation{Code: "catalog", Problem: "source_catalog is required"})
	case filepath.ToSlash(filepath.Clean(registry.SourceCatalog)) != ReleaseCatalogPath:
		out = append(out, Violation{Code: "catalog", Problem: fmt.Sprintf("source_catalog must be %q", ReleaseCatalogPath)})
	default:
		out = append(out, v.validateCatalog(registry)...)
	}
	seen := map[string]bool{}
	declaredProofs := map[string]map[string]bool{}
	declaredNoneByDesign := map[string]bool{}
	for _, capability := range registry.Capabilities {
		if strings.TrimSpace(capability.ID) == "" {
			out = append(out, Violation{Code: "id", Problem: "capability id is required"})
			continue
		}
		if seen[capability.ID] {
			out = append(out, Violation{Capability: capability.ID, Code: "duplicate-id", Problem: "capability id appears more than once"})
			continue
		}
		seen[capability.ID] = true
		if strings.TrimSpace(capability.Name) == "" {
			out = append(out, Violation{Capability: capability.ID, Code: "name", Problem: "name is required"})
		}
		switch capability.Status {
		case "delivered", "partial", "future", "removed":
		default:
			out = append(out, Violation{Capability: capability.ID, Code: "status", Problem: "status must be delivered, partial, future, or removed"})
		}
		if strings.TrimSpace(capability.Owner) == "" {
			out = append(out, Violation{Capability: capability.ID, Code: "owner", Problem: "owner is required"})
		}
		uiAliases := map[string]bool{}
		for featureID, rawReason := range capability.UIAliases {
			reason := strings.TrimSpace(rawReason)
			if strings.TrimSpace(featureID) == "" || featureID == capability.ID {
				out = append(out, Violation{Capability: capability.ID, Cell: "ui", Code: "ui-alias", Problem: "ui_aliases keys must name a different, non-empty feature ID"})
				continue
			}
			if utf8.RuneCountInString(reason) < minimumDispositionReason {
				out = append(out, Violation{Capability: capability.ID, Cell: "ui", Code: "ui-alias", Problem: fmt.Sprintf("UI alias %q reason must be at least %d characters", featureID, minimumDispositionReason)})
				continue
			}
			uiAliases[featureID] = true
		}
		evidenceStatus := capability.EffectiveEvidenceStatus()
		switch evidenceStatus {
		case "complete", "partial":
		default:
			out = append(out, Violation{Capability: capability.ID, Code: "evidence-status", Problem: "evidence_status must be complete or partial"})
		}
		gapCells := 0
		for _, named := range capability.NamedCells() {
			if strings.TrimSpace(named.Cell.NoneByDesign) != "" {
				declaredNoneByDesign[capability.ID+"."+named.Name] = true
			}
			if strings.TrimSpace(named.Cell.Gap) != "" {
				gapCells++
			}
			out = append(out, v.validateCell(capability.ID, named.Name, evidenceStatus, named.Cell, uiAliases)...)
			if named.Name == "real_stack_proof" {
				for _, ref := range named.Cell.Refs {
					if declaredProofs[ref] == nil {
						declaredProofs[ref] = map[string]bool{}
					}
					declaredProofs[ref][capability.ID] = true
				}
			}
		}
		for featureID := range uiAliases {
			used := false
			for _, ref := range capability.UI.Refs {
				payload := strings.TrimPrefix(ref, "ui:")
				declared, _, ok := strings.Cut(payload, "@")
				if ok && declared == featureID {
					used = true
					break
				}
			}
			if !used {
				out = append(out, Violation{Capability: capability.ID, Cell: "ui", Code: "ui-alias-unused", Problem: fmt.Sprintf("UI alias %q is not used by the ui cell", featureID)})
			}
		}
		if evidenceStatus == "partial" && gapCells == 0 {
			out = append(out, Violation{Capability: capability.ID, Code: "evidence-status", Problem: "evidence_status partial requires at least one explicit gap cell"})
		}
	}
	for key := range v.noneByDesign {
		if declaredNoneByDesign[key] {
			continue
		}
		capability, cell, _ := strings.Cut(key, ".")
		out = append(out, Violation{Capability: capability, Cell: cell, Code: "stale-none-by-design-policy", Problem: fmt.Sprintf("%s permits this exclusion but the registry does not declare it", NoneByDesignPolicyPath)})
	}
	for ref, binding := range v.proofs {
		for capability := range binding.capabilities {
			if !seen[capability] {
				out = append(out, Violation{Capability: capability, Cell: "real_stack_proof", Code: "proof-catalog-capability", Problem: fmt.Sprintf("proof catalog binds %q to a capability outside the registry denominator", ref)})
				continue
			}
			if !declaredProofs[ref][capability] {
				out = append(out, Violation{Capability: capability, Cell: "real_stack_proof", Code: "proof-catalog-stale", Problem: fmt.Sprintf("proof catalog binds %q but the capability does not declare that ref", ref)})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Capability != b.Capability {
			return capabilityLess(a.Capability, b.Capability)
		}
		if a.Cell != b.Cell {
			return cellIndex(a.Cell) < cellIndex(b.Cell)
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Problem < b.Problem
	})
	return out
}

func cellIndex(name string) int {
	for i, candidate := range CellNames {
		if candidate == name {
			return i
		}
	}
	return len(CellNames)
}

func (v *Validator) validateCatalog(registry Registry) []Violation {
	relative, err := cleanRelative(registry.SourceCatalog)
	if err != nil {
		return []Violation{{Code: "catalog", Problem: err.Error()}}
	}
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return []Violation{{Code: "catalog", Problem: err.Error()}}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []Violation{{Code: "catalog", Problem: fmt.Sprintf("read source catalog: %v", err)}}
	}
	var catalog struct {
		Schema  string `json:"schema"`
		Purpose string `json:"purpose"`
		Claims  []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Owner string `json:"owner"`
			Title string `json:"title,omitempty"`
		} `json:"claims"`
	}
	if err := decodeStrictJSON(data, &catalog); err != nil {
		return []Violation{{Code: "catalog", Problem: fmt.Sprintf("decode source catalog: %v", err)}}
	}
	if catalog.Schema != "probectl.release-claim-catalog/v1" {
		return []Violation{{Code: "catalog", Problem: "source catalog schema must be \"probectl.release-claim-catalog/v1\""}}
	}
	if strings.TrimSpace(catalog.Purpose) == "" {
		return []Violation{{Code: "catalog", Problem: "source catalog purpose is required"}}
	}
	type catalogRow struct {
		kind  string
		owner string
	}
	rows := map[string]catalogRow{}
	duplicates := map[string]bool{}
	var out []Violation
	for index, claim := range catalog.Claims {
		if strings.TrimSpace(claim.ID) == "" || claim.ID != strings.TrimSpace(claim.ID) ||
			strings.TrimSpace(claim.Kind) == "" || claim.Kind != strings.TrimSpace(claim.Kind) ||
			strings.TrimSpace(claim.Owner) == "" || claim.Owner != strings.TrimSpace(claim.Owner) {
			out = append(out, Violation{Code: "catalog-row", Problem: fmt.Sprintf("release catalog claim %d needs canonical non-empty id, kind, and owner", index)})
			continue
		}
		if _, exists := rows[claim.ID]; exists {
			duplicates[claim.ID] = true
			continue
		}
		rows[claim.ID] = catalogRow{kind: claim.Kind, owner: claim.Owner}
	}
	got := map[string]string{}
	for _, capability := range registry.Capabilities {
		got[capability.ID] = capability.Owner
	}
	for id := range duplicates {
		out = append(out, Violation{Capability: id, Code: "catalog-duplicate", Problem: "release catalog repeats this capability ID"})
	}
	for id := range v.expectedCapabilities {
		row, cataloged := rows[id]
		if !cataloged {
			out = append(out, Violation{Capability: id, Code: "catalog-row-missing", Problem: "independent denominator capability is absent from the release catalog"})
			continue
		}
		if row.kind != "capability" {
			out = append(out, Violation{Capability: id, Code: "catalog-kind", Problem: fmt.Sprintf("independent denominator requires kind=capability, got %q", row.kind)})
		}
		if _, ok := got[id]; !ok {
			out = append(out, Violation{Capability: id, Code: "catalog-missing", Problem: "cataloged capability is absent from capabilities.yaml"})
			continue
		}
		if got[id] != row.owner {
			out = append(out, Violation{Capability: id, Code: "catalog-owner", Problem: fmt.Sprintf("owner %q does not match catalog owner %q", got[id], row.owner)})
		}
	}
	for id := range got {
		if !v.expectedCapabilities[id] {
			out = append(out, Violation{Capability: id, Code: "catalog-extra", Problem: "registry capability is outside the independent completeness denominator"})
		}
	}
	for id, row := range rows {
		if row.kind == "capability" && !v.expectedCapabilities[id] {
			out = append(out, Violation{Capability: id, Code: "catalog-unexpected-capability", Problem: "release catalog has a kind=capability row outside the independent completeness denominator"})
		}
	}
	return out
}

func (v *Validator) validateCell(id, name, evidenceStatus string, cell Cell, uiAliases map[string]bool) []Violation {
	reason := strings.TrimSpace(cell.NoneByDesign)
	gap := strings.TrimSpace(cell.Gap)
	forms := 0
	if len(cell.Refs) > 0 {
		forms++
	}
	if reason != "" {
		forms++
	}
	if gap != "" {
		forms++
	}
	if forms == 0 {
		return []Violation{{Capability: id, Cell: name, Code: "missing-cell", Problem: "cell needs refs, a none_by_design reason, or an explicit gap"}}
	}
	if forms > 1 {
		return []Violation{{Capability: id, Cell: name, Code: "ambiguous-cell", Problem: "refs, none_by_design, and gap are mutually exclusive"}}
	}
	if reason != "" {
		if utf8.RuneCountInString(reason) < minimumDispositionReason {
			return []Violation{{Capability: id, Cell: name, Code: "weak-none-by-design", Problem: fmt.Sprintf("none_by_design reason must be at least %d characters", minimumDispositionReason)}}
		}
		if !v.noneByDesign[id+"."+name] {
			return []Violation{{Capability: id, Cell: name, Code: "unapproved-none-by-design", Problem: fmt.Sprintf("none_by_design is not approved by %s", NoneByDesignPolicyPath)}}
		}
		return nil
	}
	if gap != "" {
		var out []Violation
		if evidenceStatus != "partial" {
			out = append(out, Violation{Capability: id, Cell: name, Code: "gap-status", Problem: "gap is allowed only when evidence_status is partial"})
		}
		if utf8.RuneCountInString(gap) < minimumDispositionReason {
			out = append(out, Violation{Capability: id, Cell: name, Code: "weak-gap", Problem: fmt.Sprintf("gap reason must be at least %d characters", minimumDispositionReason)})
		}
		return out
	}
	seen := map[string]bool{}
	var out []Violation
	for _, raw := range cell.Refs {
		ref := strings.TrimSpace(raw)
		if ref == "" {
			out = append(out, Violation{Capability: id, Cell: name, Code: "empty-ref", Problem: "evidence ref is empty"})
			continue
		}
		if seen[ref] {
			out = append(out, Violation{Capability: id, Cell: name, Code: "duplicate-ref", Problem: fmt.Sprintf("duplicate evidence ref %q", ref)})
			continue
		}
		seen[ref] = true
		if err := v.validateRef(id, name, ref, uiAliases); err != nil {
			out = append(out, Violation{Capability: id, Cell: name, Code: "invalid-ref", Problem: err.Error()})
		}
	}
	return out
}

func (v *Validator) validateRef(capability, cell, ref string, uiAliases map[string]bool) error {
	prefix, payload, ok := strings.Cut(ref, ":")
	if !ok || payload == "" {
		return fmt.Errorf("%q must use a supported evidence prefix", ref)
	}
	allowed := map[string]map[string]bool{
		"engine":           {"file": true},
		"binary":           {"file": true},
		"api":              {"api": true, "file": true},
		"cli":              {"cli": true},
		"ui":               {"ui": true},
		"docs":             {"file": true},
		"config_keys":      {"config": true},
		"telemetry":        {"file": true},
		"real_stack_proof": {"test": true},
		"migration":        {"file": true},
	}
	if !allowed[cell][prefix] {
		return fmt.Errorf("%q uses %s evidence in the %s cell", ref, prefix, cell)
	}
	switch prefix {
	case "file":
		if err := validateFileLocation(cell, payload); err != nil {
			return err
		}
		requireNeedle := cell == "binary" || cell == "api" || cell == "docs"
		if err := v.validateFile(cell, payload, requireNeedle); err != nil {
			return err
		}
		if cell == "engine" || cell == "telemetry" {
			return v.validateImplementationEvidence(cell, payload)
		}
		if cell == "binary" {
			return v.validateBinaryReachability(payload)
		}
		if cell == "api" && filepath.Ext(strings.SplitN(payload, "#", 2)[0]) == ".go" {
			return v.validateGoProtocolReachability(payload)
		}
		return nil
	case "api":
		operation := normalizeOperation(payload)
		if !v.operations[operation] {
			return fmt.Errorf("OpenAPI operation %q does not exist", operation)
		}
	case "cli":
		if !v.commands[payload] {
			return fmt.Errorf("CLI command %q does not exist in the executable command catalog", payload)
		}
	case "ui":
		featureID, route, ok := strings.Cut(payload, "@")
		if !ok || featureID == "" || route == "" || !strings.HasPrefix(route, "/") {
			return fmt.Errorf("UI ref %q must be ui:<feature-id>@/<route>", ref)
		}
		if !v.surfaceExists(featureID, route) {
			return fmt.Errorf("web/src/surfaces.ts has no %s declaration at route %s", featureID, route)
		}
		if featureID != capability && !uiAliases[featureID] {
			return fmt.Errorf("UI feature %s belongs to a different capability; declare a reasoned ui_aliases entry to reuse it", featureID)
		}
	case "config":
		if !configKeyPattern.MatchString(payload) {
			return fmt.Errorf("config key %q must be an exact PROBECTL_* environment key", payload)
		}
		if !containsConfigKey(v.configDoc, payload) {
			return fmt.Errorf("config key %q is absent from docs/configuration.md", payload)
		}
	case "test":
		if err := validateFileLocation(cell, payload); err != nil {
			return err
		}
		if err := v.validateGoTest(payload); err != nil {
			return fmt.Errorf("real-stack proof: %w", err)
		}
		binding, ok := v.proofs[ref]
		if !ok {
			return fmt.Errorf("real-stack proof %q is absent from %s", ref, RealStackProofCatalogPath)
		}
		if !binding.capabilities[capability] {
			return fmt.Errorf("real-stack proof %q is not bound to capability %s in %s", ref, capability, RealStackProofCatalogPath)
		}
	default:
		return fmt.Errorf("unsupported evidence prefix %q", prefix)
	}
	return nil
}

func (v *Validator) validateGoTest(payload string) error {
	pathText, testName, ok := strings.Cut(payload, "#")
	if !ok {
		return fmt.Errorf("test ref %q needs an exact Go Test function", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	if err := v.rejectEvidenceSymlinkPath(relative); err != nil {
		return err
	}
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fmt.Errorf("parse test file %q: %w", relative, err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != testName || fn.Recv != nil || fn.Type.Results != nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
			continue
		}
		star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		selector, ok := star.X.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "T" {
			continue
		}
		packageName, ok := selector.X.(*ast.Ident)
		if ok && packageName.Name == "testing" {
			return nil
		}
	}
	return fmt.Errorf("test file %q has no top-level func %s(*testing.T)", relative, testName)
}

func (v *Validator) rejectEvidenceSymlinkPath(relative string) error {
	current := v.root
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect evidence path %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("evidence path %q contains symlink component %q", relative, component)
		}
	}
	return nil
}

func (v *Validator) validateRealStackTestBody(payload string) error {
	pathText, testName, ok := strings.Cut(payload, "#")
	if !ok {
		return fmt.Errorf("test ref %q needs an exact Go Test function", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	if err := v.rejectEvidenceSymlinkPath(relative); err != nil {
		return err
	}
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return fmt.Errorf("parse test file %q: %w", relative, err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != testName || fn.Body == nil {
			continue
		}
		if len(fn.Body.List) == 0 {
			return fmt.Errorf("real-stack test %s is a no-op: its body is empty", testName)
		}
		parameter := goTestParameterName(fn)
		if hasUnconditionalTestingSkipAlias(fn.Body, parameter) {
			return fmt.Errorf("real-stack test %s is a no-op: it unconditionally invokes a skip alias", testName)
		}
		for _, statement := range fn.Body.List {
			terminal, ok := unconditionalRealStackTerminal(statement, parameter)
			if !ok {
				continue
			}
			if terminal.kind == "skip" || !hasGuaranteedProofCallBefore(fn.Body, terminal.position, parameter) {
				return fmt.Errorf("real-stack test %s is a no-op: %s", testName, terminal.reason)
			}
		}
		if !hasExecutableRealStackCall(fn.Body, parameter) {
			return fmt.Errorf("real-stack test %s is a no-op: it has no executable proof call", testName)
		}
		return nil
	}
	return fmt.Errorf("test file %q has no top-level func %s(*testing.T)", relative, testName)
}

func goTestParameterName(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 {
		return ""
	}
	return fn.Type.Params.List[0].Names[0].Name
}

func isDirectTestingSkip(expression ast.Expr, parameter string) bool {
	if parameter == "" {
		return false
	}
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return false
	}
	return isTestingSkipCall(call, parameter)
}

func isTestingSkipCall(call *ast.CallExpr, parameter string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "Skip") {
		return false
	}
	if isIdentifier(selector.X, parameter) {
		return true
	}
	if len(call.Args) == 0 || !isIdentifier(call.Args[0], parameter) {
		return false
	}
	expression := selector.X
	if parenthesized, ok := expression.(*ast.ParenExpr); ok {
		expression = parenthesized.X
	}
	star, ok := expression.(*ast.StarExpr)
	if !ok {
		return false
	}
	testingType, ok := star.X.(*ast.SelectorExpr)
	return ok && isIdentifier(testingType.X, "testing") && testingType.Sel.Name == "T"
}

func isTestingSkipValue(expression ast.Expr, parameter string) bool {
	if parenthesized, ok := expression.(*ast.ParenExpr); ok {
		expression = parenthesized.X
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "Skip") {
		return false
	}
	if isIdentifier(selector.X, parameter) {
		return true
	}
	target := selector.X
	if parenthesized, ok := target.(*ast.ParenExpr); ok {
		target = parenthesized.X
	}
	star, ok := target.(*ast.StarExpr)
	if !ok {
		return false
	}
	testingType, ok := star.X.(*ast.SelectorExpr)
	return ok && isIdentifier(testingType.X, "testing") && testingType.Sel.Name == "T"
}

func hasUnconditionalTestingSkipAlias(body *ast.BlockStmt, parameter string) bool {
	aliases := map[string]bool{}
	var visitBlock func(*ast.BlockStmt, map[string]bool) bool
	visitBlock = func(block *ast.BlockStmt, current map[string]bool) bool {
		for _, statement := range block.List {
			switch typed := statement.(type) {
			case *ast.AssignStmt:
				for i, right := range typed.Rhs {
					if i >= len(typed.Lhs) || !isTestingSkipValue(right, parameter) {
						continue
					}
					if identifier, ok := typed.Lhs[i].(*ast.Ident); ok {
						current[identifier.Name] = true
					}
				}
			case *ast.DeclStmt:
				declaration, ok := typed.Decl.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, specification := range declaration.Specs {
					value, ok := specification.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, right := range value.Values {
						if i < len(value.Names) && isTestingSkipValue(right, parameter) {
							current[value.Names[i].Name] = true
						}
					}
				}
			case *ast.ExprStmt:
				if callUsesAlias(typed.X, current) {
					return true
				}
			case *ast.DeferStmt:
				if identifier, ok := typed.Call.Fun.(*ast.Ident); ok && current[identifier.Name] {
					return true
				}
			case *ast.BlockStmt:
				if visitBlock(typed, cloneBoolMap(current)) {
					return true
				}
			case *ast.IfStmt:
				if condition, constant := constantBoolean(typed.Cond); constant && condition && visitBlock(typed.Body, cloneBoolMap(current)) {
					return true
				}
			case *ast.LabeledStmt:
				block := &ast.BlockStmt{List: []ast.Stmt{typed.Stmt}}
				if visitBlock(block, cloneBoolMap(current)) {
					return true
				}
			}
		}
		return false
	}
	return visitBlock(body, aliases)
}

func callUsesAlias(expression ast.Expr, aliases map[string]bool) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return false
	}
	identifier, ok := call.Fun.(*ast.Ident)
	return ok && aliases[identifier.Name]
}

func cloneBoolMap(source map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

type realStackTerminal struct {
	kind     string
	reason   string
	position token.Pos
}

func unconditionalRealStackTerminal(statement ast.Stmt, parameter string) (realStackTerminal, bool) {
	switch typed := statement.(type) {
	case *ast.ReturnStmt:
		if len(typed.Results) == 0 {
			return realStackTerminal{kind: "return", reason: "it returns before executing proof work", position: typed.Pos()}, true
		}
	case *ast.ExprStmt:
		if isDirectTestingSkip(typed.X, parameter) {
			return realStackTerminal{kind: "skip", reason: "it unconditionally skips", position: typed.Pos()}, true
		}
	case *ast.DeferStmt:
		if isTestingSkipCall(typed.Call, parameter) {
			return realStackTerminal{kind: "skip", reason: "it unconditionally defers a skip", position: typed.Pos()}, true
		}
	case *ast.BlockStmt:
		for _, nested := range typed.List {
			if terminal, ok := unconditionalRealStackTerminal(nested, parameter); ok {
				return terminal, true
			}
		}
	case *ast.IfStmt:
		if condition, constant := constantBoolean(typed.Cond); constant && condition {
			return unconditionalRealStackTerminal(typed.Body, parameter)
		}
	case *ast.LabeledStmt:
		return unconditionalRealStackTerminal(typed.Stmt, parameter)
	}
	return realStackTerminal{}, false
}

func hasGuaranteedProofCallBefore(body *ast.BlockStmt, before token.Pos, parameter string) bool {
	for _, statement := range body.List {
		if statement.Pos() >= before {
			break
		}
		switch typed := statement.(type) {
		case *ast.BlockStmt:
			if hasGuaranteedProofCallBefore(typed, before, parameter) {
				return true
			}
		case *ast.IfStmt:
			if condition, constant := constantBoolean(typed.Cond); constant && condition && hasGuaranteedProofCallBefore(typed.Body, before, parameter) {
				return true
			}
		default:
			if statementHasProofCall(typed, before, parameter) {
				return true
			}
		}
	}
	return false
}

func hasExecutableRealStackCall(body *ast.BlockStmt, parameter string) bool {
	excluded := excludedSyntax(body)
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		if node == nil || found {
			return false
		}
		if syntaxExcluded(node, excluded) {
			return false
		}
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isNonProofCall(call, parameter) {
			return false
		}
		found = true
		return false
	})
	return found
}

func statementHasProofCall(statement ast.Stmt, before token.Pos, parameter string) bool {
	found := false
	ast.Inspect(statement, func(node ast.Node) bool {
		if node == nil || found {
			return false
		}
		if node.Pos() >= before {
			return false
		}
		if _, ok := node.(*ast.FuncLit); ok {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isNonProofCall(call, parameter) {
			return false
		}
		found = true
		return false
	})
	return found
}

func isNonProofCall(call *ast.CallExpr, parameter string) bool {
	if isTestingSkipCall(call, parameter) {
		return true
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok && isIdentifier(selector.X, parameter) {
		switch selector.Sel.Name {
		case "Cleanup", "Helper", "Log", "Logf", "Parallel":
			return true
		}
	}
	if identifier, ok := call.Fun.(*ast.Ident); ok {
		switch identifier.Name {
		case "append", "cap", "complex", "copy", "imag", "len", "make", "max", "min", "new", "real":
			return true
		}
	}
	return false
}

func (v *Validator) validateRealStackProfile(payload, profile string) error {
	pathText, testName, ok := strings.Cut(payload, "#")
	if !ok {
		return fmt.Errorf("test ref %q needs an exact Go Test function", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	relative = filepath.ToSlash(relative)
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read proof source %q: %w", relative, err)
	}
	switch profile {
	case "integration":
		base := filepath.Base(relative)
		if base != "integration_test.go" && !strings.HasSuffix(base, "_integration_test.go") {
			return fmt.Errorf("integration proof must be an *_integration_test.go file with a positive integration build constraint")
		}
		if err := v.validatePositiveProfileBuildConstraint(relative, "integration"); err != nil {
			return fmt.Errorf("integration proof must be an *_integration_test.go file with a positive integration build constraint: %w", err)
		}
	case "e2e":
		if relative != "test/e2e/e2e_test.go" || testName != "TestE2E" || !goTestHasEnvGuard(data, testName, "PROBECTL_E2E", "Getenv", token.NEQ, "1", "Skip") {
			return fmt.Errorf("e2e proof must be test/e2e/e2e_test.go#TestE2E with the required PROBECTL_E2E execution guard")
		}
	case "ebpf-kernel":
		if relative != "internal/ebpf/live_smoke_ebpf_test.go" || !strings.HasPrefix(testName, "TestLive") {
			return fmt.Errorf("ebpf-kernel proof must be a TestLive* function in the ebpf-tagged live smoke file")
		}
		if err := v.validatePositiveProfileBuildConstraint(relative, "ebpf"); err != nil {
			return fmt.Errorf("ebpf-kernel proof must be a TestLive* function in the ebpf-tagged live smoke file: %w", err)
		}
	case "device-live":
		if relative != "internal/device/snmp_test.go" || testName != "TestSNMPIntegration" || !goTestHasEnvGuard(data, testName, "PROBECTL_TEST_SNMP_REQUIRED", "getenvDefault", token.EQL, "1", "Fatal") {
			return fmt.Errorf("device-live proof must be the required live SNMP integration function")
		}
	default:
		return fmt.Errorf("unsupported real-stack profile %q", profile)
	}
	return nil
}

func (v *Validator) validatePositiveProfileBuildConstraint(relative, profileTag string) error {
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	context := build.Default
	context.GOOS = "linux"
	context.GOARCH = "amd64"
	context.CgoEnabled = false
	context.BuildTags = []string{profileTag}
	withProfile, err := context.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	context.BuildTags = nil
	withoutProfile, err := context.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	if !withProfile || withoutProfile {
		return fmt.Errorf("constraint must include the file with %q and exclude it without that tag", profileTag)
	}
	return nil
}

func goTestHasEnvGuard(source []byte, testName, envKey, getter string, operator token.Token, expected, terminal string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "guard_test.go", source, 0)
	if err != nil {
		return false
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != testName || fn.Body == nil {
			continue
		}
		guarded := false
		for _, condition := range directLiveIfStatements(fn.Body) {
			binary, ok := condition.Cond.(*ast.BinaryExpr)
			if !ok || binary.Op != operator || !isExpectedEnvCall(binary.X, getter, envKey) || !isStringLiteral(binary.Y, expected) {
				continue
			}
			ast.Inspect(condition.Body, func(bodyNode ast.Node) bool {
				if bodyNode == nil {
					return false
				}
				if _, ok := bodyNode.(*ast.FuncLit); ok {
					return false
				}
				call, ok := bodyNode.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && isIdentifier(selector.X, "t") && strings.HasPrefix(selector.Sel.Name, terminal) {
					guarded = true
				}
				return true
			})
			if guarded {
				break
			}
		}
		return guarded
	}
	return false
}

func directLiveIfStatements(body *ast.BlockStmt) []*ast.IfStmt {
	var out []*ast.IfStmt
	var visit func(*ast.BlockStmt)
	visit = func(block *ast.BlockStmt) {
		dead := false
		for _, statement := range block.List {
			if dead {
				break
			}
			switch value := statement.(type) {
			case *ast.IfStmt:
				condition, constant := constantBoolean(value.Cond)
				if !constant || condition {
					out = append(out, value)
					visit(value.Body)
				}
				if alternate, ok := value.Else.(*ast.BlockStmt); ok && (!constant || !condition) {
					visit(alternate)
				}
			case *ast.BlockStmt:
				visit(value)
			case *ast.ReturnStmt:
				dead = true
			}
		}
	}
	visit(body)
	return out
}

func isExpectedEnvCall(expression ast.Expr, getter, envKey string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 || !isStringLiteral(call.Args[0], envKey) {
		return false
	}
	switch called := call.Fun.(type) {
	case *ast.Ident:
		return called.Name == getter
	case *ast.SelectorExpr:
		return getter == "Getenv" && called.Sel.Name == getter && isIdentifier(called.X, "os")
	}
	return false
}

func isStringLiteral(expression ast.Expr, expected string) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(literal.Value)
	return err == nil && value == expected
}

func (v *Validator) validateRealStackRunner(profile string) error {
	switch profile {
	case "integration":
		if err := v.validateIntegrationMakeTarget(); err != nil {
			return err
		}
		return v.validateWorkflowInvocation(".github/workflows/ci.yml", "integration", []string{"make", "test-integration"})
	case "e2e":
		if err := v.validateMakeTarget("e2e", "PROBECTL_E2E=1"); err != nil {
			return err
		}
		return v.validateWorkflowInvocation(".github/workflows/nightly.yml", "e2e", []string{"make", "e2e"})
	case "ebpf-kernel":
		return v.validateWorkflowInvocation(".github/workflows/ci.yml", "ebpf-kernel-matrix", []string{"go", "test", "-tags", "ebpf"})
	case "device-live":
		if err := v.validateWorkflowInvocation(".github/workflows/ci.yml", "device-live", []string{"bash", "scripts/device_snmp_live_ci.sh"}); err != nil {
			return err
		}
		return v.validateDeviceLiveScript()
	default:
		return fmt.Errorf("unsupported real-stack profile %q", profile)
	}
}

func (v *Validator) validateIntegrationMakeTarget() error {
	const (
		relative = "Makefile"
		target   = "test-integration"
	)
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runner %q: %w", relative, err)
	}
	recipe, err := makeTargetRecipe(data, target)
	if err != nil {
		return fmt.Errorf("runner %q %w", relative, err)
	}
	rootCommand, ok := integrationRootCommand(recipe)
	if !ok {
		return fmt.Errorf("runner %q target %q does not execute go test with the integration tag and ./... package scope", relative, target)
	}
	if rootCommand.mode == "module-loop" && !makeVariableIncludes(data, "GO_MODULE_DIRS", ".") {
		return fmt.Errorf("runner %q target %q does not include the root module in GO_MODULE_DIRS", relative, target)
	}
	if rootCommand.configuredGo {
		words, found := makeVariableWords(data, "GO")
		if !found || len(words) != 1 || words[0] != "go" {
			return fmt.Errorf("runner %q target %q does not bind $(GO) to the Go tool", relative, target)
		}
	}
	if words, found := makeVariableWords(data, "GOFLAGS"); found && len(words) > 0 {
		return fmt.Errorf("runner %q target %q sets GOFLAGS that can narrow proof execution", relative, target)
	}
	if strings.Contains(recipe, "scripts/with_integration_stack_lock.sh") {
		if err := v.validateIntegrationWrapper("scripts/with_integration_stack_lock.sh"); err != nil {
			return err
		}
	}
	return nil
}

func (v *Validator) validateIntegrationWrapper(relative string) error {
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read integration wrapper %q: %w", relative, err)
	}
	if shellRebindsArguments(string(data)) || !shellInvokes(string(data), []string{"$@"}) {
		return fmt.Errorf("integration wrapper %q does not fail-closed while forwarding its command", relative)
	}
	return nil
}

func shellRebindsArguments(script string) bool {
	normalized := strings.NewReplacer("&&", ";", "||", ";").Replace(executableText([]byte(script)))
	for _, line := range strings.Split(normalized, "\n") {
		for _, statement := range strings.Split(line, ";") {
			fields := strings.Fields(strings.TrimSpace(statement))
			if len(fields) >= 2 && fields[0] == "set" && fields[1] == "--" {
				return true
			}
		}
	}
	return false
}

func makeTargetRecipe(data []byte, target string) (string, error) {
	lines := strings.Split(executableText(data), "\n")
	start := -1
	for i, line := range lines {
		if makeDefinesTarget(line, target) {
			if start >= 0 {
				return "", fmt.Errorf("repeats target %q", target)
			}
			start = i + 1
		}
	}
	if start < 0 {
		return "", fmt.Errorf("is missing target %q", target)
	}
	var recipe strings.Builder
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "\t") {
			break
		}
		recipe.WriteString(line)
		recipe.WriteByte('\n')
	}
	return recipe.String(), nil
}

func makeDefinesTarget(line, target string) bool {
	if strings.HasPrefix(line, "\t") {
		return false
	}
	colon := strings.IndexByte(line, ':')
	if colon < 0 || (colon+1 < len(line) && line[colon+1] == '=') {
		return false
	}
	for _, candidate := range strings.Fields(strings.TrimSpace(line[:colon])) {
		if candidate == target {
			return true
		}
	}
	return false
}

type integrationRootEvidence struct {
	mode         string
	configuredGo bool
}

func integrationRootCommand(recipe string) (integrationRootEvidence, bool) {
	executable := executableText([]byte(recipe))
	normalized := strings.Join(strings.Fields(strings.ReplaceAll(executable, "\\\n", " ")), " ")
	fields := strings.Fields(normalized)
	for i := 0; i+1 < len(fields); i++ {
		if cleanShellField(fields[i]) != "go" || cleanShellField(fields[i+1]) != "test" {
			continue
		}
		hasTag := false
		hasAllPackages := false
		forbiddenArgument := false
		unsafeTerminator := false
		commandEnd := len(fields)
		for j := i + 2; j < len(fields); j++ {
			rawField := strings.Trim(fields[j], "\"'\\")
			field := cleanShellField(fields[j])
			if field == "&&" || field == "||" || field == ";" || field == "|" || field == "&" || field == "|&" {
				commandEnd = j
				break
			}
			switch {
			case field == "-tags=integration":
				hasTag = true
			case field == "-tags" && j+1 < len(fields) && cleanShellField(fields[j+1]) == "integration":
				hasTag = true
			case field == "./...":
				hasAllPackages = true
			}
			if forbiddenIntegrationGoArgument(field) || (field == "-count" && j+1 < len(fields) && zeroInteger(cleanShellField(fields[j+1]))) {
				forbiddenArgument = true
			}
			if strings.HasSuffix(rawField, ";") {
				unsafeTerminator = true
				commandEnd = j + 1
				break
			}
		}
		if !hasTag || !hasAllPackages || forbiddenArgument || unsafeTerminator || integrationCommandMasksFailure(fields[commandEnd:]) || integrationCommandPrefixOverrides(fields[:i]) {
			continue
		}
		prefix := strings.Join(fields[:i], " ")
		if regexp.MustCompile(`(?:^|[;(])\s*(?:exit|return)(?:\s|;|$)`).MatchString(prefix) {
			continue
		}
		configuredGo := strings.Trim(fields[i], "\"'\\") == "$(GO)"
		moduleLoop := i >= 3 && cleanShellField(fields[i-3]) == "cd" && cleanShellField(fields[i-2]) == "$$d" && cleanShellField(fields[i-1]) == "&&"
		if moduleLoop {
			if strings.Contains(normalized, "for d in $(GO_MODULE_DIRS); do") {
				return integrationRootEvidence{mode: "module-loop", configuredGo: configuredGo}, true
			}
			continue
		}
		if regexp.MustCompile(`(?:^|[;(])\s*cd\s+[^;&]+\s+&&\s*$`).MatchString(prefix) {
			continue
		}
		if directShellCommandStart(fields, i) {
			return integrationRootEvidence{mode: "root", configuredGo: configuredGo}, true
		}
	}
	return integrationRootEvidence{}, false
}

func forbiddenIntegrationGoArgument(field string) bool {
	if field == "-args" || field == "--" || strings.HasPrefix(field, "-test.") {
		return true
	}
	for _, prefix := range []string{"-exec", "-list", "-run", "-short", "-skip"} {
		if field == prefix || strings.HasPrefix(field, prefix+"=") {
			return true
		}
	}
	if value, ok := strings.CutPrefix(field, "-count="); ok {
		return zeroInteger(value)
	}
	return false
}

func zeroInteger(value string) bool {
	parsed, err := strconv.ParseInt(value, 10, 64)
	return err == nil && parsed == 0
}

func integrationCommandPrefixOverrides(prefix []string) bool {
	for _, field := range prefix {
		cleaned := strings.TrimLeft(cleanShellField(field), "(")
		name, _, ok := strings.Cut(cleaned, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "GOENV", "GOFLAGS", "PATH":
			return true
		}
	}
	return false
}

func integrationCommandMasksFailure(suffix []string) bool {
	for i, field := range suffix {
		raw := strings.Trim(field, "\"'\\")
		cleaned := cleanShellField(field)
		if raw == ";" || cleaned == "&" || (strings.Contains(cleaned, "|") && cleaned != "||") {
			return true
		}
		if cleaned != "||" {
			continue
		}
		if i+1 >= len(suffix) {
			return true
		}
		next := cleanShellField(suffix[i+1])
		if next == "true" || next == ":" {
			return true
		}
		return next != "exit" || i+2 >= len(suffix) || cleanShellField(suffix[i+2]) == "0"
	}
	return false
}

func directShellCommandStart(fields []string, index int) bool {
	if index == 0 {
		return true
	}
	for i := index - 1; i >= 0; i-- {
		raw := strings.Trim(fields[i], "\"'\\")
		cleaned := cleanShellField(raw)
		if raw == "||" {
			return false
		}
		if raw == ";" || raw == "&&" || strings.HasSuffix(raw, ";") {
			return true
		}
		if strings.Contains(cleaned, "=") || cleaned == "env" {
			continue
		}
		return false
	}
	return true
}

func cleanShellField(field string) string {
	field = strings.TrimSpace(field)
	field = strings.Trim(field, "\"';\\")
	field = strings.TrimPrefix(field, "@")
	if strings.HasPrefix(field, "(") && !strings.HasPrefix(field, "$(") {
		field = strings.TrimPrefix(field, "(")
	}
	if strings.HasSuffix(field, ")") && !strings.HasPrefix(field, "$(") {
		field = strings.TrimSuffix(field, ")")
	}
	if field == "$(GO)" {
		return "go"
	}
	return field
}

func makeVariableIncludes(data []byte, variable, wanted string) bool {
	words, found := makeVariableWords(data, variable)
	if !found {
		return false
	}
	for _, word := range words {
		if word == wanted {
			return true
		}
	}
	return false
}

func makeVariableWords(data []byte, variable string) ([]string, bool) {
	var words []string
	found := false
	for _, line := range strings.Split(executableText(data), "\n") {
		if strings.HasPrefix(line, "\t") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, variable) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, variable))
		for _, assignment := range []string{":=", "?=", "+=", "="} {
			if !strings.HasPrefix(rest, assignment) {
				continue
			}
			value := strings.Fields(strings.TrimSpace(strings.TrimPrefix(rest, assignment)))
			switch assignment {
			case "?=":
				if !found {
					words = value
					found = true
				}
			case "+=":
				words = append(words, value...)
				found = true
			default:
				words = value
				found = true
			}
			break
		}
	}
	return words, found
}

func (v *Validator) validateMakeTarget(target, anchor string) error {
	const relative = "Makefile"
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runner %q: %w", relative, err)
	}
	recipe, err := makeTargetRecipe(data, target)
	if err != nil {
		return fmt.Errorf("runner %q %w", relative, err)
	}
	if !strings.Contains(recipe, anchor) {
		return fmt.Errorf("runner %q target %q is missing %q", relative, target, anchor)
	}
	return nil
}

func (v *Validator) validateWorkflowInvocation(relative, job string, command []string) error {
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runner %q: %w", relative, err)
	}
	var workflow struct {
		Env      map[string]any `yaml:"env"`
		Defaults struct {
			Run struct {
				Shell any `yaml:"shell"`
			} `yaml:"run"`
		} `yaml:"defaults"`
		Jobs map[string]struct {
			If              any            `yaml:"if"`
			ContinueOnError any            `yaml:"continue-on-error"`
			Env             map[string]any `yaml:"env"`
			Defaults        struct {
				Run struct {
					Shell any `yaml:"shell"`
				} `yaml:"run"`
			} `yaml:"defaults"`
			Steps []struct {
				If              any            `yaml:"if"`
				ContinueOnError any            `yaml:"continue-on-error"`
				Run             string         `yaml:"run"`
				Shell           any            `yaml:"shell"`
				Env             map[string]any `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return fmt.Errorf("decode runner %q: %w", relative, err)
	}
	definition, ok := workflow.Jobs[job]
	if !ok {
		return fmt.Errorf("runner %q is missing job %q", relative, job)
	}
	if !workflowUsesDefaultShell(workflow.Defaults.Run.Shell) || !workflowUsesDefaultShell(definition.Defaults.Run.Shell) || !workflowConditionAlwaysRuns(definition.If) || !workflowFailureIsBlocking(definition.ContinueOnError) || !workflowEnvironmentIsSafe(command, workflow.Env, definition.Env) {
		return fmt.Errorf("runner %q job %q is missing executable command %q", relative, job, strings.Join(command, " "))
	}
	for _, step := range definition.Steps {
		if !workflowConditionAlwaysRuns(step.If) || !workflowFailureIsBlocking(step.ContinueOnError) || !workflowUsesDefaultShell(step.Shell) || !workflowEnvironmentIsSafe(command, step.Env) {
			continue
		}
		if shellInvokes(step.Run, command) {
			return nil
		}
	}
	return fmt.Errorf("runner %q job %q is missing executable command %q", relative, job, strings.Join(command, " "))
}

func workflowConditionAlwaysRuns(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return normalizedWorkflowConstant(typed) == "true"
	default:
		return false
	}
}

func workflowFailureIsBlocking(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case bool:
		return !typed
	case string:
		return normalizedWorkflowConstant(typed) == "false"
	default:
		return false
	}
}

func workflowUsesDefaultShell(value any) bool {
	if value == nil {
		return true
	}
	text, ok := value.(string)
	return ok && strings.TrimSpace(text) == ""
}

func workflowEnvironmentIsSafe(command []string, environments ...map[string]any) bool {
	blocked := map[string]bool{"BASH_ENV": true, "ENV": true, "GOFLAGS": true, "MAKEFLAGS": true}
	if len(command) > 0 && command[0] == "make" {
		blocked["GO"] = true
		blocked["GOWORK"] = true
	}
	for _, environment := range environments {
		for key := range environment {
			if blocked[strings.ToUpper(strings.TrimSpace(key))] {
				return false
			}
		}
	}
	return true
}

func normalizedWorkflowConstant(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}") {
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "${{"), "}}"))
	}
	return value
}

func (v *Validator) validateDeviceLiveScript() error {
	const relative = "scripts/device_snmp_live_ci.sh"
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read runner %q: %w", relative, err)
	}
	executable := executableText(data)
	hasRequiredTarget := false
	for _, line := range strings.Split(executable, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), `: "${PROBECTL_TEST_SNMP_TARGET:?`) {
			hasRequiredTarget = true
			break
		}
	}
	if !hasRequiredTarget {
		return fmt.Errorf("runner %q is missing fail-closed PROBECTL_TEST_SNMP_TARGET expansion", relative)
	}
	if !shellInvokesInControlFlow(executable, []string{"go", "test"}) || !strings.Contains(executable, `-run '^TestSNMPIntegration$'`) || !shellEndsWithFailure(executable) {
		return fmt.Errorf("runner %q is missing executable TestSNMPIntegration command", relative)
	}
	return nil
}

func shellInvokes(script string, command []string) bool {
	return shellInvokesMode(script, command, false)
}

func shellInvokesInControlFlow(script string, command []string) bool {
	return shellInvokesMode(script, command, true)
}

func shellInvokesMode(script string, command []string, allowControlFlow bool) bool {
	lines := strings.Split(executableText([]byte(script)), "\n")
	controlDepth := 0
	errexit := false
	shadowed := false
	for lineIndex, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		controlDepth = shellControlDepthBefore(line, controlDepth)
		if controlDepth == 0 {
			if setting, changed := shellErrexitSetting(line); changed {
				errexit = setting
			}
		}
		if controlDepth == 0 && isUnconditionalShellExit(line) {
			return false
		}
		if len(command) > 0 && shellDefinesCommand(line, command[0]) {
			shadowed = true
		}
		fields := strings.Fields(line)
		for i := range fields {
			fields[i] = strings.Trim(fields[i], `"'`)
		}
		for i := 0; i+len(command) <= len(fields); i++ {
			matched := true
			for j, want := range command {
				if fields[i+j] != want {
					matched = false
					break
				}
			}
			conditional := controlDepth > 0 || (i > 0 && fields[0] == "if")
			if matched && !shadowed && (allowControlFlow || !conditional) && safeShellPrefix(fields[:i]) && !shellSuffixMasksFailure(fields[i+len(command):]) && (errexit || !hasLaterShellCommand(lines[lineIndex+1:])) {
				return true
			}
		}
		controlDepth = shellControlDepthAfter(line, controlDepth)
	}
	return false
}

func shellDefinesCommand(line, command string) bool {
	trimmed := strings.TrimSpace(line)
	functionPattern := regexp.MustCompile(`^(?:function\s+)?` + regexp.QuoteMeta(command) + `\s*\(\s*\)\s*\{`)
	aliasPattern := regexp.MustCompile(`^alias\s+` + regexp.QuoteMeta(command) + `\s*=`)
	return functionPattern.MatchString(trimmed) || aliasPattern.MatchString(trimmed)
}

func shellControlDepthBefore(line string, depth int) int {
	for _, closing := range []string{"fi", "done", "esac", "}"} {
		if (line == closing || strings.HasPrefix(line, closing+" ")) && depth > 0 {
			return depth - 1
		}
	}
	return depth
}

func shellControlDepthAfter(line string, depth int) int {
	for _, opening := range []string{"if ", "for ", "while ", "until ", "case ", "select ", "function "} {
		if strings.HasPrefix(line, opening) {
			return depth + 1
		}
	}
	if strings.HasSuffix(line, "() {") {
		return depth + 1
	}
	return depth
}

func shellErrexitSetting(line string) (bool, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "set" {
		return false, false
	}
	changed := false
	enabled := false
	for i, field := range fields[1:] {
		if strings.HasPrefix(field, "-") && strings.Contains(field, "e") {
			changed = true
			enabled = true
		}
		if field == "-o" && i+2 < len(fields) && fields[i+2] == "errexit" {
			changed = true
			enabled = true
		}
		if strings.HasPrefix(field, "+") && strings.Contains(field, "e") {
			changed = true
			enabled = false
		}
		if field == "+o" && i+2 < len(fields) && fields[i+2] == "errexit" {
			changed = true
			enabled = false
		}
	}
	return enabled, changed
}

func isUnconditionalShellExit(line string) bool {
	statements := strings.NewReplacer("&&", ";", "||", ";").Replace(line)
	for _, statement := range strings.Split(statements, ";") {
		fields := strings.Fields(strings.TrimSpace(statement))
		if len(fields) > 0 && (fields[0] == "exit" || fields[0] == "return") {
			return true
		}
	}
	return false
}

func shellEndsWithFailure(script string) bool {
	lines := strings.Split(executableText([]byte(script)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(line, ";"))
		if len(fields) != 2 || fields[0] != "exit" {
			return false
		}
		status, err := strconv.Atoi(fields[1])
		return err == nil && status != 0
	}
	return false
}

func shellSuffixMasksFailure(suffix []string) bool {
	for i, field := range suffix {
		trimmed := strings.Trim(field, `"'`)
		if strings.Contains(trimmed, "|") || trimmed == "&" {
			return true
		}
		if trimmed != ";" || i+1 >= len(suffix) {
			continue
		}
		next := strings.Trim(suffix[i+1], `"';`)
		if next == "true" || next == ":" || next == "exit" || next == "return" {
			return true
		}
	}
	return false
}

func hasLaterShellCommand(lines []string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			return true
		}
	}
	return false
}

func safeShellPrefix(prefix []string) bool {
	if len(prefix) == 0 {
		return true
	}
	if prefix[0] != "env" && prefix[0] != "if" {
		return false
	}
	for _, field := range prefix {
		switch strings.TrimSpace(field) {
		case "&&", "||", ";", "false", "echo", "printf":
			return false
		}
	}
	return true
}

func executableText(data []byte) string {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		quoted := rune(0)
		escaped := false
		for offset, r := range line {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' && quoted == '"' {
				escaped = true
				continue
			}
			if r == '\'' || r == '"' {
				switch quoted {
				case 0:
					quoted = r
				case r:
					quoted = 0
				}
				continue
			}
			if r == '#' && quoted == 0 && (offset == 0 || line[offset-1] == ' ' || line[offset-1] == '\t') {
				line = line[:offset]
				break
			}
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func validateFileLocation(cell, payload string) error {
	pathText, anchor, hasAnchor := strings.Cut(payload, "#")
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	relative = filepath.ToSlash(relative)
	hasPrefix := func(prefixes ...string) bool {
		for _, prefix := range prefixes {
			if relative == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(relative, prefix) {
				return true
			}
		}
		return false
	}
	switch cell {
	case "engine":
		if !hasPrefix("internal/", "ee/", "analyzer/", "browser-worker/", "deploy/") {
			return fmt.Errorf("engine evidence %q must live in an implementation tree", relative)
		}
		if relative == "internal" || relative == "ee" || relative == "deploy" {
			return fmt.Errorf("engine evidence %q is an umbrella tree; name one production package or file", relative)
		}
	case "binary":
		if !hasPrefix("cmd/", "internal/control/") {
			return fmt.Errorf("binary evidence %q must live under cmd/ or internal/control/", relative)
		}
		trimmedAnchor := strings.TrimSpace(anchor)
		if trimmedAnchor == "func runServe" || strings.Contains(trimmedAnchor, "control.New(rt.cfg") {
			return fmt.Errorf("binary evidence %q uses the generic control-server entrypoint instead of a capability-specific assembly seam", payload)
		}
	case "api":
		if !hasPrefix("internal/", "ee/", "cmd/") {
			return fmt.Errorf("non-REST API evidence %q must live in an implementation tree", relative)
		}
		if filepath.Ext(relative) != ".go" {
			return fmt.Errorf("non-REST API evidence %q must be a Go file with statically checked dispatch", relative)
		}
	case "docs":
		if !hasPrefix("docs/") && relative != "probectl-PRD-v1.0.md" && relative != "probectl-PRD-v1.1.md" {
			return fmt.Errorf("documentation evidence %q must live under docs/ or be a current PRD", relative)
		}
	case "telemetry":
		if !hasPrefix("internal/", "ee/") {
			return fmt.Errorf("telemetry evidence %q must live in an implementation tree", relative)
		}
		if relative == "internal" || relative == "ee" {
			return fmt.Errorf("telemetry evidence %q is an umbrella tree; name one production package or file", relative)
		}
	case "migration":
		if !hasPrefix("migrations/") || filepath.Ext(relative) != ".sql" {
			return fmt.Errorf("migration evidence %q must be a SQL file under migrations/", relative)
		}
	case "real_stack_proof":
		if !hasPrefix("test/", "internal/", "cmd/", "ee/") || !strings.HasSuffix(relative, "_test.go") {
			return fmt.Errorf("real-stack proof %q must be a Go test file in a testable repository package", relative)
		}
		if !hasAnchor || !regexp.MustCompile(`^Test[A-Za-z0-9_]+$`).MatchString(anchor) {
			return fmt.Errorf("real-stack proof %q must name one exact Go Test function", payload)
		}
	}
	return nil
}

func normalizeOperation(value string) string {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return value
	}
	return strings.ToUpper(fields[0]) + " " + fields[1]
}

func (v *Validator) surfaceExists(featureID, route string) bool {
	for _, declaration := range v.surfaces {
		if declaration.kind == "native" && declaration.route == route && declaration.featureIDs[featureID] {
			return true
		}
	}
	return false
}

func (v *Validator) validateFile(cell, payload string, requireNeedle bool) error {
	pathText, needle, hasNeedle := strings.Cut(payload, "#")
	if requireNeedle && (!hasNeedle || strings.TrimSpace(needle) == "") {
		return fmt.Errorf("file ref %q needs a #literal anchor", payload)
	}
	relative, err := cleanRelative(pathText)
	if err != nil {
		return err
	}
	if err := v.rejectEvidenceSymlinkPath(relative); err != nil {
		return err
	}
	path, err := v.resolveWithinRoot(relative)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("evidence path %q: %w", relative, err)
	}
	if info.IsDir() {
		if cell == "docs" {
			return fmt.Errorf("documentation evidence %q must name one regular document, not a directory", relative)
		}
		if !hasNeedle {
			return nil
		}
		found := false
		err := filepath.WalkDir(path, func(candidate string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if candidate != path && (entry.Name() == ".git" || entry.Name() == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return fmt.Errorf("evidence directory contains symlink %q", filepath.ToSlash(candidate))
			}
			data, readErr := os.ReadFile(candidate)
			if readErr != nil {
				return readErr
			}
			if strings.Contains(searchableEvidenceText(cell, candidate, data), needle) {
				found = true
				return fs.SkipAll
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("search evidence path %q: %w", relative, err)
		}
		if !found {
			return fmt.Errorf("evidence path %q does not contain literal %q", relative, needle)
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read evidence path %q: %w", relative, err)
	}
	if cell == "migration" && !containsExecutableSQL(data) {
		return fmt.Errorf("migration evidence path %q contains no executable SQL statement", relative)
	}
	if !hasNeedle {
		return nil
	}
	if !strings.Contains(searchableEvidenceText(cell, path, data), needle) {
		return fmt.Errorf("evidence path %q does not contain literal %q", relative, needle)
	}
	return nil
}

func containsConfigKey(document, key string) bool {
	if key == "" {
		return false
	}
	pattern := `(^|[^A-Z0-9_])` + regexp.QuoteMeta(key) + `([^A-Z0-9_]|$)`
	return regexp.MustCompile(pattern).FindStringIndex(visibleMarkdownText(document)) != nil
}

func searchableEvidenceText(cell, path string, data []byte) string {
	text := string(data)
	switch {
	case cell == "api" && filepath.Ext(path) == ".go":
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, data, parser.ParseComments)
		if err != nil {
			return ""
		}
		withoutComments := append([]byte(nil), data...)
		for _, group := range file.Comments {
			start := set.Position(group.Pos()).Offset
			end := set.Position(group.End()).Offset
			if start < 0 || end < start || end > len(withoutComments) {
				return ""
			}
			for index := start; index < end; index++ {
				withoutComments[index] = ' '
			}
		}
		return string(withoutComments)
	case cell == "docs" && (filepath.Ext(path) == ".md" || filepath.Ext(path) == ".html"):
		if filepath.Ext(path) == ".md" {
			return visibleMarkdownText(text)
		}
		return stripDelimitedComments(text, "<!--", "-->")
	default:
		return text
	}
}

func visibleMarkdownText(text string) string {
	withoutHTMLComments := stripDelimitedComments(text, "<!--", "-->")
	referenceDefinition := regexp.MustCompile(`(?m)^[ \t]{0,3}\[[^\]\r\n]+\]:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*`)
	return referenceDefinition.ReplaceAllStringFunc(withoutHTMLComments, func(hidden string) string {
		return strings.Map(func(character rune) rune {
			if character == '\n' || character == '\r' {
				return character
			}
			return ' '
		}, hidden)
	})
}

func stripDelimitedComments(text, opening, closing string) string {
	for {
		start := strings.Index(text, opening)
		if start < 0 {
			return text
		}
		endOffset := strings.Index(text[start+len(opening):], closing)
		if endOffset < 0 {
			return text[:start]
		}
		end := start + len(opening) + endOffset + len(closing)
		text = text[:start] + strings.Repeat(" ", end-start) + text[end:]
	}
}

func containsExecutableSQL(data []byte) bool {
	text := stripDelimitedComments(string(data), "/*", "*/")
	var executable strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if comment := strings.Index(line, "--"); comment >= 0 {
			line = line[:comment]
		}
		executable.WriteString(line)
		executable.WriteByte('\n')
	}
	statement := strings.ToUpper(stripSQLQuotedText(executable.String()))
	return regexp.MustCompile(`(^|[[:space:];])(ALTER|COMMENT|CREATE|DELETE|DO|DROP|GRANT|INSERT|REVOKE|TRUNCATE|UPDATE)([[:space:]]|$)`).FindStringIndex(statement) != nil
}

func stripSQLQuotedText(text string) string {
	data := []byte(text)
	for index := 0; index < len(data); {
		switch data[index] {
		case '\'', '"':
			quote := data[index]
			data[index] = ' '
			index++
			for index < len(data) {
				if data[index] == '\n' {
					index++
					continue
				}
				if data[index] == quote {
					data[index] = ' '
					if index+1 < len(data) && data[index+1] == quote {
						data[index+1] = ' '
						index += 2
						continue
					}
					index++
					break
				}
				data[index] = ' '
				index++
			}
		case '$':
			closing := sqlDollarQuoteDelimiter(data[index:])
			if closing == "" {
				index++
				continue
			}
			endOffset := bytes.Index(data[index+len(closing):], []byte(closing))
			if endOffset < 0 {
				index++
				continue
			}
			end := index + len(closing) + endOffset + len(closing)
			for cursor := index; cursor < end; cursor++ {
				if data[cursor] != '\n' {
					data[cursor] = ' '
				}
			}
			index = end
		default:
			index++
		}
	}
	return string(data)
}

func sqlDollarQuoteDelimiter(data []byte) string {
	if len(data) < 2 || data[0] != '$' {
		return ""
	}
	for index := 1; index < len(data); index++ {
		if data[index] == '$' {
			return string(data[:index+1])
		}
		if (data[index] < 'a' || data[index] > 'z') && (data[index] < 'A' || data[index] > 'Z') && (data[index] < '0' || data[index] > '9') && data[index] != '_' {
			return ""
		}
	}
	return ""
}

func (v *Validator) resolveWithinRoot(relative string) (string, error) {
	path := filepath.Join(v.root, relative)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("evidence path %q: %w", relative, err)
	}
	within, err := filepath.Rel(v.root, resolved)
	if err != nil {
		return "", fmt.Errorf("resolve evidence path %q: %w", relative, err)
	}
	if within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("evidence path %q escapes the repository through a symlink", relative)
	}
	return resolved, nil
}

func cleanRelative(value string) (string, error) {
	if value == "" || filepath.IsAbs(value) {
		return "", fmt.Errorf("evidence path %q must be repository-relative", value)
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("evidence path %q escapes the repository", value)
	}
	return clean, nil
}
