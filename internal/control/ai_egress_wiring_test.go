// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAIEgressGateProductionWiring(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)

	constructions := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		constructions += strings.Count(string(b), "ai.NewEgressGate(")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if constructions != 1 {
		t.Fatalf("control package must have exactly one production ai.NewEgressGate construction site, got %d", constructions)
	}

	mcpGo, err := os.ReadFile(filepath.Join(dir, "mcp.go"))
	if err != nil {
		t.Fatal(err)
	}
	mcpSrc := string(mcpGo)
	if strings.Contains(mcpSrc, "NewAIEgressGate(") || strings.Contains(mcpSrc, "ai.NewEgressGate(") {
		t.Fatal("NewMCPServer must receive the shared AI egress gate; it must not construct one")
	}
	if !strings.Contains(mcpSrc, "panic(\"control.NewMCPServer requires the shared AI egress gate\")") {
		t.Fatal("NewMCPServer must fail fast when the shared AI egress gate is missing")
	}

	serverGo, err := os.ReadFile(filepath.Join(dir, "server.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(serverGo), "s.egressGate = NewAIEgressGate(cfg, log, pool)") {
		t.Fatal("Server.New must store the shared AI egress gate on the server")
	}
}
