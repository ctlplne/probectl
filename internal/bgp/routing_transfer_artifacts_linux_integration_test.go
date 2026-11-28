// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package bgp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type transferArtifacts struct {
	dir string
}

func newTransferArtifacts(t *testing.T) transferArtifacts {
	t.Helper()
	root := os.Getenv("PROBECTL_TEST_TRANSFER_ARTIFACTS")
	if root == "" {
		return transferArtifacts{}
	}
	dir, err := os.MkdirTemp(root, "attempt-")
	if err != nil {
		t.Fatalf("create routing-transfer diagnostic directory: %v", err)
	}
	return transferArtifacts{dir: dir}
}

func (a transferArtifacts) write(t *testing.T, name string, value []byte) {
	t.Helper()
	if a.dir != "" {
		if err := os.WriteFile(filepath.Join(a.dir, name), value, 0o600); err != nil {
			t.Errorf("save %s: %v", name, err)
		}
	}
}

func (a transferArtifacts) counterBrackets(t *testing.T, lanes [2]transferStockLane) {
	t.Helper()
	for i, lane := range lanes {
		report := fmt.Appendf(nil, "before %s %s %s out_octets %v\nafter %s %s %s out_octets %v\n",
			lane.before.capture, lane.before.started.Format(time.RFC3339Nano), lane.before.completed.Format(time.RFC3339Nano), lane.before.octets,
			lane.after.capture, lane.after.started.Format(time.RFC3339Nano), lane.after.completed.Format(time.RFC3339Nano), lane.after.octets)
		a.write(t, fmt.Sprintf("lane-%d-counter-brackets.txt", i), report)
	}
}

func (a transferArtifacts) exporterState(t *testing.T, lanes [2]transferStockLane, phase string) {
	t.Helper()
	if a.dir == "" {
		return
	}
	for i, lane := range lanes {
		if lane.exporter == "" {
			continue
		}
		for _, operation := range []string{"statistics", "dump-flows"} {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			out, err := exec.CommandContext(ctx, "docker", "exec", lane.exporter,
				"softflowctl", "-c", "/tmp/softflowd.ctl", operation).CombinedOutput()
			cancel()
			if err != nil {
				out = fmt.Appendf(out, "\n%s: %v\n", operation, err)
			}
			a.write(t, fmt.Sprintf("exporter-%d-%s-%s.txt", i, phase, operation), out)
		}
	}
}

func (a transferArtifacts) exporterFailure(t *testing.T, lanes [2]transferStockLane) {
	t.Helper()
	if a.dir == "" || !t.Failed() {
		return
	}
	a.exporterState(t, lanes, "failure")
	for i, lane := range lanes {
		name := fmt.Sprintf("exporter-%d.log", i)
		if lane.exporter == "" {
			a.write(t, name, []byte("No exporter was registered before the test failed.\n"))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, err := exec.CommandContext(ctx, "docker", "logs", "--tail", "250", lane.exporter).CombinedOutput()
		cancel()
		if err != nil {
			out = fmt.Appendf(out, "\ndocker logs: %v\n", err)
		}
		a.write(t, name, out)
	}
}

func (a transferArtifacts) bindings(t *testing.T, st *shipped.Stack, lanes [2]transferStockLane) {
	t.Helper()
	if a.dir == "" {
		return
	}
	pool := st.ApplicationReadPool(t)
	reader := store.NewInterfaceRoleInputs(pool)
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: 32 << 20, WorkUnits: 32 << 20}
	for i, lane := range lanes {
		scope := entity.Scope{TenantID: lane.reg.tenantID, ContextID: lane.reg.contextID}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(scope.TenantID))
		err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := reader.FlowBindingsInScope(ctx, sc, scope, budget)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(rows, "", "  ")
			if err == nil {
				a.write(t, fmt.Sprintf("lane-%d-signed-bindings.json", i), out)
			}
			return err
		})
		if err != nil {
			t.Errorf("read lane %d signed fixture bindings: %v", i, err)
		}
	}
}

func (a transferArtifacts) flowRows(t *testing.T, st *shipped.Stack, lanes [2]transferStockLane, ifIndex uint32, started time.Time) {
	t.Helper()
	if a.dir == "" {
		return
	}
	for i, lane := range lanes {
		readTransferStockFlowCaptures(t, st, lane, ifIndex, started, a, i)
	}
}

// Capture only the synthetic workload and the two IPFIX destinations, inside
// the exact owned router namespace. Do not capture lab auth or SNMP traffic.
func (a transferArtifacts) startPCAP(t *testing.T, lab *routingLab, lanes [2]transferStockLane) {
	t.Helper()
	if a.dir == "" {
		return
	}
	pid := strings.TrimSpace(lab.docker(t, "inspect", "--format", "{{.State.Pid}}", lab.container("rtr-a")))
	if n, err := strconv.Atoi(pid); err != nil || n <= 1 {
		t.Fatalf("invalid owned capture namespace: %q", pid)
	}
	parts := []string{"host " + transferStockAddress + " and port 37200"}
	for _, lane := range lanes {
		host, port, err := net.SplitHostPort(lane.collector)
		if err != nil || net.ParseIP(host) == nil {
			t.Fatalf("invalid owned IPFIX destination: %q", lane.collector)
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			t.Fatalf("invalid owned IPFIX port: %q", port)
		}
		parts = append(parts, "(dst host "+host+" and dst port "+port+")")
	}
	filter := "ip and udp and ((" + strings.Join(parts, ") or (") + "))"
	pcap, err := os.Create(filepath.Join(a.dir, "owned-router.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(a.dir, "tcpdump.log"))
	if err != nil {
		_ = pcap.Close()
		t.Fatal(err)
	}
	cmd := exec.Command("sudo", "-n", "timeout", "--signal=INT", "--kill-after=2s", "8m",
		"nsenter", "--target", pid, "--net", "--", "tcpdump", "-i", "any",
		"-p", "-nn", "-U", "-s", "0", "-c", "10000", "-w", "-", filter)
	cmd.Stdout, cmd.Stderr = pcap, log
	if err := cmd.Start(); err != nil {
		_ = pcap.Close()
		_ = log.Close()
		t.Fatalf("start owned router capture: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = pcap.Close()
		_ = log.Close()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
		}
	})
	shipped.Await(t, "capture attached to the owned router", 8*time.Second, func() bool {
		contents, err := os.ReadFile(log.Name())
		return err == nil && strings.Contains(string(contents), "listening on")
	})
}
