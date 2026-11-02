// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/device"
	devicev1 "github.com/ctlplne/probectl/internal/gen/probectl/device/v1"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

// CI's device-live job runs this against its loopback net-snmp daemon. The
// reviewed export goes through the shipped CLI, parser and running collector;
// the bus receipt proves both the selected cadence and tenant lane.
func TestNMSImportConfigExportLiveDeviceAgent(t *testing.T) {
	target := os.Getenv("PROBECTL_TEST_SNMP_TARGET")
	if target == "" {
		if os.Getenv("PROBECTL_TEST_SNMP_REQUIRED") == "1" {
			t.Fatal("live SNMP target required")
		}
		t.Skip("device-live CI supplies a real loopback SNMP target")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		t.Fatalf("invalid live SNMP target: %v", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("invalid live SNMP port: %v", err)
	}
	const tenantID = "00000000-0000-4000-8000-000000000201"
	const contextID = "00000000-0000-4000-8000-000000000202"
	const sourceID = "00000000-0000-4000-8000-000000000203"
	const planID = "00000000-0000-4000-8000-000000000204"
	const itemID = "11111111222233334444555555555555"
	const agentID = "nms-poll-ci"
	preview := nmsimport.PollTargetPreview{TenantID: tenantID, ContextID: contextID,
		SourceID: sourceID, ItemID: itemID, HostID: "edge-r1",
		EntityID: "00000000-0000-4000-8000-000000000205", AgentID: agentID,
		TargetAddress: host, PollSeconds: 15, PlanID: planID, Revision: 1}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/nms-imports/poll-target-preview" ||
			r.Header.Get("X-Probectl-Tenant") != tenantID {
			t.Errorf("wrong tenant-scoped preview request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var req nmsimport.PollTargetPreview
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil ||
			req.ContextID != contextID || req.SourceID != sourceID || req.ItemID != itemID ||
			req.AgentID != agentID || req.TargetAddress != host {
			t.Errorf("wrong exact preview selection: %+v err=%v", req, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(preview)
	}))
	t.Cleanup(api.Close)
	nameFile := filepath.Join(t.TempDir(), "device-credential-name")
	if err := os.WriteFile(nameFile, []byte("ci-snmp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "reviewed-device.yaml")
	_, stderr, code := runWithEnv(t, api, map[string]string{"PROBECTL_TENANT": tenantID},
		"nms-import", "config-export", "--context-id", contextID,
		"--source-id", sourceID, "--item-id", itemID, "--agent-id", agentID,
		"--target-address", host, "--port", portText, "--transport", "snmpv2c",
		"--credential-name-file", nameFile, "--expected-plan-id", planID,
		"--expected-revision", "1", "--out", configFile)
	if code != 0 || stderr != "" {
		t.Fatalf("export refused current live target: code=%d stderr=%q", code, stderr)
	}
	cfg, err := device.Load(configFile)
	if err != nil || cfg.TenantID != tenantID || cfg.AgentID != agentID ||
		len(cfg.Devices) != 1 || cfg.Devices[0].Interval != 15*time.Second ||
		cfg.Devices[0].Port != uint16(port) {
		t.Fatalf("agent refused generated config: %+v err=%v", cfg, err)
	}
	creds := device.NewEnvCredentials(func(key string) string {
		if key == "PROBECTL_DEVICE_CRED_CI_SNMP_COMMUNITY" {
			return os.Getenv("PROBECTL_TEST_SNMP_COMMUNITY")
		}
		return ""
	})
	b := bus.NewMemory()
	t.Cleanup(func() { _ = b.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	receipts := make(chan bus.Message, 4)
	subDone := make(chan error, 1)
	go func() {
		subDone <- b.Subscribe(ctx, bus.DeviceMetricsTopic, "nms-live-proof", func(_ context.Context, msg bus.Message) error {
			select {
			case receipts <- msg:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	if !b.WaitForSubscribers(ctx, bus.DeviceMetricsTopic, 1) {
		t.Fatal("device metric subscriber did not start")
	}
	collector, err := device.New(cfg, device.NewBusEmitter(b, tenantID), creds,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- collector.Run(ctx) }()
	var times []int64
	for len(times) < 2 {
		select {
		case msg := <-receipts:
			if bus.TenantFromKey(msg.Key) != tenantID {
				t.Fatalf("metric escaped tenant bus lane: %q", msg.Key)
			}
			var batch devicev1.DeviceMetricBatch
			if err := proto.Unmarshal(msg.Value, &batch); err != nil || len(batch.Metrics) == 0 {
				t.Fatalf("device bus receipt: metrics=%d err=%v", len(batch.Metrics), err)
			}
			first := batch.Metrics[0]
			if first.TenantId != tenantID || first.AgentId != agentID ||
				first.DeviceAddress != host || first.Source != device.SourceSNMP ||
				first.TimeUnixNano <= 0 {
				t.Fatalf("wrong tenant or agent in live SNMP receipt: %+v", first)
			}
			if len(times) == 0 || times[len(times)-1] != first.TimeUnixNano {
				times = append(times, first.TimeUnixNano)
			}
		case <-ctx.Done():
			t.Fatalf("running agent emitted %d valid polls: %v stats=%v", len(times),
				ctx.Err(), collector.StatsSnapshot())
		}
	}
	gap := time.Duration(times[1] - times[0])
	if gap < 14*time.Second || gap > 40*time.Second {
		t.Fatalf("exported 15s cadence was not observed: gap=%s", gap)
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("collector stopped with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not stop after cancellation")
	}
	select {
	case <-subDone:
	case <-time.After(5 * time.Second):
		t.Fatal("bus subscriber did not stop after cancellation")
	}
}
