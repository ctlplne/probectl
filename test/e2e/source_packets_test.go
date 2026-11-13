// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

const (
	releasePacketCount   = 4096
	releasePacketPayload = 1200
	// Reuse the exact already-shipped real-exporter fixture, including pins.
	releasePacketImage = "probectl-qa-beta-fx2-softflowd:alpine-3.22.6-v1.1.0-r0"
)

func releasePacketReaders(t *testing.T, sessions []releaseSession, readers []api) []api {
	t.Helper()
	if len(sessions) != 2 || len(readers) != 2 {
		t.Fatal("real packet reporting requires two existing SSO sessions")
	}
	result := make([]api, 2)
	for i := range result {
		anonymous := readers[i]
		anonymous.token = ""
		code, raw := anonymous.do(t, http.MethodPost, "/v1/api-tokens", map[string]any{
			"name": "real-packet-reports-" + strconv.Itoa(i), "expires_in_hours": 1,
			"scopes": []string{"tenant.read", "agent.write", "entities.read", "ai.query", "flow.read", "flow.views.write", "metrics.read", "metrics.write", "governance.write", "tags.read", "tags.write"},
		}, "Cookie", "probectl_session="+sessions[i].Cookie)
		var minted struct{ Token string }
		if code != http.StatusCreated || json.Unmarshal(raw, &minted) != nil || minted.Token == "" {
			t.Fatal("real SSO session could not mint the scoped packet-report credential", code)
		}
		result[i] = api{base: readers[i].base, client: readers[i].client, token: minted.Token}
	}
	return result
}

func buildReleasePacketExporter(t *testing.T, root string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "docker", "build", "-q", "-t", releasePacketImage, "-")
	command.Dir = root
	command.Stdin = strings.NewReader("FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8\nRUN apk add --no-cache softflowd=1.1.0-r0\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build existing pinned packet exporter: %v: %.4096s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", releasePacketImage).Run() })
}

func (p *releaseFlowReport) packetRuleInput() map[string]string {
	return map[string]string{"tag_id": p.packetTag, "target_kind": "exporter", "match_kind": "cidr",
		"address_side": "exporter", "cidr": "127.0.0.1/32", "value": p.packetValue}
}

func (p *releaseFlowReport) preparePacketTag(t *testing.T, agent string) {
	t.Helper()
	var routing struct {
		ContextID string `json:"context_id"`
		TenantID  string `json:"tenant_id"`
	}
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/entity-contexts",
		map[string]string{"site_label": "same packet site", "vrf_label": "same packet VRF"}, &routing)
	if routing.ContextID == "" || routing.TenantID != p.tenant {
		t.Fatal("real packet context changed the credential-derived tenant")
	}
	p.packetContext = routing.ContextID
	var device entity.Record
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/entities", map[string]string{
		"context_id": p.packetContext, "kind": "device", "label": "real packet source device",
	}, &device)
	if device.ID == "" || device.Kind != entity.Device || device.Scope.TenantID != p.tenant || device.Scope.ContextID != p.packetContext {
		t.Fatal("real packet device changed its authenticated tenant or context")
	}
	p.packetEntity = device.ID
	// Bind before the collector captures any traffic. A later assignment
	// cannot retroactively give an old packet capture canonical ownership.
	p.api.json(t, http.StatusOK, http.MethodPut, "/v1/entity-source-contexts", map[string]string{
		"agent_id": agent, "source_kind": "flow_exporter", "source_ref": "127.0.0.1", "context_id": routing.ContextID,
		"anchor_entity_id": p.packetEntity,
	}, nil)
	var tag, rule struct{ ID string }
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/tags", map[string]string{"key": "packet_customer"}, &tag)
	if tag.ID == "" {
		t.Fatal("real packet tag has no owned definition")
	}
	p.packetTag, p.packetValue = tag.ID, "packet-initial-"+p.tenant
	p.api.json(t, http.StatusCreated, http.MethodPost, "/v1/entity-contexts/"+p.packetContext+"/tag-rules", p.packetRuleInput(), &rule)
	if rule.ID == "" {
		t.Fatal("real packet rule has no owned identity")
	}
	p.packetRule = rule.ID
}

func (p *releaseFlowReport) assertPacketIdentity(t *testing.T, foreign *releaseFlowReport) {
	t.Helper()
	endpoint := "/v1/entities/resolve?context_id=" + p.packetContext + "&kind=flow_exporter_id&value=127.0.0.1"
	waitFor(t, "actual packet exporter canonical identity", 30*time.Second, func() bool {
		var resolved entity.Resolution
		p.api.json(t, http.StatusOK, http.MethodGet, endpoint, nil, &resolved)
		return resolved.Status == entity.Resolved && !resolved.MoreCandidates && resolved.EntityID == p.packetEntity &&
			resolved.Scope.TenantID == p.tenant && resolved.Scope.ContextID == p.packetContext
	})
	code, body := foreign.api.do(t, http.MethodGet, endpoint, nil)
	if code != http.StatusNotFound || bytes.Contains(body, []byte(p.packetEntity)) {
		t.Fatal("packet exporter canonical identity crossed tenant storage", code)
	}
}

func (p *releaseFlowReport) retagCapturedHistory(t *testing.T, plan map[string]any) {
	t.Helper()
	verify := func() {
		var result struct {
			Flow struct {
				Totals map[string]string `json:"totals"`
				Rows   []struct {
					Group map[string]string `json:"group"`
				} `json:"rows"`
			} `json:"flow"`
		}
		p.api.json(t, http.StatusOK, http.MethodPost, "/v1/explorer/query", map[string]any{"source": "flow", "flow": plan}, &result)
		if len(result.Flow.Rows) != 1 || result.Flow.Totals["bytes:total"] != strconv.FormatUint(uint64(p.quantity), 10) || result.Flow.Totals["flows:total"] != "1" || result.Flow.Totals["packets:total"] != strconv.Itoa(releasePacketCount) {
			t.Fatal("real packet rule changed exact retained packet byte/flow quantities")
		}
		group := result.Flow.Rows[0].Group
		if group["tag.packet_customer"] != p.packetValue || group["protocol"] != "ipfix" || group["exporter"] != "127.0.0.1" || group["src_addr"] != p.address {
			t.Fatal("real packet history lost its current rule, actual protocol or owned exporter")
		}
	}
	verify()
	p.packetValue = "packet-updated-" + p.tenant
	p.api.json(t, http.StatusOK, http.MethodPut, "/v1/entity-contexts/"+p.packetContext+"/tag-rules/"+p.packetRule, p.packetRuleInput(), nil)
	verify()
}

func (p *releaseFlowReport) verifyPacketCSVCells(t *testing.T, row []string, columns map[string]int) {
	t.Helper()
	cell := func(name string) string {
		index, ok := columns[name]
		if !ok || index < 0 || index >= len(row) {
			t.Fatal("real packet CSV column is missing or incomplete", name)
		}
		return row[index]
	}
	if cell("packets:total") != strconv.Itoa(releasePacketCount) {
		t.Fatal("real source report lost independently emitted packet count")
	}
	if row[0] == "detail" && (cell("tag.packet_customer") != p.packetValue || cell("protocol") != "ipfix" || cell("exporter") != "127.0.0.1") {
		t.Fatal("real source report lost current rule tag, actual IPFIX or registered loopback exporter")
	}
}

func (p *releaseFlowReport) sendCapturedPackets(t *testing.T, destination string) func() {
	t.Helper()
	name := "probectl-qa-beta-e2e-softflowd-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	// Absorb measured CI scheduling bursts without dropping selected packets.
	// The traffic, exact independent counters and capture deadline stay fixed.
	runCmd(t, "", nil, "docker", "create", "--name", name, "--network", "host", "--cap-add", "NET_RAW",
		"--read-only", "--tmpfs", "/tmp:rw,nosuid,noexec", releasePacketImage,
		"softflowd", "-d", "-N", "-i", "lo", "-v", "10", "-B", "1048576", "-n", destination,
		"-c", "/tmp/softflowd.ctl", "icmp and dst host 127.0.0.1")
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	runCmd(t, "", nil, "docker", "start", name)
	waitFor(t, "owned real loopback packet exporter", 20*time.Second, func() bool {
		_, err := releasePacketControl(t, name, "statistics")
		return err == nil
	})
	ping := func(source, count, interval string) {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "docker", "exec", name, "ping", "-q", "-c", count, "-i", interval,
			"-s", strconv.Itoa(releasePacketPayload), "-I", source, "-W", "1", "127.0.0.1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("owned real packet burst failed: %v: %.1024s", err, output)
		}
	}
	// The selected flow contains exactly 4096 IPv4 requests, each with20-byte
	// IP header,8-byte ICMP header and1200 payload bytes. Replies are filtered.
	ping(p.address, strconv.Itoa(releasePacketCount), "0.001")
	// The existing exporter has zero pcap timeout. A distinct-source burst
	// flushes the final partial capture block without entering the selected
	// flow, whose byte/packet calculation must remain unchanged.
	ping("127.0.0.100", "256", "0.001")
	complete := false
	defer func() {
		if !complete {
			logReleasePacketStatistics(t, name)
		}
	}()
	waitFor(t, "actual selected packets in exporter capture", 10*time.Second, func() bool {
		output, err := releasePacketControl(t, name, "dump-flows")
		return err == nil && completeReleasePacketCapture(output, p.address)
	})
	complete = true
	logReleasePacketStatistics(t, name)
	runCmd(t, "", nil, "docker", "exec", name, "softflowctl", "-c", "/tmp/softflowd.ctl", "expire-all")
	return func() { _ = exec.Command("docker", "stop", "-t", "2", name).Run() }
}
