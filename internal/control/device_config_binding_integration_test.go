// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDeviceConfigArchiveBindsExactOwnedSourceAndIndependentVersionStream(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	ops := device.NewPostgresOpsStore(f.pool)
	f.server.WithDeviceOps(ops)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], "metrics.write")
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	type bindingResponse struct {
		Kind             string    `json:"kind"`
		ContextID        string    `json:"context_id"`
		DeviceEntityID   string    `json:"device_entity_id"`
		AgentID          string    `json:"agent_id"`
		SourceRef        string    `json:"source_ref"`
		SourceAssignedAt time.Time `json:"source_assigned_at"`
		AgentAssignedAt  time.Time `json:"agent_assigned_at"`
		BoundAt          time.Time `json:"bound_at"`
	}
	type configResponse struct {
		ID           string           `json:"id"`
		TenantID     string           `json:"tenant_id"`
		Version      int              `json:"version"`
		Content      string           `json:"content"`
		ContentHash  string           `json:"content_hash"`
		PreviousHash string           `json:"previous_hash"`
		Drifted      bool             `json:"drifted"`
		Binding      *bindingResponse `json:"binding"`
	}
	bound := func() map[string]string {
		return map[string]string{"context_id": f.contextID, "device_entity_id": f.routerID, "agent_id": "role-snmp", "source_ref": "192.0.2.1"}
	}
	archive := func(tenant, name, content string, binding map[string]string) (int, configResponse) {
		t.Helper()
		payload := map[string]any{"device": name, "content": content, "source": "operator-submitted"}
		if binding != nil {
			payload["binding"] = binding
		}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/device/configs", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		var value configResponse
		if response.StatusCode == http.StatusCreated {
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Log("archive public refusal", response.StatusCode, string(raw))
		}
		return response.StatusCode, value
	}
	for lane, tenant := range f.tenants {
		marker := []string{"tenant-a-config", "tenant-b-config"}[lane]
		if code, legacy := archive(tenant, "same-name", "hostname legacy", nil); code != http.StatusCreated || legacy.Binding != nil || legacy.Version != 1 {
			t.Fatal("legacy archive prerequisite changed", code)
		}
		code, first := archive(tenant, "same-name", "hostname "+marker, bound())
		if code != http.StatusCreated || first.Binding == nil {
			t.Fatal("archive cannot bind an explicit owned canonical device/source", code)
		}
		binding := first.Binding
		if first.TenantID != tenant || first.Version != 1 || first.PreviousHash != "" || first.Drifted || binding.Kind != "operator_bound_archive" || binding.ContextID != f.contextID || binding.DeviceEntityID != f.routerID || binding.AgentID != "role-snmp" || binding.SourceRef != "192.0.2.1" || binding.SourceAssignedAt.IsZero() || binding.AgentAssignedAt.IsZero() || binding.BoundAt.Before(binding.SourceAssignedAt) || binding.BoundAt.Before(binding.AgentAssignedAt) {
			t.Fatal("archive inherited a name-only predecessor or fabricated binding authority")
		}
		code, second := archive(tenant, "renamed-display", "hostname "+marker+"\ninterface Gi0/1\n no shutdown", bound())
		if code != http.StatusCreated || second.Version != 2 || !second.Drifted || second.PreviousHash != first.ContentHash || !strings.Contains(second.Content, marker) || strings.Contains(second.Content, []string{"tenant-b-config", "tenant-a-config"}[lane]) {
			t.Fatal("canonical archive version stream followed a display name or another tenant", code)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var foreign int
			err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_configs WHERE tenant_id=$1`, f.tenants[1-lane]).Scan(&foreign)
			if err == nil && foreign != 0 {
				t.Fatal("archive RLS exposes a sibling tenant")
			}
			return err
		})
	}
	a := f.tenants[0]
	for _, key := range []string{"context_id", "device_entity_id", "agent_id", "source_ref"} {
		input := bound()
		delete(input, key)
		if code, _ := archive(a, "partial", "hostname partial", input); code < 400 {
			t.Fatal("partial canonical archive binding succeeded", key, code)
		}
	}
	for key, value := range map[string]string{"context_id": pathHealthTestID(t), "device_entity_id": f.otherRouter, "source_ref": "198.51.100.99"} {
		input := bound()
		input[key] = value
		if code, _ := archive(a, "forged", "hostname forged", input); code < 400 {
			t.Fatal("unowned or mismatched source bound an archive", key, code)
		}
	}
	t.Log("real-integration: verified TLS archive, application-role PG/RLS, explicit canonical context/device/source assignment epochs and independent version streams; configs/source observations are modeled operator inputs, no device-collection attestation")
}
