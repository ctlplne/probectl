// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

const (
	deviceDefaultLimit = 100
	deviceMaxLimit     = 500
	deviceMetricPrefix = "probectl_device_"
)

type deviceInventoryItem struct {
	ID        string            `json:"id"`
	Address   string            `json:"address"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	FirstSeen time.Time         `json:"first_seen,omitempty"`
	LastSeen  time.Time         `json:"last_seen,omitempty"`
}

type deviceMetricSummary struct {
	ID              string    `json:"id"`
	Device          string    `json:"device"`
	DeviceName      string    `json:"device_name,omitempty"`
	AgentID         string    `json:"agent_id,omitempty"`
	Source          string    `json:"source,omitempty"`
	IfIndex         string    `json:"if_index,omitempty"`
	IfName          string    `json:"if_name,omitempty"`
	Component       string    `json:"component,omitempty"`
	PhysicalChannel string    `json:"physical_channel,omitempty"`
	Name            string    `json:"name,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	Metric          string    `json:"metric"`
	Value           float64   `json:"value"`
	LastSeen        time.Time `json:"last_seen"`
}

type deviceNeighborRetention struct {
	MaxPerDevice        int `json:"max_per_device"`
	MaxPerTenant        int `json:"max_per_tenant"`
	StaleRetentionHours int `json:"stale_retention_hours"`
}

type deviceNeighborResponse struct {
	ContractVersion   string                    `json:"contract_version"`
	Items             []device.NeighborEvidence `json:"items"`
	CollectionRunning bool                      `json:"collection_running"`
	EffectiveLimit    int                       `json:"effective_limit"`
	Truncated         bool                      `json:"truncated"`
	AsOf              time.Time                 `json:"as_of"`
	LatestAt          *time.Time                `json:"latest_at,omitempty"`
	Retention         deviceNeighborRetention   `json:"retention"`
}

type deviceCollectionOutcomeRetention struct {
	MaxPerTenant  int `json:"max_per_tenant"`
	RetentionDays int `json:"retention_days"`
}

type deviceCollectionOutcomeResponse struct {
	ContractVersion   string                           `json:"contract_version"`
	Items             []device.CollectionOutcome       `json:"items"`
	CollectionRunning bool                             `json:"collection_running"`
	EffectiveLimit    int                              `json:"effective_limit"`
	Truncated         bool                             `json:"truncated"`
	AsOf              time.Time                        `json:"as_of"`
	Retention         deviceCollectionOutcomeRetention `json:"retention"`
}

type deviceSyslogRequest struct {
	Device        string            `json:"device"`
	SourceAddress string            `json:"source_address,omitempty"`
	Message       string            `json:"message,omitempty"`
	Raw           string            `json:"raw,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	ObservedAt    time.Time         `json:"observed_at,omitempty"`
}

type deviceConfigArchiveRequest struct {
	Device     string                      `json:"device"`
	Source     string                      `json:"source,omitempty"`
	Content    string                      `json:"content"`
	ObservedAt time.Time                   `json:"observed_at,omitempty"`
	Binding    *deviceConfigBindingRequest `json:"binding,omitempty"`
}

type deviceConfigBindingRequest struct {
	ContextID      string `json:"context_id"`
	DeviceEntityID string `json:"device_entity_id"`
	AgentID        string `json:"agent_id"`
	SourceRef      string `json:"source_ref"`
}

// handleListDevices serves GET /v1/devices — topology-visible managed network
// devices for the caller's tenant. Device telemetry feeds the topology graph,
// so this is the inventory read model that already has tenant scoping.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	if limit > deviceMaxLimit {
		limit = deviceMaxLimit
	}
	if s.topo == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":            []deviceInventoryItem{},
			"topology_running": false,
			"effective_limit":  limit,
		})
		return nil
	}
	graph, err := s.topo.ForTenant(tid)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":            []deviceInventoryItem{},
			"topology_running": false,
			"effective_limit":  limit,
		})
		return nil
	}
	snap := graph.Latest()
	items := devicesFromSnapshot(snap)
	if len(items) > limit {
		items = items[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":            items,
		"topology_running": true,
		"at":               snap.At.UTC(),
		"effective_limit":  limit,
	})
	return nil
}

func (s *Server) handleIngestDeviceSyslog(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var req deviceSyslogRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	raw := strings.TrimSpace(req.Raw)
	if raw == "" {
		raw = strings.TrimSpace(req.Message)
	}
	if raw == "" {
		return apierror.BadRequest("device syslog message is required")
	}
	ev := device.ParseSyslogLine(raw, req.Device, req.ObservedAt)
	ev.TenantID = tid
	ev.SourceAddress = strings.TrimSpace(req.SourceAddress)
	ev.Labels = copyStringMap(req.Labels)
	if strings.TrimSpace(req.Message) != "" && req.Raw == "" {
		ev.Raw = req.Message
	}
	row, err := s.deviceOps.RecordSyslog(r.Context(), ev)
	if err != nil {
		return apierror.BadRequest(err.Error())
	}
	// AUD-08 (docs/guardrails.md G7): this mutation is declared explicit-mode in
	// the audit-policy matrix, so the handler — not the route wrapper — must
	// append the declared tenant-chain event once the ingest has persisted. A
	// pool-less lightweight server has no audit chain to write, so it skips the
	// append (matching the explicit-mode pattern in handleOncallTest).
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "device.syslog_ingest", row.Device,
				map[string]any{"syslog_id": row.ID, "severity": row.Severity})
		}); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusCreated, row)
	return nil
}

func (s *Server) handleListDeviceSyslog(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	if limit > deviceMaxLimit {
		limit = deviceMaxLimit
	}
	rows, err := s.deviceOps.ListSyslog(r.Context(), tid, device.OpsFilter{
		Device: strings.TrimSpace(r.URL.Query().Get("device")),
		Limit:  limit,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           rows,
		"syslog_running":  true,
		"effective_limit": limit,
	})
	return nil
}

func (s *Server) handleArchiveDeviceConfig(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var req deviceConfigArchiveRequest
	if err := decodeJSONLimit(r, 2<<20, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Device) == "" || strings.TrimSpace(req.Content) == "" {
		return apierror.BadRequest("device and content are required")
	}
	var binding *device.ConfigArchiveBinding
	if req.Binding != nil {
		ctx, err := bindFlowRoleContext(r.Context(), auth.PrincipalFrom(r.Context()))
		if err != nil {
			return err
		}
		r = r.WithContext(ctx)
		binding = &device.ConfigArchiveBinding{ContextID: req.Binding.ContextID, DeviceEntityID: req.Binding.DeviceEntityID, AgentID: req.Binding.AgentID, SourceRef: req.Binding.SourceRef}
		if err := s.authorizeConfigArchiveBinding(r, binding, permMetricsWrite); err != nil {
			return err
		}
	}
	row, err := s.deviceOps.ArchiveConfig(r.Context(), device.ConfigVersion{
		TenantID:   tid,
		Device:     req.Device,
		Source:     strings.TrimSpace(req.Source),
		Content:    req.Content,
		ObservedAt: req.ObservedAt,
		Binding:    binding,
	})
	if err != nil {
		if errors.Is(err, device.ErrConfigBinding) {
			return apierror.Validation("a complete current owned archive binding and observation time are required")
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return apierror.NotFound("the owned canonical device/source assignment is unavailable")
		}
		return apierror.Unavailable("device configuration archive is temporarily unavailable")
	}
	// AUD-08 (docs/guardrails.md G7): config archive is declared explicit-mode in
	// the audit-policy matrix, so the handler appends the declared tenant-chain
	// event after the snapshot is stored. Pool-less lightweight servers have no
	// audit chain and skip the append (see handleOncallTest for the pattern).
	if s.pool != nil {
		if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
			return s.recordAudit(ctx, sc, r, "device.config_archive", row.Device,
				map[string]any{"config_id": row.ID, "version": row.Version, "drifted": row.Drifted})
		}); err != nil {
			return err
		}
	}
	if binding != nil {
		if err := s.authorizeConfigArchiveBinding(r, row.Binding, permMetricsWrite); err != nil {
			return err
		}
	}
	writeJSON(w, http.StatusCreated, row)
	return nil
}

func (s *Server) handleListDeviceConfigs(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	if limit > deviceMaxLimit {
		limit = deviceMaxLimit
	}
	ids := r.URL.Query()["id"]
	unique := map[string]bool{}
	for _, id := range ids {
		if id == "" || len(id) > 128 {
			return apierror.BadRequest("invalid original configuration ID")
		}
		unique[id] = true
	}
	if len(unique) > limit {
		return apierror.TooLarge("exact configuration selection exceeds the admitted page")
	}
	rows, err := s.deviceOps.ListConfigs(r.Context(), tid, device.OpsFilter{
		Device:    strings.TrimSpace(r.URL.Query().Get("device")),
		Limit:     limit,
		ConfigIDs: ids,
	})
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		if len(rows) != len(unique) {
			return apierror.NotFound("original configuration selection is unavailable")
		}
		for _, row := range rows {
			if !unique[row.ID] || row.Content == "" {
				return apierror.NotFound("original configuration selection is unavailable")
			}
		}
	}
	boundRows := false
	for _, row := range rows {
		if row.Binding != nil {
			boundRows = true
		}
	}
	response := map[string]any{"items": rows, "archive_running": true, "effective_limit": limit, "redaction_policy": "common network secrets are redacted before storage"}
	if boundRows {
		body, err := json.Marshal(response)
		if err != nil {
			return apierror.Unavailable("complete configuration archive is unavailable")
		}
		current, err := s.deviceOps.ListConfigs(r.Context(), tid, device.OpsFilter{Device: strings.TrimSpace(r.URL.Query().Get("device")), Limit: limit, ConfigIDs: ids})
		if err != nil {
			return apierror.Unavailable("current configuration archive is unavailable")
		}
		before, err := json.Marshal(rows)
		if err != nil {
			return apierror.Unavailable("complete configuration archive is unavailable")
		}
		after, err := json.Marshal(current)
		if err != nil || !bytes.Equal(before, after) {
			return apierror.Unavailable("configuration archive changed during read; retry")
		}
		for _, row := range rows {
			if row.Binding != nil {
				if err := s.authorizeConfigArchiveBinding(r, row.Binding, ai.PermMetricsRead); err != nil {
					return err
				}
			}
		}
		writeJSON(w, http.StatusOK, json.RawMessage(body))
		return nil
	}
	writeJSON(w, http.StatusOK, response)
	return nil
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func devicesFromSnapshot(snap topology.Snapshot) []deviceInventoryItem {
	items := []deviceInventoryItem{}
	for _, n := range snap.Nodes {
		if n.Kind != topology.NodeDevice {
			continue
		}
		address := n.Attributes["probectl.device.address"]
		if address == "" {
			address = strings.TrimPrefix(n.ID, "device:")
		}
		item := deviceInventoryItem{
			ID:        n.ID,
			Address:   address,
			Name:      n.Label,
			FirstSeen: n.FirstSeen.UTC(),
			LastSeen:  n.LastSeen.UTC(),
		}
		if len(n.Attributes) > 0 {
			item.Labels = map[string]string{}
			for k, v := range n.Attributes {
				item.Labels[k] = v
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].LastSeen.After(items[j].LastSeen)
		}
		return items[i].ID < items[j].ID
	})
	return items
}

// handleDeviceMetrics serves GET /v1/device/metrics — latest device metric
// summaries, newest first. It is bounded and tenant-forced; caller-supplied
// tenant labels are ignored by construction.
func (s *Server) handleDeviceMetrics(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if budget.Validate() != nil {
		return apierror.Unavailable("device metric query admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
	defer cancel()
	if s.fairnessGate != nil {
		release, err := s.fairnessGate.BeginQuery(ctx, tid)
		if err != nil {
			return tagQueryAdmissionError(err)
		}
		defer release()
	}
	r = r.WithContext(ctx)
	deviceFilter := strings.TrimSpace(r.URL.Query().Get("device"))
	metricFilter := normalizeDeviceMetricFilter(r.URL.Query().Get("metric"))
	var series []tsdb.Series
	source := ""
	snap, ok := s.tsdbWriter.(promSnapshotter)
	if s.tsdbWriter == nil || !ok {
		// DPR-050: the production TSDB (Prometheus remote write) keeps no local
		// snapshot; ask it for the tenant's latest device samples instead of
		// answering "not running" while the metrics sit in the TSDB.
		if q, qok := s.tsdbWriter.(deviceMetricQuerier); qok && s.tsdbWriter != nil {
			series, err = deviceMetricSeriesFromTSDB(r.Context(), q, tid, deviceFilter, metricFilter)
			if err != nil {
				return err
			}
			source = "tsdb"
		} else {
			writeJSON(w, http.StatusOK, map[string]any{
				"items":           []deviceMetricSummary{},
				"metrics_running": false,
				"effective_limit": limit,
			})
			return nil
		}
	} else {
		series = snap.Snapshot()
	}
	remaining := budget.MemoryBytes / 4
	for _, sample := range series {
		if err := ctx.Err(); err != nil {
			return err
		}
		if sample.Labels["tenant_id"] != tid || !strings.HasPrefix(sample.Metric, deviceMetricPrefix) || deviceFilter != "" && sample.Labels["device"] != deviceFilter || metricFilter != "" && sample.Metric != metricFilter {
			continue
		}
		charge := int64(4096 + len(sample.Metric)*16)
		for key, value := range sample.Labels {
			charge += int64(len(key)+len(value)) * 16
		}
		if charge > remaining {
			return apierror.TooLarge("complete device metric population exceeds configured query memory")
		}
		remaining -= charge
	}
	items := latestDeviceMetricSummaries(series, tid, deviceFilter, metricFilter, limit)
	response := map[string]any{
		"items":           items,
		"metrics_running": true,
		"effective_limit": limit,
	}
	if source != "" {
		response["source"] = source
	}
	body, err := json.Marshal(response)
	if err != nil {
		return apierror.Unavailable("complete device metric output is unavailable")
	}
	if int64(len(body)) > budget.ResponseBytes || int64(len(body)) > budget.MemoryBytes/4 {
		return apierror.TooLarge("complete device metric output exceeds configured response admission")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}

// handleDeviceNeighbors serves the bounded, directly observed LLDP/CDP
// physical adjacency snapshot. Tenant scope is resolved before the store read;
// the Postgres implementation repeats tenant_id under forced RLS.
func (s *Server) handleDeviceNeighbors(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	if limit > device.MaxNeighborRead {
		limit = device.MaxNeighborRead
	}
	protocol := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("protocol")))
	if protocol != "" && protocol != device.NeighborProtocolLLDP && protocol != device.NeighborProtocolCDP {
		return apierror.BadRequest("protocol must be lldp or cdp")
	}
	now := time.Now().UTC()
	resp := deviceNeighborResponse{
		ContractVersion: "probectl.device-neighbors/v1",
		Items:           []device.NeighborEvidence{}, CollectionRunning: s.deviceNeighbors != nil,
		EffectiveLimit: limit, AsOf: now,
		Retention: deviceNeighborRetention{
			MaxPerDevice:        device.MaxNeighborsPerDevice,
			MaxPerTenant:        device.MaxNeighborsPerTenant,
			StaleRetentionHours: int(device.NeighborStaleRetention / time.Hour),
		},
	}
	if s.deviceNeighbors == nil {
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	rows, truncated, err := s.deviceNeighbors.ListNeighbors(r.Context(), tid, device.NeighborFilter{
		Device:   strings.TrimSpace(r.URL.Query().Get("device")),
		Protocol: protocol, Limit: limit,
	})
	if err != nil {
		return err
	}
	for i := range rows {
		if rows[i].ID == "" {
			rows[i].ID = rows[i].EvidenceID()
		}
		switch {
		case rows[i].ObservedAt.After(now.Add(time.Minute)):
			rows[i].Freshness = "future"
			rows[i].AgeSeconds = 0
		case now.After(rows[i].FreshUntil):
			rows[i].Freshness = "stale"
			rows[i].AgeSeconds = max(0, int64(now.Sub(rows[i].ObservedAt).Seconds()))
		default:
			rows[i].Freshness = "current"
			rows[i].AgeSeconds = max(0, int64(now.Sub(rows[i].ObservedAt).Seconds()))
		}
		if resp.LatestAt == nil || rows[i].ObservedAt.After(*resp.LatestAt) {
			at := rows[i].ObservedAt
			resp.LatestAt = &at
		}
	}
	resp.Items, resp.Truncated = rows, truncated
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// handleDeviceCollectionOutcomes serves one bounded current receipt per
// explicitly configured target/protocol. It never includes credentials, raw
// SNMP values, discovered-neighbor identities, or free-form error strings.
func (s *Server) handleDeviceCollectionOutcomes(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", deviceDefaultLimit)
	if err != nil {
		return err
	}
	if limit > device.MaxCollectionOutcomeRead {
		limit = device.MaxCollectionOutcomeRead
	}
	state := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if state != "" && !device.ValidCollectionState(state) {
		return apierror.BadRequest("state must be ok_with_rows, healthy_empty, unsupported, failed, or never_observed")
	}
	resp := deviceCollectionOutcomeResponse{
		ContractVersion: "probectl.device-collection-outcomes/v1",
		Items:           []device.CollectionOutcome{}, CollectionRunning: s.deviceOutcomes != nil,
		EffectiveLimit: limit, AsOf: time.Now().UTC(),
		Retention: deviceCollectionOutcomeRetention{
			MaxPerTenant:  device.MaxCollectionOutcomesPerTenant,
			RetentionDays: int(device.CollectionOutcomeRetention / (24 * time.Hour)),
		},
	}
	if s.deviceOutcomes == nil {
		writeJSON(w, http.StatusOK, resp)
		return nil
	}
	rows, truncated, err := s.deviceOutcomes.ListCollectionOutcomes(r.Context(), tid, device.CollectionOutcomeFilter{
		AgentID: strings.TrimSpace(r.URL.Query().Get("agent_id")),
		Target:  strings.TrimSpace(r.URL.Query().Get("target")),
		State:   state,
		Limit:   limit,
	})
	if err != nil {
		return err
	}
	resp.Items, resp.Truncated = rows, truncated
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func latestDeviceMetricSummaries(series []tsdb.Series, tenant, deviceFilter, metricFilter string, limit int) []deviceMetricSummary {
	latest := map[string]deviceMetricSummary{}
	for _, s := range series {
		if !strings.HasPrefix(s.Metric, deviceMetricPrefix) || s.Labels["tenant_id"] != tenant {
			continue
		}
		if metricFilter != "" && s.Metric != metricFilter {
			continue
		}
		if deviceFilter != "" && s.Labels["device"] != deviceFilter {
			continue
		}
		item := deviceMetricSummary{
			ID:              deviceMetricKey(s),
			Device:          s.Labels["device"],
			DeviceName:      s.Labels["device_name"],
			AgentID:         s.Labels["agent_id"],
			Source:          s.Labels["source"],
			IfIndex:         s.Labels["if_index"],
			IfName:          s.Labels["if_name"],
			Component:       s.Labels["component"],
			PhysicalChannel: s.Labels["physical_channel"],
			Name:            s.Metric,
			Summary:         deviceMetricSummaryText(s.Labels),
			Metric:          s.Metric,
			Value:           s.Value,
			LastSeen:        time.UnixMilli(s.TimeMillis).UTC(),
		}
		if item.Device == "" {
			continue
		}
		if prev, ok := latest[item.ID]; !ok || item.LastSeen.After(prev.LastSeen) {
			latest[item.ID] = item
		}
	}
	out := make([]deviceMetricSummary, 0, len(latest))
	for _, item := range latest {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func deviceMetricSummaryText(labels map[string]string) string {
	parts := []string{labels["device"]}
	if labels["component"] != "" {
		parts = append(parts, "component "+labels["component"])
		if labels["physical_channel"] != "" {
			parts = append(parts, "channel "+labels["physical_channel"])
		}
	}
	if labels["if_name"] != "" {
		parts = append(parts, labels["if_name"])
	} else if labels["if_index"] != "" {
		parts = append(parts, "ifIndex "+labels["if_index"])
	}
	return strings.Join(nonEmptyStrings(parts), " ")
}

func deviceMetricKey(s tsdb.Series) string {
	key := strings.Join([]string{
		s.Labels["agent_id"],
		s.Labels["device"],
		s.Labels["if_index"],
		s.Labels["if_name"],
		s.Metric,
	}, "|")
	if s.Labels["component"] != "" || s.Labels["physical_channel"] != "" {
		// Preserve legacy IDs; unambiguous structured keys distinguish a
		// component aggregate from channel0 and from punctuation in names.
		encoded, _ := json.Marshal([]string{s.Labels["source"], s.Labels["component"], s.Labels["physical_channel"]})
		key += "|component:" + string(encoded)
	}
	return key
}

func nonEmptyStrings(in []string) []string {
	out := in[:0]
	for _, v := range in {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func normalizeDeviceMetricFilter(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "probectl.device.") {
		raw = strings.TrimPrefix(raw, "probectl.device.")
		return deviceMetricPrefix + sanitizePromName(raw)
	}
	if strings.HasPrefix(raw, deviceMetricPrefix) {
		return sanitizePromName(raw)
	}
	return deviceMetricPrefix + sanitizePromName(raw)
}

func sanitizePromName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

// deviceMetricQuerier is what the Prometheus-backed writer offers for reading
// the tenant's device metrics back (DPR-050).
type deviceMetricQuerier interface {
	InstantVector(ctx context.Context, promql string) ([]tsdb.LabeledSample, error)
}

// deviceMetricSeriesFromTSDB fetches the latest sample of every device metric
// of one tenant from the backing TSDB as an instant vector, scoped by tenant
// in the selector itself (never filtered client-side only), and shapes it
// like a memory snapshot so the summary logic is shared.
func deviceMetricSeriesFromTSDB(ctx context.Context, q deviceMetricQuerier, tenantID, deviceFilter, metricFilter string) ([]tsdb.Series, error) {
	for _, v := range []string{tenantID, deviceFilter, metricFilter} {
		if strings.ContainsAny(v, "\"\\\n") {
			return nil, apierror.BadRequest("device metrics filter contains characters that cannot appear in a label value")
		}
	}
	var sel strings.Builder
	sel.WriteString("{")
	if metricFilter != "" {
		sel.WriteString(`__name__="` + metricFilter + `",`)
	} else {
		sel.WriteString(`__name__=~"` + deviceMetricPrefix + `.+",`)
	}
	sel.WriteString(`tenant_id="` + tenantID + `"`)
	if deviceFilter != "" {
		sel.WriteString(`,device="` + deviceFilter + `"`)
	}
	sel.WriteString("}")
	samples, err := q.InstantVector(ctx, sel.String())
	if err != nil {
		return nil, apierror.Unavailable("device metrics are temporarily unavailable from the TSDB").Wrap(err)
	}
	now := time.Now().UnixMilli()
	out := make([]tsdb.Series, 0, len(samples))
	for _, sm := range samples {
		labels := make(map[string]string, len(sm.Labels))
		for k, v := range sm.Labels {
			if k != "__name__" {
				labels[k] = v
			}
		}
		out = append(out, tsdb.Series{Metric: sm.Labels["__name__"], Labels: labels, Value: sm.Value, TimeMillis: now})
	}
	return out, nil
}
