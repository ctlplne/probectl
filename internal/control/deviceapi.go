// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/topology"
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
	ID         string    `json:"id"`
	Device     string    `json:"device"`
	DeviceName string    `json:"device_name,omitempty"`
	AgentID    string    `json:"agent_id,omitempty"`
	Source     string    `json:"source,omitempty"`
	IfIndex    string    `json:"if_index,omitempty"`
	IfName     string    `json:"if_name,omitempty"`
	Name       string    `json:"name,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	LastSeen   time.Time `json:"last_seen"`
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
	if limit > deviceMaxLimit {
		limit = deviceMaxLimit
	}
	snap, ok := s.tsdbWriter.(promSnapshotter)
	if s.tsdbWriter == nil || !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":           []deviceMetricSummary{},
			"metrics_running": false,
			"effective_limit": limit,
		})
		return nil
	}
	items := latestDeviceMetricSummaries(snap.Snapshot(), tid,
		strings.TrimSpace(r.URL.Query().Get("device")),
		normalizeDeviceMetricFilter(r.URL.Query().Get("metric")),
		limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           items,
		"metrics_running": true,
		"effective_limit": limit,
	})
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
			ID:         deviceMetricKey(s),
			Device:     s.Labels["device"],
			DeviceName: s.Labels["device_name"],
			AgentID:    s.Labels["agent_id"],
			Source:     s.Labels["source"],
			IfIndex:    s.Labels["if_index"],
			IfName:     s.Labels["if_name"],
			Name:       s.Metric,
			Summary:    deviceMetricSummaryText(s.Labels),
			Metric:     s.Metric,
			Value:      s.Value,
			LastSeen:   time.UnixMilli(s.TimeMillis).UTC(),
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
	if labels["if_name"] != "" {
		parts = append(parts, labels["if_name"])
	} else if labels["if_index"] != "" {
		parts = append(parts, "ifIndex "+labels["if_index"])
	}
	return strings.Join(nonEmptyStrings(parts), " ")
}

func deviceMetricKey(s tsdb.Series) string {
	return strings.Join([]string{
		s.Labels["agent_id"],
		s.Labels["device"],
		s.Labels["if_index"],
		s.Labels["if_name"],
		s.Metric,
	}, "|")
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
