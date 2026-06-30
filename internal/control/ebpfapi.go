// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

const (
	ebpfDefaultLimit = 100
	ebpfMaxLimit     = 1000
)

type ebpfServiceEdgeItem struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id,omitempty"`
	Source          string     `json:"source"`
	Destination     string     `json:"destination"`
	DestinationPort uint16     `json:"destination_port,omitempty"`
	L7Protocol      string     `json:"l7_protocol,omitempty"`
	Bytes           uint64     `json:"bytes,omitempty"`
	Packets         uint64     `json:"packets,omitempty"`
	Connections     uint64     `json:"connections,omitempty"`
	WindowStart     *time.Time `json:"window_start,omitempty"`
	Name            string     `json:"name,omitempty"`
	Summary         string     `json:"summary,omitempty"`
}

// WithEBPFStore attaches the durable eBPF aggregate store backing
// GET /v1/ebpf/service-map. nil is a no-op.
func (s *Server) WithEBPFStore(st ebpfstore.Store) *Server {
	if st != nil {
		s.ebpfStore = st
	}
	return s
}

// handleEBPFServiceMap serves GET /v1/ebpf/service-map — the tenant's eBPF
// service-edge/L7 rollup. Durable aggregates win; topology is a best-effort
// fallback for deployments/tests where only the live graph is wired.
func (s *Server) handleEBPFServiceMap(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", ebpfDefaultLimit)
	if err != nil {
		return err
	}
	if limit > ebpfMaxLimit {
		limit = ebpfMaxLimit
	}
	since, until, err := timeRange(r)
	if err != nil {
		return apierror.Validation(err.Error())
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		source = strings.TrimSpace(r.URL.Query().Get("src"))
	}

	if s.ebpfStore != nil {
		edges, err := s.ebpfStore.TopEdges(r.Context(), tid, ebpfstore.EdgeQuery{
			Since: since, Until: until, SrcLike: source, Limit: limit,
		})
		if err != nil {
			s.log.Warn("ebpf service-map query failed", "error", err)
			return apierror.Unavailable("ebpf service-map store unavailable")
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items":           serviceEdgesFromStore(edges),
			"ebpf_running":    true,
			"source":          "store",
			"effective_limit": limit,
		})
		return nil
	}
	if s.topo == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":           []ebpfServiceEdgeItem{},
			"ebpf_running":    false,
			"source":          "none",
			"effective_limit": limit,
		})
		return nil
	}
	graph, err := s.topo.ForTenant(tid)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items":           []ebpfServiceEdgeItem{},
			"ebpf_running":    false,
			"source":          "none",
			"effective_limit": limit,
		})
		return nil
	}
	items := serviceEdgesFromTopology(graph.Latest(), source, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           items,
		"ebpf_running":    len(items) > 0,
		"source":          "topology",
		"effective_limit": limit,
	})
	return nil
}

func serviceEdgesFromStore(edges []ebpfstore.Edge) []ebpfServiceEdgeItem {
	items := make([]ebpfServiceEdgeItem, 0, len(edges))
	for _, e := range edges {
		item := ebpfServiceEdgeItem{
			ID:              serviceEdgeID(e.SrcWorkload, e.DstWorkload, e.DstPort, e.L7Protocol),
			AgentID:         e.AgentID,
			Source:          e.SrcWorkload,
			Destination:     e.DstWorkload,
			DestinationPort: e.DstPort,
			L7Protocol:      e.L7Protocol,
			Bytes:           e.Bytes,
			Packets:         e.Packets,
			Connections:     e.Connections,
			Name:            serviceEdgeName(e.SrcWorkload, e.DstWorkload),
			Summary:         serviceEdgeSummary(e.DstPort, e.L7Protocol),
		}
		if !e.WindowStart.IsZero() {
			t := e.WindowStart.UTC()
			item.WindowStart = &t
		}
		items = append(items, item)
	}
	return items
}

func serviceEdgesFromTopology(snap topology.Snapshot, source string, limit int) []ebpfServiceEdgeItem {
	items := []ebpfServiceEdgeItem{}
	for _, e := range snap.Edges {
		if e.Kind != topology.EdgeFlow {
			continue
		}
		src := strings.TrimPrefix(e.From, "service:")
		dst := strings.TrimPrefix(e.To, "service:")
		if source != "" && src != source {
			continue
		}
		protocol := e.Label
		port := uint16(0)
		if raw := e.Attributes["destination.port"]; raw != "" {
			var n uint64
			for _, r := range raw {
				if r < '0' || r > '9' {
					n = 0
					break
				}
				n = n*10 + uint64(r-'0')
			}
			if n <= 65535 {
				port = uint16(n)
			}
		}
		items = append(items, ebpfServiceEdgeItem{
			ID:              serviceEdgeID(src, dst, port, protocol),
			Source:          src,
			Destination:     dst,
			DestinationPort: port,
			L7Protocol:      protocol,
			Name:            serviceEdgeName(src, dst),
			Summary:         serviceEdgeSummary(port, protocol),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func serviceEdgeID(src, dst string, port uint16, proto string) string {
	parts := []string{src, dst}
	if port != 0 {
		parts = append(parts, "port "+strconv.FormatUint(uint64(port), 10))
	}
	if proto != "" {
		parts = append(parts, proto)
	}
	return strings.Join(parts, "|")
}

func serviceEdgeName(src, dst string) string {
	return strings.TrimSpace(src + " -> " + dst)
}

func serviceEdgeSummary(port uint16, proto string) string {
	parts := []string{}
	if proto != "" {
		parts = append(parts, proto)
	}
	if port != 0 {
		parts = append(parts, "port "+strconv.FormatUint(uint64(port), 10))
	}
	return strings.Join(parts, " ")
}
