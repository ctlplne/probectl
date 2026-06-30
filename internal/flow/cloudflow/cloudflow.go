// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package cloudflow imports cloud-provider flow logs into probectl's normalized
// flow store. It intentionally does not fetch from AWS, Azure, or GCP APIs:
// operators feed local files/objects that their own cloud export pipeline
// produced, preserving the no-phone-home guardrail.
package cloudflow

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
)

type Provider string

const (
	ProviderAWSVPC   Provider = "aws_vpc_flow_logs"
	ProviderAzureNSG Provider = "azure_nsg_flow_logs"
	ProviderGCPVPC   Provider = "gcp_vpc_flow_logs"
)

var (
	ErrNoTenant        = errors.New("cloudflow: tenant_id is required")
	ErrNoStore         = errors.New("cloudflow: flow store is required")
	ErrUnknownProvider = errors.New("cloudflow: unknown provider")
)

// Connector loads already-exported cloud flow-log lines into the tenant-scoped
// flow store. Authentication and object access happen before this layer; this
// layer refuses to trust tenant identity from the payload itself.
type Connector struct {
	store   flowstore.Store
	agentID string
	now     func() time.Time
}

// NewConnector builds a local cloud-flow importer. agentID is stamped as the
// collecting agent; when empty, a stable importer id is used.
func NewConnector(store flowstore.Store, agentID string) *Connector {
	if agentID == "" {
		agentID = "cloud-flow-importer"
	}
	return &Connector{store: store, agentID: agentID, now: time.Now}
}

// Load reads newline-delimited provider records, normalizes them, and inserts
// them into the store. Blank lines and '#' comments are ignored.
func (c *Connector) Load(ctx context.Context, provider Provider, tenantID string, r io.Reader) (int, error) {
	if c == nil || c.store == nil {
		return 0, ErrNoStore
	}
	return scan(ctx, provider, tenantID, c.agentID, r, c.now, func(ctx context.Context, recs []flow.Record) error {
		rows := make([]flowstore.Row, 0, len(recs))
		for i := range recs {
			rows = append(rows, rowFromRecord(recs[i]))
		}
		return c.store.Insert(ctx, rows)
	})
}

// Emit reads cloud flow-log lines and publishes them through the normal flow
// emitter path (`probectl.flow.events` in production). It is the flow-agent
// import mode used for local/exported cloud logs.
func Emit(ctx context.Context, provider Provider, tenantID, agentID string, r io.Reader, emit flow.Emitter) (int, error) {
	if emit == nil {
		return 0, errors.New("cloudflow: emitter is required")
	}
	if agentID == "" {
		agentID = "cloud-flow-importer"
	}
	return scan(ctx, provider, tenantID, agentID, r, time.Now, emit.Emit)
}

type recordSink func(context.Context, []flow.Record) error

func scan(ctx context.Context, provider Provider, tenantID, agentID string, r io.Reader, now func() time.Time, sink recordSink) (int, error) {
	if tenantID == "" {
		return 0, ErrNoTenant
	}
	if !validProvider(provider) {
		return 0, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
	if now == nil {
		now = time.Now
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	inserted := 0
	pending := make([]flow.Record, 0, 256)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := sink(ctx, pending); err != nil {
			return err
		}
		inserted += len(pending)
		pending = pending[:0]
		return nil
	}

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		recs, err := decodeLine(provider, tenantID, agentID, line, now().UTC())
		if err != nil {
			return inserted, fmt.Errorf("cloudflow: %s line %d: %w", provider, lineNo, err)
		}
		pending = append(pending, recs...)
		if len(pending) >= 1000 {
			if err := flush(); err != nil {
				return inserted, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return inserted, fmt.Errorf("cloudflow: read %s: %w", provider, err)
	}
	if err := flush(); err != nil {
		return inserted, err
	}
	return inserted, nil
}

func validProvider(p Provider) bool {
	switch p {
	case ProviderAWSVPC, ProviderAzureNSG, ProviderGCPVPC:
		return true
	default:
		return false
	}
}

func decodeLine(provider Provider, tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	switch provider {
	case ProviderAWSVPC:
		return parseAWSVPCLine(tenantID, agentID, line, now)
	case ProviderAzureNSG:
		return parseAzureNSGLine(tenantID, agentID, line, now)
	case ProviderGCPVPC:
		return parseGCPVPCLine(tenantID, agentID, line, now)
	default:
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, provider)
	}
}

func rowFromRecord(r flow.Record) flowstore.Row {
	p := r.ToProto()
	ts := time.Unix(0, p.GetEndUnixNano()).UTC()
	if p.GetEndUnixNano() == 0 {
		ts = time.Unix(0, p.GetObservedAtUnixNano()).UTC()
	}
	startTS := ts
	if p.GetStartUnixNano() != 0 {
		startTS = time.Unix(0, p.GetStartUnixNano()).UTC()
	}
	if startTS.After(ts) {
		startTS = ts
	}
	return flowstore.Row{
		TenantID:      p.GetTenantId(),
		AgentID:       p.GetAgentId(),
		Exporter:      p.GetExporterAddress(),
		ObsDomain:     p.GetObservationDomain(),
		Protocol:      p.GetFlowProtocol(),
		TS:            ts,
		StartTS:       startTS,
		SrcAddr:       p.GetSourceAddress(),
		DstAddr:       p.GetDestinationAddress(),
		SrcPort:       uint16(p.GetSourcePort()),
		DstPort:       uint16(p.GetDestinationPort()),
		Transport:     p.GetNetworkTransport(),
		NetType:       p.GetNetworkType(),
		InIf:          p.GetInputInterface(),
		OutIf:         p.GetOutputInterface(),
		VLAN:          uint16(p.GetVlan()),
		ToS:           uint8(p.GetTos()),
		TCPFlags:      uint8(p.GetTcpFlags()),
		NextHop:       p.GetNextHop(),
		Bytes:         p.GetBytes(),
		Packets:       p.GetPackets(),
		Sampling:      p.GetSamplingRate(),
		BytesScaled:   p.GetBytesScaled(),
		PacketsScaled: p.GetPacketsScaled(),
		SrcASN:        p.GetSourceAsn(),
		SrcASName:     p.GetSourceAsName(),
		SrcCountry:    p.GetSourceCountry(),
		DstASN:        p.GetDestinationAsn(),
		DstASName:     p.GetDestinationAsName(),
		DstCountry:    p.GetDestinationCountry(),
	}
}

func parseAWSVPCLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	fields := strings.Fields(line)
	if len(fields) < 14 {
		return nil, fmt.Errorf("aws vpc flow log needs at least 14 default fields, got %d", len(fields))
	}
	if fields[13] != "OK" {
		return nil, nil
	}
	src, err := parseAddr(fields[3])
	if err != nil {
		return nil, err
	}
	dst, err := parseAddr(fields[4])
	if err != nil {
		return nil, err
	}
	srcPort, err := parsePort(fields[5])
	if err != nil {
		return nil, err
	}
	dstPort, err := parsePort(fields[6])
	if err != nil {
		return nil, err
	}
	proto, err := parseProtocol(fields[7])
	if err != nil {
		return nil, err
	}
	packets, err := parseUint(fields[8])
	if err != nil {
		return nil, err
	}
	bytes, err := parseUint(fields[9])
	if err != nil {
		return nil, err
	}
	start, err := parseUnixSeconds(fields[10])
	if err != nil {
		return nil, err
	}
	end, err := parseUnixSeconds(fields[11])
	if err != nil {
		return nil, err
	}
	if end.Before(start) {
		start = end
	}
	return []flow.Record{{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     "aws:" + fields[2],
		Protocol:     flow.ProtoAWSVPCFlowLogs,
		ObservedAt:   now,
		Start:        start,
		End:          end,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}}, nil
}

type azureEnvelope struct {
	Records []azureRecord `json:"records"`
}

type azureRecord struct {
	Time       string          `json:"time"`
	ResourceID string          `json:"resourceId"`
	Properties azureProperties `json:"properties"`
}

type azureProperties struct {
	Version int             `json:"Version"`
	Flows   []azureRuleFlow `json:"flows"`
}

type azureRuleFlow struct {
	Rule  string         `json:"rule"`
	Flows []azureMACFlow `json:"flows"`
}

type azureMACFlow struct {
	MAC        string   `json:"mac"`
	FlowTuples []string `json:"flowTuples"`
}

func parseAzureNSGLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	var env azureEnvelope
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		return nil, err
	}
	if len(env.Records) == 0 {
		var single azureRecord
		if err := json.Unmarshal([]byte(line), &single); err != nil {
			return nil, err
		}
		if single.Properties.Version == 0 && len(single.Properties.Flows) == 0 {
			return nil, errors.New("azure nsg payload contains no records")
		}
		env.Records = []azureRecord{single}
	}

	var out []flow.Record
	for _, rec := range env.Records {
		observed := now
		if t, err := parseRFC3339(rec.Time); err == nil {
			observed = t
		}
		for _, rule := range rec.Properties.Flows {
			_ = rule.Rule
			for _, macFlow := range rule.Flows {
				exporter := "azure:" + rec.ResourceID
				if mac := strings.TrimSpace(macFlow.MAC); mac != "" {
					exporter += ":" + strings.ToLower(mac)
				}
				for _, tuple := range macFlow.FlowTuples {
					record, err := parseAzureTuple(tenantID, agentID, exporter, tuple, observed)
					if err != nil {
						return nil, err
					}
					out = append(out, record)
				}
			}
		}
	}
	return out, nil
}

func parseAzureTuple(tenantID, agentID, exporter, tuple string, observed time.Time) (flow.Record, error) {
	parts := strings.Split(tuple, ",")
	if len(parts) < 8 {
		return flow.Record{}, fmt.Errorf("azure nsg tuple needs at least 8 fields, got %d", len(parts))
	}
	start, err := parseUnixSeconds(parts[0])
	if err != nil {
		return flow.Record{}, err
	}
	src, err := parseAddr(parts[1])
	if err != nil {
		return flow.Record{}, err
	}
	dst, err := parseAddr(parts[2])
	if err != nil {
		return flow.Record{}, err
	}
	srcPort, err := parsePort(parts[3])
	if err != nil {
		return flow.Record{}, err
	}
	dstPort, err := parsePort(parts[4])
	if err != nil {
		return flow.Record{}, err
	}
	proto, err := parseAzureProtocol(parts[5])
	if err != nil {
		return flow.Record{}, err
	}
	packets := parseOptionalTupleUint(parts, 9) + parseOptionalTupleUint(parts, 11)
	bytes := parseOptionalTupleUint(parts, 10) + parseOptionalTupleUint(parts, 12)
	return flow.Record{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     exporter,
		Protocol:     flow.ProtoAzureNSGFlowLogs,
		ObservedAt:   observed,
		Start:        start,
		End:          start,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}, nil
}

type gcpLogEntry struct {
	Timestamp string `json:"timestamp"`
	Resource  struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`
	JSONPayload struct {
		Connection struct {
			SrcIP    string          `json:"src_ip"`
			DstIP    string          `json:"dest_ip"`
			SrcPort  json.RawMessage `json:"src_port"`
			DstPort  json.RawMessage `json:"dest_port"`
			Protocol json.RawMessage `json:"protocol"`
		} `json:"connection"`
		BytesSent   json.RawMessage `json:"bytes_sent"`
		PacketsSent json.RawMessage `json:"packets_sent"`
		StartTime   string          `json:"start_time"`
		EndTime     string          `json:"end_time"`
	} `json:"jsonPayload"`
}

func parseGCPVPCLine(tenantID, agentID, line string, now time.Time) ([]flow.Record, error) {
	var entry gcpLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}
	src, err := parseAddr(entry.JSONPayload.Connection.SrcIP)
	if err != nil {
		return nil, err
	}
	dst, err := parseAddr(entry.JSONPayload.Connection.DstIP)
	if err != nil {
		return nil, err
	}
	srcPort, err := parseJSONPort(entry.JSONPayload.Connection.SrcPort)
	if err != nil {
		return nil, err
	}
	dstPort, err := parseJSONPort(entry.JSONPayload.Connection.DstPort)
	if err != nil {
		return nil, err
	}
	proto, err := parseJSONProtocol(entry.JSONPayload.Connection.Protocol)
	if err != nil {
		return nil, err
	}
	bytes, err := parseJSONUint(entry.JSONPayload.BytesSent)
	if err != nil {
		return nil, err
	}
	packets, err := parseJSONUint(entry.JSONPayload.PacketsSent)
	if err != nil {
		return nil, err
	}
	observed := now
	if t, err := parseRFC3339(entry.Timestamp); err == nil {
		observed = t
	}
	start := observed
	if t, err := parseRFC3339(entry.JSONPayload.StartTime); err == nil {
		start = t
	}
	end := observed
	if t, err := parseRFC3339(entry.JSONPayload.EndTime); err == nil {
		end = t
	}
	if end.Before(start) {
		start = end
	}
	return []flow.Record{{
		TenantID:     tenantID,
		AgentID:      agentID,
		Exporter:     gcpExporter(entry),
		Protocol:     flow.ProtoGCPVPCFlowLogs,
		ObservedAt:   observed,
		Start:        start,
		End:          end,
		SrcAddr:      src,
		DstAddr:      dst,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		Transport:    proto,
		Bytes:        bytes,
		Packets:      packets,
		SamplingRate: 1,
	}}, nil
}

func gcpExporter(entry gcpLogEntry) string {
	for _, key := range []string{"subnetwork_id", "subnetwork_name", "network_name", "project_id"} {
		if v := strings.TrimSpace(entry.Resource.Labels[key]); v != "" {
			return "gcp:" + v
		}
	}
	if entry.Resource.Type != "" {
		return "gcp:" + entry.Resource.Type
	}
	return "gcp:vpc-flow-logs"
}

func parseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return netip.Addr{}, fmt.Errorf("missing IP address %q", s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse IP address %q: %w", s, err)
	}
	return addr, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, nil
	}
	n, err := parseUint(s)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

func parseProtocol(s string) (uint8, error) {
	n, err := parseUint(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n > 255 {
		return 0, fmt.Errorf("protocol %d out of range", n)
	}
	return uint8(n), nil
}

func parseAzureProtocol(s string) (uint8, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "T", "TCP":
		return 6, nil
	case "U", "UDP":
		return 17, nil
	case "I", "ICMP":
		return 1, nil
	default:
		return parseProtocol(s)
	}
}

func parseUnixSeconds(s string) (time.Time, error) {
	n, err := parseUint(strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(n), 0).UTC(), nil
}

func parseRFC3339(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func parseUint(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty unsigned integer")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse unsigned integer %q: %w", s, err)
	}
	return n, nil
}

func parseOptionalTupleUint(parts []string, idx int) uint64 {
	if idx >= len(parts) {
		return 0
	}
	s := strings.TrimSpace(parts[idx])
	if s == "" || s == "-" {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func parseJSONUint(raw json.RawMessage) (uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if strings.TrimSpace(s) == "" {
			return 0, nil
		}
		return parseUint(s)
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, nil
	}
	return 0, fmt.Errorf("parse JSON unsigned integer %s", string(raw))
}

func parseJSONPort(raw json.RawMessage) (uint16, error) {
	n, err := parseJSONUint(raw)
	if err != nil {
		return 0, err
	}
	if n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return uint16(n), nil
}

func parseJSONProtocol(raw json.RawMessage) (uint8, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseAzureProtocol(s)
	}
	n, err := parseJSONUint(raw)
	if err != nil {
		return 0, err
	}
	if n > 255 {
		return 0, fmt.Errorf("protocol %d out of range", n)
	}
	return uint8(n), nil
}
