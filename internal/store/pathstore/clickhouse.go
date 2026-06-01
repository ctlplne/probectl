package pathstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
	"github.com/imfeelingtheagi/netctl/internal/path"
)

// tenant_id is the partition key so a tenant's path data is physically separated
// (CLAUDE.md §4); it leads every ORDER BY so tenant-scoped reads prune by it.
const createHops = `CREATE TABLE IF NOT EXISTS netctl_path_hops (
  tenant_id String, path_id String, target String, target_ip String, mode String,
  ts DateTime64(3), ttl UInt8, responder String,
  sent UInt32, received UInt32, loss_ratio Float64,
  rtt_min_ms Float64, rtt_avg_ms Float64, rtt_max_ms Float64,
  mpls_labels Array(UInt32)
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, responder)`

const createLinks = `CREATE TABLE IF NOT EXISTS netctl_path_links (
  tenant_id String, path_id String, target String, ts DateTime64(3),
  ttl UInt8, from_ip String, to_ip String
) ENGINE = MergeTree PARTITION BY tenant_id ORDER BY (tenant_id, target, ts, ttl, from_ip, to_ip)`

// ClickHouse persists paths to a ClickHouse HTTP endpoint. TLS in transit is
// supported by using an https URL (CLAUDE.md §7 guardrail 12).
type ClickHouse struct {
	base   string
	client *http.Client
}

// NewClickHouse connects to a ClickHouse HTTP endpoint and ensures the schema.
func NewClickHouse(rawURL string) (*ClickHouse, error) {
	c := &ClickHouse{base: strings.TrimRight(rawURL, "/"), client: &http.Client{Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.exec(ctx, createHops, nil); err != nil {
		return nil, fmt.Errorf("pathstore: create hops table: %w", err)
	}
	if err := c.exec(ctx, createLinks, nil); err != nil {
		return nil, fmt.Errorf("pathstore: create links table: %w", err)
	}
	return c, nil
}

type hopRow struct {
	TenantID  string   `json:"tenant_id"`
	PathID    string   `json:"path_id"`
	Target    string   `json:"target"`
	TargetIP  string   `json:"target_ip"`
	Mode      string   `json:"mode"`
	TS        string   `json:"ts"`
	TTL       int      `json:"ttl"`
	Responder string   `json:"responder"`
	Sent      int      `json:"sent"`
	Received  int      `json:"received"`
	LossRatio float64  `json:"loss_ratio"`
	RTTMin    float64  `json:"rtt_min_ms"`
	RTTAvg    float64  `json:"rtt_avg_ms"`
	RTTMax    float64  `json:"rtt_max_ms"`
	MPLS      []uint32 `json:"mpls_labels"`
}

type linkRow struct {
	TenantID string `json:"tenant_id"`
	PathID   string `json:"path_id"`
	Target   string `json:"target"`
	TS       string `json:"ts"`
	TTL      int    `json:"ttl"`
	From     string `json:"from_ip"`
	To       string `json:"to_ip"`
}

// Save writes one discovery (its hops and links) under tenantID.
func (c *ClickHouse) Save(ctx context.Context, tenantID string, p *path.Path) error {
	pathID, err := randomID()
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05.000")

	var hops bytes.Buffer
	enc := json.NewEncoder(&hops)
	for _, h := range p.Hops {
		for _, n := range h.Nodes {
			labels := make([]uint32, 0, len(n.MPLS))
			for _, l := range n.MPLS {
				labels = append(labels, l.Label)
			}
			if err := enc.Encode(hopRow{
				TenantID: tenantID, PathID: pathID, Target: p.Target, TargetIP: p.TargetIP, Mode: p.Mode,
				TS: ts, TTL: h.TTL, Responder: n.IP, Sent: n.Sent, Received: n.Received, LossRatio: n.LossRatio,
				RTTMin: n.RTTMinMs, RTTAvg: n.RTTAvgMs, RTTMax: n.RTTMaxMs, MPLS: labels,
			}); err != nil {
				return err
			}
		}
	}
	if hops.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO netctl_path_hops FORMAT JSONEachRow", &hops); err != nil {
			return err
		}
	}

	var links bytes.Buffer
	lenc := json.NewEncoder(&links)
	for _, l := range p.Links {
		if err := lenc.Encode(linkRow{
			TenantID: tenantID, PathID: pathID, Target: p.Target, TS: ts, TTL: l.TTL, From: l.From, To: l.To,
		}); err != nil {
			return err
		}
	}
	if links.Len() > 0 {
		if err := c.exec(ctx, "INSERT INTO netctl_path_links FORMAT JSONEachRow", &links); err != nil {
			return err
		}
	}
	return nil
}

// Close is a no-op (the HTTP client needs no teardown).
func (c *ClickHouse) Close() error { return nil }

func (c *ClickHouse) exec(ctx context.Context, query string, body io.Reader) error {
	u := c.base + "/?query=" + url.QueryEscape(query)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, body)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("pathstore: clickhouse request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("pathstore: clickhouse status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func randomID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
