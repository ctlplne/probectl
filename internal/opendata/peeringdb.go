package opendata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// Doer is the subset of *http.Client an HTTP source needs (injectable for tests).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

const peeringDBBase = "https://www.peeringdb.com/api"

// peeringDBSource adds IXP / facility presence for an ASN from PeeringDB. It keys
// on the ASN another source (Team Cymru) resolved, and caches per ASN so a
// rate-limited API is queried at most once per ASN (ingest once — S15).
type peeringDBSource struct {
	client  Doer
	baseURL string

	mu    sync.Mutex
	cache map[uint32][]IXP
}

// NewPeeringDB builds the PeeringDB IXP source. A nil client uses a default
// HTTPS client (TLS certificate validation on, per guardrail 12).
func NewPeeringDB(client Doer) Source {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &peeringDBSource{client: client, baseURL: peeringDBBase, cache: make(map[uint32][]IXP)}
}

func (p *peeringDBSource) Descriptor() Descriptor {
	return Descriptor{
		Name:    "peeringdb",
		Kind:    KindIXP,
		Cadence: 24 * time.Hour,
		AUP: AUP{
			License:       "PeeringDB data (CC BY 4.0)",
			URL:           "https://www.peeringdb.com/aup",
			Attribution:   "Data from PeeringDB",
			CommercialUse: CommercialAttribution,
		},
	}
}

func (p *peeringDBSource) Enrich(ctx context.Context, _ netip.Addr, e *Enrichment) error {
	if e.ASN == 0 {
		return nil // needs an ASN from a prior source; nothing to do
	}
	ixps, err := p.ixpsFor(ctx, e.ASN)
	if err != nil {
		return fmt.Errorf("peeringdb netixlan: %w", err)
	}
	if len(ixps) == 0 {
		return nil
	}
	if len(e.IXPs) == 0 {
		e.IXPs = ixps
	}
	e.addProvenance(p.Descriptor(), "ixps")
	return nil
}

func (p *peeringDBSource) ixpsFor(ctx context.Context, asn uint32) ([]IXP, error) {
	p.mu.Lock()
	cached, ok := p.cache[asn]
	p.mu.Unlock()
	if ok {
		return cached, nil
	}

	url := fmt.Sprintf("%s/netixlan?asn=%d", p.baseURL, asn)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Data []struct {
			IXID    int    `json:"ix_id"`
			Name    string `json:"name"`
			IPAddr4 string `json:"ipaddr4"`
			IPAddr6 string `json:"ipaddr6"`
			Speed   int    `json:"speed"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	ixps := make([]IXP, 0, len(payload.Data))
	for _, d := range payload.Data {
		ixps = append(ixps, IXP{Name: d.Name, IXID: d.IXID, IPv4: d.IPAddr4, IPv6: d.IPAddr6, SpeedM: d.Speed})
	}
	p.mu.Lock()
	p.cache[asn] = ixps
	p.mu.Unlock()
	return ixps, nil
}
