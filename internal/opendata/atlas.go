package opendata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrAtlasDisabled is returned when RIPE Atlas scheduling is requested but not
// configured (no API key) — the optional hook degrades to a clear no-op.
var ErrAtlasDisabled = errors.New("opendata: RIPE Atlas scheduling is not configured")

const atlasBase = "https://atlas.ripe.net/api/v2"

// MeasurementSpec requests a one-off RIPE Atlas measurement. This is the optional
// active-measurement hook (F7): netctl does not run an Atlas fleet — it schedules
// on the shared platform when the operator supplies an API key and credits. Atlas
// is credit-based and its terms govern commercial/MSP use (tracked as AUP).
type MeasurementSpec struct {
	Type        string // "ping" | "traceroute"
	Target      string
	Description string
	ProbeCount  int
	AddrFamily  int // 4 or 6 (defaults to 4)
}

// MeasurementResult is the scheduled measurement's identifiers.
type MeasurementResult struct {
	MeasurementIDs []int
}

// MeasurementScheduler schedules active measurements. AtlasClient is the live
// implementation; NoopScheduler is the default when Atlas is disabled.
type MeasurementScheduler interface {
	Schedule(ctx context.Context, spec MeasurementSpec) (MeasurementResult, error)
}

// NoopScheduler is the default scheduler — Atlas off, fail closed with a clear
// error so callers degrade gracefully.
type NoopScheduler struct{}

// Schedule always reports Atlas as disabled.
func (NoopScheduler) Schedule(context.Context, MeasurementSpec) (MeasurementResult, error) {
	return MeasurementResult{}, ErrAtlasDisabled
}

// AtlasClient schedules measurements via the RIPE Atlas v2 API.
type AtlasClient struct {
	client  Doer
	apiKey  string
	baseURL string
}

// NewAtlasClient builds a live Atlas scheduler. A nil client uses a default HTTPS
// client (TLS certificate validation on, guardrail 12).
func NewAtlasClient(apiKey string, client Doer) *AtlasClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &AtlasClient{client: client, apiKey: apiKey, baseURL: atlasBase}
}

type atlasDefinition struct {
	Type        string `json:"type"`
	AF          int    `json:"af"`
	Target      string `json:"target"`
	Description string `json:"description"`
	IsOneoff    bool   `json:"is_oneoff"`
}

type atlasProbeSet struct {
	Requested int    `json:"requested"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

type atlasRequest struct {
	Definitions []atlasDefinition `json:"definitions"`
	Probes      []atlasProbeSet   `json:"probes"`
}

// Schedule submits a one-off measurement and returns its IDs.
func (a *AtlasClient) Schedule(ctx context.Context, spec MeasurementSpec) (MeasurementResult, error) {
	if a.apiKey == "" {
		return MeasurementResult{}, ErrAtlasDisabled
	}
	af := spec.AddrFamily
	if af != 6 {
		af = 4
	}
	probes := spec.ProbeCount
	if probes <= 0 {
		probes = 5
	}
	reqBody := atlasRequest{
		Definitions: []atlasDefinition{{
			Type: spec.Type, AF: af, Target: spec.Target,
			Description: spec.Description, IsOneoff: true,
		}},
		Probes: []atlasProbeSet{{Requested: probes, Type: "area", Value: "WW"}},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return MeasurementResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/measurements/", bytes.NewReader(body))
	if err != nil {
		return MeasurementResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Key "+a.apiKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return MeasurementResult{}, fmt.Errorf("atlas schedule: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return MeasurementResult{}, fmt.Errorf("atlas status %d: %s", resp.StatusCode, respBody)
	}
	var out struct {
		Measurements []int `json:"measurements"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return MeasurementResult{}, fmt.Errorf("atlas decode: %w", err)
	}
	return MeasurementResult{MeasurementIDs: out.Measurements}, nil
}
