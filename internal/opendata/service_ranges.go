// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
)

var ErrServiceRangeBudget = errors.New("complete published service ranges exceed memory admission")

// ServiceRangeMatch is a publisher's range label, not proof of an application
// running at the address. Overlapping labels remain separate, including AWS
// service subsets. The index never chooses an arbitrary winner.
type ServiceRangeMatch struct {
	Prefix  string `json:"prefix"`
	Service string `json:"service"`
	Region  string `json:"region"`
}

// ServiceRangeStatus includes the cache's original clocks even when a stale
// list can no longer attribute an address. Digest identifies original bytes.
type ServiceRangeStatus struct {
	Publisher     string              `json:"publisher"`
	Version       string              `json:"version"`
	Digest        string              `json:"digest"`
	PublishedAt   time.Time           `json:"published_at,omitzero"`
	PublishedTime string              `json:"published_time,omitempty"`
	FetchedAt     time.Time           `json:"fetched_at"`
	ValidUntil    time.Time           `json:"valid_until"`
	Status        string              `json:"status"`
	TermsURL      string              `json:"terms_url"`
	Matches       []ServiceRangeMatch `json:"matches"`
}

type serviceRangeDataset struct {
	status ServiceRangeStatus
	index  map[netip.Prefix][]ServiceRangeMatch
}

// ServiceRanges is an immutable LOCAL cache of complete publisher exports.
// It has no network client or tenant state (docs/guardrails.md G7-2, 10).
type ServiceRanges struct {
	datasets []serviceRangeDataset
	maxAge   time.Duration
}

type serviceRangeEnvelope struct {
	Version int                 `json:"version"`
	Sources []serviceRangeInput `json:"sources"`
}

type serviceRangeInput struct {
	Publisher     string          `json:"publisher"`
	FetchedAt     time.Time       `json:"fetched_at"`
	Complete      bool            `json:"complete"`
	Data          json.RawMessage `json:"data"`
	exactDocument bool
}

// LoadServiceRanges reads all original vendor documents before admitting a source.
// The byte profile covers raw input, duplicate-key validation, typed decoding
// and the full index. There is no fixed row count or partial prefix import.
func LoadServiceRanges(ctx context.Context, path string, maxAge time.Duration, memoryBytes int64, now time.Time) (*ServiceRanges, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxAge <= 0 || now.IsZero() {
		return nil, errors.New("service range freshness must be positive")
	}
	if memoryBytes < 4096 {
		return nil, ErrServiceRangeBudget
	}
	initial, err := os.Stat(path)
	if err != nil || !initial.Mode().IsRegular() {
		return nil, errors.New("service ranges require a readable regular local file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open local service ranges")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("service ranges require a regular local file")
	}
	limit := memoryBytes / 16
	if info.Size() > limit {
		return nil, ErrServiceRangeBudget
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, errors.New("cannot read local service ranges")
	}
	if int64(len(raw)) > limit {
		return nil, ErrServiceRangeBudget
	}
	return decodeServiceRanges(ctx, raw, maxAge, memoryBytes, now)
}

func decodeServiceRanges(ctx context.Context, raw []byte, maxAge time.Duration, memoryBytes int64, now time.Time) (*ServiceRanges, error) {
	if maxAge <= 0 || now.IsZero() {
		return nil, errors.New("service range freshness must be positive")
	}
	if memoryBytes < 4096 || int64(len(raw)) > memoryBytes/16 {
		return nil, ErrServiceRangeBudget
	}
	if err := validateServiceJSON(ctx, raw); err != nil {
		return nil, err
	}
	if err := requireServiceObjectKeys(raw, "version", "sources"); err != nil {
		return nil, err
	}
	var envelope serviceRangeEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("invalid complete service range envelope")
	}
	if (envelope.Version != 1 && envelope.Version != 2) || len(envelope.Sources) == 0 {
		return nil, errors.New("service range envelope version 1 or 2 and sources are required")
	}
	out := &ServiceRanges{maxAge: maxAge}
	seen := map[string]bool{}
	remaining := memoryBytes - int64(len(raw))*16
	for _, input := range envelope.Sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !input.Complete || input.FetchedAt.IsZero() || input.FetchedAt.After(now) || seen[input.Publisher] {
			return nil, errors.New("complete unique service range source and original fetch clock are required")
		}
		if input.exactDocument != (envelope.Version == 2) {
			return nil, errors.New("service range document encoding does not match its envelope version")
		}
		// Version two quotes the complete original document. Validate inside
		// that string as well: outer JSON validation cannot see duplicate keys.
		if err := validateServiceRangeDocument(ctx, input.Publisher, input.Data); err != nil {
			return nil, err
		}
		seen[input.Publisher] = true
		dataset, err := parseServiceRangeDataset(ctx, input, maxAge, &remaining)
		if err != nil {
			return nil, err
		}
		out.datasets = append(out.datasets, dataset)
	}
	slices.SortFunc(out.datasets, func(a, b serviceRangeDataset) int { return strings.Compare(a.status.Publisher, b.status.Publisher) })
	return out, nil
}

// validateServiceJSON rejects duplicate keys at every nesting level and trailing
// documents before typed parsing can silently replace completeness or identity.
func validateServiceJSON(ctx context.Context, raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("service range JSON must be valid UTF-8")
	}
	type level struct {
		object bool
		key    bool
		seen   map[string]bool
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var stack []level
	finished := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) && finished && len(stack) == 0 {
			return nil
		}
		if err != nil || finished {
			return errors.New("invalid or trailing service range JSON")
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				stack = append(stack, level{object: delimiter == '{', key: delimiter == '{', seen: map[string]bool{}})
				continue
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("invalid service range JSON nesting")
				}
				stack = stack[:len(stack)-1]
			}
		} else if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if top.object && top.key {
				key, ok := token.(string)
				folded := strings.ToLower(key)
				if !ok || top.seen[folded] {
					return errors.New("duplicate service range JSON field")
				}
				top.seen[folded], top.key = true, false
				continue
			}
		}
		if len(stack) == 0 {
			finished = true
		} else if stack[len(stack)-1].object {
			stack[len(stack)-1].key = true
		}
	}
}

func requireServiceObjectKeys(raw []byte, keys ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != len(keys) {
		return errors.New("complete service range object fields are required")
	}
	for _, key := range keys {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("complete service range object fields are required")
		}
	}
	return nil
}

func (input *serviceRangeInput) UnmarshalJSON(raw []byte) error {
	if err := requireServiceObjectKeys(raw, "publisher", "fetched_at", "complete", "data"); err != nil {
		return err
	}
	type plain serviceRangeInput
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	if len(decoded.Data) > 0 && decoded.Data[0] == '"' {
		var original string
		if err := json.Unmarshal(decoded.Data, &original); err != nil {
			return err
		}
		decoded.Data, decoded.exactDocument = json.RawMessage(original), true
	}
	*input = serviceRangeInput(decoded)
	return nil
}

func parseServiceRangeDataset(ctx context.Context, input serviceRangeInput, maxAge time.Duration, remaining *int64) (serviceRangeDataset, error) {
	dataset := serviceRangeDataset{status: ServiceRangeStatus{Publisher: input.Publisher, FetchedAt: input.FetchedAt.UTC(), ValidUntil: input.FetchedAt.Add(maxAge).UTC(), Digest: hex.EncodeToString(crypto.Hash(input.Data))}, index: map[netip.Prefix][]ServiceRangeMatch{}}
	var err error
	switch input.Publisher {
	case "aws":
		err = parseAWSServiceRanges(ctx, input.Data, &dataset, remaining)
	case "google", "google_cloud":
		err = parseGoogleServiceRanges(ctx, input.Data, &dataset, remaining)
	case "cloudflare":
		err = parseCloudflareServiceRanges(ctx, input.Data, &dataset, remaining)
	case "salesforce":
		err = parseSalesforceServiceRanges(ctx, input.Data, &dataset, remaining)
	default:
		if source, ok := zoomRangePublishers[input.Publisher]; ok {
			err = parseZoomServiceRanges(ctx, input.Data, &dataset, remaining, source)
		} else {
			err = errors.New("unsupported service range publisher")
		}
	}
	if err != nil {
		return serviceRangeDataset{}, err
	}
	if dataset.status.PublishedAt.After(input.FetchedAt) || !validServiceRangeLabel(dataset.status.Version) {
		return serviceRangeDataset{}, errors.New("invalid original service range publication time or version")
	}
	for prefix, matches := range dataset.index {
		slices.SortFunc(matches, compareServiceRangeMatch)
		dataset.index[prefix] = slices.Compact(matches)
	}
	return dataset, nil
}

func validServiceRangeLabel(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func (dataset *serviceRangeDataset) add(ctx context.Context, cidr, service, region string, remaining *int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || prefix.Addr().Is4In6() || !validServiceRangeLabel(service) || (region != "" && !validServiceRangeLabel(region)) {
		return errors.New("invalid published service prefix, service or region")
	}
	prefix = prefix.Masked()
	*remaining -= int64(512 + 4*(len(cidr)+len(service)+len(region)))
	if *remaining < 0 {
		return ErrServiceRangeBudget
	}
	dataset.index[prefix] = append(dataset.index[prefix], ServiceRangeMatch{Prefix: prefix.String(), Service: service, Region: region})
	return nil
}

func compareServiceRangeMatch(a, b ServiceRangeMatch) int {
	if c := strings.Compare(a.Service, b.Service); c != 0 {
		return c
	}
	if c := strings.Compare(a.Region, b.Region); c != 0 {
		return c
	}
	return strings.Compare(a.Prefix, b.Prefix)
}

func (source *ServiceRanges) Descriptor() Descriptor {
	return Descriptor{Name: "published-service-range-file", Kind: KindService, Cadence: source.maxAge, AUP: AUP{License: "Operator-supplied original publisher exports; publisher terms apply", URL: "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html", CommercialUse: CommercialUnknown, Redistribution: "No dataset distributed; see per-publisher terms_url. Public access does not grant resale rights."}}
}

func (source *ServiceRanges) availability(at time.Time) error {
	if len(source.datasets) == 0 {
		return errors.New("complete local published service ranges are unavailable")
	}
	for _, dataset := range source.datasets {
		if at.Before(dataset.status.FetchedAt) || !at.Before(dataset.status.ValidUntil) {
			return errors.New("published service range cache is stale; inspect original fetch time")
		}
	}
	return nil
}

func (source *ServiceRanges) Enrich(ctx context.Context, _ netip.Addr, _ *Enrichment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Materialize outside the shared IP cache so its TTL cannot renew freshness.
	return source.availability(time.Now())
}

func (source *ServiceRanges) lookup(addr netip.Addr, at time.Time, enabled bool) []ServiceRangeStatus {
	result := make([]ServiceRangeStatus, 0, len(source.datasets))
	for _, dataset := range source.datasets {
		status := dataset.status
		status.Matches = []ServiceRangeMatch{}
		switch {
		case !enabled:
			status.Status = "disabled"
		case at.Before(status.FetchedAt), !at.Before(status.ValidUntil):
			status.Status = "stale"
		default:
			addr = addr.Unmap()
			for bits := addr.BitLen(); bits >= 0; bits-- {
				prefix := netip.PrefixFrom(addr, bits).Masked()
				status.Matches = append(status.Matches, dataset.index[prefix]...)
			}
			slices.SortFunc(status.Matches, compareServiceRangeMatch)
			status.Status = "unmatched"
			if len(status.Matches) > 0 {
				status.Status = "matched"
			}
		}
		result = append(result, status)
	}
	return result
}

func (en *Enricher) withCurrentServices(ctx context.Context, addr netip.Addr, value Enrichment) Enrichment {
	en.mu.Lock()
	defer en.mu.Unlock()
	value.Services = nil
	for _, managed := range en.sources {
		source, ok := managed.src.(*ServiceRanges)
		if !ok {
			continue
		}
		if len(source.datasets) == 0 {
			value.Services = append(value.Services, ServiceRangeStatus{Publisher: "unavailable", Status: "unavailable", Matches: []ServiceRangeMatch{}})
			continue
		}
		value.Services = append(value.Services, source.lookup(addr, time.Now(), managed.health.Enabled && ctx.Err() == nil)...)
	}
	return value
}

var _ Source = (*ServiceRanges)(nil)

// Keep malformed-input errors independent of untrusted labels or local paths.
func serviceRangeDecodeError(publisher string) error {
	return fmt.Errorf("invalid complete %s service range export", publisher)
}
