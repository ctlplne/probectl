// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	maxSiteDevices    = 10000
	maxInventoryPages = 80
	maxInventoryBytes = 4 << 20
)

var rmmBearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

func inventoryClient(client *http.Client) *http.Client {
	if client == nil {
		client = crypto.HardenedHTTPClient(15 * time.Second)
	}
	strict := *client
	strict.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &strict
}

func readInventoryPage(ctx context.Context, client *http.Client, endpoint, token, vendor string, page any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("rmm: invalid %s inventory request", vendor)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("rmm: %s inventory transport failed", vendor)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("rmm: %s inventory returned HTTP %d", vendor, response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxInventoryBytes+1))
	if err != nil || len(raw) > maxInventoryBytes || json.Unmarshal(raw, page) != nil {
		return fmt.Errorf("rmm: invalid or incomplete %s inventory page", vendor)
	}
	return nil
}

// InventorySource is a credential-bound reader for one RMM site. The
// package's constructors bind the account and site before any request.
type InventorySource interface {
	site() Site
	readDevices(context.Context) ([]inventoryDevice, error)
}

type inventoryDevice struct {
	siteID   string
	id       string
	hostname string
	address  string
	os       string
}

type Candidate struct {
	ExternalID      string `json:"external_id"`
	Hostname        string `json:"hostname,omitempty"`
	Address         string `json:"address,omitempty"`
	OS              string `json:"os,omitempty"`
	ActivationState string `json:"activation_state"`
}

type DiscoveryCandidates struct {
	TenantID  tenancy.ID  `json:"tenant_id"`
	ContextID string      `json:"context_id"`
	Source    Site        `json:"source"`
	Devices   []Candidate `json:"devices"`
}

// Discover verifies the caller's site mapping before any vendor request.
// Inventory supplies endpoint attributes; the mapping supplies its scope.
// The result represents review candidates and has no write or activation path.
func (m *SiteMappings) Discover(ctx context.Context, source InventorySource) (DiscoveryCandidates, error) {
	site := source.site()
	scope, err := m.Resolve(ctx, site)
	if err != nil {
		return DiscoveryCandidates{}, err
	}
	return discoverSite(ctx, scope, source)
}

func discoverSite(ctx context.Context, scope SiteMapping, source InventorySource) (DiscoveryCandidates, error) {
	site := scope.Site
	rows, err := source.readDevices(ctx)
	if err != nil {
		return DiscoveryCandidates{}, err
	}
	if len(rows) > maxSiteDevices {
		return DiscoveryCandidates{}, errors.New("rmm: inventory exceeds the site limit")
	}
	out := DiscoveryCandidates{TenantID: scope.TenantID, ContextID: scope.ContextID, Source: site,
		Devices: make([]Candidate, 0, len(rows))}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.siteID != site.ID || !rmmSiteID.MatchString(row.id) || seen[row.id] {
			return DiscoveryCandidates{}, errors.New("rmm: inventory contained an unexpected or duplicate device")
		}
		seen[row.id] = true
		address := ""
		if ip, err := netip.ParseAddr(row.address); err == nil {
			ip = ip.Unmap()
			if ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				address = ip.String()
			}
		}
		out.Devices = append(out.Devices, Candidate{
			ExternalID: row.id, Hostname: safeInventoryLabel(row.hostname), Address: address,
			OS: safeInventoryLabel(row.os), ActivationState: device.ActivationPendingReview,
		})
	}
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].ExternalID < out.Devices[j].ExternalID })
	return out, nil
}

func safeInventoryLabel(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) > 253 || !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return ""
	}
	return s
}
