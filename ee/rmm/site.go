// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// Package rmm binds MSP RMM sites to enrollment and review destinations.
package rmm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type Vendor string

const (
	NinjaOne       Vendor = "ninjaone"
	ConnectWiseRMM Vendor = "connectwise-rmm"
	DattoRMM       Vendor = "datto-rmm"
)

// Site identifies one site inside a configured RMM account. Use vendor IDs,
// never display names. For NinjaOne site_id has form organization:location.
type Site struct {
	Vendor  Vendor `json:"vendor"`
	Account string `json:"account"`
	ID      string `json:"site_id"`
}

// SiteMapping is operator configuration. Credentials are resolved separately;
// a remote device record cannot override either local destination.
type SiteMapping struct {
	Site
	TenantID  tenancy.ID `json:"tenant_id"`
	ContextID string     `json:"context_id"`
	EnrollURL string     `json:"enrollment_url"`
	AgentGRPC string     `json:"agent_grpc_addr"`
}

type SiteMappings struct {
	byTenant map[tenancy.ID]map[Site]SiteMapping
}

var (
	ErrSiteUnavailable = errors.New("rmm: site mapping unavailable")
	rmmSiteID          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func buildSiteMappings(routes []SiteMapping) (*SiteMappings, error) {
	mappings := &SiteMappings{byTenant: map[tenancy.ID]map[Site]SiteMapping{}}
	seen := make(map[Site]struct{}, len(routes))
	for i, route := range routes {
		if !validSite(route.Site) || !canonicalUUID(route.TenantID.String()) || !canonicalUUID(route.ContextID) ||
			!validHTTPSOrigin(route.EnrollURL) || !validAgentListener(route.AgentGRPC) {
			return nil, fmt.Errorf("rmm: invalid site mapping %d", i+1)
		}
		if _, exists := seen[route.Site]; exists {
			return nil, fmt.Errorf("rmm: duplicate site mapping %d", i+1)
		}
		seen[route.Site] = struct{}{}
		if mappings.byTenant[route.TenantID] == nil {
			mappings.byTenant[route.TenantID] = map[Site]SiteMapping{}
		}
		mappings.byTenant[route.TenantID][route.Site] = route
	}
	return mappings, nil
}

func validSite(site Site) bool {
	if !rmmSiteID.MatchString(site.Account) || !rmmSiteID.MatchString(site.ID) {
		return false
	}
	switch site.Vendor {
	case NinjaOne:
		keys := strings.Split(site.ID, ":")
		return len(keys) == 2 && positiveInteger(keys[0]) && positiveInteger(keys[1])
	case ConnectWiseRMM, DattoRMM:
		return true
	default:
		return false
	}
}

func positiveInteger(raw string) bool {
	n, err := strconv.ParseUint(raw, 10, 31)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == raw
}

func canonicalUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func validHTTPSOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	return validGRPCHost(u.Hostname()) && (u.Port() == "" || validPort(u.Port()))
}

func validAgentListener(raw string) bool {
	host, port, err := net.SplitHostPort(raw)
	return err == nil && validGRPCHost(host) && validPort(port)
}

func validGRPCHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func validPort(raw string) bool {
	port, err := strconv.ParseUint(raw, 10, 16)
	return err == nil && port != 0 && strconv.FormatUint(port, 10) == raw
}

// Resolve looks up a site in the caller tenant's partition. Missing and
// foreign site IDs yield the same refusal.
func (m *SiteMappings) Resolve(ctx context.Context, site Site) (SiteMapping, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return SiteMapping{}, tenancy.ErrNoTenant
	}
	mapping, ok := m.byTenant[tenant][site]
	if !ok {
		return SiteMapping{}, ErrSiteUnavailable
	}
	return mapping, nil
}
