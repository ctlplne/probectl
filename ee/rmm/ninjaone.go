// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type NinjaOneInventory struct {
	bound        Site
	organization int64
	location     int64
	endpoint     *url.URL
	token        string
	client       *http.Client
}

var _ InventorySource = (*NinjaOneInventory)(nil)

// NewNinjaOneInventory binds a monitoring OAuth bearer to a single region,
// organization and location for the NinjaOne v2 device list.
func NewNinjaOneInventory(site Site, origin, bearer string, client *http.Client) (*NinjaOneInventory, error) {
	if site.Vendor != NinjaOne || !validSite(site) || !validHTTPSOrigin(origin) {
		return nil, errors.New("rmm: invalid NinjaOne site or HTTPS region origin")
	}
	if len(bearer) > 16384 || !rmmBearerToken.MatchString(bearer) {
		return nil, errors.New("rmm: invalid NinjaOne OAuth access token")
	}
	orgText, locText, _ := strings.Cut(site.ID, ":")
	org, orgErr := strconv.ParseInt(orgText, 10, 32)
	loc, locErr := strconv.ParseInt(locText, 10, 32)
	if orgErr != nil || locErr != nil {
		return nil, errors.New("rmm: NinjaOne organization or location is outside its identifier range")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, errors.New("rmm: invalid NinjaOne region origin")
	}
	u = u.JoinPath("v2", "devices")
	u.RawQuery = url.Values{"df": {"org=" + orgText + " AND loc=" + locText}, "pageSize": {"250"}}.Encode()
	return &NinjaOneInventory{bound: site, organization: org, location: loc,
		endpoint: u, token: bearer, client: inventoryClient(client)}, nil
}

func (c *NinjaOneInventory) site() Site { return c.bound }

type ninjaOneDevice struct {
	ID           int32  `json:"id"`
	Organization int32  `json:"organizationId"`
	Location     int32  `json:"locationId"`
	DNSName      string `json:"dnsName"`
	SystemName   string `json:"systemName"`
}

func (c *NinjaOneInventory) readDevices(ctx context.Context) ([]inventoryDevice, error) {
	var rows []inventoryDevice
	next := *c.endpoint
	query := next.Query()
	visited := map[int32]bool{}
	for range maxInventoryPages {
		var page []ninjaOneDevice
		if err := readInventoryPage(ctx, c.client, next.String(), c.token, "NinjaOne", &page); err != nil {
			return nil, err
		}
		if page == nil {
			return nil, errors.New("rmm: incomplete NinjaOne inventory page")
		}
		if len(page) == 0 {
			return rows, nil
		}
		if len(page) > maxSiteDevices-len(rows) {
			return nil, errors.New("rmm: NinjaOne inventory exceeds the site limit")
		}
		cursor := page[len(page)-1].ID
		if visited[cursor] {
			return nil, errors.New("rmm: NinjaOne inventory cursor repeated")
		}
		visited[cursor] = true
		for _, row := range page {
			if int64(row.Organization) != c.organization || int64(row.Location) != c.location {
				return nil, errors.New("rmm: NinjaOne returned a device from outside the configured site")
			}
			if row.ID <= 0 {
				return nil, errors.New("rmm: NinjaOne returned an invalid device identifier")
			}
			hostname := safeInventoryLabel(row.DNSName)
			if hostname == "" {
				hostname = row.SystemName
			}
			rows = append(rows, inventoryDevice{siteID: c.bound.ID, id: strconv.FormatInt(int64(row.ID), 10), hostname: hostname})
		}
		query.Set("after", strconv.FormatInt(int64(cursor), 10))
		next.RawQuery = query.Encode()
	}
	return nil, errors.New("rmm: NinjaOne inventory exceeds the page limit")
}
