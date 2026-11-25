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
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type DattoInventory struct {
	bound    Site
	endpoint *url.URL
	token    string
	client   *http.Client
}

var _ InventorySource = (*DattoInventory)(nil)

// NewDattoInventory binds a scoped OAuth bearer and Datto platform origin to
// the documented /api/v2/site/{siteUid}/devices endpoint.
func NewDattoInventory(site Site, origin, bearer string, client *http.Client) (*DattoInventory, error) {
	if site.Vendor != DattoRMM || !validSite(site) || !validHTTPSOrigin(origin) {
		return nil, errors.New("rmm: invalid Datto site or HTTPS platform origin")
	}
	if len(bearer) > 16384 || !rmmBearerToken.MatchString(bearer) {
		return nil, errors.New("rmm: invalid Datto OAuth access token")
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, errors.New("rmm: invalid Datto platform origin")
	}
	// Resolve continuations against the same absolute path for both forms of the origin.
	u.Path = "/"
	return &DattoInventory{bound: site, endpoint: u.JoinPath("api", "v2", "site", site.ID, "devices"), token: bearer, client: inventoryClient(client)}, nil
}

func (c *DattoInventory) site() Site { return c.bound }

type dattoInventoryPage struct {
	Page *struct {
		Next json.RawMessage `json:"nextPageUrl"`
	} `json:"pageDetails"`
	Devices []struct {
		UID      string `json:"uid"`
		SiteUID  string `json:"siteUid"`
		Hostname string `json:"hostname"`
		IP       string `json:"intIpAddress"`
		OS       string `json:"operatingSystem"`
	} `json:"devices"`
}

func (c *DattoInventory) readDevices(ctx context.Context) ([]inventoryDevice, error) {
	var rows []inventoryDevice
	next := c.endpoint
	visited := map[string]bool{}
	for pageNum := 0; next != nil && pageNum < maxInventoryPages; pageNum++ {
		location := next.String()
		if visited[location] {
			return nil, errors.New("rmm: Datto inventory has a pagination loop")
		}
		visited[location] = true
		var page dattoInventoryPage
		if err := readInventoryPage(ctx, c.client, location, c.token, "Datto", &page); err != nil {
			return nil, err
		}
		if page.Page == nil || page.Devices == nil {
			return nil, errors.New("rmm: invalid or incomplete Datto inventory page")
		}
		if len(page.Devices) > maxSiteDevices-len(rows) {
			return nil, errors.New("rmm: Datto inventory exceeds the site limit")
		}
		for _, row := range page.Devices {
			if row.SiteUID != c.bound.ID {
				return nil, errors.New("rmm: Datto returned a device from outside the configured site")
			}
			rows = append(rows, inventoryDevice{siteID: row.SiteUID, id: row.UID, hostname: row.Hostname, address: row.IP, os: row.OS})
		}
		var err error
		next, err = c.nextPage(page.Page.Next)
		if err != nil {
			return nil, err
		}
	}
	if next != nil {
		return nil, errors.New("rmm: Datto inventory exceeds the page limit")
	}
	return rows, nil
}

func (c *DattoInventory) nextPage(raw json.RawMessage) (*url.URL, error) {
	if string(raw) == "null" {
		return nil, nil
	}
	var link string
	if json.Unmarshal(raw, &link) != nil || link == "" {
		return nil, errors.New("rmm: Datto omitted its inventory page boundary")
	}
	next, err := c.endpoint.Parse(link)
	if err != nil || next.Scheme != c.endpoint.Scheme || !strings.EqualFold(next.Host, c.endpoint.Host) ||
		next.User != nil || next.Fragment != "" || next.RawFragment != "" ||
		next.Path != c.endpoint.Path || next.RawPath != "" {
		return nil, errors.New("rmm: Datto inventory continuation left the configured site")
	}
	values, err := url.ParseQuery(next.RawQuery)
	if err != nil || !validDattoPageQuery(values) {
		return nil, errors.New("rmm: Datto inventory continuation has invalid paging parameters")
	}
	next.RawQuery = values.Encode()
	return next, nil
}

func validDattoPageQuery(q url.Values) bool {
	for key, values := range q {
		if (key != "page" && key != "max") || len(values) != 1 {
			return false
		}
		number, err := strconv.ParseUint(values[0], 10, 31)
		if err != nil || strconv.FormatUint(number, 10) != values[0] || (key == "max" && number == 0) {
			return false
		}
	}
	return len(q["page"]) == 1
}
