// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

// ServiceNow performs read-only Table API correlation using the deployment's
// existing integration credential and domain access. Pages never add authority.
type ServiceNow struct {
	base, table, secret string
	client              *http.Client
	policy              LookupPolicy
	policyErr           error
}

// NewServiceNow builds the provider; table defaults to cmdb_ci. An optional
// deployment profile replaces starting capacity without imposing an object quota.
func NewServiceNow(base, table, secret string, profiles ...LookupPolicy) *ServiceNow {
	if table == "" {
		table = "cmdb_ci"
	}
	policy, err := lookupPolicy(profiles)
	return &ServiceNow{base: strings.TrimRight(base, "/"), table: table, secret: secret,
		client: crypto.HardenedHTTPClient(policy.Timeout), policy: policy, policyErr: err}
}

// Name implements Provider.
func (*ServiceNow) Name() string { return "servicenow" }

type serviceNowCI struct {
	SysID     string `json:"sys_id"`
	Name      string `json:"name"`
	Class     string `json:"sys_class_name"`
	IPAddress string `json:"ip_address"`
	FQDN      string `json:"fqdn"`
}

// Lookup implements Provider. Table offsets count physical records before ACL
// filtering; an empty visible page is not evidence of source exhaustion.
func (s *ServiceNow) Lookup(ctx context.Context, key string) ([]CI, error) {
	if _, err := lookupTenant(ctx); err != nil {
		return nil, err
	}
	ctx, cancel, err := beginLookup(ctx, s, s.policy, s.policyErr)
	if err != nil {
		return nil, err
	}
	defer cancel()
	key = CanonicalKey(key)
	if key == "" {
		return nil, nil
	}
	q := url.Values{}
	q.Set("sysparm_query", fmt.Sprintf("ip_address=%s^ORfqdn=%s^ORname=%s^ORDERBYsys_id", key, key, key))
	q.Set("sysparm_fields", "sys_id,name,sys_class_name,ip_address,fqdn")
	q.Set("sysparm_limit", strconv.Itoa(cmdbPageSize))
	q.Set("sysparm_no_count", "false")
	q.Set("sysparm_suppress_pagination_header", "false")
	q.Set("sysparm_query_no_domain", "false")
	endpoint := s.base + "/api/now/table/" + url.PathEscape(s.table)
	var offset int64
	total := int64(-1)
	out := []CI{}
	seen := map[string]bool{}
	for {
		q.Set("sysparm_offset", strconv.FormatInt(offset, 10))
		page, count, next, err := s.readPage(ctx, endpoint, q)
		if err != nil {
			return nil, err
		}
		if count < 0 || (total >= 0 && count != total) || offset > count || int64(len(page)) > count-offset {
			return nil, ErrLookupIncomplete
		}
		total = count
		for _, row := range page {
			if row.SysID == "" || seen[row.SysID] {
				return nil, ErrLookupIncomplete
			}
			if CanonicalKey(row.IPAddress) != key && CanonicalKey(row.FQDN) != key && CanonicalKey(row.Name) != key {
				return nil, ErrTenantBinding
			}
			if err := lookupMemory(ctx, s, 2048); err != nil {
				return nil, err
			}
			seen[row.SysID] = true
			out = append(out, CI{SysID: row.SysID, Name: row.Name, Class: row.Class, IPAddress: row.IPAddress, FQDN: row.FQDN,
				URL: s.base + "/nav_to.do?uri=" + url.QueryEscape(s.table+".do?sys_id="+row.SysID)})
		}
		if next == "" {
			// A larger-than-requested complete response can witness the full
			// count itself. Otherwise the documented physical limit must have
			// covered the remaining range, including ACL-hidden records.
			limit, _ := strconv.ParseInt(q.Get("sysparm_limit"), 10, 64)
			if total-offset > limit && int64(len(page)) != total-offset {
				return nil, ErrLookupIncomplete
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return out, nil
		}
		following, err := serviceNowNextOffset(endpoint, q, next)
		limit, _ := strconv.ParseInt(q.Get("sysparm_limit"), 10, 64)
		if err != nil || following <= offset || following >= total || following-offset > limit || int64(len(page)) > following-offset {
			return nil, ErrLookupIncomplete
		}
		// Retain a smaller server page width in reconstructed requests so a
		// later missing continuation cannot falsely complete a wider range.
		q.Set("sysparm_limit", strconv.FormatInt(following-offset, 10))
		offset = following
	}
}

func (s *ServiceNow) readPage(ctx context.Context, endpoint string, q url.Values) ([]serviceNowCI, int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.secret)))
	response, err := s.client.Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("servicenow: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, "", fmt.Errorf("servicenow: status %d", response.StatusCode)
	}
	counts := response.Header.Values("X-Total-Count")
	if len(counts) != 1 {
		return nil, 0, "", ErrLookupIncomplete
	}
	count, err := strconv.ParseInt(strings.TrimSpace(counts[0]), 10, 64)
	if err != nil || count < 0 {
		return nil, 0, "", ErrLookupIncomplete
	}
	next, err := serviceNowNextLink(response.Header.Values("Link"))
	if err != nil {
		return nil, 0, "", err
	}
	body, err := readLookupBody(ctx, s, response.Body)
	if err != nil {
		return nil, 0, "", fmt.Errorf("servicenow read: %w", err)
	}
	if validateNetBoxJSON(body) != nil {
		return nil, 0, "", ErrLookupIncomplete
	}
	var page struct {
		Result []serviceNowCI `json:"result"`
	}
	if json.Unmarshal(body, &page) != nil || page.Result == nil {
		return nil, 0, "", ErrLookupIncomplete
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, "", err
	}
	return page.Result, count, next, nil
}
