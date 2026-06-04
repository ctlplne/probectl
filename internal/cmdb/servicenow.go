package cmdb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// ServiceNow looks up CIs via the Table API:
//
//	GET {base}/api/now/table/{table}?sysparm_query=ip_address={k}^ORfqdn={k}^ORname={k}
//
// The secret is "user:password" (Basic auth, mirroring the S33 ITSM
// connector), read from the environment by the builder — never from config
// files. Outbound TLS certificates are validated (guardrail 12).
type ServiceNow struct {
	base   string
	table  string
	secret string
	client *http.Client
}

// maxCIsPerLookup bounds one lookup's result set.
const maxCIsPerLookup = 10

// NewServiceNow builds the provider. base is the instance URL (e.g.
// https://acme.service-now.com); table defaults to cmdb_ci.
func NewServiceNow(base, table, secret string) *ServiceNow {
	if table == "" {
		table = "cmdb_ci"
	}
	return &ServiceNow{
		base:   strings.TrimRight(base, "/"),
		table:  table,
		secret: secret,
		client: crypto.HardenedHTTPClient(15 * time.Second),
	}
}

// Name implements Provider.
func (s *ServiceNow) Name() string { return "servicenow" }

// Lookup implements Provider.
func (s *ServiceNow) Lookup(ctx context.Context, key string) ([]CI, error) {
	q := url.Values{}
	// ^OR is ServiceNow's encoded-query disjunction. key is canonicalized
	// (CanonicalKey) before it gets here and is URL-encoded by Encode.
	q.Set("sysparm_query", fmt.Sprintf("ip_address=%s^ORfqdn=%s^ORname=%s", key, key, key))
	q.Set("sysparm_fields", "sys_id,name,sys_class_name,ip_address,fqdn")
	q.Set("sysparm_limit", fmt.Sprint(maxCIsPerLookup))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.base+"/api/now/table/"+url.PathEscape(s.table)+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.secret)))
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("servicenow: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("servicenow read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Never echo the response body at error level — treat it as untrusted.
		return nil, fmt.Errorf("servicenow: status %d", resp.StatusCode)
	}
	var parsed struct {
		Result []struct {
			SysID     string `json:"sys_id"`
			Name      string `json:"name"`
			Class     string `json:"sys_class_name"`
			IPAddress string `json:"ip_address"`
			FQDN      string `json:"fqdn"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("servicenow: unexpected response shape")
	}
	out := make([]CI, 0, len(parsed.Result))
	for _, r := range parsed.Result {
		if r.SysID == "" {
			continue
		}
		out = append(out, CI{
			SysID:     r.SysID,
			Name:      r.Name,
			Class:     r.Class,
			IPAddress: r.IPAddress,
			FQDN:      r.FQDN,
			URL:       s.base + "/nav_to.do?uri=" + url.QueryEscape(s.table+".do?sys_id="+r.SysID),
		})
	}
	return out, nil
}
