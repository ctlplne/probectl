// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package terraformprovider implements the native Terraform provider for
// self-hosted probectl deployments.
package terraformprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/ctlplne/probectl/internal/crypto"
)

// New returns the Terraform provider schema.
func New() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_url": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("PROBECTL_API_URL", nil),
				Description: "Self-hosted probectl API base URL. Remote URLs must be https; http is accepted only for loopback test instances.",
			},
			"tenant": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("PROBECTL_TENANT", nil),
				Description: "Tenant header for tenant-scoped /v1 resources.",
			},
			"token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("PROBECTL_API_TOKEN", nil),
				Description: "Bearer token for the self-hosted probectl API.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"probectl_test":            resourceTest(),
			"probectl_alert_route":     resourceAlertRoute(),
			"probectl_provider_tenant": resourceProviderTenant(),
			"probectl_api_resource":    resourceAPIResource(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"probectl_tenant":  dataSourceTenant(),
			"probectl_tenants": dataSourceTenants(),
			"probectl_test":    dataSourceTest(),
			"probectl_tests":   dataSourceTests(),
			"probectl_agent":   dataSourceAgent(),
			"probectl_agents":  dataSourceAgents(),
		},
	}
	p.ConfigureContextFunc = configure
	return p
}

type client struct {
	baseURL string
	tenant  string
	token   string
	hc      *http.Client
}

func configure(_ context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	baseURL := strings.TrimRight(d.Get("api_url").(string), "/")
	if err := validateAPIURL(baseURL); err != nil {
		return nil, diag.FromErr(err)
	}
	return &client{
		baseURL: baseURL,
		tenant:  strings.TrimSpace(d.Get("tenant").(string)),
		token:   d.Get("token").(string),
		hc:      crypto.HardenedHTTPClient(30 * time.Second),
	}, nil
}

func validateAPIURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("api_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse api_url: %w", err)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("api_url must be https; http is allowed only for loopback")
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *client) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// The provider/management plane is a distinct privilege domain. Never
	// leak a tenant selector onto it, even when this provider instance also
	// has a tenant configured for /v1 reads.
	if c.tenant != "" && !strings.HasPrefix(path, "/provider/") {
		req.Header.Set("X-Probectl-Tenant", c.tenant)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func resourceTest() *schema.Resource {
	return &schema.Resource{
		CreateContext: createTest,
		ReadContext:   readTest,
		UpdateContext: updateTest,
		DeleteContext: deleteByPath("/v1/tests/{id}"),
		Schema: map[string]*schema.Schema{
			"name":             {Type: schema.TypeString, Required: true},
			"type":             {Type: schema.TypeString, Required: true},
			"target":           {Type: schema.TypeString, Optional: true},
			"interval_seconds": {Type: schema.TypeInt, Optional: true, Default: 60},
			"timeout_seconds":  {Type: schema.TypeInt, Optional: true, Default: 3},
			"enabled":          {Type: schema.TypeBool, Optional: true, Default: true},
			"params":           {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
		},
	}
}

func testBody(d *schema.ResourceData) map[string]any {
	return map[string]any{
		"name":             d.Get("name").(string),
		"type":             d.Get("type").(string),
		"target":           d.Get("target").(string),
		"interval_seconds": d.Get("interval_seconds").(int),
		"timeout_seconds":  d.Get("timeout_seconds").(int),
		"enabled":          d.Get("enabled").(bool),
		"params":           stringMap(d.Get("params").(map[string]any)),
	}
}

func createTest(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPost, "/v1/tests", testBody(d), &out); err != nil {
		return diag.FromErr(err)
	}
	return setIDFromResponse(d, out)
}

func readTest(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	status, err := meta.(*client).do(ctx, http.MethodGet, "/v1/tests/"+url.PathEscape(d.Id()), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	setString(d, "name", out["name"])
	setString(d, "type", out["type"])
	setString(d, "target", out["target"])
	setInt(d, "interval_seconds", out["interval_seconds"])
	setInt(d, "timeout_seconds", out["timeout_seconds"])
	setBool(d, "enabled", out["enabled"])
	return nil
}

func updateTest(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPut, "/v1/tests/"+url.PathEscape(d.Id()), testBody(d), &out); err != nil {
		return diag.FromErr(err)
	}
	return setIDFromResponse(d, out)
}

func resourceAlertRoute() *schema.Resource {
	return &schema.Resource{
		CreateContext: createAlertRoute,
		ReadContext:   readAlertRoute,
		UpdateContext: updateAlertRoute,
		DeleteContext: deleteByPath("/v1/alerts/{id}"),
		Schema: map[string]*schema.Schema{
			"name":             {Type: schema.TypeString, Required: true},
			"metric":           {Type: schema.TypeString, Required: true},
			"type":             {Type: schema.TypeString, Optional: true, Default: "threshold"},
			"comparison":       {Type: schema.TypeString, Optional: true, Default: "gt"},
			"threshold":        {Type: schema.TypeFloat, Optional: true},
			"window":           {Type: schema.TypeInt, Optional: true},
			"sensitivity":      {Type: schema.TypeFloat, Optional: true},
			"for_n":            {Type: schema.TypeInt, Optional: true},
			"renotify_seconds": {Type: schema.TypeInt, Optional: true},
			"severity":         {Type: schema.TypeString, Optional: true, Default: "warning"},
			"enabled":          {Type: schema.TypeBool, Optional: true, Default: true},
			"match":            {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"channel":          {Type: schema.TypeList, Optional: true, Elem: channelSchema()},
			"alerting_active":  {Type: schema.TypeBool, Computed: true},
			"inactive_warning": {Type: schema.TypeString, Computed: true},
		},
	}
}

func channelSchema() *schema.Resource {
	return &schema.Resource{Schema: map[string]*schema.Schema{
		"type":       {Type: schema.TypeString, Required: true},
		"url":        {Type: schema.TypeString, Optional: true},
		"recipients": {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
		"secret":     {Type: schema.TypeString, Optional: true, Sensitive: true},
	}}
}

func alertBody(d *schema.ResourceData) map[string]any {
	return map[string]any{
		"name":             d.Get("name").(string),
		"metric":           d.Get("metric").(string),
		"type":             d.Get("type").(string),
		"comparison":       d.Get("comparison").(string),
		"threshold":        d.Get("threshold").(float64),
		"window":           d.Get("window").(int),
		"sensitivity":      d.Get("sensitivity").(float64),
		"for_n":            d.Get("for_n").(int),
		"renotify_seconds": d.Get("renotify_seconds").(int),
		"severity":         d.Get("severity").(string),
		"enabled":          d.Get("enabled").(bool),
		"match":            stringMap(d.Get("match").(map[string]any)),
		"channels":         channels(d.Get("channel").([]any)),
	}
}

func channels(raw []any) []map[string]any {
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		m, _ := item.(map[string]any)
		ch := map[string]any{
			"type": m["type"],
			"url":  m["url"],
		}
		if v, ok := m["secret"].(string); ok && v != "" {
			ch["secret"] = v
		}
		if rec, ok := m["recipients"].([]any); ok {
			vals := make([]string, 0, len(rec))
			for _, r := range rec {
				vals = append(vals, fmt.Sprint(r))
			}
			ch["recipients"] = vals
		}
		out = append(out, ch)
	}
	return out
}

func createAlertRoute(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPost, "/v1/alerts", alertBody(d), &out); err != nil {
		return diag.FromErr(err)
	}
	if w, ok := out["warning"]; ok {
		_ = d.Set("inactive_warning", fmt.Sprint(w))
	}
	return setIDFromResponse(d, out)
}

func readAlertRoute(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	status, err := meta.(*client).do(ctx, http.MethodGet, "/v1/alerts/"+url.PathEscape(d.Id()), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	setString(d, "name", out["name"])
	setString(d, "metric", out["metric"])
	setString(d, "type", out["type"])
	setString(d, "comparison", out["comparison"])
	setFloat(d, "threshold", out["threshold"])
	setInt(d, "window", out["window"])
	setString(d, "severity", out["severity"])
	setBool(d, "enabled", out["enabled"])
	return nil
}

func updateAlertRoute(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPut, "/v1/alerts/"+url.PathEscape(d.Id()), alertBody(d), &out); err != nil {
		return diag.FromErr(err)
	}
	return setIDFromResponse(d, out)
}

func resourceProviderTenant() *schema.Resource {
	return &schema.Resource{
		CreateContext: createProviderTenant,
		ReadContext:   readProviderTenant,
		UpdateContext: updateProviderTenant,
		DeleteContext: providerTenantAction("offboard"),
		Schema: map[string]*schema.Schema{
			"slug":            {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":            {Type: schema.TypeString, Required: true},
			"isolation_model": {Type: schema.TypeString, Optional: true},
			"residency":       {Type: schema.TypeString, Optional: true},
			"status":          {Type: schema.TypeString, Computed: true},
		},
	}
}

func providerTenantBody(d *schema.ResourceData) map[string]any {
	body := map[string]any{"slug": d.Get("slug").(string), "name": d.Get("name").(string)}
	if v := d.Get("isolation_model").(string); v != "" {
		body["isolation_model"] = v
	}
	if v := d.Get("residency").(string); v != "" {
		body["residency"] = v
	}
	return body
}

func createProviderTenant(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPost, "/provider/v1/tenants", providerTenantBody(d), &out); err != nil {
		return diag.FromErr(err)
	}
	if diags := setIDFromResponse(d, out); diags.HasError() {
		return diags
	}
	setString(d, "status", out["status"])
	return nil
}

func readProviderTenant(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var out struct {
		Items []map[string]any `json:"items"`
	}
	status, err := meta.(*client).do(ctx, http.MethodGet, "/provider/v1/tenants", nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	for _, item := range out.Items {
		if fmt.Sprint(item["id"]) == d.Id() {
			setString(d, "slug", item["slug"])
			setString(d, "name", item["name"])
			setString(d, "status", item["status"])
			setString(d, "isolation_model", item["isolation_model"])
			setString(d, "residency", item["residency"])
			return nil
		}
	}
	d.SetId("")
	return nil
}

func updateProviderTenant(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	body := map[string]any{"name": d.Get("name").(string)}
	var out map[string]any
	if _, err := meta.(*client).do(ctx, http.MethodPatch, "/provider/v1/tenants/"+url.PathEscape(d.Id()), body, &out); err != nil {
		return diag.FromErr(err)
	}
	setString(d, "status", out["status"])
	return nil
}

func providerTenantAction(action string) schema.DeleteContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		if _, err := meta.(*client).do(ctx, http.MethodPost, "/provider/v1/tenants/"+url.PathEscape(d.Id())+"/"+action, nil, nil); err != nil {
			return diag.FromErr(err)
		}
		d.SetId("")
		return nil
	}
}

func resourceAPIResource() *schema.Resource {
	return &schema.Resource{
		CreateContext: createAPIResource,
		ReadContext:   readAPIResource,
		UpdateContext: createAPIResource,
		DeleteContext: deleteAPIResource,
		Schema: map[string]*schema.Schema{
			"method":        {Type: schema.TypeString, Required: true},
			"path":          {Type: schema.TypeString, Required: true},
			"body":          {Type: schema.TypeString, Optional: true, Sensitive: true},
			"id_attribute":  {Type: schema.TypeString, Optional: true, Default: "id"},
			"read_method":   {Type: schema.TypeString, Optional: true, Default: "GET"},
			"read_path":     {Type: schema.TypeString, Optional: true},
			"delete_method": {Type: schema.TypeString, Optional: true, Default: "DELETE"},
			"delete_path":   {Type: schema.TypeString, Optional: true},
			"response_json": {Type: schema.TypeString, Computed: true, Sensitive: true},
		},
	}
}

func createAPIResource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	body, err := parseOptionalJSON(d.Get("body").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	var out map[string]any
	if _, err := meta.(*client).do(ctx, strings.ToUpper(d.Get("method").(string)), d.Get("path").(string), body, &out); err != nil {
		return diag.FromErr(err)
	}
	raw, _ := json.Marshal(out)
	_ = d.Set("response_json", string(raw))
	idAttr := d.Get("id_attribute").(string)
	if idAttr != "" {
		if id := fmt.Sprint(out[idAttr]); id != "" && id != "<nil>" {
			d.SetId(id)
			return nil
		}
	}
	d.SetId(stableID(d.Get("method").(string), d.Get("path").(string), d.Get("body").(string)))
	return nil
}

func readAPIResource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	readPath := d.Get("read_path").(string)
	if readPath == "" {
		return nil
	}
	var out map[string]any
	status, err := meta.(*client).do(ctx, strings.ToUpper(d.Get("read_method").(string)), strings.ReplaceAll(readPath, "{id}", url.PathEscape(d.Id())), nil, &out)
	if status == http.StatusNotFound {
		d.SetId("")
		return nil
	}
	if err != nil {
		return diag.FromErr(err)
	}
	raw, _ := json.Marshal(out)
	_ = d.Set("response_json", string(raw))
	return nil
}

func deleteAPIResource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	deletePath := d.Get("delete_path").(string)
	if deletePath == "" {
		d.SetId("")
		return nil
	}
	if _, err := meta.(*client).do(ctx, strings.ToUpper(d.Get("delete_method").(string)), strings.ReplaceAll(deletePath, "{id}", url.PathEscape(d.Id())), nil, nil); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func parseOptionalJSON(raw string) (any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func deleteByPath(pattern string) schema.DeleteContextFunc {
	return func(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
		path := strings.ReplaceAll(pattern, "{id}", url.PathEscape(d.Id()))
		if _, err := meta.(*client).do(ctx, http.MethodDelete, path, nil, nil); err != nil {
			return diag.FromErr(err)
		}
		d.SetId("")
		return nil
	}
}

func setIDFromResponse(d *schema.ResourceData, out map[string]any) diag.Diagnostics {
	id := strings.TrimSpace(fmt.Sprint(out["id"]))
	if id == "" || id == "<nil>" {
		return diag.FromErr(fmt.Errorf("probectl response did not include id"))
	}
	d.SetId(id)
	return nil
}

func stringMap(raw map[string]any) map[string]string {
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func setString(d *schema.ResourceData, key string, value any) {
	if value == nil {
		return
	}
	_ = d.Set(key, fmt.Sprint(value))
}

func setBool(d *schema.ResourceData, key string, value any) {
	if v, ok := value.(bool); ok {
		_ = d.Set(key, v)
	}
}

func setInt(d *schema.ResourceData, key string, value any) {
	switch v := value.(type) {
	case int:
		_ = d.Set(key, v)
	case float64:
		_ = d.Set(key, int(v))
	case json.Number:
		if n, err := strconv.Atoi(v.String()); err == nil {
			_ = d.Set(key, n)
		}
	}
}

func setFloat(d *schema.ResourceData, key string, value any) {
	if v, ok := value.(float64); ok {
		_ = d.Set(key, v)
	}
}

func stableID(parts ...string) string {
	h := fnv.New128a()
	_, _ = h.Write([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h.Sum(nil))
}
