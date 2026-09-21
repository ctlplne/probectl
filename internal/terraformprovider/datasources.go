// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package terraformprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

const defaultDataSourcePageSize = 200

type dataPage[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor"`
}

type tenantData struct {
	ID             string `json:"id"`
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	IsolationModel string `json:"isolation_model"`
	Residency      string `json:"residency"`
	CreatedAt      string `json:"created_at"`
}

type testData struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params"`
	Enabled         bool              `json:"enabled"`
	CreatedAt       string            `json:"created_at"`
	UpdatedAt       string            `json:"updated_at"`
}

type agentData struct {
	ID           string   `json:"id"`
	TenantID     string   `json:"tenant_id"`
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agent_version"`
	Status       string   `json:"status"`
	Capabilities []string `json:"capabilities"`
	SPIFFEID     string   `json:"spiffe_id"`
	RegisteredAt string   `json:"registered_at"`
	LastSeenAt   string   `json:"last_seen_at"`
	CreatedAt    string   `json:"created_at"`
}

func dataSourceTenant() *schema.Resource {
	fields := tenantFields(false)
	fields["tenant_id"] = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringIsNotEmpty,
		Description:  "Provider-plane tenant ID to look up.",
	}
	return &schema.Resource{
		Description: "Reads one tenant's lifecycle metadata from the separate provider/management plane; it never reads tenant telemetry.",
		ReadContext: readTenantDataSource,
		Schema:      fields,
	}
}

func dataSourceTenants() *schema.Resource {
	return &schema.Resource{
		Description: "Lists provider-plane tenant lifecycle metadata; it never reads tenant telemetry.",
		ReadContext: readTenantsDataSource,
		Schema: map[string]*schema.Schema{
			"tenants": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "All tenants visible to the authenticated provider operator.",
				Elem:        &schema.Resource{Schema: tenantFields(true)},
			},
		},
	}
}

func dataSourceTest() *schema.Resource {
	fields := testFields(false)
	fields["test_id"] = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringIsNotEmpty,
		Description:  "Tenant-scoped synthetic test ID to look up.",
	}
	return &schema.Resource{
		Description: "Reads one synthetic test within the provider's configured tenant.",
		ReadContext: readTestDataSource,
		Schema:      fields,
	}
}

func dataSourceTests() *schema.Resource {
	return &schema.Resource{
		Description: "Reads one bounded cursor page of synthetic tests within the provider's configured tenant.",
		ReadContext: readTestsDataSource,
		Schema:      pageSchema("tests", testFields(true)),
	}
}

func dataSourceAgent() *schema.Resource {
	fields := agentFields(false)
	fields["agent_id"] = &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringIsNotEmpty,
		Description:  "Tenant-scoped registered agent ID to look up.",
	}
	return &schema.Resource{
		Description: "Reads one registered agent within the provider's configured tenant.",
		ReadContext: readAgentDataSource,
		Schema:      fields,
	}
}

func dataSourceAgents() *schema.Resource {
	return &schema.Resource{
		Description: "Reads one bounded cursor page of registered agents within the provider's configured tenant.",
		ReadContext: readAgentsDataSource,
		Schema:      pageSchema("agents", agentFields(true)),
	}
}

func tenantFields(includeID bool) map[string]*schema.Schema {
	fields := map[string]*schema.Schema{
		"slug":            computedString("Stable tenant slug."),
		"name":            computedString("Tenant display name."),
		"status":          computedString("Provider lifecycle status."),
		"isolation_model": computedString("Tenant isolation model."),
		"residency":       computedString("Configured data-plane residency."),
		"created_at":      computedString("Tenant creation timestamp."),
	}
	if includeID {
		fields["id"] = computedString("Tenant ID.")
	}
	return fields
}

func testFields(includeID bool) map[string]*schema.Schema {
	fields := map[string]*schema.Schema{
		"tenant_id":        computedString("Owning tenant ID."),
		"name":             computedString("Synthetic test name."),
		"type":             computedString("Synthetic test type."),
		"target":           computedString("Probe target."),
		"interval_seconds": computedInt("Probe interval in seconds."),
		"timeout_seconds":  computedInt("Probe timeout in seconds."),
		"params": {
			Type:        schema.TypeMap,
			Computed:    true,
			Description: "Type-specific string parameters.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
		"enabled":    {Type: schema.TypeBool, Computed: true, Description: "Whether the test is enabled."},
		"created_at": computedString("Test creation timestamp."),
		"updated_at": computedString("Test update timestamp."),
	}
	if includeID {
		fields["id"] = computedString("Synthetic test ID.")
	}
	return fields
}

func agentFields(includeID bool) map[string]*schema.Schema {
	fields := map[string]*schema.Schema{
		"tenant_id":     computedString("Owning tenant ID."),
		"name":          computedString("Agent display name."),
		"hostname":      computedString("Agent-reported hostname."),
		"agent_version": computedString("Agent-reported version."),
		"status":        computedString("Registry status."),
		"capabilities": {
			Type:        schema.TypeList,
			Computed:    true,
			Description: "Agent-reported capabilities.",
			Elem:        &schema.Schema{Type: schema.TypeString},
		},
		"spiffe_id":     computedString("Verified SPIFFE workload identity."),
		"registered_at": computedString("Registration timestamp."),
		"last_seen_at":  computedString("Most recent authenticated heartbeat timestamp."),
		"created_at":    computedString("Registry-row creation timestamp."),
	}
	if includeID {
		fields["id"] = computedString("Registered agent ID.")
	}
	return fields
}

func pageSchema(itemName string, itemFields map[string]*schema.Schema) map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"after": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Exclusive cursor from a previous page's next_cursor.",
		},
		"limit": {
			Type:         schema.TypeInt,
			Optional:     true,
			Default:      defaultDataSourcePageSize,
			ValidateFunc: validation.IntBetween(1, 1000),
			Description:  "Maximum records in this page (1-1000).",
		},
		"next_cursor": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Cursor to pass as after for the next page; empty at the end.",
		},
		itemName: {
			Type:        schema.TypeList,
			Computed:    true,
			Description: "Records in this bounded page.",
			Elem:        &schema.Resource{Schema: itemFields},
		},
	}
}

func computedString(description string) *schema.Schema {
	return &schema.Schema{Type: schema.TypeString, Computed: true, Description: description}
}

func computedInt(description string) *schema.Schema {
	return &schema.Schema{Type: schema.TypeInt, Computed: true, Description: description}
}

func readTenantDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	id := d.Get("tenant_id").(string)
	var page dataPage[tenantData]
	if _, err := meta.(*client).do(ctx, http.MethodGet, "/provider/v1/tenants", nil, &page); err != nil {
		return diag.FromErr(err)
	}
	for _, tenant := range page.Items {
		if tenant.ID != id {
			continue
		}
		d.SetId(tenant.ID)
		return setDataSourceFields(d, flattenTenant(tenant, false))
	}
	return diag.Errorf("probectl tenant %q was not found", id)
}

func readTenantsDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var page dataPage[tenantData]
	if _, err := meta.(*client).do(ctx, http.MethodGet, "/provider/v1/tenants", nil, &page); err != nil {
		return diag.FromErr(err)
	}
	items := make([]map[string]any, 0, len(page.Items))
	for _, tenant := range page.Items {
		if tenant.ID == "" {
			return diag.Errorf("probectl provider tenant response omitted id")
		}
		items = append(items, flattenTenant(tenant, true))
	}
	d.SetId(stableID("probectl_tenants"))
	return setDataSourceFields(d, map[string]any{"tenants": items})
}

func readTestDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	id := d.Get("test_id").(string)
	var out testData
	c := meta.(*client)
	status, err := c.do(ctx, http.MethodGet, "/v1/tests/"+url.PathEscape(id), nil, &out)
	if status == http.StatusNotFound {
		return diag.Errorf("probectl test %q was not found in the configured tenant", id)
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if out.ID != id {
		return diag.Errorf("probectl test lookup %q returned mismatched id %q", id, out.ID)
	}
	if err := validateTenantItem(c.tenant, "test", out.ID, out.TenantID); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	return setDataSourceFields(d, flattenTest(out, false))
}

func readTestsDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var page dataPage[testData]
	path := dataPagePath("/v1/tests", d)
	c := meta.(*client)
	if _, err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return diag.FromErr(err)
	}
	items := make([]map[string]any, 0, len(page.Items))
	for _, test := range page.Items {
		if err := validateTenantItem(c.tenant, "test", test.ID, test.TenantID); err != nil {
			return diag.FromErr(err)
		}
		items = append(items, flattenTest(test, true))
	}
	d.SetId(stableID("probectl_tests", c.tenant, d.Get("after").(string), strconv.Itoa(d.Get("limit").(int))))
	return setDataSourceFields(d, map[string]any{"tests": items, "next_cursor": page.NextCursor})
}

func readAgentDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	id := d.Get("agent_id").(string)
	var out agentData
	c := meta.(*client)
	status, err := c.do(ctx, http.MethodGet, "/v1/agents/"+url.PathEscape(id), nil, &out)
	if status == http.StatusNotFound {
		return diag.Errorf("probectl agent %q was not found in the configured tenant", id)
	}
	if err != nil {
		return diag.FromErr(err)
	}
	if out.ID != id {
		return diag.Errorf("probectl agent lookup %q returned mismatched id %q", id, out.ID)
	}
	if err := validateTenantItem(c.tenant, "agent", out.ID, out.TenantID); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(out.ID)
	return setDataSourceFields(d, flattenAgent(out, false))
}

func readAgentsDataSource(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	var page dataPage[agentData]
	path := dataPagePath("/v1/agents", d)
	c := meta.(*client)
	if _, err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
		return diag.FromErr(err)
	}
	items := make([]map[string]any, 0, len(page.Items))
	for _, agent := range page.Items {
		if err := validateTenantItem(c.tenant, "agent", agent.ID, agent.TenantID); err != nil {
			return diag.FromErr(err)
		}
		items = append(items, flattenAgent(agent, true))
	}
	d.SetId(stableID("probectl_agents", c.tenant, d.Get("after").(string), strconv.Itoa(d.Get("limit").(int))))
	return setDataSourceFields(d, map[string]any{"agents": items, "next_cursor": page.NextCursor})
}

func validateTenantItem(configuredTenant, kind, id, responseTenant string) error {
	if id == "" {
		return fmt.Errorf("probectl %s response omitted id", kind)
	}
	if responseTenant == "" {
		return fmt.Errorf("probectl %s %q response omitted tenant_id", kind, id)
	}
	if configuredTenant != "" && responseTenant != configuredTenant {
		return fmt.Errorf("probectl %s %q belongs to tenant %q, not configured tenant %q", kind, id, responseTenant, configuredTenant)
	}
	return nil
}

func dataPagePath(base string, d *schema.ResourceData) string {
	query := url.Values{}
	if after := d.Get("after").(string); after != "" {
		query.Set("after", after)
	}
	query.Set("limit", strconv.Itoa(d.Get("limit").(int)))
	return base + "?" + query.Encode()
}

func flattenTenant(tenant tenantData, includeID bool) map[string]any {
	out := map[string]any{
		"slug": tenant.Slug, "name": tenant.Name, "status": tenant.Status,
		"isolation_model": tenant.IsolationModel, "residency": tenant.Residency,
		"created_at": tenant.CreatedAt,
	}
	if includeID {
		out["id"] = tenant.ID
	}
	return out
}

func flattenTest(test testData, includeID bool) map[string]any {
	out := map[string]any{
		"tenant_id": test.TenantID, "name": test.Name, "type": test.Type,
		"target": test.Target, "interval_seconds": test.IntervalSeconds,
		"timeout_seconds": test.TimeoutSeconds, "params": test.Params,
		"enabled": test.Enabled, "created_at": test.CreatedAt, "updated_at": test.UpdatedAt,
	}
	if includeID {
		out["id"] = test.ID
	}
	return out
}

func flattenAgent(agent agentData, includeID bool) map[string]any {
	out := map[string]any{
		"tenant_id": agent.TenantID, "name": agent.Name, "hostname": agent.Hostname,
		"agent_version": agent.AgentVersion, "status": agent.Status,
		"capabilities": agent.Capabilities, "spiffe_id": agent.SPIFFEID,
		"registered_at": agent.RegisteredAt, "last_seen_at": agent.LastSeenAt,
		"created_at": agent.CreatedAt,
	}
	if includeID {
		out["id"] = agent.ID
	}
	return out
}

func setDataSourceFields(d *schema.ResourceData, fields map[string]any) diag.Diagnostics {
	for key, value := range fields {
		if err := d.Set(key, value); err != nil {
			return diag.FromErr(fmt.Errorf("set Terraform data source field %s: %w", key, err))
		}
	}
	return nil
}
