// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

type AutotaskCredentials struct {
	UserName        string `json:"username"`
	Secret          string `json:"api_secret"`
	IntegrationCode string `json:"integration_code"`
}

// AutotaskAPI binds an Autotask credential to one validated REST zone.
type AutotaskAPI struct {
	base        *url.URL
	credentials AutotaskCredentials
	client      Doer
}

func NewAutotaskAPI(endpoint string, credentials AutotaskCredentials, injected Doer) (*AutotaskAPI, error) {
	base, err := psaHTTPSURL(endpoint)
	if err != nil || !strings.HasSuffix(strings.TrimRight(base.Path, "/"), "/atservicesrest/v1.0") {
		return nil, errors.New("autotask: configure the HTTPS REST v1.0 zone URL")
	}
	for _, value := range []string{credentials.UserName, credentials.Secret, credentials.IntegrationCode} {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("autotask: API authentication is incomplete")
		}
	}
	return &AutotaskAPI{base: base, credentials: credentials, client: clientWithoutRedirects(injected)}, nil
}

func (c *AutotaskAPI) headers() map[string]string {
	return map[string]string{
		"UserName": c.credentials.UserName, "Secret": c.credentials.Secret, "ApiIntegrationCode": c.credentials.IntegrationCode,
	}
}

// Get decodes the item returned by a point lookup in the bound zone.
func (c *AutotaskAPI) Get(ctx context.Context, result any, resource ...string) error {
	body, err := doJSONBytes(ctx, c.client, http.MethodGet, c.base.JoinPath(resource...).String(), c.headers(), nil)
	if err != nil {
		return err
	}
	var response struct {
		Item json.RawMessage `json:"item"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Item) == 0 ||
		bytes.Equal(response.Item, []byte("null")) || json.Unmarshal(response.Item, result) != nil {
		return errors.New("autotask: invalid item response")
	}
	return nil
}

type AutotaskFilter struct {
	Operator string `json:"op"`
	Field    string `json:"field"`
	Value    any    `json:"value"`
}

// Query reads a bounded page. The API supplies a null nextPageUrl when there
// are no more rows. An absent marker cannot establish that a result is complete.
func (c *AutotaskAPI) Query(ctx context.Context, entity string, fields []string, filters []AutotaskFilter, result any) error {
	query := struct {
		IncludeFields []string         `json:"IncludeFields"`
		Filter        []AutotaskFilter `json:"filter"`
	}{IncludeFields: fields, Filter: filters}
	body, err := c.write(ctx, http.MethodPost, query, entity, "query")
	if err != nil {
		return err
	}
	var response struct {
		Items json.RawMessage `json:"items"`
		Page  struct {
			NextURL json.RawMessage `json:"nextPageUrl"`
		} `json:"pageDetails"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Items) == 0 || bytes.Equal(response.Items, []byte("null")) ||
		!bytes.Equal(response.Page.NextURL, []byte("null")) || json.Unmarshal(response.Items, result) != nil {
		return errors.New("autotask: incomplete ticket or contract query response")
	}
	return nil
}

// Create posts one resource and verifies the vendor's acknowledgement.
func (c *AutotaskAPI) Create(ctx context.Context, entity string, payload any) (int64, error) {
	body, err := c.write(ctx, http.MethodPost, payload, entity)
	if err != nil {
		return 0, err
	}
	var reply struct {
		ID int64 `json:"itemId"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.ID <= 0 {
		return 0, errors.New("autotask: create response did not identify the resource")
	}
	return reply.ID, nil
}

func (c *AutotaskAPI) write(ctx context.Context, method string, payload any, resource ...string) ([]byte, error) {
	return doJSON(ctx, c.client, method, c.base.JoinPath(resource...).String(), c.headers(), payload)
}

// autotaskMapping binds one registered tenant to one Autotask company and an
// optional contract. Status and priority IDs come from that company's PSA setup.
type autotaskMapping struct {
	TenantID       string        `json:"-"`
	CompanyID      int64         `json:"company_id"`
	ContractID     int64         `json:"contract_id"`
	QueueID        int64         `json:"queue_id"`
	Priority       int64         `json:"priority"`
	OpenStatus     int64         `json:"open_status"`
	ResolvedStatus int64         `json:"resolved_status"`
	DueAfter       time.Duration `json:"-"`
	ProgressField  string        `json:"progress_field"`
}

type autotask struct {
	incidentUI *url.URL
	mapping    autotaskMapping
	api        *AutotaskAPI
}

var _ LifecycleConnector = (*autotask)(nil)

func configuredAutotask(tenant, endpoint, resolvedSecret string, client Doer) (*autotask, error) {
	var settings struct {
		autotaskMapping
		AutotaskCredentials
		ConsoleOrigin string `json:"console_origin"`
		DueAfter      string `json:"due_after"`
	}
	decoder := json.NewDecoder(strings.NewReader(resolvedSecret))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errors.New("autotask: invalid connection settings")
	}
	due, err := time.ParseDuration(settings.DueAfter)
	if err != nil {
		return nil, errors.New("autotask: due_after must be a positive duration")
	}
	settings.TenantID = tenant
	settings.autotaskMapping.DueAfter = due
	return newAutotask(endpoint, settings.ConsoleOrigin, settings.autotaskMapping, settings.AutotaskCredentials, client)
}

func newAutotask(endpoint, consoleOrigin string, mapping autotaskMapping, credentials AutotaskCredentials, injected Doer) (*autotask, error) {
	console, err := psaHTTPSURL(consoleOrigin)
	if err != nil || strings.TrimRight(console.Path, "/") != "" {
		return nil, errors.New("autotask: configure the HTTPS probectl console origin")
	}
	if mapping.TenantID == "" || mapping.CompanyID <= 0 || mapping.ContractID < 0 || mapping.QueueID < 0 ||
		mapping.Priority <= 0 || mapping.OpenStatus <= 0 || mapping.ResolvedStatus <= 0 ||
		mapping.OpenStatus == mapping.ResolvedStatus || mapping.DueAfter <= 0 || strings.TrimSpace(mapping.ProgressField) == "" {
		return nil, errors.New("autotask: ticket mapping is incomplete")
	}
	api, err := NewAutotaskAPI(endpoint, credentials, injected)
	if err != nil {
		return nil, err
	}
	return &autotask{incidentUI: console.JoinPath("ui", "incidents"), mapping: mapping, api: api}, nil
}

func (*autotask) Name() string           { return "autotask" }
func (*autotask) Capability() Capability { return CapabilityTicket }

type autotaskTicketRecord struct {
	ID         int64  `json:"id"`
	CompanyID  int64  `json:"companyID"`
	ContractID int64  `json:"contractID"`
	ExternalID string `json:"externalID"`
	Status     int64  `json:"status"`
}

type autotaskTicketWrite struct {
	ID          int64           `json:"id,omitempty"`
	CompanyID   int64           `json:"companyID,omitempty"`
	ContractID  int64           `json:"contractID,omitempty"`
	QueueID     int64           `json:"queueID,omitempty"`
	Priority    int64           `json:"priority,omitempty"`
	Status      int64           `json:"status,omitempty"`
	Due         *time.Time      `json:"dueDateTime,omitempty"`
	ExternalID  string          `json:"externalID,omitempty"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	Fields      []autotaskField `json:"userDefinedFields,omitempty"`
}

type autotaskField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (c *autotask) incidentKey(inc incident.Incident) (string, error) {
	if inc.TenantID != c.mapping.TenantID || inc.ID == "" {
		return "", errors.New("autotask: incident is outside the registered tenant")
	}
	digest := crypto.Hash([]byte(inc.TenantID + "\x00" + inc.ID))
	// Autotask caps externalID at 50 characters. The ID is safe to expose
	// and includes the tenant even when two connectors share a PSA company.
	return "pbctl-" + hex.EncodeToString(digest)[:40], nil
}

func (c *autotask) description(inc incident.Incident) string {
	link := *c.incidentUI
	link.RawQuery = url.Values{"incident": {inc.ID}}.Encode()
	return fmt.Sprintf("probectl incident (%s). Signals: %d. Open the tenant incident to export its signed evidence: %s",
		inc.Severity, inc.SignalCount, link.String())
}

func (c *autotask) progress(inc incident.Incident) []autotaskField {
	value := fmt.Sprintf("%d signals, last seen %s", inc.SignalCount, inc.LastSeenAt.UTC().Format(time.RFC3339))
	return []autotaskField{{Name: c.mapping.ProgressField, Value: value}}
}

func (c *autotask) owns(record autotaskTicketRecord, externalID string) bool {
	return record.ID > 0 && record.CompanyID == c.mapping.CompanyID && record.ExternalID == externalID &&
		(c.mapping.ContractID == 0 || record.ContractID == c.mapping.ContractID)
}

func (c *autotask) queryTickets(ctx context.Context, filters ...AutotaskFilter) ([]autotaskTicketRecord, error) {
	var items []autotaskTicketRecord
	err := c.api.Query(ctx, "Tickets",
		[]string{"id", "companyID", "contractID", "externalID", "status"},
		append([]AutotaskFilter{{"eq", "companyID", c.mapping.CompanyID}}, filters...), &items)
	return items, err
}

func (c *autotask) find(ctx context.Context, externalID string) (int64, error) {
	items, err := c.queryTickets(ctx, AutotaskFilter{"eq", "externalID", externalID})
	if err != nil {
		return 0, err
	}
	if len(items) > 1 {
		return 0, errors.New("autotask: ticket lookup did not identify a unique result")
	}
	if len(items) == 0 {
		return 0, nil
	}
	if !c.owns(items[0], externalID) {
		return 0, errors.New("autotask: ticket lookup returned a different ownership mapping")
	}
	return items[0].ID, nil
}

func (*autotask) statusBatchSize() int { return 50 }

func (c *autotask) ResolvedTickets(ctx context.Context, snapshots []TicketStatusSnapshot) ([]TicketStatusSnapshot, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	if len(snapshots) > c.statusBatchSize() {
		return nil, errors.New("autotask: ticket status batch exceeds its limit")
	}
	type expected struct {
		snapshot   TicketStatusSnapshot
		externalID string
	}
	byID := make(map[int64]expected, len(snapshots))
	ids := make([]int64, 0, len(snapshots))
	for _, snapshot := range snapshots {
		key, err := c.incidentKey(incident.Incident{TenantID: snapshot.TenantID, ID: snapshot.IncidentID})
		id, ok := autotaskTicketID(snapshot.ExternalRef)
		if err != nil || !ok || snapshot.Connector != c.Name() || byID[id].externalID != "" {
			return nil, errors.New("autotask: ticket status batch has an invalid or ambiguous mapping")
		}
		byID[id] = expected{snapshot, key}
		ids = append(ids, id)
	}
	items, err := c.queryTickets(ctx, AutotaskFilter{"in", "id", ids}, AutotaskFilter{"eq", "status", c.mapping.ResolvedStatus})
	if err != nil {
		return nil, err
	}
	resolved := make([]TicketStatusSnapshot, 0, len(items))
	for _, item := range items {
		match, exists := byID[item.ID]
		if !exists || !c.owns(item, match.externalID) || item.Status != c.mapping.ResolvedStatus {
			return nil, errors.New("autotask: ticket status response did not match the requested ownership")
		}
		delete(byID, item.ID)
		resolved = append(resolved, match.snapshot)
	}
	return resolved, nil
}

func (c *autotask) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	delivery, err := c.RecoverOpen(ctx, inc)
	if err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
	}
	if delivery.ExternalRef != "" {
		return delivery, nil
	}
	key, err := c.incidentKey(inc)
	if err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
	}
	due := time.Now().UTC().Add(c.mapping.DueAfter)
	id, err := c.api.Create(ctx, "Tickets", autotaskTicketWrite{
		CompanyID: c.mapping.CompanyID, ContractID: c.mapping.ContractID, QueueID: c.mapping.QueueID,
		Priority: c.mapping.Priority, Status: c.mapping.OpenStatus, Due: &due, ExternalID: key,
		Title: "probectl incident " + inc.ID, Description: attributedNotification(ctx, c.description(inc)), Fields: c.progress(inc),
	})
	if err != nil {
		return Delivery{}, ticketCreateError(err)
	}
	return Delivery{ExternalRef: strconv.FormatInt(id, 10), Status: "open"}, nil
}

func (c *autotask) RecoverOpen(ctx context.Context, inc incident.Incident) (Delivery, error) {
	key, err := c.incidentKey(inc)
	if err != nil {
		return Delivery{}, err
	}
	id, err := c.find(ctx, key)
	if err != nil || id == 0 {
		return Delivery{}, err
	}
	return Delivery{ExternalRef: strconv.FormatInt(id, 10), Status: "open"}, nil
}

func (c *autotask) Update(ctx context.Context, inc incident.Incident, ref string) error {
	return c.patch(ctx, inc, ref, 0)
}

func (c *autotask) Resolve(ctx context.Context, inc incident.Incident, ref string) error {
	return c.patch(ctx, inc, ref, c.mapping.ResolvedStatus)
}

func (c *autotask) Reopen(ctx context.Context, inc incident.Incident, ref string) error {
	return c.patch(ctx, inc, ref, c.mapping.OpenStatus)
}

func (c *autotask) patch(ctx context.Context, inc incident.Incident, ref string, status int64) error {
	key, err := c.incidentKey(inc)
	if err != nil {
		return err
	}
	id, ok := autotaskTicketID(ref)
	if !ok {
		return errors.New("autotask: malformed ticket reference")
	}
	var ticket autotaskTicketRecord
	if err := c.api.Get(ctx, &ticket, "Tickets", ref); err != nil {
		return err
	}
	if ticket.ID != id || !c.owns(ticket, key) {
		return errors.New("autotask: ticket is no longer owned by the registered mapping")
	}
	_, err = c.api.write(ctx, http.MethodPatch, autotaskTicketWrite{
		ID: id, Status: status, Fields: c.progress(inc),
	}, "Tickets")
	return err
}

func autotaskTicketID(ref string) (int64, bool) {
	id, err := strconv.ParseInt(ref, 10, 64)
	return id, err == nil && id > 0 && strconv.FormatInt(id, 10) == ref
}
