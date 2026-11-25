// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

type haloMapping struct {
	ClientID       int32  `json:"customer_id"`
	ContractID     int32  `json:"contract_id"`
	SiteID         int32  `json:"site_id"`
	UserID         int32  `json:"user_id"`
	TicketTypeID   int32  `json:"ticket_type_id"`
	PriorityID     int32  `json:"priority_id"`
	OpenStatus     int32  `json:"open_status"`
	ResolvedStatus int32  `json:"resolved_status"`
	ProgressField  int32  `json:"progress_field_id"`
	DueAfter       string `json:"due_after"`
	ConsoleOrigin  string `json:"console_origin"`
}

type haloPSA struct {
	tenant     string
	incidentUI *url.URL
	mapping    haloMapping
	dueAfter   time.Duration
	api        *HaloAPI
}

var (
	_ LifecycleConnector    = (*haloPSA)(nil)
	_ openRecoveryConnector = (*haloPSA)(nil)
	_ ticketStatusConnector = (*haloPSA)(nil)
)

func configuredHaloPSA(tenant, endpoint, resolvedSecret string, injected Doer) (*haloPSA, error) {
	var settings struct {
		haloMapping
		HaloCredentials
	}
	decoder := json.NewDecoder(strings.NewReader(resolvedSecret))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&settings) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF {
		return nil, errors.New("halopsa: invalid connection settings")
	}
	console, err := psaHTTPSURL(settings.ConsoleOrigin)
	if err != nil || (console.Path != "" && console.Path != "/") {
		return nil, errors.New("halopsa: configure the HTTPS probectl console origin")
	}
	due, err := time.ParseDuration(settings.DueAfter)
	m := settings.haloMapping
	if err != nil || due <= 0 || tenant == "" || m.ClientID <= 0 || m.ContractID < 0 ||
		m.SiteID < 0 || m.UserID < 0 || m.TicketTypeID <= 0 || m.PriorityID <= 0 ||
		m.OpenStatus <= 0 || m.ResolvedStatus <= 0 || m.OpenStatus == m.ResolvedStatus || m.ProgressField <= 0 {
		return nil, errors.New("halopsa: ticket mapping is incomplete")
	}
	api, err := NewHaloAPI(endpoint, settings.HaloCredentials, injected)
	if err != nil {
		return nil, err
	}
	return &haloPSA{
		tenant: tenant, mapping: m, dueAfter: due, incidentUI: console.JoinPath("ui", "incidents"), api: api,
	}, nil
}

func (*haloPSA) Name() string           { return "halopsa" }
func (*haloPSA) Capability() Capability { return CapabilityTicket }

type haloTicket struct {
	ID           int32  `json:"id"`
	ClientID     int32  `json:"client_id"`
	ContractID   int32  `json:"contract_id"`
	ThirdPartyID string `json:"third_party_id_string"`
	Status       int32  `json:"status_id"`
}

type haloField struct {
	ID    int32  `json:"id"`
	Value string `json:"value"`
}

type haloTicketWrite struct {
	ID           int32       `json:"id,omitempty"`
	ClientID     int32       `json:"client_id,omitempty"`
	ContractID   int32       `json:"contract_id,omitempty"`
	SiteID       int32       `json:"site_id,omitempty"`
	UserID       int32       `json:"user_id,omitempty"`
	TicketType   int32       `json:"tickettype_id,omitempty"`
	Priority     int32       `json:"priority_id,omitempty"`
	Status       int32       `json:"status_id,omitempty"`
	ThirdPartyID string      `json:"third_party_id_string,omitempty"`
	Summary      string      `json:"summary,omitempty"`
	Details      string      `json:"details,omitempty"`
	TargetDate   *time.Time  `json:"targetdate,omitempty"`
	Fields       []haloField `json:"customfields,omitempty"`
}

func (c *haloPSA) ticketKey(tenant, incidentID string) (string, error) {
	if tenant != c.tenant || incidentID == "" {
		return "", errors.New("halopsa: incident is outside the registered tenant")
	}
	digest := crypto.Hash([]byte(tenant + "\x00" + incidentID))
	return "pbctl-" + hex.EncodeToString(digest)[:40], nil
}

func haloID(id int32) string { return strconv.FormatInt(int64(id), 10) }

func haloTicketID(ref string) (int32, bool) {
	id, err := strconv.ParseInt(ref, 10, 32)
	if err != nil || id <= 0 || id > math.MaxInt32 || strconv.FormatInt(id, 10) != ref {
		return 0, false
	}
	return int32(id), true
}

func (c *haloPSA) ownsClient(ticket haloTicket, key string) bool {
	return ticket.ID > 0 && ticket.ClientID == c.mapping.ClientID && ticket.ThirdPartyID == key
}

func (c *haloPSA) ownsTicket(ticket haloTicket, key string) bool {
	return c.ownsClient(ticket, key) && (c.mapping.ContractID == 0 || ticket.ContractID == c.mapping.ContractID)
}

func (c *haloPSA) validateContract(ctx context.Context) error {
	if c.mapping.ContractID == 0 {
		return nil
	}
	var contract struct {
		ID       int32 `json:"id"`
		ClientID int32 `json:"client_id"`
	}
	err := c.api.Get(ctx, &contract, nil, "ClientContract", haloID(c.mapping.ContractID))
	if err != nil {
		return err
	}
	if contract.ID != c.mapping.ContractID || contract.ClientID != c.mapping.ClientID {
		return errors.New("halopsa: contract is outside the registered customer")
	}
	return nil
}

func (c *haloPSA) ownedTicket(ctx context.Context, id int32, key string) (haloTicket, error) {
	var ticket haloTicket
	if err := c.api.Get(ctx, &ticket, nil, "Tickets", haloID(id)); err != nil {
		return ticket, err
	}
	if ticket.ID != id || !c.ownsTicket(ticket, key) {
		return haloTicket{}, errors.New("halopsa: ticket is outside the registered mapping")
	}
	return ticket, nil
}

func (c *haloPSA) query(ctx context.Context, query url.Values, limit int) ([]haloTicket, error) {
	query.Set("client_id", haloID(c.mapping.ClientID))
	query.Set("pageinate", "true")
	query.Set("page_no", "1")
	query.Set("page_size", strconv.Itoa(limit))
	if c.mapping.ContractID > 0 {
		query.Set("ticketcontract_id", haloID(c.mapping.ContractID))
	}
	var response struct {
		Tickets []haloTicket `json:"tickets"`
		Count   *int         `json:"record_count"`
	}
	if err := c.api.Get(ctx, &response, query, "Tickets"); err != nil {
		return nil, err
	}
	if response.Count == nil || *response.Count != len(response.Tickets) || len(response.Tickets) > limit {
		return nil, errors.New("halopsa: incomplete or oversized ticket search response")
	}
	return response.Tickets, nil
}

func (c *haloPSA) fields(inc incident.Incident) []haloField {
	return []haloField{{ID: c.mapping.ProgressField, Value: fmt.Sprintf(
		"%d signals, last seen %s", inc.SignalCount, inc.LastSeenAt.UTC().Format(time.RFC3339))}}
}

func (c *haloPSA) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	found, err := c.RecoverOpen(ctx, inc)
	if err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
	}
	if found.ExternalRef != "" {
		return found, nil
	}
	if err := c.validateContract(ctx); err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
	}
	key, err := c.ticketKey(inc.TenantID, inc.ID)
	if err != nil {
		return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
	}
	link := *c.incidentUI
	link.RawQuery = url.Values{"incident": {inc.ID}}.Encode()
	due := time.Now().UTC().Add(c.dueAfter)
	m := c.mapping
	body, err := c.api.Post(ctx, []haloTicketWrite{{
		ClientID: m.ClientID, ContractID: m.ContractID, SiteID: m.SiteID, UserID: m.UserID,
		TicketType: m.TicketTypeID, Priority: m.PriorityID, Status: m.OpenStatus, ThirdPartyID: key,
		TargetDate: &due, Summary: "probectl incident " + inc.ID, Fields: c.fields(inc),
		Details: attributedNotification(ctx, fmt.Sprintf("probectl incident (%s). Signals: %d. Open the tenant incident to export its signed evidence: %s",
			inc.Severity, inc.SignalCount, link.String())),
	}}, nil, "Tickets")
	if err != nil {
		if errors.Is(err, errHaloPostNotSent) {
			return Delivery{}, fmt.Errorf("%w: %w", errTicketCreateRejected, err)
		}
		return Delivery{}, ticketCreateError(err)
	}
	var created haloTicket
	if json.Unmarshal(body, &created) != nil || !c.ownsTicket(created, key) {
		return Delivery{}, errors.New("halopsa: create response did not identify the owned ticket")
	}
	return Delivery{ExternalRef: haloID(created.ID), Status: "open"}, nil
}

func (c *haloPSA) RecoverOpen(ctx context.Context, inc incident.Incident) (Delivery, error) {
	key, err := c.ticketKey(inc.TenantID, inc.ID)
	if err != nil {
		return Delivery{}, err
	}
	tickets, err := c.query(ctx, url.Values{"third_party_id_string": {key}}, 2)
	if err != nil || len(tickets) == 0 {
		return Delivery{}, err
	}
	if len(tickets) != 1 || !c.ownsClient(tickets[0], key) {
		return Delivery{}, errors.New("halopsa: ticket lookup did not identify one owned ticket")
	}
	id := tickets[0].ID
	if c.mapping.ContractID > 0 {
		if _, err := c.ownedTicket(ctx, id, key); err != nil {
			return Delivery{}, err
		}
	}
	return Delivery{ExternalRef: haloID(id), Status: "open"}, nil
}

func (c *haloPSA) Update(ctx context.Context, inc incident.Incident, ref string) error {
	return c.transition(ctx, inc, ref, 0)
}

func (c *haloPSA) Resolve(ctx context.Context, inc incident.Incident, ref string) error {
	return c.transition(ctx, inc, ref, c.mapping.ResolvedStatus)
}

func (c *haloPSA) Reopen(ctx context.Context, inc incident.Incident, ref string) error {
	return c.transition(ctx, inc, ref, c.mapping.OpenStatus)
}

func (c *haloPSA) transition(ctx context.Context, inc incident.Incident, ref string, status int32) error {
	key, err := c.ticketKey(inc.TenantID, inc.ID)
	if err != nil {
		return err
	}
	id, ok := haloTicketID(ref)
	if !ok {
		return errors.New("halopsa: malformed ticket reference")
	}
	if _, err := c.ownedTicket(ctx, id, key); err != nil {
		return err
	}
	_, err = c.api.Post(ctx, []haloTicketWrite{{ID: id, Status: status, Fields: c.fields(inc)}}, nil, "Tickets")
	return err
}

func (*haloPSA) statusBatchSize() int { return 8 }

func (c *haloPSA) ResolvedTickets(ctx context.Context, snapshots []TicketStatusSnapshot) ([]TicketStatusSnapshot, error) {
	if len(snapshots) == 0 {
		return nil, nil
	}
	if len(snapshots) > c.statusBatchSize() {
		return nil, errors.New("halopsa: ticket status batch exceeds its limit")
	}
	type expected struct {
		snapshot TicketStatusSnapshot
		key      string
	}
	byID := make(map[int32]expected, len(snapshots))
	ids := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		key, err := c.ticketKey(snapshot.TenantID, snapshot.IncidentID)
		id, ok := haloTicketID(snapshot.ExternalRef)
		if err != nil || !ok || snapshot.Connector != c.Name() || byID[id].key != "" {
			return nil, errors.New("halopsa: ticket status batch has an invalid or ambiguous mapping")
		}
		byID[id] = expected{snapshot, key}
		ids = append(ids, snapshot.ExternalRef)
	}
	items, err := c.query(ctx, url.Values{
		"ticketids": {strings.Join(ids, ",")}, "status_id": {haloID(c.mapping.ResolvedStatus)},
	}, len(snapshots))
	if err != nil {
		return nil, err
	}
	resolved := make([]TicketStatusSnapshot, 0, len(items))
	for _, item := range items {
		match, exists := byID[item.ID]
		if !exists || !c.ownsClient(item, match.key) || item.Status != c.mapping.ResolvedStatus {
			return nil, errors.New("halopsa: ticket status response did not match the requested ownership")
		}
		delete(byID, item.ID)
		// The list projection omits contract_id. Verify the individual ticket
		// whenever the connection has a contract binding.
		if c.mapping.ContractID > 0 {
			current, err := c.ownedTicket(ctx, item.ID, match.key)
			if err != nil {
				return nil, err
			}
			if current.Status != c.mapping.ResolvedStatus {
				continue
			}
		}
		resolved = append(resolved, match.snapshot)
	}
	return resolved, nil
}
