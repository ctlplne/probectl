// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package notify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

const (
	PSAContractVersion = "probectl-psa-ticket/v1"
	PSASignatureHeader = "X-Probectl-Signature"
	PSAContractHeader  = "X-Probectl-Contract"
)

type psaTicket struct {
	ExternalKey string            `json:"external_key"`
	Title       string            `json:"title"`
	Status      string            `json:"status"`
	Severity    incident.Severity `json:"severity"`
	OpenedAt    time.Time         `json:"opened_at"`
	LastSeenAt  time.Time         `json:"last_seen_at"`
	SignalCount int               `json:"signal_count"`
	Evidence    string            `json:"evidence"`
}

type psaEvent struct {
	Contract          string    `json:"contract"`
	IdempotencyKey    string    `json:"idempotency_key"`
	Action            string    `json:"action"`
	TenantScopeDigest string    `json:"tenant_scope_digest"`
	ExternalRef       string    `json:"external_ref,omitempty"`
	Ticket            psaTicket `json:"ticket"`
}

// psa is the vendor-neutral design-partner seam. It sends no raw tenant id,
// target, signal body, or credential. The receiving PSA maps the stable fields
// into its own customer/contract/ticket schema.
type psa struct {
	endpoint string
	secret   []byte
	client   Doer
}

func newPSA(endpoint, secret string, client Doer) *psa {
	return &psa{endpoint: strings.TrimRight(endpoint, "/"), secret: []byte(secret), client: clientOr(client)}
}

func (*psa) Name() string           { return "psa" }
func (*psa) Capability() Capability { return CapabilityTicket }

func (p *psa) Open(ctx context.Context, inc incident.Incident) (Delivery, error) {
	return p.deliver(ctx, "create", inc, "")
}

func (p *psa) Update(ctx context.Context, inc incident.Incident, ref string) error {
	_, err := p.deliver(ctx, "update", inc, ref)
	return err
}

func (p *psa) Resolve(ctx context.Context, inc incident.Incident, ref string) error {
	_, err := p.deliver(ctx, "resolve", inc, ref)
	return err
}

func (p *psa) Reopen(ctx context.Context, inc incident.Incident, ref string) error {
	_, err := p.deliver(ctx, "reopen", inc, ref)
	return err
}

func (p *psa) deliver(ctx context.Context, action string, inc incident.Incident, ref string) (Delivery, error) {
	if len(p.secret) == 0 {
		return Delivery{}, errors.New("psa: signing secret is empty")
	}
	status := string(inc.Status)
	if status == "" {
		status = "open"
	}
	key := fmt.Sprintf("probectl:%s:%s:%d", inc.ID, action, inc.SignalCount)
	if action == "resolve" || action == "reopen" {
		key = fmt.Sprintf("probectl:%s:%s", inc.ID, action)
	}
	tenantDigest := "sha256:" + hex.EncodeToString(crypto.Hash([]byte(inc.TenantID)))
	event := psaEvent{
		Contract: PSAContractVersion, IdempotencyKey: key, Action: action,
		TenantScopeDigest: tenantDigest, ExternalRef: ref,
		Ticket: psaTicket{
			ExternalKey: inc.ID, Title: "probectl incident " + inc.ID, Status: status,
			Severity: inc.Severity, OpenedAt: inc.StartedAt, LastSeenAt: inc.LastSeenAt,
			SignalCount: inc.SignalCount,
			Evidence:    "redacted evidence remains tenant-scoped in probectl; use a signed incident export",
		},
	}
	body, err := json.Marshal(event)
	if err != nil {
		return Delivery{}, err
	}
	headers := map[string]string{
		PSAContractHeader:  PSAContractVersion,
		PSASignatureHeader: "sha256=" + hex.EncodeToString(crypto.Sign(p.secret, body)),
		"Idempotency-Key":  key,
	}
	response, err := doJSONBytes(ctx, p.client, http.MethodPost, p.endpoint, headers, body)
	if err != nil {
		return Delivery{}, err
	}
	if action != "create" {
		return Delivery{ExternalRef: ref, Status: status}, nil
	}
	var receipt struct {
		ExternalRef string `json:"external_ref"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(response, &receipt); err != nil || strings.TrimSpace(receipt.ExternalRef) == "" {
		return Delivery{}, errors.New("psa: create response requires external_ref")
	}
	return Delivery{ExternalRef: receipt.ExternalRef, Status: firstNonEmpty(receipt.Status, "open")}, nil
}
