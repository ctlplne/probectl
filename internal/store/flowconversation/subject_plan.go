// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SubjectErasurePlan is an immutable private selector, not authority or a
// completed erasure receipt. It never crosses public JSON/formatting boundaries.
type SubjectErasurePlan struct{ value *subjectErasurePlan }
type subjectErasurePlan struct {
	tenant   string
	request  MaintenanceRequest
	wire     subjectPlanWire
	borrowed bool
}
type subjectPlanWire struct {
	Version     int             `json:"version"`
	Subject     string          `json:"subject"`
	Aliases     []string        `json:"aliases"`
	Salt        []byte          `json:"salt"`
	Application json.RawMessage `json:"application,omitempty"`
}

func (SubjectErasurePlan) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*SubjectErasurePlan) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (SubjectErasurePlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.SubjectErasurePlan[private]")
}

// PrepareSubjectErasurePlan freezes aliases already resolved by a current
// privacy operation. Normalization never confers permission or validates the
// caller's destructive selector; that remains the lifecycle service's job.
func (c *Codec) PrepareSubjectErasurePlan(ctx context.Context, operation, subject string, aliases []string, application ...[]byte) (SubjectErasurePlan, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return SubjectErasurePlan{}, err
	}
	if err := c.available(); err != nil {
		return SubjectErasurePlan{}, err
	}
	if !historyID(operation) || !utf8.ValidString(subject) || strings.TrimSpace(subject) == "" {
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	if len(application) > 1 {
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	// Charge input before allocating a canonical copy; duplicates also cost work.
	used := len(subject)
	if used > c.budget.PlainBytes {
		return SubjectErasurePlan{}, ErrMessageBudget
	}
	for _, alias := range aliases {
		if len(alias) >= c.budget.PlainBytes-used {
			return SubjectErasurePlan{}, ErrMessageBudget
		}
		used += len(alias) + 1
		if !utf8.ValidString(alias) || strings.TrimSpace(alias) == "" {
			return SubjectErasurePlan{}, ErrMessageIntegrity
		}
	}
	var app []byte
	version := 1
	if len(application) == 1 {
		if len(application[0]) > c.budget.PlainBytes-used {
			return SubjectErasurePlan{}, ErrMessageBudget
		}
		if !exactMessageJSON(ctx, application[0]) {
			return SubjectErasurePlan{}, messageError(ctx, ErrMessageIntegrity)
		}
		var err error
		app, err = json.Marshal(json.RawMessage(application[0]))
		if err != nil || len(app) == 0 || app[0] != '{' {
			clear(app)
			return SubjectErasurePlan{}, ErrMessageIntegrity
		}
		version = 2
	}
	values := make([]string, 0, len(aliases)+1)
	values = append(values, strings.ToLower(strings.TrimSpace(subject)))
	for _, alias := range aliases {
		values = append(values, strings.ToLower(strings.TrimSpace(alias)))
	}
	sort.Strings(values)
	values = slices.Compact(values)
	salt, err := crypto.Random(32)
	if err != nil {
		clear(app)
		return SubjectErasurePlan{}, ErrMessageUnavailable
	}
	plan := SubjectErasurePlan{&subjectErasurePlan{tenant: tenant,
		request: MaintenanceRequest{ID: operation, Kind: MaintenanceSubjectErase},
		wire:    subjectPlanWire{Version: version, Subject: strings.TrimSpace(subject), Aliases: values, Salt: salt, Application: app}}}
	body, err := c.subjectPlanBody(ctx, plan)
	if err != nil {
		clear(salt)
		clear(app)
		return SubjectErasurePlan{}, err
	}
	defer clear(body)
	plan.value.request.Binding = bindingArray(crypto.Hash(body))
	return plan, nil
}

func (c *Codec) subjectPlanBody(ctx context.Context, plan SubjectErasurePlan) ([]byte, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.available(); err != nil {
		return nil, err
	}
	if plan.value == nil || plan.value.tenant != tenant || !historyID(plan.value.request.ID) || plan.value.request.Kind != MaintenanceSubjectErase || !validSubjectPlanWire(plan.value.wire) {
		return nil, ErrMessageIntegrity
	}
	body, err := json.Marshal(plan.value.wire)
	if err != nil {
		return nil, ErrMessageIntegrity
	}
	if len(body) > c.budget.PlainBytes {
		clear(body)
		return nil, ErrMessageBudget
	}
	if err := ctx.Err(); err != nil {
		clear(body)
		return nil, err
	}
	return body, nil
}

func validSubjectPlanWire(w subjectPlanWire) bool {
	if (w.Version != 1 && w.Version != 2) || (w.Version == 1 && len(w.Application) != 0) || (w.Version == 2 && (len(w.Application) == 0 || w.Application[0] != '{' || !utf8.Valid(w.Application) || !json.Valid(w.Application))) || w.Subject == "" || w.Subject != strings.TrimSpace(w.Subject) || !utf8.ValidString(w.Subject) || len(w.Salt) != 32 || bytes.Equal(w.Salt, make([]byte, 32)) || len(w.Aliases) == 0 {
		return false
	}
	for i, alias := range w.Aliases {
		if alias == "" || !utf8.ValidString(alias) || alias != strings.ToLower(strings.TrimSpace(alias)) || i > 0 && w.Aliases[i-1] >= alias {
			return false
		}
	}
	_, found := slices.BinarySearch(w.Aliases, strings.ToLower(w.Subject))
	return found
}

// VisitSelector lends private application metadata, never message source or a
// grant. Application schema/identity belongs to lifecycle code. Independent
// current authority must surround Resume and actual source admission separately.
// Copies cannot mutate the approved plan and are cleared after the visitor.
func (p SubjectErasurePlan) VisitSelector(ctx context.Context, fn func(string, []string, []byte) error) error {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || p.value == nil || p.value.tenant != tenant.String() || auth.PrincipalFrom(ctx) != nil || fn == nil || !validSubjectPlanWire(p.value.wire) {
		return messageError(ctx, ErrMessageDenied)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	aliases, app := slices.Clone(p.value.wire.Aliases), bytes.Clone(p.value.wire.Application)
	defer clear(aliases)
	defer clear(app)
	if err := fn(p.value.wire.Subject, aliases, app); err != nil {
		return err
	}
	return ctx.Err()
}

// Release clears private selector state after its owning lifecycle operation
// finishes. It neither acknowledges source drain nor changes durable intent.
func (p SubjectErasurePlan) Release() {
	if p.value != nil && !p.value.borrowed {
		clearSubjectSourcePlan(p)
	}
}

func subjectPlanAAD(tenant string, request MaintenanceRequest) []byte {
	aad := []byte("probectl.flow.conversation.subject_plan.v1\x00" + tenant + "\x00" + request.ID + "\x00" + string(request.Kind) + "\x00")
	return append(aad, request.Binding[:]...)
}

func (c *Codec) sealSubjectPlan(ctx context.Context, plan SubjectErasurePlan) (string, error) {
	body, err := c.subjectPlanBody(ctx, plan)
	if err != nil {
		return "", err
	}
	defer clear(body)
	p := plan.value
	if !validMaintenanceRequest(p.request) || bindingArray(crypto.Hash(body)) != p.request.Binding {
		return "", ErrMessageIntegrity
	}
	stored, err := c.seal(ctx, p.tenant, body, subjectPlanAAD(p.tenant, p.request))
	if err != nil || !c.hasScheme(stored) {
		return "", messageError(ctx, ErrMessageUnavailable)
	}
	if len(stored) > c.budget.StoredBytes {
		return "", ErrMessageBudget
	}
	return stored, ctx.Err()
}

func (c *Codec) openSubjectPlan(ctx context.Context, request MaintenanceRequest, stored string) (SubjectErasurePlan, error) {
	tenant, err := maintenanceTenant(ctx)
	if err != nil {
		return SubjectErasurePlan{}, err
	}
	if err := c.available(); err != nil {
		return SubjectErasurePlan{}, err
	}
	if !validMaintenanceRequest(request) || request.Kind != MaintenanceSubjectErase || !c.hasScheme(stored) {
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	if len(stored) > c.budget.StoredBytes {
		return SubjectErasurePlan{}, ErrMessageBudget
	}
	body, err := c.open(ctx, tenant, stored, subjectPlanAAD(tenant, request))
	defer clear(body)
	if err != nil {
		return SubjectErasurePlan{}, messageError(ctx, ErrMessageIntegrity)
	}
	if len(body) > c.budget.PlainBytes {
		return SubjectErasurePlan{}, ErrMessageBudget
	}
	var w subjectPlanWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&w); err != nil || !validSubjectPlanWire(w) || bindingArray(crypto.Hash(body)) != request.Binding {
		clear(w.Salt)
		clear(w.Application)
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	canonical, err := json.Marshal(w)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, body) {
		clear(w.Salt)
		clear(w.Application)
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(w.Salt)
		clear(w.Application)
		return SubjectErasurePlan{}, err
	}
	return SubjectErasurePlan{&subjectErasurePlan{tenant: tenant, request: request, wire: w}}, nil
}
