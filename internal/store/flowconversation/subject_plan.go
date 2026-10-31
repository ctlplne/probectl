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

	"github.com/ctlplne/probectl/internal/crypto"
)

// SubjectErasurePlan is an immutable private selector, not authority or a
// completed erasure receipt. It never crosses public JSON/formatting boundaries.
type SubjectErasurePlan struct{ value *subjectErasurePlan }
type subjectErasurePlan struct {
	tenant  string
	request MaintenanceRequest
	wire    subjectPlanWire
}
type subjectPlanWire struct {
	Version int      `json:"version"`
	Subject string   `json:"subject"`
	Aliases []string `json:"aliases"`
	Salt    []byte   `json:"salt"`
}

func (SubjectErasurePlan) MarshalJSON() ([]byte, error) { return nil, errMessagePrivate }
func (*SubjectErasurePlan) UnmarshalJSON([]byte) error  { return errMessagePrivate }
func (SubjectErasurePlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "flowconversation.SubjectErasurePlan[private]")
}

// PrepareSubjectErasurePlan freezes aliases already resolved by a current
// privacy operation. Normalization never confers permission or validates the
// caller's destructive selector; that remains the lifecycle service's job.
func (c *Codec) PrepareSubjectErasurePlan(ctx context.Context, operation, subject string, aliases []string) (SubjectErasurePlan, error) {
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
	values := make([]string, 0, len(aliases)+1)
	values = append(values, strings.ToLower(strings.TrimSpace(subject)))
	for _, alias := range aliases {
		values = append(values, strings.ToLower(strings.TrimSpace(alias)))
	}
	sort.Strings(values)
	values = slices.Compact(values)
	salt, err := crypto.Random(32)
	if err != nil {
		return SubjectErasurePlan{}, ErrMessageUnavailable
	}
	plan := SubjectErasurePlan{&subjectErasurePlan{tenant: tenant,
		request: MaintenanceRequest{ID: operation, Kind: MaintenanceSubjectErase},
		wire:    subjectPlanWire{Version: 1, Subject: strings.TrimSpace(subject), Aliases: values, Salt: salt}}}
	body, err := c.subjectPlanBody(ctx, plan)
	if err != nil {
		clear(salt)
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
	if w.Version != 1 || w.Subject == "" || w.Subject != strings.TrimSpace(w.Subject) || !utf8.ValidString(w.Subject) || len(w.Salt) != 32 || bytes.Equal(w.Salt, make([]byte, 32)) || len(w.Aliases) == 0 {
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
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	canonical, err := json.Marshal(w)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, body) {
		clear(w.Salt)
		return SubjectErasurePlan{}, ErrMessageIntegrity
	}
	if err := ctx.Err(); err != nil {
		clear(w.Salt)
		return SubjectErasurePlan{}, err
	}
	return SubjectErasurePlan{&subjectErasurePlan{tenant: tenant, request: request, wire: w}}, nil
}
