// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
)

type remediationDelegateSpy struct {
	proposeCalls []string
	listCalls    []string
	getCalls     []string
	approveCalls []string
	rejectCalls  []string
}

func (s *remediationDelegateSpy) Propose(_ context.Context, tenantID, _ string, in ProposeInput) (Proposal, error) {
	s.proposeCalls = append(s.proposeCalls, tenantID)
	return Proposal{ID: "proposal-" + tenantID, TenantID: tenantID, Kind: in.Kind, State: StateProposed}, nil
}

func (s *remediationDelegateSpy) List(_ context.Context, tenantID string) ([]Proposal, error) {
	s.listCalls = append(s.listCalls, tenantID)
	return []Proposal{{ID: "proposal-" + tenantID, TenantID: tenantID, State: StateProposed}}, nil
}

func (s *remediationDelegateSpy) Get(_ context.Context, tenantID, id string) (Proposal, error) {
	s.getCalls = append(s.getCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateProposed}, nil
}

func (s *remediationDelegateSpy) Approve(_ context.Context, tenantID, _, id, _ string) (Proposal, error) {
	s.approveCalls = append(s.approveCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateApproved}, nil
}

func (s *remediationDelegateSpy) Reject(_ context.Context, tenantID, _, id, _ string) (Proposal, error) {
	s.rejectCalls = append(s.rejectCalls, tenantID)
	return Proposal{ID: id, TenantID: tenantID, State: StateRejected}, nil
}

func (*remediationDelegateSpy) ApprovalsEnabled() bool { return true }

func TestLicenseReadOnlyRemediationMutationGateClockAdvancedDelegateSpy(t *testing.T) {
	readOnlyAt := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	now := readOnlyAt.Add(-time.Second)
	spy := &remediationDelegateSpy{}
	service := GateServiceWrites(spy, license.WriteCapability(func() bool {
		return now.Before(readOnlyAt)
	}))
	ctx := context.Background()
	tenants := []string{"tenant-a", "tenant-b"}

	for _, tenantID := range tenants {
		proposal, err := service.Propose(ctx, tenantID, "user:admin@example.test", ProposeInput{
			Kind: KindOpenTicket, Title: "inspect",
		})
		if err != nil {
			t.Fatalf("active propose for %s: %v", tenantID, err)
		}
		if _, err := service.Approve(ctx, tenantID, "user:admin@example.test", proposal.ID, "go"); err != nil {
			t.Fatalf("active approve for %s: %v", tenantID, err)
		}
		if _, err := service.Reject(ctx, tenantID, "user:admin@example.test", proposal.ID, "stop"); err != nil {
			t.Fatalf("active reject for %s: %v", tenantID, err)
		}
	}

	now = readOnlyAt
	for _, tenantID := range tenants {
		if _, err := service.List(ctx, tenantID); err != nil {
			t.Fatalf("read-only list for %s: %v", tenantID, err)
		}
		if _, err := service.Get(ctx, tenantID, "proposal-"+tenantID); err != nil {
			t.Fatalf("read-only get for %s: %v", tenantID, err)
		}
		mutations := []struct {
			name string
			call func() error
		}{
			{"propose", func() error {
				_, err := service.Propose(ctx, tenantID, "user:admin@example.test", ProposeInput{Kind: KindOpenTicket, Title: "blocked"})
				return err
			}},
			{"approve", func() error {
				_, err := service.Approve(ctx, tenantID, "user:admin@example.test", "proposal-"+tenantID, "blocked")
				return err
			}},
			{"reject", func() error {
				_, err := service.Reject(ctx, tenantID, "user:admin@example.test", "proposal-"+tenantID, "blocked")
				return err
			}},
		}
		for _, mutation := range mutations {
			if err := mutation.call(); !errors.Is(err, license.ErrReadOnly) {
				t.Fatalf("read-only %s for %s = %v, want ErrReadOnly", mutation.name, tenantID, err)
			}
		}
	}

	if len(spy.proposeCalls) != len(tenants) ||
		len(spy.approveCalls) != len(tenants) ||
		len(spy.rejectCalls) != len(tenants) {
		t.Fatalf("read-only mutation reached delegate: propose=%v approve=%v reject=%v",
			spy.proposeCalls, spy.approveCalls, spy.rejectCalls)
	}
	if len(spy.listCalls) != len(tenants) || len(spy.getCalls) != len(tenants) {
		t.Fatalf("read-only reads did not reach delegate: list=%v get=%v", spy.listCalls, spy.getCalls)
	}
	if !service.ApprovalsEnabled() {
		t.Fatal("read-only surface must preserve the delegate's readable approval configuration")
	}
}
