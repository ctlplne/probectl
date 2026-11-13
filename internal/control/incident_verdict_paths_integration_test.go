// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentVerdictPathsKeepOriginalRoundsCurrentBindingAndTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	paths := pathstore.NewMemory()
	reader := &verdictPathPublicationStore{Store: paths}
	f.server.pathStore = reader
	seedInterfaceRoleMCPConsent(f)
	type selected struct {
		actor      *auth.Principal
		id, testID string
		input      incident.VerdictInput
		publish    incidentEvidenceFinalizer
	}
	lanes := map[string]selected{}
	for lane, tenant := range f.tenants {
		value := selected{id: gouuid.NewString()}
		sender := gouuid.NewString()
		definition := seedVerdictRealHTTPTest(t, f, tenant, sender, "https://service.example/health", "unused-in-this-storage-proof")
		value.testID = definition.ID
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permIncidentRead, permTestRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO incidents(tenant_id,id,title,entity_context_id,entity_id,identity_lookup_attempted) VALUES($1,$2,'original path verdict',$3,$4,true)`, tenant, value.id, f.contextID, f.routerID); err != nil {
				return err
			}
			current, err := readCurrentUserAuthorityScope(ctx, sc, f.users[tenant])
			if err == nil {
				value.actor = auth.ClonePrincipal(current.principal)
			}
			return err
		})
		at := f.observedAt(tenant)
		p := verdictOriginalPath(incidentVerdictEvidence{tenantID: tenant, from: at}).rounds[0].Path
		if lane == 1 {
			p.Hops[0].Nodes[0].Received = 0
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := paths.Save(pathstore.WithDiscoveryCompletedAt(pathstore.WithDiscoveryStartedAt(ctx, at), at), tenant, &p); err != nil {
			t.Fatal(err)
		}
		value.input = incident.VerdictInput{From: at, To: at.Add(time.Nanosecond)}
		got, err := f.server.computeIncidentVerdictWithPublication(ctx, value.actor, value.id, value.input.From, value.input.To, 128<<20, nil, &value.publish)
		if err != nil || got.Domain != incident.FaultUnknown || value.publish == nil {
			t.Fatal("path evidence invented a fault or lost final authority", got.Domain, err)
		}
		want := 1 - lane
		for _, index := range []int{1, 2} {
			if len(got.Hypotheses[index].Against) != want {
				t.Fatal("path round crossed tenant or disappeared from exact window", lane, index, len(got.Hypotheses[index].Against))
			}
			if want != 0 && (got.Hypotheses[index].Against[0].SourceKind != "control_plane_path" || got.Hypotheses[index].Against[0].EvidenceID != "") {
				t.Fatal("control-plane path was presented as agent evidence")
			}
		}
		proveIncidentVerdictServedReaders(t, f, tenant, value.id, value.input, got)
		proveIncidentVerdictSignedExport(t, f, tenant, value.id, value.input, got)
		if _, err := f.server.computeIncidentVerdictWithPublication(ctx, value.actor, value.id, value.input.From, value.input.To, 128<<20, nil, &value.publish); err != nil {
			t.Fatal("capture original publication after independent served controls", err)
		}
		lanes[tenant] = value
	}
	a, b := f.tenants[0], f.tenants[1]
	value := lanes[a]
	reader.mutateTenant = a
	if err := value.publish(tenancy.WithTenant(t.Context(), tenancy.ID(a))); err == nil {
		t.Fatal("changed original path body retained publication authority")
	}
	reader.mutateTenant = ""
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2`, a, value.testID)
		return err
	})
	if err := value.publish(tenancy.WithTenant(t.Context(), tenancy.ID(a))); err == nil {
		t.Fatal("withdrawn original path binding retained publication authority")
	}
	if err := lanes[b].publish(tenancy.WithTenant(t.Context(), tenancy.ID(b))); err != nil {
		t.Fatal("tenant A withdrawal changed tenant B's selected rounds", err)
	}
	// PostgreSQL/RLS, served TLS/native/signing and binding withdrawal are
	// real; path rounds are modeled and are not physical traceroute proof.
}

type verdictPathPublicationStore struct {
	pathstore.Store
	mutateTenant string
}

func (s *verdictPathPublicationStore) History(ctx context.Context, tenant, target string, query pathstore.HistoryQuery) ([]pathstore.Snapshot, error) {
	rounds, err := s.Store.History(ctx, tenant, target, query)
	if err == nil && tenant == s.mutateTenant && len(query.IDs) != 0 && len(rounds) != 0 {
		rounds[0].Path.Hops[0].Nodes[0].Received = 0
	}
	return rounds, err
}
