// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestSubjectSourceRefusesInvalidPurposeAndBorrowedContextsBeforeSQL(t *testing.T) {
	f := newMessageCodecFixture(t)
	request := maintenanceRequestFixture(f)
	pending := Invalidation{&invalidation{tenant: f.scope.TenantID, request: request, generation: 2}}
	allow := func(context.Context, string) error { return nil }
	fn := func(context.Context, SubjectErasurePlan) error {
		t.Error("invalid source context entered callback")
		return nil
	}
	var journal *Journal
	for _, ctx := range []context.Context{
		t.Context(), f.requestContext(t), tenancy.WithTenant(f.context, tenancy.ID(f.scope.OwnerID)),
		context.WithValue(f.context, subjectSourceLeaseKey{}, (*subjectSourceLease)(nil)),
		context.WithValue(f.context, tenantExportLeaseKey{}, (*operationLease)(nil)),
	} {
		if err := journal.withSubjectMatchSource(ctx, f.codec, pending, allow, fn); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("unscoped/request/foreign/source context reached pending source SQL", err)
		}
	}
	for _, kind := range []MaintenanceKind{MaintenanceTenantErase, MaintenanceRetention, MaintenanceKeyRotation, "model_flag"} {
		other := *pending.value
		other.request.Kind = kind
		if err := journal.withSubjectMatchSource(f.context, f.codec, Invalidation{&other}, allow, fn); !errors.Is(err, ErrMessageDenied) {
			t.Fatal("another pending purpose opened subject matching", err)
		}
	}
	if err := journal.withSubjectMatchSource(f.context, f.codec, pending, nil, fn); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing independent authority reached storage", err)
	}
	if err := journal.withSubjectMatchSource(f.context, f.codec, pending, allow, nil); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("missing source callback reached storage", err)
	}
	if err := journal.withSubjectReader(f.context, func(context.Context) error { t.Error("reader entered without source admission"); return nil }); !errors.Is(err, ErrMessageDenied) {
		t.Fatal("unregistered matching reader reached source", err)
	}
}

func TestSubjectSourceCleanupCarriesNoMatchingOrCreatorAuthority(t *testing.T) {
	f := newMessageCodecFixture(t)
	ctx := context.WithValue(f.requestContext(t), subjectSourceLeaseKey{}, &subjectSourceLease{})
	ctx = context.WithValue(ctx, operationLeaseKey{}, &operationLease{})
	ctx = context.WithValue(ctx, tenantExportLeaseKey{}, &operationLease{})
	canceled, stop := context.WithCancel(ctx)
	stop()
	clean, cancel := cleanupActivityContext(canceled, &activityRef{tenant: f.scope.TenantID})
	defer cancel()
	if clean.Err() != nil || auth.PrincipalFrom(clean) != nil || clean.Value(subjectSourceLeaseKey{}) != nil || clean.Value(operationLeaseKey{}) != nil || clean.Value(tenantExportLeaseKey{}) != nil {
		t.Fatal("source-free cleanup retained cancellation or source/creator authority")
	}
	if tenant, err := maintenanceTenant(clean); err != nil || tenant != f.scope.TenantID {
		t.Fatal("source-free cleanup lost exact tenant routing", err)
	}
}
