// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"maps"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) seasonalTestRevision(ctx context.Context, actor *auth.Principal, testID string, expected *time.Time) (time.Time, error) {
	var version time.Time
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		version, err = s.seasonalTestInScope(ctx, sc, principal, testID, expected)
		return err
	})
	return version, err
}

func (s *Server) seasonalTestInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, testID string, expected *time.Time) (time.Time, error) {
	if err := s.authorize(ctx, actor, "test.read", auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
		return time.Time{}, err
	}
	test, err := (store.Tests{}).Get(ctx, sc, testID)
	if err != nil {
		return time.Time{}, err
	}
	if test.TenantID != sc.Tenant.String() || !test.Enabled || (expected != nil && !test.UpdatedAt.Equal(*expected)) {
		return time.Time{}, store.ErrAlertSeasonalChanged
	}
	return test.UpdatedAt, nil
}

func bindSeasonalTestSelector(rule alert.Rule, testID string) (alert.Rule, error) {
	if current := rule.Match["test_id"]; current != "" && current != testID {
		return alert.Rule{}, apierror.Validation("the selected test must match the rule's test_id label")
	}
	if rule.Match == nil {
		rule.Match = make(map[string]string, 1)
	} else {
		rule.Match = maps.Clone(rule.Match)
	}
	rule.Match["test_id"] = testID
	return rule, nil
}
