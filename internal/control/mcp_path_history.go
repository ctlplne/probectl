// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) nativePathHistory(ctx context.Context, actor *auth.Principal, command mcp.PathHistoryCommand) (json.RawMessage, error) {
	b := nativeCanonicalDeviceBackend{server: s}
	if err := b.check(ctx, actor); err != nil {
		return nil, err
	}
	if s.requireMFA && !actor.MFASatisfied {
		return nil, apierror.Forbidden("current MFA is required to read path history")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	values := url.Values{"from": {command.From}, "to": {command.To}, "round_id": command.RoundIDs}
	if command.Limit != nil {
		values.Set("limit", strconv.Itoa(*command.Limit))
	}
	request, err := http.NewRequestWithContext(auth.WithPrincipal(ctx, actor), http.MethodGet, "/v1/tests/"+url.PathEscape(command.TestID)+"/path/history?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request.SetPathValue("id", command.TestID)
	query, err := parsePathHistoryQuery(request)
	if err != nil {
		return nil, err
	}
	readTest := func(active context.Context) (*store.Test, error) {
		if err := s.authorize(active, actor, permTestRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return nil, err
		}
		return s.pathDiscoveryTest(request.WithContext(auth.WithPrincipal(active, actor)))
	}
	test, err := readTest(ctx)
	if err != nil {
		return nil, err
	}
	if test.TenantID != actor.TenantID {
		return nil, tenancy.ErrNoTenant
	}
	rounds, err := s.readPathHistory(ctx, test.TenantID, pathHost(test.Target), query)
	if err != nil {
		return nil, err
	}
	type nativeRound struct {
		pathstore.Snapshot
		ID mcp.NativePathRoundID `json:"id"`
	}
	items := make([]nativeRound, 0, len(rounds))
	for _, round := range rounds {
		items = append(items, nativeRound{round, mcp.NativePathRoundID(round.ID)})
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		if err := b.check(active, actor); err != nil {
			return err
		}
		current, err := readTest(active)
		if err != nil {
			return err
		}
		if current.TenantID != test.TenantID || !current.UpdatedAt.Equal(test.UpdatedAt) {
			return apierror.Conflict("path test changed before publication")
		}
		return active.Err()
	}, func() {}); err != nil {
		return nil, err
	}
	return json.Marshal(map[string][]nativeRound{"items": items})
}
