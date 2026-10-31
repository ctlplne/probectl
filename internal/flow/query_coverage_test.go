// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestQueryViewMemoryPagesRemainTenantAndOwnerScoped(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	store := NewMemoryQueryViewStore(nil, 0)
	store.now = func() time.Time { return clock }
	save := func(tenant, owner, name, visibility string) SavedQueryView {
		t.Helper()
		definition := queryViewFixture()
		definition.Name, definition.Visibility = name, visibility
		item, err := store.SaveQueryView(ctx, tenant, owner, SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Second)
		return item
	}
	shared := save("red", "alice", "A shared", "tenant")
	private := save("red", "alice", "B private", "private")
	owned := save("red", "bob", "C owned", "private")
	foreign := save("blue", "bob", "D foreign", "tenant")

	first, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != shared.ID || first.Next != shared.ID {
		t.Fatalf("first page escaped scope or skipped cursor: %+v %v", first, err)
	}
	second, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{After: first.Next, Limit: 1})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != owned.ID || second.Next != "" {
		t.Fatalf("second page changed scope/order: %+v %v", second, err)
	}
	alice, err := store.ListQueryViews(ctx, "red", "alice", QueryViewList{})
	if err != nil || len(alice.Items) != 2 || alice.Items[0].ID != shared.ID || alice.Items[1].ID != private.ID {
		t.Fatalf("owner-private view missing or foreign owner visible: %+v %v", alice, err)
	}
	blue, err := store.ListQueryViews(ctx, "blue", "bob", QueryViewList{})
	if err != nil || len(blue.Items) != 1 || blue.Items[0].ID != foreign.ID {
		t.Fatalf("tenant partition crossed: %+v %v", blue, err)
	}
	for _, hidden := range []string{private.ID, foreign.ID} {
		if _, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{After: hidden}); !errors.Is(err, ErrQueryViewNotFound) {
			t.Fatalf("hidden cursor became a disclosure oracle: %v", err)
		}
	}
	for _, input := range []QueryViewList{{Limit: 1001}, {Sort: "sql"}, {Tab: "all-tenants"}, {Visibility: "public"}} {
		if _, err := store.ListQueryViews(ctx, "red", "bob", input); err == nil {
			t.Fatalf("unbounded/unsupported list input accepted: %+v", input)
		}
	}

	favorite := true
	if err := store.SetQueryViewPreference(ctx, "red", "bob", shared.ID, &favorite, true); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Second)
	if err := store.SetQueryViewPreference(ctx, "red", "bob", owned.ID, nil, true); err != nil {
		t.Fatal(err)
	}
	recent, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "recents", Limit: 1})
	if err != nil || len(recent.Items) != 1 || recent.Items[0].ID != owned.ID || recent.Next != owned.ID {
		t.Fatalf("recents order/cursor wrong: %+v %v", recent, err)
	}
	rest, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "recents", After: recent.Next})
	if err != nil || len(rest.Items) != 1 || rest.Items[0].ID != shared.ID {
		t.Fatalf("recents continuation wrong: %+v %v", rest, err)
	}
	favorites, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "favorites"})
	if err != nil || len(favorites.Items) != 1 || favorites.Items[0].ID != shared.ID {
		t.Fatalf("preference crossed owner/view: %+v %v", favorites, err)
	}
	if _, err := store.ListQueryViews(ctx, "red", "bob", QueryViewList{Tab: "recents", After: private.ID}); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatalf("private recent cursor accepted: %v", err)
	}
	if err := store.DeleteQueryView(ctx, "red", "alice", private.ID, "invalid"); err == nil {
		t.Fatal("invalid revision deleted view")
	}
	if err := store.DeleteQueryView(ctx, "red", "alice", private.ID, "2"); !errors.Is(err, ErrQueryViewConflict) {
		t.Fatalf("stale revision deleted view: %v", err)
	}
	if _, err := store.GetQueryView(ctx, "red", "alice", private.ID); err != nil {
		t.Fatalf("failed delete mutated row: %v", err)
	}
}

func TestPreparedQueryFilterTypedNegationAndRanges(t *testing.T) {
	type tc struct {
		name, field string
		op          QueryOperator
		values      []string
		pass, fail  string
	}
	cases := []tc{
		{"not equal", "dst_port", QueryNotEqual, []string{"443"}, "80", "443"},
		{"not in", "dst_port", QueryNotIn, []string{"80", "443"}, "8080", "80"},
		{"contains", "src_as_name", QueryContains, []string{"transit"}, "MY TRANSIT", "peer"},
		{"not contains", "src_as_name", QueryNotContains, []string{"transit"}, "peer", "TRANSIT"},
		{"regex", "src_as_name", QueryRegex, []string{"^Transit"}, "Transit-X", "Peer-X"},
		{"not regex", "src_as_name", QueryNotRegex, []string{"^Transit"}, "Peer-X", "Transit-X"},
		{"cidr", "src_addr", QueryCIDR, []string{"192.0.2.0/24"}, "192.0.2.7", "198.51.100.7"},
		{"not cidr", "src_addr", QueryNotCIDR, []string{"192.0.2.0/24"}, "198.51.100.7", "192.0.2.7"},
		{"any flag", "tcp_flag_names", QueryHasAnyFlag, []string{"SYN", "ACK"}, "SYN,FIN", "FIN"},
		{"no flag", "tcp_flag_names", QueryHasNoFlag, []string{"SYN", "ACK"}, "FIN", "ACK,FIN"},
		{"bit names", "tcp_flag_names", QueryBitAnd, []string{"2"}, "SYN,ACK", "FIN"},
		{"numeric between", "raw_bytes", QueryBetween, []string{"10", "20"}, "15", "21"},
		{"numeric outside", "raw_bytes", QueryNotBetween, []string{"10", "20"}, "21", "15"},
		{"timestamp between", "ts", QueryBetween, []string{"2026-10-28T12:00:00Z", "2026-10-28T12:01:00Z"}, "2026-10-28T12:00:30Z", "2026-10-28T12:02:00Z"},
		{"timestamp greater", "ts", QueryGreater, []string{"2026-10-28T12:00:00Z"}, "2026-10-28T12:00:01Z", "2026-10-28T11:59:59Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			filter, err := PrepareQueryFilter(&QueryFilterGroup{Conditions: []QueryPredicate{{Field: c.field, Op: c.op, Values: c.values}}})
			if err != nil {
				t.Fatal(err)
			}
			if !filter.Matches(func(field string) string {
				if field != c.field {
					t.Fatalf("unexpected field %q", field)
				}
				return c.pass
			}) {
				t.Fatal("positive typed value rejected")
			}
			if filter.Matches(func(field string) string {
				if field != c.field {
					t.Fatalf("unexpected field %q", field)
				}
				return c.fail
			}) {
				t.Fatal("negative typed value accepted")
			}
		})
	}
}

func TestQualityReceiptProtoRoundTripKeepsTenantAndWindow(t *testing.T) {
	base := validQualityReceipt()
	want, err := ValidateQualityReceipt(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateQualityReceipt(QualityReceiptFromProto(base.ToProto()))
	if err != nil {
		t.Fatalf("bus roundtrip no longer validates: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quality receipt changed over bus: got %+v want %+v", got, want)
	}
	if got := QualityReceiptFromProto(nil); !reflect.DeepEqual(got, QualityReceipt{}) {
		t.Fatalf("nil bus receipt was accepted: %+v", got)
	}
	base.LastValidRecordAt = nil
	base.RecordsDecoded = 0
	base = EvaluateQualityState(base, base.WindowEndedAt)
	got = QualityReceiptFromProto(base.ToProto())
	if got.LastValidRecordAt != nil || got.Reason != QualityReasonNoValidRecords {
		t.Fatalf("empty decode window invented a valid record: %+v", got)
	}
}

type viewScanFixture struct {
	definition []byte
	version    int64
	err        error
}

func (r viewScanFixture) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = "79edb183-b784-44bb-a733-36c115d7583f"
	*dest[1].(*string) = "red"
	*dest[2].(*string) = "alice"
	*dest[3].(*[]byte) = r.definition
	*dest[4].(*int64) = r.version
	*dest[5].(*time.Time) = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	*dest[6].(*time.Time) = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	*dest[7].(*bool) = false
	*dest[8].(**time.Time) = nil
	return nil
}

type filterScanFixture struct {
	expression []byte
	version    int64
	err        error
}

func (r filterScanFixture) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = "5b6e522d-9d44-40e6-a848-c22d5378efcf"
	*dest[1].(*string) = "red"
	*dest[2].(*string) = "owned filter"
	*dest[3].(*string) = "description"
	*dest[4].(*[]byte) = r.expression
	*dest[5].(*int64) = r.version
	*dest[6].(*string) = "alice"
	*dest[7].(*time.Time) = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	*dest[8].(*time.Time) = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	return nil
}

func TestStoredQueryScannerRejectsCorruptionBeforeReturningConfiguration(t *testing.T) {
	definition, err := json.Marshal(queryViewFixture())
	if err != nil {
		t.Fatal(err)
	}
	good := viewScanFixture{definition: definition, version: 1}
	item, err := scanQueryView(good)
	if err != nil || item.TenantID != "red" || item.OwnerID != "alice" || item.Version != "1" || item.Definition.Name != "Complete query" {
		t.Fatalf("valid stored view failed: %+v %v", item, err)
	}
	for name, bad := range map[string]viewScanFixture{
		"missing":          {err: pgx.ErrNoRows},
		"zero revision":    {definition: definition, version: 0},
		"oversized":        {definition: []byte(strings.Repeat("x", 2*MaxPlanGrammarBytes+1)), version: 1},
		"malformed":        {definition: []byte(`{"plan":`), version: 1},
		"unknown field":    {definition: []byte(`{"untrusted_sql":"SELECT *"}`), version: 1},
		"trailing content": {definition: append(append([]byte{}, definition...), []byte(` {}`)...), version: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanQueryView(bad); err == nil {
				t.Fatal("corrupt stored query returned to caller")
			}
		})
	}
	if _, err := scanQueryView(viewScanFixture{err: pgx.ErrNoRows}); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatalf("missing query leaked storage detail: %v", err)
	}
	if _, err := NewPostgresQueryViewStore(nil, 0, nil).GetQueryView(context.Background(), "red", "alice", item.ID); err == nil {
		t.Fatal("missing DB accepted as an empty view")
	}

	expression, err := json.Marshal(QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := scanQueryFilter(filterScanFixture{expression: expression, version: 1})
	if err != nil || filter.TenantID != "red" || filter.VersionText != "1" {
		t.Fatalf("valid stored filter failed: %+v %v", filter, err)
	}
	for name, bad := range map[string]filterScanFixture{
		"oversized":         {expression: []byte(strings.Repeat("x", 2*MaxPlanGrammarBytes+1)), version: 1},
		"malformed":         {expression: []byte(`{"conditions":`), version: 1},
		"unknown predicate": {expression: []byte(`{"conditions":[{"field":"tenant_id","op":"eq","values":["foreign"]}]}`), version: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanQueryFilter(bad); err == nil {
				t.Fatal("corrupt saved filter returned to caller")
			}
		})
	}
	if _, err := scanQueryFilter(filterScanFixture{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("scanner hid missing row: %v", err)
	}
}

func TestQueryViewListFiltersAndPreferenceBudgetKeepTheirOwnScope(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	store := NewMemoryQueryViewStore(nil, 0)
	store.now = func() time.Time { return clock }
	add := func(name, visibility string) SavedQueryView {
		t.Helper()
		def := queryViewFixture()
		def.Name, def.Visibility = name, visibility
		item, err := store.SaveQueryView(ctx, "red", "alice", SaveQueryView{Definition: def})
		if err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Minute)
		return item
	}
	first := add("Alpha", "tenant")
	second := add("Beta", "private")
	third := add("Gamma", "tenant")
	for _, tc := range []struct {
		list QueryViewList
		want []string
	}{
		{QueryViewList{Visibility: "tenant", Owner: "alice", Sort: "created_at"}, []string{third.ID, first.ID}},
		{QueryViewList{Search: "beta", Label: "edge"}, []string{second.ID}},
		{QueryViewList{Search: "beta", Label: "missing"}, nil},
		{QueryViewList{Visibility: "private", Owner: "bob"}, nil},
	} {
		page, err := store.ListQueryViews(ctx, "red", "alice", tc.list)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			ids = append(ids, item.ID)
		}
		if len(ids) != len(tc.want) || len(ids) > 0 && !reflect.DeepEqual(ids, tc.want) {
			t.Fatalf("list %+v returned %v, want %v", tc.list, ids, tc.want)
		}
	}
	updated, err := store.SaveQueryView(ctx, "red", "alice", SaveQueryView{ID: first.ID, Version: first.Version, Definition: first.Definition})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListQueryViews(ctx, "red", "alice", QueryViewList{Sort: "updated_at", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != updated.ID {
		t.Fatalf("updated sort did not lead with latest revision: %+v %v", page, err)
	}
	store.maxBytes = 1 // apply a tighter preference budget after the views exist
	if err := store.SetQueryViewPreference(ctx, "red", "alice", first.ID, nil, true); err != nil {
		t.Fatalf("first preference refused: %v", err)
	}
	favorite := true
	if err := store.SetQueryViewPreference(ctx, "red", "alice", second.ID, &favorite, false); !errors.Is(err, ErrQueryViewBudget) {
		t.Fatalf("preference cap not enforced: %v", err)
	}
	if got, err := store.GetQueryView(ctx, "red", "alice", second.ID); err != nil || got.Favorite {
		t.Fatalf("failed preference write mutated view: %+v %v", got, err)
	}
	if err := store.SetQueryViewPreference(ctx, "blue", "alice", first.ID, &favorite, false); !errors.Is(err, ErrQueryViewNotFound) {
		t.Fatalf("foreign tenant preference accepted: %v", err)
	}
	if _, err := store.GetQueryView(ctx, "red", "", first.ID); err == nil {
		t.Fatal("ownerless read accepted")
	}
	if _, err := store.ListQueryViews(ctx, "", "alice", QueryViewList{}); err == nil {
		t.Fatal("tenantless list accepted")
	}
}

func TestQualityReceiptRejectsContradictoryWindowsAndStates(t *testing.T) {
	base := validQualityReceipt()
	for name, mutate := range map[string]func(*QualityReceipt){
		"missing tenant":                         func(r *QualityReceipt) { r.TenantID = "" },
		"unknown protocol":                       func(r *QualityReceipt) { r.Protocol = "invented" },
		"unknown sampling":                       func(r *QualityReceipt) { r.SamplingState = "invented" },
		"missing window":                         func(r *QualityReceipt) { r.WindowStartedAt = time.Time{} },
		"reverse window":                         func(r *QualityReceipt) { r.WindowStartedAt = r.WindowEndedAt.Add(time.Second) },
		"overlong window":                        func(r *QualityReceipt) { r.WindowStartedAt = r.WindowEndedAt.Add(-25 * time.Hour) },
		"future packet":                          func(r *QualityReceipt) { r.LastPacketAt = r.WindowEndedAt.Add(time.Second) },
		"future valid record":                    func(r *QualityReceipt) { at := r.LastPacketAt.Add(time.Second); r.LastValidRecordAt = &at },
		"decoded without timestamp":              func(r *QualityReceipt) { r.LastValidRecordAt = nil },
		"wrong derived state":                    func(r *QualityReceipt) { r.State = QualityStateDegraded },
		"template protocol unknown":              func(r *QualityReceipt) { r.TemplateState = QualityTemplateUnknown },
		"template-free protocol claims template": func(r *QualityReceipt) { r.Protocol = ProtoNetFlow5 },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			mutate(&r)
			if _, err := ValidateQualityReceipt(r); err == nil {
				t.Fatal("contradictory receipt accepted")
			}
		})
	}
}

func TestPreparedPredicateFailsClosedOnMalformedRuntimeValues(t *testing.T) {
	for _, tc := range []struct {
		p     QueryPredicate
		value string
	}{
		{QueryPredicate{Field: "src_addr", Op: QueryCIDR, Values: []string{"192.0.2.0/24"}}, "not-an-ip"},
		{QueryPredicate{Field: "raw_bytes", Op: QueryBetween, Values: []string{"10", "20"}}, "not-a-number"},
		{QueryPredicate{Field: "ts", Op: QueryBetween, Values: []string{"2026-10-28T12:00:00Z", "2026-10-28T12:01:00Z"}}, "not-a-time"},
		{QueryPredicate{Field: "tcp_flag_names", Op: QueryBitAnd, Values: []string{"2"}}, "UNKNOWN"},
	} {
		prepared, err := PrepareQueryFilter(&QueryFilterGroup{Conditions: []QueryPredicate{tc.p}})
		if err != nil {
			t.Fatal(err)
		}
		if prepared.Matches(func(string) string { return tc.value }) {
			t.Fatalf("malformed runtime value %q passed %+v", tc.value, tc.p)
		}
	}
	for _, raw := range []QueryPredicate{
		{Field: "tenant_id", Op: QueryEqual, Values: []string{"red"}},
		{Field: "src_as_name", Op: QueryRegex, Values: []string{"["}},
		{Field: "raw_bytes", Op: QueryBitAnd, Values: []string{"not-a-mask"}},
		{Field: "src_addr", Op: "raw_sql", Values: []string{"1=1"}},
	} {
		if _, err := prepareQueryPredicate(raw); err == nil {
			t.Fatalf("malformed internal predicate compiled: %+v", raw)
		}
	}
}

func TestSavedFilterPaginationDeleteAndCancellationRemainTenantScoped(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryQueryFilterStore(0)
	input := SaveQueryFilter{Name: "owned", Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}}}
	ids := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		item, err := store.SaveQueryFilter(ctx, "red", "alice", input)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, item.ID)
	}
	sort.Strings(ids)
	foreign, err := store.SaveQueryFilter(ctx, "blue", "alice", input)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListQueryFilters(ctx, "red", "", 2)
	if err != nil || len(page.Items) != 2 || page.Items[0].ID != ids[0] || page.Items[1].ID != ids[1] || page.Next != ids[1] {
		t.Fatalf("first page crossed scope/skipped cursor: %+v %v", page, err)
	}
	last, err := store.ListQueryFilters(ctx, "red", page.Next, 2)
	if err != nil || len(last.Items) != 1 || last.Items[0].ID != ids[2] || last.Next != "" {
		t.Fatalf("continuation changed scope: %+v %v", last, err)
	}
	if _, err := store.ListQueryFilters(ctx, "blue", "", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetQueryFilter(ctx, "red", foreign.ID); !errors.Is(err, ErrQueryFilterNotFound) {
		t.Fatalf("foreign filter visible: %v", err)
	}
	for _, size := range []int{0, 1001} {
		if _, err := store.ListQueryFilters(ctx, "red", "", size); err == nil {
			t.Fatalf("unbounded size %d accepted", size)
		}
	}
	if _, err := store.ListQueryFilters(ctx, "", "", 1); err == nil {
		t.Fatal("tenantless list accepted")
	}
	if err := store.DeleteQueryFilter(ctx, "red", "", ids[0], 1); err == nil {
		t.Fatal("actorless delete accepted")
	}
	if err := store.DeleteQueryFilter(ctx, "red", "alice", ids[0], 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetQueryFilter(ctx, "red", ids[0]); !errors.Is(err, ErrQueryFilterNotFound) {
		t.Fatalf("deleted filter remained readable: %v", err)
	}
	if _, err := store.GetQueryFilter(ctx, "", ids[1]); err == nil {
		t.Fatal("tenantless read accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.ListQueryFilters(canceled, "red", "", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read continued: %v", err)
	}
}

func TestCollectorRunCancellationClosesBoundListeners(t *testing.T) {
	collector, err := New(testConfig(), &captureEmitter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- collector.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for collector.localAddr("netflow") == "" {
		select {
		case err := <-done:
			t.Fatalf("collector exited before binding: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("collector never bound the configured listener")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not stop on cancel")
	}
	if got := collector.localAddr("netflow"); got != "" {
		t.Fatalf("listener remained bound: %s", got)
	}
	// The production backoff helper must honor a canceled context rather than
	// delaying shutdown after an emission error.
	started := time.Now()
	collector.defaultSleep(ctx, time.Hour)
	if time.Since(started) > time.Second {
		t.Fatal("canceled emit backoff delayed shutdown")
	}
}
