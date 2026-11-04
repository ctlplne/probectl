// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

const redTenant = "00000000-0000-0000-0000-000000000011"
const blueTenant = "00000000-0000-0000-0000-000000000022"

var redScope = Scope{redTenant, "alice@example.test"}

type memoryRepository struct {
	mu     sync.Mutex
	locks  map[string]*sync.RWMutex
	epochs map[string]epoch
	tokens map[string]string
	items  map[string]manifest
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{locks: map[string]*sync.RWMutex{}, epochs: map[string]epoch{}, tokens: map[string]string{}, items: map[string]manifest{}}
}
func (r *memoryRepository) lease(ctx context.Context, tenant string, exclusive bool, fn func(context.Context) error) error {
	r.mu.Lock()
	lock := r.locks[tenant]
	if lock == nil {
		lock = &sync.RWMutex{}
		r.locks[tenant] = lock
	}
	r.mu.Unlock()
	if exclusive {
		lock.Lock()
		defer lock.Unlock()
	} else {
		lock.RLock()
		defer lock.RUnlock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(ctx)
}
func (r *memoryRepository) state(_ context.Context, tenant string) (epoch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.epochs[tenant]
	if v.Generation == 0 {
		v.Generation = 1
		r.epochs[tenant] = v
	}
	return v, nil
}
func (r *memoryRepository) reserve(_ context.Context, m manifest, budget int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.epochs[m.TenantID]
	if state.Invalidating || state.Generation != m.Generation {
		return ErrInvalidating
	}
	used := int64(0)
	for _, v := range r.items {
		if v.TenantID == m.TenantID {
			used += v.ChargedBytes
		}
	}
	if m.ChargedBytes > budget || used > budget-m.ChargedBytes {
		return ErrBudget
	}
	r.items[m.TenantID+"/"+m.ID] = m
	return nil
}
func (r *memoryRepository) publish(_ context.Context, m manifest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := r.epochs[m.TenantID]
	if state.Invalidating || state.Generation != m.Generation {
		return ErrInvalidating
	}
	m.Ready = true
	r.items[m.TenantID+"/"+m.ID] = m
	return nil
}
func (r *memoryRepository) get(_ context.Context, scope Scope, id string) (manifest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.items[scope.TenantID+"/"+id]
	if !ok || !m.Ready || m.Owner != scope.Owner {
		return manifest{}, ErrNotFound
	}
	return m, nil
}
func (r *memoryRepository) remove(_ context.Context, tenant, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, tenant+"/"+id)
	return nil
}
func (r *memoryRepository) expired(_ context.Context, tenant string, now time.Time, limit int) ([]manifest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := []manifest{}
	for _, m := range r.items {
		if m.TenantID == tenant && (!m.Ready || !m.ExpiresAt.After(now)) {
			result = append(result, m)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}
func (r *memoryRepository) beginInvalidation(ctx context.Context, tenant, token string, prepare Preparation) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if prepare != nil {
		if err := prepare(ctx, tenancy.Scope{Tenant: tenancy.ID(tenant)}); err != nil {
			return false, err
		}
	}
	v := r.epochs[tenant]
	if v.Generation == 0 {
		v.Generation = 1
	}
	v.Generation++
	v.Invalidating = true
	r.epochs[tenant] = v
	r.tokens[tenant] = token
	return true, nil
}
func (r *memoryRepository) endInvalidation(_ context.Context, tenant, token string, _ bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.epochs[tenant]
	if !v.Invalidating || r.tokens[tenant] != token {
		return ErrInvalidating
	}
	v.Generation++
	v.Invalidating = false
	r.epochs[tenant] = v
	delete(r.tokens, tenant)
	return nil
}
func (r *memoryRepository) clear(_ context.Context, tenant string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, m := range r.items {
		if m.TenantID == tenant {
			delete(r.items, key)
		}
	}
	return nil
}
func (r *memoryRepository) any(_ context.Context, tenant string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.items {
		if m.TenantID == tenant {
			return true, nil
		}
	}
	return false, nil
}

func (r *memoryRepository) reclaimable(ctx context.Context, tenant string, now time.Time) (bool, error) {
	items, err := r.expired(ctx, tenant, now, 1)
	return len(items) != 0, err
}

type fixtureFence struct{}

func (fixtureFence) WithTenantWrites(ctx context.Context, tenants []string, fn func(context.Context) error) error {
	if len(tenants) != 1 || !canonicalID(tenants[0]) {
		return tenancy.ErrNoTenant
	}
	return fn(ctx)
}

type observedObjects struct {
	objectstore.Store
	reads      atomic.Int64
	puts       atomic.Int64
	failPut    atomic.Int64
	failDelete atomic.Bool
}

func (s *observedObjects) GetLimited(ctx context.Context, key string, limit int64) (objectstore.Object, error) {
	s.reads.Add(1)
	return s.Store.GetLimited(ctx, key, limit)
}
func (s *observedObjects) Put(ctx context.Context, key, content string, data []byte) error {
	if s.puts.Add(1) == s.failPut.Load() {
		return errors.New("injected object put failure")
	}
	return s.Store.Put(ctx, key, content, data)
}
func (s *observedObjects) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	if s.failDelete.Load() {
		return 0, errors.New("injected object deletion failure")
	}
	return s.Store.DeletePrefix(ctx, prefix)
}

func fixtureService(t *testing.T) (*Service, *memoryRepository, *observedObjects) {
	t.Helper()
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("qa-snapshot", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryRepository()
	objects := &observedObjects{Store: objectstore.NewMemory()}
	s := &Service{repo: repo, objects: objects, router: tenancy.PooledRouter{}, fence: fixtureFence{}, validate: func(context.Context, Scope, json.RawMessage) error { return nil }, config: Config{TempDir: t.TempDir()}.defaults(), now: time.Now, seal: sealer.Seal, open: sealer.Open, hasScheme: func(value string) bool { return strings.HasPrefix(value, "dv1:") }}
	return s, repo, objects
}

func allowSnapshot(context.Context, Scope, []string) error { return nil }
func fixtureInput(n int) Input {
	rows := make([]json.RawMessage, n)
	for i := range rows {
		rows[i] = json.RawMessage(fmt.Sprintf(`{"group":{"src_addr":"host%05d"},"metrics":{"bytes:total":"18446744073709551616001"}}`, i))
	}
	return Input{Query: json.RawMessage(`{ "from":"2020-01-01", "table_rows":50000 }`), Header: json.RawMessage(`{"other":{"other":true},"totals":{"bytes:total":"922337203685477580800050000"}}`), Validity: json.RawMessage(`{"source":"raw","oldest_input":"2026-10-28"}`), Rows: rows, ValidUntil: time.Now().Add(time.Hour)}
}
func createFixture(t *testing.T, s *Service, scope Scope, n, pageSize int) Page {
	t.Helper()
	page, err := s.Create(t.Context(), scope, []string{"flow.read", "ai.query"}, pageSize, allowSnapshot, func(context.Context) (Input, error) { return fixtureInput(n), nil })
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func TestSnapshotsFiftyThousandRowsAcrossReplicasStayExactAndFrozen(t *testing.T) {
	s, _, objects := fixtureService(t)
	input := fixtureInput(MaxRows)
	first, err := s.Create(t.Context(), redScope, []string{"flow.read", "ai.query", "metrics.read"}, 4999, allowSnapshot, func(context.Context) (Input, error) { return input, nil })
	if err != nil {
		t.Fatal(err)
	}
	// Another replica has no local result, key, cursor or membership state.
	second := *s
	input.Rows[4999] = json.RawMessage(`{"late_ingestion":"must not change cached page two"}`)
	page := first
	count := 0
	pages := 0
	for {
		pages++
		before := objects.reads.Load()
		for _, row := range page.Rows {
			expected := fmt.Sprintf(`{"group":{"src_addr":"host%05d"},"metrics":{"bytes:total":"18446744073709551616001"}}`, count)
			if string(row) != expected {
				t.Fatalf("row %d changed: %s", count, row)
			}
			count++
		}
		if page.SelectedRows != MaxRows || string(page.Data) != string(first.Data) {
			t.Fatal("global summaries changed between pages")
		}
		if page.NextCursor == "" {
			break
		}
		page, err = second.Resume(t.Context(), redScope, page.NextCursor, allowSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		if reads := objects.reads.Load() - before; reads > 3 {
			t.Fatalf("page read %d objects, expected common header + at most two chunks", reads)
		}
	}
	if count != MaxRows || pages != 11 {
		t.Fatalf("membership %d rows / %d pages", count, pages)
	}
	exported := 0
	err = second.Walk(t.Context(), redScope, first.SnapshotID, allowSnapshot, func(header Header) error {
		if header.SelectedRows != MaxRows {
			return ErrIntegrity
		}
		return nil
	}, func(rows []json.RawMessage) error {
		if len(rows) > chunkRows {
			t.Fatal("unbounded export chunk")
		}
		for _, row := range rows {
			if !strings.Contains(string(row), fmt.Sprintf("host%05d", exported)) {
				return ErrIntegrity
			}
			exported++
		}
		return nil
	})
	if err != nil || exported != MaxRows {
		t.Fatalf("export membership %d: %v", exported, err)
	}
	keys, err := objects.List(t.Context(), "tenant/"+redTenant+"/")
	if err != nil || len(keys) != 11 {
		t.Fatalf("chunk inventory %d: %v", len(keys), err)
	}
	for _, key := range keys {
		blob, err := objects.Get(t.Context(), key)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(blob.Data), "host00000") || strings.Contains(string(blob.Data), "18446744073709551616001") {
			t.Fatal("plaintext cached result")
		}
	}
}

func TestSnapshotsScopePermissionsIntegrityAndRetentionFailClosed(t *testing.T) {
	tests := []string{"foreign tenant", "foreign owner", "missing tenant", "permission revoked", "retention changed", "cursor modified", "manifest modified", "chunk removed", "chunk corrupted", "expired", "wrong silo"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			s, repo, objects := fixtureService(t)
			first := createFixture(t, s, redScope, 3, 1)
			scope := redScope
			cursor := first.NextCursor
			authorize := Authorize(allowSnapshot)
			want := ErrNotFound
			noRead := true
			switch name {
			case "foreign tenant":
				scope.TenantID = blueTenant
			case "foreign owner":
				scope.Owner = "bob@example.test"
			case "missing tenant":
				scope.TenantID = ""
				want = tenancy.ErrNoTenant
			case "permission revoked":
				want = errors.New("metrics.read revoked")
				authorize = func(_ context.Context, _ Scope, required []string) error {
					if !slices.Contains(required, "flow.read") {
						t.Fatal("stored source permissions missing")
					}
					return want
				}
			case "retention changed":
				want = errors.New("source coverage no longer available")
				s.validate = func(context.Context, Scope, json.RawMessage) error { return want }
			case "cursor modified":
				payload, _, mac, err := parseCursor(cursor)
				if err != nil {
					t.Fatal(err)
				}
				payload.Offset++
				body, _ := json.Marshal(payload)
				cursor = encodeCursor(body, mac)
				if _, _, _, err := parseCursor(cursor); err != nil {
					t.Fatal("MAC tamper fixture must retain valid cursor syntax")
				}
				want = ErrCursor
			case "manifest modified":
				repo.mu.Lock()
				m := repo.items[redTenant+"/"+first.SnapshotID]
				m.PageSize++
				repo.items[redTenant+"/"+first.SnapshotID] = m
				repo.mu.Unlock()
				want = ErrIntegrity
			case "chunk removed":
				_, err := objects.DeletePrefix(t.Context(), "tenant/"+redTenant+"/"+objectKey(first.SnapshotID, 1))
				if err != nil {
					t.Fatal(err)
				}
				want = ErrIntegrity
				noRead = false
			case "chunk corrupted":
				key := "tenant/" + redTenant + "/" + objectKey(first.SnapshotID, 1)
				blob, err := objects.Get(t.Context(), key)
				if err != nil {
					t.Fatal(err)
				}
				blob.Data[0] ^= 1
				if err := objects.Store.Put(t.Context(), key, "application/octet-stream", blob.Data); err != nil {
					t.Fatal(err)
				}
				want = ErrIntegrity
				noRead = false
			case "expired":
				s.now = func() time.Time { return first.ExpiresAt }
			case "wrong silo":
				s.router = tenancy.DeclaredRouter{Model: tenancy.IsolationSiloed}
			}
			before := objects.reads.Load()
			if _, err := s.Resume(t.Context(), scope, cursor, authorize); !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if noRead && objects.reads.Load() != before {
				t.Fatal("refused request read result objects")
			}
		})
	}
}

func TestSnapshotsFailedWritesStayChargedUntilVerifiedCleanup(t *testing.T) {
	s, repo, objects := fixtureService(t)
	objects.failPut.Store(2)
	objects.failDelete.Store(true)
	_, err := s.Create(t.Context(), redScope, []string{"flow.read"}, 1, allowSnapshot, func(context.Context) (Input, error) { return fixtureInput(2), nil })
	if err == nil || !strings.Contains(err.Error(), "deletion failure") {
		t.Fatalf("cleanup failure not reported: %v", err)
	}
	items, err := repo.expired(t.Context(), redTenant, time.Now(), 10)
	if err != nil || len(items) != 1 || items[0].Ready || items[0].ChargedBytes <= 0 {
		t.Fatalf("failed write not pending/charged: %+v %v", items, err)
	}
	if _, err := repo.get(t.Context(), redScope, items[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("partial manifest was published")
	}
	objects.failDelete.Store(false)
	if n, err := s.SweepTenant(t.Context(), redTenant, 10); err != nil || n != 1 {
		t.Fatalf("reclaim: %d %v", n, err)
	}
	if exists, _ := repo.any(t.Context(), redTenant); exists {
		t.Fatal("reclaimed snapshot still charged")
	}
	keys, err := objects.List(t.Context(), "tenant/"+redTenant+"/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("orphan ciphertext: %v %v", keys, err)
	}
}

func TestSnapshotsInvalidationDrainsBuildersAndKeepsSibling(t *testing.T) {
	s, _, objects := fixtureService(t)
	blue := createFixture(t, s, Scope{blueTenant, redScope.Owner}, 3, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	built := make(chan Page, 1)
	buildError := make(chan error, 1)
	go func() {
		page, err := s.Create(t.Context(), redScope, []string{"flow.read"}, 1, allowSnapshot, func(context.Context) (Input, error) { close(entered); <-release; return fixtureInput(3), nil })
		built <- page
		buildError <- err
	}()
	<-entered
	invalidated := make(chan error, 1)
	var mutated atomic.Bool
	go func() {
		invalidated <- s.Invalidate(t.Context(), redTenant, func(context.Context) error { mutated.Store(true); return nil })
	}()
	if mutated.Load() {
		t.Fatal("source deletion passed a builder holding the source-read lease")
	}
	close(release)
	page := <-built
	if err := <-buildError; err != nil {
		t.Fatal(err)
	}
	if err := <-invalidated; err != nil {
		t.Fatal(err)
	}
	if !mutated.Load() {
		t.Fatal("source mutation did not run")
	}
	if _, err := s.Resume(t.Context(), redScope, page.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old cursor survived: %v", err)
	}
	if _, err := s.Resume(t.Context(), Scope{blueTenant, redScope.Owner}, blue.NextCursor, allowSnapshot); err != nil {
		t.Fatalf("sibling affected: %v", err)
	}
	keys, err := objects.List(t.Context(), "tenant/"+redTenant+"/")
	if err != nil || len(keys) != 0 {
		t.Fatalf("erased cache objects remain: %v %v", keys, err)
	}
}

func TestSnapshotsInvalidationFailureAndCrashRemainClosedUntilRetry(t *testing.T) {
	s, repo, objects := fixtureService(t)
	first := createFixture(t, s, redScope, 3, 1)
	objects.failDelete.Store(true)
	mutated := false
	if err := s.Invalidate(t.Context(), redTenant, func(context.Context) error { mutated = true; return nil }); err == nil || mutated {
		t.Fatalf("failed physical deletion mutated source: %v", err)
	}
	if _, err := s.Resume(t.Context(), redScope, first.NextCursor, allowSnapshot); !errors.Is(err, ErrInvalidating) {
		t.Fatalf("failed invalidation reopened cursor: %v", err)
	}
	collected := false
	if _, err := s.Create(t.Context(), redScope, []string{"flow.read"}, 1, allowSnapshot, func(context.Context) (Input, error) { collected = true; return fixtureInput(3), nil }); !errors.Is(err, ErrInvalidating) || collected {
		t.Fatalf("failed invalidation allowed source query: %v", err)
	}
	objects.failDelete.Store(false)
	if err := s.Invalidate(t.Context(), redTenant, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_ = createFixture(t, s, redScope, 2, 1)
	// A committed transition survives loss of its lease/process. A stale
	// completion token cannot reopen a later transition.
	if _, err := repo.beginInvalidation(t.Context(), redTenant, "abandoned", nil); err != nil {
		t.Fatal(err)
	}
	if err := repo.endInvalidation(t.Context(), redTenant, "stale", true); !errors.Is(err, ErrInvalidating) {
		t.Fatal("stale completion reopened cache")
	}
	if err := s.Invalidate(t.Context(), redTenant, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_ = createFixture(t, s, redScope, 2, 1)
}

func TestSnapshotsBudgetsEncryptionAndInputExpiry(t *testing.T) {
	for _, name := range []string{"tenant quota", "object bytes", "keyless"} {
		t.Run(name, func(t *testing.T) {
			s, repo, objects := fixtureService(t)
			want := ErrBudget
			switch name {
			case "tenant quota":
				s.config.TenantBytes = 1
			case "object bytes":
				s.config.ObjectBytes = 64
			case "keyless":
				s.seal = func(_ context.Context, _ string, body, _ []byte) (string, error) { return string(body), nil }
				want = ErrEncryption
			}
			if _, err := s.Create(t.Context(), redScope, []string{"flow.read"}, 1, allowSnapshot, func(context.Context) (Input, error) { return fixtureInput(3), nil }); !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			if exists, _ := repo.any(t.Context(), redTenant); exists || objects.puts.Load() != 0 {
				t.Fatal("refusal persisted data")
			}
		})
	}
	s, _, _ := fixtureService(t)
	deadline := time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)
	page, err := s.Create(t.Context(), redScope, []string{"flow.read"}, 1, allowSnapshot, func(context.Context) (Input, error) {
		input := fixtureInput(3)
		input.ValidUntil = deadline
		return input, nil
	})
	if err != nil || !page.ExpiresAt.Equal(deadline) {
		t.Fatalf("cache extended input clock: %s %v", page.ExpiresAt, err)
	}
	s.now = func() time.Time { return deadline }
	if _, err := s.Resume(t.Context(), redScope, page.NextCursor, allowSnapshot); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired input replayed: %v", err)
	}
}

func TestSnapshotsPreparedPolicyFailurePreservesOldResults(t *testing.T) {
	s, repo, objects := fixtureService(t)
	page := createFixture(t, s, redScope, 3, 1)
	before, err := repo.state(t.Context(), redTenant)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := objects.List(t.Context(), "tenant/"+redTenant+"/")
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("policy audit refused")
	mutated := false
	err = s.InvalidatePrepared(t.Context(), redTenant, func(context.Context, tenancy.Scope) error { return refused }, func(context.Context) error { mutated = true; return nil })
	if !errors.Is(err, refused) || mutated {
		t.Fatalf("failed preparation mutated cache/source: %v", err)
	}
	after, err := repo.state(t.Context(), redTenant)
	if err != nil || after != before {
		t.Fatalf("failed preparation advanced generation: %+v %v", after, err)
	}
	remaining, err := objects.List(t.Context(), "tenant/"+redTenant+"/")
	if err != nil || !slices.Equal(keys, remaining) {
		t.Fatalf("failed preparation purged results: %v", err)
	}
	if _, err := s.Resume(t.Context(), redScope, page.NextCursor, allowSnapshot); err != nil {
		t.Fatalf("old-policy result became unusable: %v", err)
	}
}
