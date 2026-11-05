// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowsnapshot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

type Service struct {
	repo      repository
	objects   objectstore.Store
	router    tenancy.Router
	fence     tenancy.WriterFence
	validate  Validate
	config    Config
	now       func() time.Time
	seal      func(context.Context, string, []byte, []byte) (string, error)
	open      func(context.Context, string, string, []byte) ([]byte, error)
	hasScheme func(string) bool
	admission chan struct{}
	setupErr  error
}

// New requires existing deployment encryption, writer fencing, routing and
// authoritative source validation. A missing seam refuses use rather than
// substituting a process-local cache, plaintext, or pooled routing.
func New(pool *pgxpool.Pool, objects objectstore.Store, router tenancy.Router, fence tenancy.WriterFence, validate Validate, config Config) *Service {
	admission, err := admissionFor(pool)
	config = config.defaults()
	return &Service{repo: &postgres{pool: pool, headerBytes: config.privateHeaderBytes()}, objects: objects, router: router, fence: fence, validate: validate, config: config, now: time.Now, seal: tenantcrypto.Seal, open: tenantcrypto.Open, hasScheme: tenantcrypto.HasScheme, admission: admission, setupErr: err}
}

func (s *Service) available() error {
	if s == nil || s.repo == nil || s.fence == nil {
		return errors.New("flow snapshot service unavailable")
	}
	if s.setupErr != nil {
		return s.setupErr
	}
	return nil
}

// Lifecycle is the only seam needed by erasure and retention; it cannot read
// snapshots or keys. An objectless deployment must prove no cache manifests
// exist while holding the exclusive lease before mutating a source.
type Lifecycle interface {
	Invalidate(context.Context, string, func(context.Context) error) error
}

// Preparation changes an authoritative policy and its audit in the SAME tenant
// transaction as the cache-generation marker. A failed policy/audit cannot
// purge old-policy results or advance their generation.
type Preparation func(context.Context, tenancy.Scope) error

type PreparedLifecycle interface {
	Lifecycle
	InvalidatePrepared(context.Context, string, Preparation, func(context.Context) error) error
}

type Maintainer interface {
	Reclaimable(context.Context, string) (bool, error)
	SweepTenant(context.Context, string, int) (int, error)
}

// Reclaimable reads only an existence bit under tenant RLS, not encrypted
// headers or result objects. The worker avoids empty intent/audit traffic.
func (s *Service) Reclaimable(ctx context.Context, tenant string) (bool, error) {
	if s == nil || s.repo == nil || s.now == nil {
		return false, errors.New("flow snapshot metadata unavailable")
	}
	return s.repo.reclaimable(ctx, tenant, s.now())
}

func NewLifecycle(pool *pgxpool.Pool, objects objectstore.Store, fence tenancy.WriterFence) PreparedLifecycle {
	admission, err := admissionFor(pool)
	config := Config{}.defaults()
	return &Service{repo: &postgres{pool: pool, headerBytes: config.privateHeaderBytes()}, objects: objects, fence: fence, admission: admission, setupErr: err, now: time.Now, config: config}
}

func (s *Service) readable() error {
	if err := s.available(); err != nil {
		return err
	}
	if s.objects == nil || s.router == nil || s.validate == nil {
		return errors.New("flow snapshot data service unavailable")
	}
	return nil
}

func (s *Service) leased(ctx context.Context, tenant string, exclusive bool, fn func(context.Context) error) error {
	if !canonicalID(tenant) {
		return tenancy.ErrNoTenant
	}
	if err := s.available(); err != nil {
		return err
	}
	if s.admission != nil {
		select {
		case s.admission <- struct{}{}:
			defer func() { <-s.admission }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.fence.WithTenantWrites(ctx, []string{tenant}, func(ctx context.Context) error { return s.repo.lease(ctx, tenant, exclusive, fn) })
}

func (s *Service) objectLane(ctx context.Context, tenant string) (string, error) {
	targets, err := s.router.TargetsFor(ctx, tenant)
	if err != nil {
		return "", err
	}
	switch targets.Model {
	case "", tenancy.IsolationPooled:
		if targets.ObjectPrefix != "" && targets.ObjectPrefix != objectstore.TenantKey(tenant) {
			return "", ErrIntegrity
		}
		return "pooled", nil
	case tenancy.IsolationSiloed, tenancy.IsolationHybrid:
		if targets.ObjectPrefix != tenancy.SiloObjectPrefix(tenant) {
			return "", ErrIntegrity
		}
		return "silo", nil
	default:
		return "", ErrIntegrity
	}
}

func (s *Service) laneStore(tenant, lane string) (objectstore.TenantStore, error) {
	if !canonicalID(tenant) {
		return nil, tenancy.ErrNoTenant
	}
	switch lane {
	case "pooled":
		return objectstore.ForTenant(s.objects, tenant)
	case "silo":
		return objectstore.ForTenantPrefix(s.objects, tenancy.SiloObjectPrefix(tenant), tenant)
	default:
		return nil, ErrIntegrity
	}
}

func (s *Service) current(ctx context.Context, m manifest) error {
	if !m.Ready || m.Generation < 1 || m.Rows < 0 || m.Rows > MaxRows || m.PageSize < 1 || m.PageSize > MaxPageRows || !canonicalID(m.ID) || !s.now().Before(m.ExpiresAt) {
		return ErrNotFound
	}
	state, err := s.repo.state(ctx, m.TenantID)
	if err != nil {
		return err
	}
	if state.Invalidating {
		return ErrInvalidating
	}
	if state.Generation != m.Generation {
		return ErrNotFound
	}
	lane, err := s.objectLane(ctx, m.TenantID)
	if err != nil {
		return err
	}
	if lane != m.Lane {
		return ErrNotFound
	}
	return nil
}

func permissions(required []string) ([]string, error) {
	result := slices.Clone(required)
	result = append(result, "ai.query", "flow.read")
	slices.Sort(result)
	result = slices.Compact(result)
	if len(result) < 1 || len(result) > 64 {
		return nil, ErrIntegrity
	}
	for _, permission := range result {
		if strings.TrimSpace(permission) == "" || len(permission) > 128 {
			return nil, ErrIntegrity
		}
	}
	return result, nil
}

// Create holds both lifecycle leases BEFORE collect reads its source and until
// publication. The result remains pending/invisible until every encrypted
// object is durable and retention is revalidated. Failed writes remain charged
// until their exact prefix is verifiably empty.
func (s *Service) Create(ctx context.Context, scope Scope, required []string, pageSize int, authorize Authorize, collect func(context.Context) (Input, error)) (Page, error) {
	if err := scope.validate(); err != nil {
		return Page{}, err
	}
	if pageSize < 1 || pageSize > MaxPageRows || authorize == nil || collect == nil {
		return Page{}, ErrIntegrity
	}
	if err := s.readable(); err != nil {
		return Page{}, err
	}
	required, err := permissions(required)
	if err != nil {
		return Page{}, err
	}
	var result Page
	err = s.leased(ctx, scope.TenantID, false, func(ctx context.Context) (returned error) {
		state, err := s.repo.state(ctx, scope.TenantID)
		if err != nil {
			return err
		}
		if state.Invalidating {
			return ErrInvalidating
		}
		if err := authorize(ctx, scope, slices.Clone(required)); err != nil {
			return err
		}
		input, err := collect(ctx)
		if err != nil {
			return err
		}
		if err := s.validate(ctx, scope, input.Validity); err != nil {
			return err
		}
		staged, err := s.stage(ctx, scope, state.Generation, required, pageSize, input)
		if err != nil {
			return err
		}
		defer staged.close()
		m := staged.manifest
		if err := s.repo.reserve(ctx, m, s.config.TenantBytes); err != nil {
			return err
		}
		published := false
		defer func() {
			if !published {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				defer cancel()
				returned = errors.Join(returned, s.removeObjects(cleanup, m))
			}
		}()
		store, err := s.laneStore(scope.TenantID, m.Lane)
		if err != nil {
			return err
		}
		for i := range staged.private.Objects {
			body, err := os.ReadFile(filepath.Join(staged.dir, fmt.Sprint(i)))
			if err != nil {
				return err
			}
			err = store.Put(ctx, objectKey(m.ID, i), "application/octet-stream", body)
			crypto.Zeroize(body)
			if err != nil {
				return err
			}
		}
		if !s.now().Before(m.ExpiresAt) {
			return ErrNotFound
		}
		if err := s.validate(ctx, scope, input.Validity); err != nil {
			return err
		}
		if err := s.repo.publish(ctx, m); err != nil {
			return err
		}
		m.Ready = true
		result, err = s.readPage(ctx, m, staged.private, 0)
		if err != nil {
			return err
		}
		published = true
		return nil
	})
	return result, err
}

func (s *Service) load(ctx context.Context, scope Scope, id string, authorize Authorize) (manifest, privateHeader, error) {
	if err := s.readable(); err != nil {
		return manifest{}, privateHeader{}, err
	}
	if authorize == nil {
		return manifest{}, privateHeader{}, ErrIntegrity
	}
	m, err := s.repo.get(ctx, scope, id)
	if err != nil && !errors.Is(err, ErrBudget) {
		return manifest{}, privateHeader{}, err
	}
	// SQL withholds an oversized private field while retaining only public
	// control metadata. Global permissions do not prove current source/context
	// access: that receipt is encrypted in the unavailable private field.
	admissionErr := err
	if m.Scope != scope {
		return manifest{}, privateHeader{}, ErrNotFound
	}
	if err := s.current(ctx, m); err != nil {
		return manifest{}, privateHeader{}, err
	}
	if err := authorize(ctx, scope, slices.Clone(m.Permissions)); err != nil {
		return manifest{}, privateHeader{}, err
	}
	if admissionErr != nil {
		return manifest{}, privateHeader{}, ErrNotFound
	}
	private, err := s.openPrivate(ctx, m)
	if errors.Is(err, ErrBudget) {
		return manifest{}, privateHeader{}, ErrNotFound
	}
	return m, private, err
}

// Resume never reruns source queries or resolves saved filters again. Every
// replica checks the same owner, current permissions, coverage and cursor MAC.
func (s *Service) Resume(ctx context.Context, scope Scope, cursor string, authorize Authorize) (Page, error) {
	if err := scope.validate(); err != nil {
		return Page{}, err
	}
	payload, body, mac, err := parseCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	var result Page
	err = s.leased(ctx, scope.TenantID, false, func(ctx context.Context) error {
		m, private, err := s.load(ctx, scope, payload.ID, authorize)
		if err != nil {
			return err
		}
		defer private.zeroize()
		if !crypto.Verify(private.CursorKey, body, mac) || payload.QueryHash != m.QueryHash || payload.PageSize != m.PageSize || payload.Expires != m.ExpiresAt.UnixMicro() || payload.Offset < 1 || payload.Offset >= m.Rows || payload.Offset%m.PageSize != 0 {
			return ErrCursor
		}
		result, err = s.readPage(ctx, m, private, payload.Offset)
		return err
	})
	return result, err
}

// Walk supplies the common header once, then bounded row chunks in frozen
// order. Consumers prepare exports privately and publish only after Walk
// succeeds, because the last chunk and final retention check may still fail.
func (s *Service) Walk(ctx context.Context, scope Scope, id string, authorize Authorize, onHeader func(Header) error, onRows func([]json.RawMessage) error, prepared ...func() error) error {
	if err := scope.validate(); err != nil {
		return err
	}
	if onHeader == nil || onRows == nil {
		return ErrIntegrity
	}
	if len(prepared) > 1 {
		return ErrIntegrity
	}
	return s.leased(ctx, scope.TenantID, false, func(ctx context.Context) error {
		m, private, err := s.load(ctx, scope, id, authorize)
		if err != nil {
			return err
		}
		defer private.zeroize()
		header, err := s.readHeader(ctx, m, private)
		if err != nil {
			return err
		}
		if err := onHeader(header); err != nil {
			return err
		}
		for i := 1; i < len(private.Objects); i++ {
			rows, err := s.readRows(ctx, m, private, i)
			if err != nil {
				return err
			}
			if err := onRows(rows); err != nil {
				return err
			}
		}
		// Flush/hash/rewind prepared exports while the read lease still holds.
		// Only then revalidate source clocks and generation and release it.
		if len(prepared) == 1 {
			if prepared[0] == nil {
				return ErrIntegrity
			}
			if err := prepared[0](); err != nil {
				return err
			}
		}
		if err := s.validate(ctx, scope, private.Validity); err != nil {
			return err
		}
		return s.current(ctx, m)
	})
}

// Invalidate drains builders/readers, commits a fail-closed transition, purges
// both owned cache lanes, then runs the source mutation. A crash or any failure
// leaves the committed transition closed; retry adopts it under the exclusive
// lease. Full tenant offboarding uses its existing outer exclusive fence and
// removes both entire tenant namespaces, rather than recursively calling this.
func (s *Service) Invalidate(ctx context.Context, tenant string, mutate func(context.Context) error) error {
	return s.invalidate(ctx, tenant, nil, mutate)
}

func (s *Service) InvalidatePrepared(ctx context.Context, tenant string, prepare Preparation, mutate func(context.Context) error) error {
	if prepare == nil {
		return ErrIntegrity
	}
	return s.invalidate(ctx, tenant, prepare, mutate)
}

func (s *Service) invalidate(ctx context.Context, tenant string, prepare Preparation, mutate func(context.Context) error) error {
	if mutate == nil {
		return ErrIntegrity
	}
	return s.leased(ctx, tenant, true, func(ctx context.Context) error {
		token, err := crypto.UUIDv4()
		if err != nil {
			return err
		}
		audited, err := s.repo.beginInvalidation(ctx, tenant, token, prepare)
		if err != nil {
			return err
		}
		if s.objects == nil {
			exists, err := s.repo.any(ctx, tenant)
			if err != nil {
				return err
			}
			if exists {
				return errors.New("flow snapshot object store is required to verify cache erasure")
			}
		} else {
			for _, lane := range []string{"pooled", "silo"} {
				store, err := s.laneStore(tenant, lane)
				if err != nil {
					return err
				}
				if _, err := store.DeletePrefix(ctx, objectPrefix); err != nil {
					return err
				}
				if err := verifyEmpty(ctx, store, objectPrefix); err != nil {
					return err
				}
			}
		}
		if err := s.repo.clear(ctx, tenant); err != nil {
			return err
		}
		if err := mutate(ctx); err != nil {
			return err
		}
		return s.repo.endInvalidation(ctx, tenant, token, audited)
	})
}

// SweepTenant reclaims expired and abandoned pending results. Taking the
// exclusive lease proves no pending writer can put another object afterward.
// A bounded batch can be scheduled repeatedly without loading a tenant's full
// inventory; deletion failures retain metadata and its byte charge.
func (s *Service) SweepTenant(ctx context.Context, tenant string, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrBudget
	}
	removed := 0
	err := s.leased(ctx, tenant, true, func(ctx context.Context) error {
		items, err := s.repo.expired(ctx, tenant, s.now(), limit)
		if err != nil {
			return err
		}
		for _, m := range items {
			if m.TenantID != tenant {
				return ErrIntegrity
			}
			if err := s.removeObjects(ctx, m); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

func verifyEmpty(ctx context.Context, store objectstore.TenantStore, prefix string) error {
	keys, err := store.ListLimited(ctx, prefix, 1)
	if err != nil {
		return err
	}
	if len(keys) != 0 {
		return ErrIntegrity
	}
	return nil
}

func (s *Service) removeObjects(ctx context.Context, m manifest) error {
	if !canonicalID(m.ID) {
		return ErrIntegrity
	}
	store, err := s.laneStore(m.TenantID, m.Lane)
	if err != nil {
		return err
	}
	prefix := objectPrefix + m.ID + "/"
	if _, err := store.DeletePrefix(ctx, prefix); err != nil {
		return err
	}
	if err := verifyEmpty(ctx, store, prefix); err != nil {
		return err
	}
	return s.repo.remove(ctx, m.TenantID, m.ID)
}

func objectKey(id string, index int) string { return objectPrefix + id + "/" + fmt.Sprint(index) }

func (s *Service) readHeader(ctx context.Context, m manifest, private privateHeader) (Header, error) {
	if err := s.validate(ctx, m.Scope, private.Validity); err != nil {
		return Header{}, err
	}
	plaintext, err := s.readObject(ctx, m, private, 0)
	if err != nil {
		return Header{}, err
	}
	defer crypto.Zeroize(plaintext)
	var common commonHeader
	if err := json.Unmarshal(plaintext, &common); err != nil {
		return Header{}, ErrIntegrity
	}
	if hex.EncodeToString(crypto.Hash(common.Query)) != m.QueryHash || !json.Valid(common.Data) {
		return Header{}, ErrIntegrity
	}
	return Header{SnapshotID: m.ID, ExpiresAt: m.ExpiresAt, Query: common.Query, Data: common.Data, SelectedRows: m.Rows, PageSize: m.PageSize}, nil
}

func (s *Service) readRows(ctx context.Context, m manifest, private privateHeader, index int) ([]json.RawMessage, error) {
	plaintext, err := s.readObject(ctx, m, private, index)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(plaintext)
	var rows []json.RawMessage
	if err := json.Unmarshal(plaintext, &rows); err != nil {
		return nil, ErrIntegrity
	}
	expected := min(chunkRows, m.Rows-(index-1)*chunkRows)
	if len(rows) != expected || expected < 1 {
		return nil, ErrIntegrity
	}
	return rows, nil
}

func (s *Service) readPage(ctx context.Context, m manifest, private privateHeader, offset int) (Page, error) {
	header, err := s.readHeader(ctx, m, private)
	if err != nil {
		return Page{}, err
	}
	result := Page{Header: header, Offset: offset, Rows: []json.RawMessage{}}
	end := min(offset+m.PageSize, m.Rows)
	for position := offset; position < end; {
		index := position/chunkRows + 1
		rows, err := s.readRows(ctx, m, private, index)
		if err != nil {
			return Page{}, err
		}
		start := position % chunkRows
		n := min(end-position, len(rows)-start)
		result.Rows = append(result.Rows, rows[start:start+n]...)
		position += n
	}
	if end < m.Rows {
		result.NextCursor, err = makeCursor(m, private.CursorKey, end)
		if err != nil {
			return Page{}, err
		}
	}
	if err := s.validate(ctx, m.Scope, private.Validity); err != nil {
		return Page{}, err
	}
	if err := s.current(ctx, m); err != nil {
		return Page{}, err
	}
	return result, nil
}

func (s *Service) readObject(ctx context.Context, m manifest, private privateHeader, index int) ([]byte, error) {
	if index < 0 || index >= len(private.Objects) {
		return nil, ErrIntegrity
	}
	ref := private.Objects[index]
	if ref.Bytes <= 0 || ref.Bytes > s.config.ObjectBytes {
		return nil, ErrBudget
	}
	store, err := s.laneStore(m.TenantID, m.Lane)
	if err != nil {
		return nil, err
	}
	object, err := store.GetLimited(ctx, objectKey(m.ID, index), ref.Bytes)
	if err != nil {
		return nil, errors.Join(ErrIntegrity, err)
	}
	if int64(len(object.Data)) != ref.Bytes || hex.EncodeToString(crypto.Hash(object.Data)) != ref.Hash {
		return nil, ErrIntegrity
	}
	plaintext, err := crypto.Decrypt(private.DataKey, object.Data, objectAAD(m, index))
	if err != nil {
		return nil, ErrIntegrity
	}
	return plaintext, nil
}

func objectAAD(m manifest, index int) []byte {
	value, _ := json.Marshal(struct {
		Version                      int
		Tenant, Owner, ID, QueryHash string
		Generation                   int64
		Index                        int
	}{1, m.TenantID, m.Owner, m.ID, m.QueryHash, m.Generation, index})
	return value
}

type cursorPayload struct {
	Version          int    `json:"v"`
	ID               string `json:"id"`
	Offset, PageSize int
	QueryHash        string
	Expires          int64
}

func makeCursor(m manifest, key []byte, offset int) (string, error) {
	body, err := json.Marshal(cursorPayload{1, m.ID, offset, m.PageSize, m.QueryHash, m.ExpiresAt.UnixMicro()})
	if err != nil {
		return "", err
	}
	return encodeCursor(body, crypto.Sign(key, body)), nil
}

func parseCursor(cursor string) (cursorPayload, []byte, []byte, error) {
	bad := func() (cursorPayload, []byte, []byte, error) { return cursorPayload{}, nil, nil, ErrCursor }
	if len(cursor) > 2048 {
		return bad()
	}
	body, mac, err := decodeCursorParts(cursor)
	if err != nil || len(mac) != 32 {
		return bad()
	}
	var payload cursorPayload
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Version != 1 || !canonicalID(payload.ID) {
		return bad()
	}
	canonical, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonical, body) {
		return bad()
	}
	return payload, body, mac, nil
}
