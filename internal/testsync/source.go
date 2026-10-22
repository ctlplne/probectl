// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// MaxBundleTests bounds one tenant's distributed test set. A larger set is
// refused with ErrTestSetTooLarge rather than truncated: an agent must never
// run a silently partial set. Agents apply their own (lower) cap on top.
const MaxBundleTests = 2000

// versionCacheTTL bounds how stale a cached tenant version may be. Heartbeats
// and not-modified pulls from a whole fleet read it, so it is cached per tenant
// and a change reaches agents within this window plus one heartbeat.
const versionCacheTTL = 2 * time.Second

// ErrTestSetTooLarge is returned when a tenant's enabled tests exceed
// MaxBundleTests.
var ErrTestSetTooLarge = errors.New("testsync: tenant test set exceeds the distributable maximum")

// Source is the control-plane half of central test distribution: it reads a
// tenant's enabled tests and its test-set version under the tenant's RLS scope
// (docs/guardrails.md G7-1) and signs them with the deployment's test-bundle
// key. The tenant is always the caller's verified identity (the agent's client
// certificate, or the API principal), never a request field.
type Source struct {
	pool *pgxpool.Pool
	priv []byte
	pub  []byte
	now  func() time.Time

	mu       sync.Mutex
	versions map[string]cachedVersion
	bundles  map[string]cachedBundle
}

type cachedVersion struct {
	version uint64
	at      time.Time
}

type cachedBundle struct {
	version uint64
	signed  []byte
}

// NewSource builds a source signing with the Ed25519 PKCS#8 private-key PEM.
// The matching public key (PublicKeyPEM) is what agents verify against.
func NewSource(pool *pgxpool.Pool, privPEM []byte) (*Source, error) {
	if pool == nil {
		return nil, errors.New("testsync: source needs a database pool")
	}
	pub, err := crypto.PublicPEMFromPrivate(privPEM)
	if err != nil {
		return nil, fmt.Errorf("testsync: signing key: %w", err)
	}
	return &Source{
		pool: pool, priv: append([]byte(nil), privPEM...), pub: pub, now: time.Now,
		versions: map[string]cachedVersion{}, bundles: map[string]cachedBundle{},
	}, nil
}

// PublicKeyPEM returns the public half agents verify bundles with. It is
// handed to agents at enrollment and printed by `probectl-control testsync
// public-key`.
func (s *Source) PublicKeyPEM() []byte { return append([]byte(nil), s.pub...) }

// Version returns the tenant's current test-set version, cached per tenant for
// versionCacheTTL.
func (s *Source) Version(ctx context.Context, tenantID string) (uint64, error) {
	s.mu.Lock()
	c, ok := s.versions[tenantID]
	s.mu.Unlock()
	if ok && s.now().Sub(c.at) < versionCacheTTL {
		return c.version, nil
	}
	var v uint64
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var e error
			v, e = (store.TestSets{}).Version(ctx, sc)
			return e
		})
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.versions[tenantID] = cachedVersion{version: v, at: s.now()}
	s.mu.Unlock()
	return v, nil
}

// Bundle returns the tenant's signed bundle at its current version. The
// version and the tests are read in one tenant transaction, version first (see
// store.TestSets.EnabledTests). A bundle already signed for that version is
// reused, so a fleet pulling after one change costs one signature.
func (s *Source) Bundle(ctx context.Context, tenantID string) (uint64, []byte, error) {
	var (
		version uint64
		tests   []store.Test
	)
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			v, e := (store.TestSets{}).Version(ctx, sc)
			if e != nil {
				return e
			}
			version = v
			s.mu.Lock()
			cb, hit := s.bundles[tenantID]
			s.mu.Unlock()
			if hit && cb.version == v {
				return nil
			}
			tests, e = (store.TestSets{}).EnabledTests(ctx, sc, MaxBundleTests+1)
			return e
		})
	if err != nil {
		return 0, nil, err
	}
	s.mu.Lock()
	cb, hit := s.bundles[tenantID]
	s.mu.Unlock()
	if hit && cb.version == version {
		return version, cb.signed, nil
	}
	if len(tests) > MaxBundleTests {
		return 0, nil, ErrTestSetTooLarge
	}
	signed, err := Sign(FromStore(tenantID, version, tests), s.priv)
	if err != nil {
		return 0, nil, err
	}
	s.mu.Lock()
	s.bundles[tenantID] = cachedBundle{version: version, signed: signed}
	s.versions[tenantID] = cachedVersion{version: version, at: s.now()}
	s.mu.Unlock()
	return version, signed, nil
}

// FromStore converts a tenant's stored tests into the bundle an agent runs at
// the given version. Only enabled tests are included.
func FromStore(tenantID string, version uint64, tests []store.Test) Bundle {
	b := Bundle{TenantID: tenantID, Epoch: int64(version), Tests: []Test{}}
	for _, t := range tests {
		if !t.Enabled {
			continue
		}
		b.Tests = append(b.Tests, Test{
			ID: t.ID, Type: t.Type, Target: t.Target,
			IntervalSeconds: t.IntervalSeconds, TimeoutSeconds: t.TimeoutSeconds,
			Params: t.Params,
		})
	}
	return b
}
