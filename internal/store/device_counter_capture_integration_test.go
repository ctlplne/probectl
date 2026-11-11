// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type counterCaptureFixture struct {
	pool                                 *pgxpool.Pool
	service                              *DeviceCounterCaptures
	tenant, area, device, sender, serial string
	input                                entity.CounterCaptureInput
	digest                               [32]byte
}

func TestDeviceCounterWitnessPreservesPollAcrossCacheOnlyInvalidation(t *testing.T) {
	fixtures := deviceCounterFixtures(t)
	f := fixtures[0]
	// Model the existing cache-only begin/end transitions, without erasing
	// a source, counter payload or directory identity. Original poll clocks
	// must not be moved forward to make an unrelated cache rebuild pass.
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, f.tenant); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=true,transition_token=$2 WHERE tenant_id=$1`, f.tenant, uuid.NewString())
		return err
	})
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL WHERE tenant_id=$1`, f.tenant)
		return err
	})
	for _, lane := range fixtures {
		ref, err := lane.service.CaptureAuthenticated(lane.ctx(t.Context()), lane.sender, lane.serial, lane.digest, lane.input, 1<<20)
		if err != nil {
			t.Fatal("cache-only invalidation discarded an original authorized counter poll", err)
		}
		got, err := lane.service.LookupWitness(lane.ctx(t.Context()), lane.sender, lane.digest, lane.input)
		if err != nil || got.Scope.TenantID != lane.tenant || !got.CapturedAt.Equal(ref.CapturedAt) {
			t.Fatal("counter cache invalidation changed the original witness or tenant", err)
		}
	}
}

func TestDeviceCounterPublicationUsesCurrentWitnessWithoutExhaustingRouterPool(t *testing.T) {
	fixtures := deviceCounterFixtures(t)
	settings := fixtures[0].pool.Config()
	settings.MaxConns, settings.MinConns = 1, 0
	main, err := pgxpool.NewWithConfig(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(main.Close)
	verifier, err := pgxpool.NewWithConfig(t.Context(), settings.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.Close)
	guard := NewDeviceCounterCaptures(verifier)
	for _, fixture := range fixtures {
		ref, err := fixture.service.CaptureAuthenticated(fixture.ctx(t.Context()), fixture.sender, fixture.serial, fixture.digest, fixture.input, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(fixture.ctx(t.Context()), 5*time.Second)
		called := false
		err = guard.PublishUnderWitness(ctx, fixture.sender, fixture.digest, fixture.input, 90, func(ctx context.Context, witness DeviceCounterCapture) error {
			called = true
			if witness.Key != ref.Key || witness.Scope.TenantID != fixture.tenant || witness.DeviceID != fixture.device || witness.SenderSerial != fixture.serial {
				return errors.New("publication changed certified source provenance")
			}
			// Exercise the DB connection a cold/expired router refresh needs
			// while the independent verifier transaction remains open.
			var one int
			return main.QueryRow(ctx, `SELECT 1`).Scan(&one)
		})
		cancel()
		if err != nil || !called {
			t.Fatal("current whole-poll publication exhausted the one-connection main/router pool", called, err)
		}
		inTenant(t.Context(), t, fixture.pool, fixture.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id=$2`, fixture.tenant, fixture.sender)
			return err
		})
		called = false
		err = guard.PublishUnderWitness(fixture.ctx(t.Context()), fixture.sender, fixture.digest, fixture.input, 90, func(context.Context, DeviceCounterCapture) error { called = true; return nil })
		if !errors.Is(err, ErrCounterCaptureUnavailable) || called {
			t.Fatal("a rebound source reached counter history publication", called, err)
		}
	}
}

func TestDeviceCounterErasureFenceKeepsLegacyWritersAndWholeTransition(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint("legacy=", legacy), func(t *testing.T) {
			f := deviceCounterFixtures(t)[0]
			inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
				if err := sourceepoch.PrepareInScope(ctx, sc); err != nil {
					return err
				}
				if err := tenancy.LockTenantAuditStream(ctx, sc.Q, f.tenant); err != nil {
					return err
				}
				if legacy {
					// Exact old application statement: new migrations must not
					// relax erasure during a rolling binary upgrade.
					_, err := sc.Q.Exec(ctx, `INSERT INTO flow_snapshot_epochs(tenant_id,generation,invalidating,transition_token)
 VALUES($1::uuid,1,true,$2::uuid) ON CONFLICT(tenant_id) DO UPDATE
 SET generation=flow_snapshot_epochs.generation+1,invalidating=true,transition_token=EXCLUDED.transition_token`, f.tenant, uuid.NewString())
					return err
				}
				return sourceepoch.InvalidateSourceGenerationInScope(ctx, sc)
			})
			during := f.input
			inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
				if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&during.PollStartedAt); err != nil {
					return err
				}
				_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET observation_erasing=false WHERE tenant_id=$1`, f.tenant)
				if err != nil {
					return err
				}
				var erasing bool
				if err := sc.Q.QueryRow(ctx, `SELECT observation_erasing FROM flow_snapshot_epochs WHERE tenant_id=$1`, f.tenant).Scan(&erasing); err != nil {
					return err
				}
				if !erasing {
					t.Fatal("in-progress erasure marker was cleared before completion")
				}
				return nil
			})
			during.PollCompletedAt = during.PollStartedAt
			if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, during, 1<<20); err == nil {
				t.Fatal("in-progress erasure accepted a counter poll")
			}
			inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL WHERE tenant_id=$1`, f.tenant)
				return err
			})
			if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, during, 1<<20); !errors.Is(err, ErrCounterCaptureUnavailable) {
				t.Fatal("late first receipt from inside erasure escaped the completed cutoff", err)
			}
		})
	}
}

func deviceCounterFixtures(t *testing.T) [2]counterCaptureFixture {
	t.Helper()
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var result [2]counterCaptureFixture
	area, device := uuid.NewString(), uuid.NewString()
	for lane := range result {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("counter-%d-%d", lane, time.Now().UnixNano()), "counter witness")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Errorf("remove own counter tenant: %v", err)
			}
		})
		f := counterCaptureFixture{pool: pool, service: NewDeviceCounterCaptures(pool), tenant: tenant.ID, area: area, device: device,
			sender: "shared-counter-agent", serial: strings.ReplaceAll(uuid.NewString(), "-", ""), digest: [32]byte{1, 255},
			input: entity.CounterCaptureInput{ConfiguredTarget: "10.42.0.1", PointCount: 5001}}
		if err := NewAgentIdentities(pool).Record(t.Context(), f.tenant, f.sender, crypto.EntitySPIFFEID(f.tenant, f.sender), f.serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		inTenant(t.Context(), t, pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same site','same VRF')`, f.tenant, area, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same device')`, f.tenant, area, device); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`, f.tenant, f.sender, area); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id) VALUES($1,$2,'device_target',$3,$4,$5)`, f.tenant, f.sender, f.input.ConfiguredTarget, area, device); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&f.input.PollStartedAt)
		})
		f.input.PollStartedAt = f.input.PollStartedAt.Add(123 * time.Nanosecond)
		f.input.PollCompletedAt = f.input.PollStartedAt.Add(time.Nanosecond)
		result[lane] = f
	}
	return result
}

func (f counterCaptureFixture) ctx(ctx context.Context) context.Context {
	return tenancy.WithTenant(ctx, tenancy.ID(f.tenant))
}

func TestDeviceCounterScopedReaderKeepsRotationAndTenantBoundary(t *testing.T) {
	fixtures := deviceCounterFixtures(t)
	var original [2]entity.CounterCaptureReference
	for i, f := range fixtures {
		var err error
		original[i], err = f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, f.input, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			got, err := f.service.LookupWitnessInScope(ctx, sc, f.sender, f.digest, f.input)
			if err != nil || got.CounterCaptureReference != original[i] || got.Scope.TenantID != f.tenant {
				return fmt.Errorf("existing tenant snapshot lost its original witness: %w", err)
			}
			foreign := tenancy.WithTenant(ctx, tenancy.ID(fixtures[1-i].tenant))
			if _, err := f.service.LookupWitnessInScope(foreign, sc, f.sender, f.digest, f.input); !errors.Is(err, entity.ErrScopeMismatch) {
				return fmt.Errorf("contradictory context crossed the witness SQL scope: %w", err)
			}
			return nil
		})
	}
	red, blue := fixtures[0], fixtures[1]
	// Model elapsed certificate lifetime after the immutable first capture,
	// without changing the host clock or inventing a new capture timestamp.
	if _, err := red.pool.Exec(t.Context(), `UPDATE agent_identities SET not_after=clock_timestamp() WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, red.tenant, red.sender, red.serial); err != nil {
		t.Fatal("update own issued-identity lifetime fixture", err)
	}
	if _, err := red.service.LookupWitness(red.ctx(t.Context()), red.sender, red.digest, red.input); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("history without a current issued source identity remained readable", err)
	}
	renewed, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	renewed = strings.ReplaceAll(renewed, "-", "")
	if err := NewAgentIdentities(red.pool).Record(t.Context(), red.tenant, red.sender, crypto.EntitySPIFFEID(red.tenant, red.sender), renewed, time.Now().Add(time.Hour), red.serial); err != nil {
		t.Fatal(err)
	}
	inTenant(t.Context(), t, red.pool, red.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := red.service.LookupWitnessInScope(ctx, sc, red.sender, red.digest, red.input)
		if err != nil || got.CounterCaptureReference != original[0] || got.SenderSerial != red.serial {
			return fmt.Errorf("normal source rotation replaced or hid original history: %w", err)
		}
		return nil
	})
	if _, _, err := NewAgentIdentities(red.pool).RevokeAgent(t.Context(), red.tenant, red.sender, "fixture-revocation"); err != nil {
		t.Fatal(err)
	}
	inTenant(t.Context(), t, red.pool, red.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := red.service.LookupWitnessInScope(ctx, sc, red.sender, red.digest, red.input); !errors.Is(err, ErrCounterCaptureUnavailable) {
			return fmt.Errorf("revoked source remained a historical reader witness: %w", err)
		}
		return nil
	})
	if sibling, err := blue.service.LookupWitness(blue.ctx(t.Context()), blue.sender, blue.digest, blue.input); err != nil || sibling.CounterCaptureReference != original[1] {
		t.Fatal("source expiry or revocation changed sibling history", sibling, err)
	}
	t.Log("real-integration: TLS PostgreSQL app-role scope and retained first capture with modeled issued identities/expiry; source mTLS and served actor authorization remain separate")
}

func TestDeviceCounterWitnessUsesOriginalPollAndStableFirstCapture(t *testing.T) {
	f := deviceCounterFixtures(t)[0]
	ctx := f.ctx(t.Context())
	if _, err := f.service.LookupWitness(ctx, f.sender, f.digest, f.input); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("raw claims created an authenticated sender witness", err)
	}
	first, err := f.service.CaptureAuthenticated(ctx, f.sender, f.serial, f.digest, f.input, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key, err := entity.CounterCaptureKey(f.tenant, f.sender, f.digest, f.input)
	if err != nil || first.Key != key || first.CapturedAt.UnixNano() <= 0 {
		t.Fatal("original poll witness lost its exact identity or first clock", err)
	}
	replay, err := f.service.CaptureAuthenticated(ctx, f.sender, f.serial, f.digest, f.input, 1<<20)
	if err != nil || replay != first {
		t.Fatal("exact retry renewed its first capture", err)
	}
	got, err := f.service.LookupWitness(ctx, f.sender, f.digest, f.input)
	if err != nil || got.Scope != (entity.Scope{TenantID: f.tenant, ContextID: f.area}) || got.DeviceID != f.device || got.SenderSerial != f.serial {
		t.Fatal("source witness lost its operator-selected scope or certified sender", err)
	}
	inTenant(ctx, t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var start, end, count int64
		if err := sc.Q.QueryRow(ctx, `SELECT poll_started_unix_nanos,poll_completed_unix_nanos,point_count FROM device_counter_capture_sources WHERE capture_key=$1`, key[:]).Scan(&start, &end, &count); err != nil {
			return err
		}
		if start != f.input.PollStartedAt.UnixNano() || end != f.input.PollCompletedAt.UnixNano() || count != 5001 {
			t.Fatal("counter source stored rounded poll bounds or an incomplete batch")
		}
		return nil
	})
	changed := f.input
	changed.PointCount++
	if _, err := f.service.LookupWitness(ctx, f.sender, f.digest, changed); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("partial or altered batch reused an authenticated witness", err)
	}
	if _, err := f.service.CaptureAuthenticated(ctx, f.sender, f.serial, f.digest, changed, 4352); !errors.Is(err, ErrCounterCaptureBudget) {
		t.Fatal("complete retained state exceeded its finite tenant admission", err)
	}
}

func TestDeviceCounterWitnessTenantRebindRevocationAndErasureIsolation(t *testing.T) {
	fixtures := deviceCounterFixtures(t)
	var refs [2]entity.CounterCaptureReference
	for lane, f := range fixtures {
		var err error
		refs[lane], err = f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, f.input, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var own, foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_counter_captures`).Scan(&own); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_counter_captures WHERE tenant_id=$1`, fixtures[1-lane].tenant).Scan(&foreign); err != nil {
				return err
			}
			if own != 1 || foreign != 0 {
				t.Fatal("counter receipts leaked across storage tenant boundaries", own, foreign)
			}
			return nil
		})
		if _, err := f.service.LookupWitness(f.ctx(t.Context()), f.sender+"-spoofed", f.digest, f.input); err == nil {
			t.Fatal("a bus agent claim supplied sender authority")
		}
		if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, fixtures[1-lane].serial, f.digest, f.input, 1<<20); !errors.Is(err, ErrEvidenceIdentityInactive) {
			t.Fatal("foreign certificate serial entered a tenant witness", err)
		}
		if err := tenancy.InTenant(f.ctx(t.Context()), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO device_counter_captures(tenant_id,capture_key) VALUES($1,$2)`, fixtures[1-lane].tenant, make([]byte, 32))
			return err
		}); err == nil {
			t.Fatal("storage admitted a foreign-tenant counter receipt")
		}
	}
	if refs[0].Key == refs[1].Key {
		t.Fatal("same source fields in two tenants shared a witness key")
	}
	f := fixtures[0]
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id=$2`, f.tenant, f.sender)
		return err
	})
	if _, err := f.service.LookupWitness(f.ctx(t.Context()), f.sender, f.digest, f.input); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("rebound source revived an earlier incarnation", err)
	}
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&f.input.PollStartedAt)
	})
	f.input.PollCompletedAt = f.input.PollStartedAt
	if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, f.input, 1<<20); err != nil {
		t.Fatal("new poll after a legitimate source rebind was refused", err)
	}
	fixtures[0] = f
	f = fixtures[1]
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, f.tenant); err != nil {
			return err
		}
		if err := sourceepoch.InvalidateSourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `DELETE FROM device_counter_capture_sources WHERE tenant_id=$1`, f.tenant)
		return err
	})
	if _, err := f.service.LookupWitness(f.ctx(t.Context()), f.sender, f.digest, f.input); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("erased or invalidating counter witness remained readable", err)
	}
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_snapshot_epochs SET generation=generation+1,invalidating=false,transition_token=NULL WHERE tenant_id=$1`, f.tenant)
		return err
	})
	if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, f.input, 1<<20); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("late witness recreated an erased poll", err)
	}
	unseenDigest := f.digest
	unseenDigest[30] = 42
	if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, unseenDigest, f.input, 1<<20); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("previously unseen delayed poll bypassed the completed erasure cutoff", err)
	}
	fresh := f.input
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&fresh.PollStartedAt)
	})
	fresh.PollCompletedAt = fresh.PollStartedAt
	if _, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, f.digest, fresh, 1<<20); err != nil {
		t.Fatal("a new authorized poll after erasure could not be captured", err)
	}
	inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='counter_security_test' WHERE tenant_id=$1 AND serial=$2`, f.tenant, f.serial)
		return err
	})
	if _, err := f.service.LookupWitness(f.ctx(t.Context()), f.sender, f.digest, fresh); !errors.Is(err, ErrCounterCaptureUnavailable) {
		t.Fatal("revoked sender kept a current source witness", err)
	}
	other := fixtures[0]
	if _, err := other.service.LookupWitness(other.ctx(t.Context()), other.sender, other.digest, other.input); err != nil {
		t.Fatal("revocation in one tenant invalidated the other tenant's same-ID sender", err)
	}
}
