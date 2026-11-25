// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	endpointwire "github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/lifecycle"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type endpointPackageTestStore struct {
	objectstore.Store
	mu        sync.Mutex
	reads     []string
	afterCopy func()
}

func (s *endpointPackageTestStore) CopyLimited(ctx context.Context, key string, dst io.Writer, limit int64) (int64, error) {
	s.mu.Lock()
	s.reads = append(s.reads, key)
	s.mu.Unlock()
	n, err := s.Store.CopyLimited(ctx, key, dst, limit)
	if err == nil && s.afterCopy != nil {
		s.afterCopy()
	}
	return n, err
}

func (s *endpointPackageTestStore) readKeys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reads...)
}

func TestEndpointPackageAuthorizationUsesTheCertificateTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	objects := &endpointPackageTestStore{Store: objectstore.NewMemory()}
	f.server.WithEndpointPackageStore(objects)
	const platform = "darwin/arm64"
	const planID = "rollout-same-id"
	bodies := []string{strings.Repeat("approved red package", 5000), "approved blue package"}
	var peers []crypto.SPIFFEID
	var digests []string
	for index, tenant := range f.tenants {
		peer, err := crypto.ParseSPIFFEID(crypto.AgentSPIFFEID(tenant, uuid(t)))
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, peer)
		digest := "sha256:" + hex.EncodeToString(crypto.Hash([]byte(bodies[index])))
		digests = append(digests, digest)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			process := endpointwire.ManagedProcess{Platform: platform, RunID: uuid(t)}
			if _, err := (store.Agents{}).RegisterEndpointProcess(ctx, sc, peer.AgentID, "managed-laptop", "managed-laptop",
				"v0.2.0", peer.String(), nil, nil, &process); err != nil {
				return err
			}
			plan := &agent.RolloutPlan{Target: agent.VerifiedArtifact{
				Version: "v0.2.0", Digest: digest, Method: "cosign verify-blob fixture.pkg", VerifiedBy: f.users[tenant],
				Endpoint: &agent.EndpointArtifact{Platform: platform, ExecutableIdentity: "cdhash:" + strings.Repeat("c", 40)},
			}, Waves: []agent.Wave{{Cohort: lifecycle.CohortCanary, AgentIDs: []string{peer.AgentID}, Status: agent.WavePending}},
				VerifyWindow: time.Minute, HeartbeatSLO: time.Minute}
			if _, err := plan.Advance(time.Now()); err != nil {
				return err
			}
			raw, err := encodeRolloutPlan(plan)
			if err != nil {
				return err
			}
			if _, err := (store.Rollouts{}).Create(ctx, sc, planID, raw); err != nil {
				return err
			}
			if _, err := (store.Rollouts{}).Create(ctx, sc, "rollout-"+peer.AgentID, raw); err != nil {
				return err
			}
			owned, err := objectstore.ForTenant(objects, tenant)
			if err != nil {
				return err
			}
			return owned.Put(ctx, endpointPackagePath(plan.Target), "application/octet-stream", []byte(bodies[index]))
		})
	}
	for index, peer := range peers {
		offer, revision, err := f.server.AuthorizeEndpointRolloutRelease(t.Context(), peer, planID, platform)
		if err != nil || revision != 1 || offer.Digest != digests[index] {
			t.Fatalf("tenant %d did not receive its own approved digest: %s, %d, %v", index, offer.Digest, revision, err)
		}
		foreign := peers[1-index]
		offer, revision, err = f.server.AuthorizeEndpointRolloutRelease(t.Context(), peer, "rollout-"+foreign.AgentID, platform)
		domainErr, ok := apierror.As(err)
		if !ok || domainErr.Kind != apierror.KindNotFound || offer.Digest != "" || revision != 0 {
			t.Fatal("a verified device received a different tenant's release", offer.Digest, revision, err)
		}
		before := len(objects.readKeys())
		if err := f.server.DeliverEndpointRolloutPackage(t.Context(), peer, "rollout-"+foreign.AgentID, platform,
			func(agent.VerifiedArtifact, int64, io.Reader) error {
				t.Fatal("another tenant's package reached the transport")
				return nil
			}); err == nil || len(objects.readKeys()) != before {
			t.Fatal("foreign rollout touched package storage", err)
		}
		sent := false
		err = f.server.DeliverEndpointRolloutPackage(t.Context(), peer, planID, platform,
			func(target agent.VerifiedArtifact, size int64, source io.Reader) error {
				body, err := io.ReadAll(source)
				if err != nil || target.Digest != digests[index] || size != int64(len(bodies[index])) || string(body) != bodies[index] {
					t.Fatal("transport received bytes or metadata from the wrong release", target.Digest, size, err)
				}
				sent = true
				return nil
			})
		reads := objects.readKeys()
		if err != nil || !sent || len(reads) != before+1 ||
			!strings.HasPrefix(reads[before], objectstore.TenantKey(peer.TenantID)+"/") {
			t.Fatal("package transfer did not stay on the current tenant namespace", err)
		}
	}
	t.Run("mTLS delivers only each certificate tenant's package", func(t *testing.T) {
		connect := endpointPackageTLSClients(t, f, nil)
		console := httptest.NewTLSServer(f.server.Handler())
		t.Cleanup(console.Close)
		for index, peer := range peers {
			f.in(peer.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
				return (store.Roles{}).AddPermission(ctx, sc, f.roles[peer.TenantID], permAgentWrite)
			})
			request := map[string]any{
				"version": "v0.2.0", "digest": digests[1-index], "verify_method": "cosign verify-blob fixture.pkg",
				"endpoint": map[string]string{"platform": platform, "executable_identity": "cdhash:" + strings.Repeat("c", 40)},
			}
			created := "/v1/rollouts"
			planningStart := len(objects.readKeys())
			callSeasonalAPI(t, console, f.tokens[peer.TenantID], http.MethodPost, created, request, http.StatusBadRequest)
			request["digest"] = digests[index]
			owned, err := objectstore.ForTenant(objects, peer.TenantID)
			if err != nil {
				t.Fatal(err)
			}
			path := endpointPackagePath(agent.VerifiedArtifact{
				Digest: digests[index], Endpoint: &agent.EndpointArtifact{Platform: platform},
			})
			if err := owned.Put(t.Context(), path, "application/octet-stream", []byte(strings.Repeat("x", len(bodies[index])))); err != nil {
				t.Fatal(err)
			}
			callSeasonalAPI(t, console, f.tokens[peer.TenantID], http.MethodPost, created, request, http.StatusConflict)
			if err := owned.Put(t.Context(), path, "application/octet-stream", []byte(bodies[index])); err != nil {
				t.Fatal(err)
			}
			body := callSeasonalAPI(t, console, f.tokens[peer.TenantID], http.MethodPost, created, request, http.StatusCreated)
			planningReads := objects.readKeys()[planningStart:]
			if len(planningReads) != 3 || planningReads[1] != owned.Key(path) || planningReads[2] != owned.Key(path) ||
				!strings.HasPrefix(planningReads[0], objectstore.TenantKey(peer.TenantID)+"/") {
				t.Fatalf("planning read packages outside its tenant or skipped re-verification: %v", planningReads)
			}
			var planned struct {
				ID       string                       `json:"id"`
				Endpoint rolloutEndpointConfiguration `json:"endpoint"`
			}
			if err := json.Unmarshal(body, &planned); err != nil || planned.ID == "" || planned.Endpoint.Platform != platform {
				t.Fatalf("operator rollout did not retain native metadata: %s, %v", body, err)
			}
			out := filepath.Join(t.TempDir(), "managed.pkg")
			before := len(objects.readKeys())
			unissued := connect(peer, false)
			if _, err := unissued.DownloadEndpointPackage(t.Context(), planID, platform, out); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("trusted but unissued certificate reached the release path: %v", err)
			}
			client := connect(peer, true)
			foreign := "rollout-" + peers[1-index].AgentID
			if _, err := client.DownloadEndpointPackage(t.Context(), foreign, platform, out); status.Code(err) != codes.NotFound || len(objects.readKeys()) != before {
				t.Fatalf("foreign rollout reached package storage: %v", err)
			}
			if _, err := client.DownloadEndpointPackage(t.Context(), planned.ID, platform, out); status.Code(err) != codes.NotFound || len(objects.readKeys()) != before {
				t.Fatalf("a pending rollout was usable without an operator release: %v", err)
			}
			callSeasonalAPI(t, console, f.tokens[peer.TenantID], http.MethodPost, created+"/"+planned.ID+"/advance", nil, http.StatusOK)
			metadata, err := client.DownloadEndpointPackage(t.Context(), planned.ID, platform, out)
			if err != nil || metadata.GetPackageDigest() != digests[index] {
				t.Fatalf("certificate got a different package: %v, %v", metadata, err)
			}
			got, err := os.ReadFile(out)
			reads := objects.readKeys()
			if err != nil || string(got) != bodies[index] || len(reads) != before+1 ||
				!strings.HasPrefix(reads[before], objectstore.TenantKey(peer.TenantID)+"/") {
				t.Fatalf("staged installer escaped the certificate tenant: %v", err)
			}
		}
	})
	t.Run("authorization withdrawn before transfer completion", func(t *testing.T) {
		connect := endpointPackageTLSClients(t, f, func(ctx context.Context, peer crypto.SPIFFEID, id string) error {
			if id != "rollout-"+peer.AgentID {
				return nil
			}
			if peer.AgentID == peers[1].AgentID {
				_, _, err := store.NewAgentIdentities(f.pool).RevokeAgent(ctx, peer.TenantID, peer.AgentID, f.users[peer.TenantID])
				return err
			}
			return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				row, err := (store.Rollouts{}).Get(ctx, sc, id)
				if err != nil {
					return err
				}
				plan, err := decodeRolloutPlan(row)
				if err != nil {
					return err
				}
				plan.Halt("fixture withdrew release before stream success")
				data, err := encodeRolloutPlan(plan)
				if err != nil {
					return err
				}
				_, err = (store.Rollouts{}).Update(ctx, sc, id, row.Revision, data)
				return err
			})
		})
		for index, deny := range []codes.Code{codes.NotFound, codes.Unauthenticated} {
			peer := peers[index]
			out := filepath.Join(t.TempDir(), "withdrawn.pkg")
			metadata, err := connect(peer, true).DownloadEndpointPackage(t.Context(), "rollout-"+peer.AgentID, platform, out)
			if status.Code(err) != deny || metadata != nil {
				t.Fatalf("tenant %d completed a withdrawn transfer: %v, %v", index, metadata, err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("tenant %d's withdrawn installer appeared on disk: %v", index, err)
			}
			sibling := peers[1-index]
			metadata, err = connect(sibling, true).DownloadEndpointPackage(t.Context(), planID, platform, out)
			if err != nil || metadata.GetPackageDigest() != digests[1-index] {
				t.Fatalf("tenant %d's withdrawal affected its sibling's transfer: %v, %v", index, metadata, err)
			}
		}
	})
	first, second := peers[0], peers[1]
	if status, err := f.server.tenantStatus.TenantStatus(t.Context(), first.TenantID); err != nil || status != "active" {
		t.Fatal("could not warm the first tenant's active lifecycle cache", status, err)
	}
	if _, err := store.NewTenants(f.pool).UpdateStatus(t.Context(), first.TenantID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.server.AuthorizeEndpointRolloutRelease(t.Context(), first, planID, platform); err == nil {
		t.Fatal("a previous active observation authorized a suspended tenant")
	}
	offer, _, err := f.server.AuthorizeEndpointRolloutRelease(t.Context(), second, planID, platform)
	if err != nil || offer.Digest != digests[1] {
		t.Fatal("suspending one tenant affected its sibling's approved release", err)
	}
	owned, err := objectstore.ForTenant(objects, second.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	path := endpointPackagePath(offer)
	blockDelivery := func(agent.VerifiedArtifact, int64, io.Reader) error {
		t.Fatal("an invalidated package reached the transport")
		return nil
	}
	if err := owned.Put(t.Context(), path, "application/octet-stream", []byte("tampered package")); err != nil {
		t.Fatal(err)
	}
	err = f.server.DeliverEndpointRolloutPackage(t.Context(), second, planID, platform, blockDelivery)
	if domainErr, ok := apierror.As(err); !ok || domainErr.Kind != apierror.KindConflict {
		t.Fatal("stored package did not fail its approved digest check", err)
	}
	if err := owned.Put(t.Context(), path, "application/octet-stream", []byte(bodies[1])); err != nil {
		t.Fatal(err)
	}
	objects.afterCopy = func() {
		f.in(second.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			row, err := (store.Rollouts{}).Get(ctx, sc, planID)
			if err != nil {
				return err
			}
			plan, err := decodeRolloutPlan(row)
			if err != nil {
				return err
			}
			plan.Halt("fixture withdrew release while staging")
			data, err := encodeRolloutPlan(plan)
			if err != nil {
				return err
			}
			_, err = (store.Rollouts{}).Update(ctx, sc, planID, row.Revision, data)
			return err
		})
	}
	if err := f.server.DeliverEndpointRolloutPackage(t.Context(), second, planID, platform, blockDelivery); err == nil {
		t.Fatal("a wave halted during package staging still delivered")
	}
}

func endpointPackageTLSClients(t *testing.T, f *roleExplanationAPIFixture,
	afterSend func(context.Context, crypto.SPIFFEID, string) error) func(crypto.SPIFFEID, bool) *agent.Client {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl-package-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := verdictEvidenceFile(t, dir, "ca.crt", ca.CertPEM())
	server, err := agenttransport.New(verdictEvidenceFile(t, dir, "server.crt", cert), verdictEvidenceFile(t, dir, "server.key", key),
		caFile, f.pool, nil, nil, f.server.log)
	if err != nil {
		t.Fatal(err)
	}
	server.WithEndpointPackages(func(ctx context.Context, peer crypto.SPIFFEID, id, platform string,
		send func(*agentv1.EndpointPackageMetadata, io.Reader) error) error {
		return f.server.StreamEndpointRolloutPackage(ctx, peer, id, platform, func(metadata *agentv1.EndpointPackageMetadata, body io.Reader) error {
			if err := send(metadata, body); err != nil || afterSend == nil {
				return err
			}
			return afterSend(ctx, peer, id)
		})
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(ctx, listener) }()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return func(peer crypto.SPIFFEID, issued bool) *agent.Client {
		t.Helper()
		cert, key, err := ca.IssueClientCert(peer.AgentID, peer.String(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if issued {
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("invalid fixture certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(f.pool).Record(t.Context(), peer.TenantID, peer.AgentID, peer.String(), leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		id := uuid(t)
		client, err := agent.Dial(listener.Addr().String(), verdictEvidenceFile(t, dir, id+".crt", cert), verdictEvidenceFile(t, dir, id+".key", key), caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
}

func TestRolloutVerificationTimeoutPersistsTenantHalt(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	owner, sibling := f.tenants[0], f.tenants[1]
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAgentRead)
		})
	}
	const id = "rollout-verification-timeout"
	path := "/v1/rollouts/" + id
	plan := &agent.RolloutPlan{Target: agent.VerifiedArtifact{
		Version: "v0.2.0", Digest: "sha256:" + strings.Repeat("a", 64), Method: "cosign verify", VerifiedBy: f.users[owner],
	}, Waves: []agent.Wave{{Cohort: lifecycle.CohortCanary, AgentIDs: []string{"unobserved-agent"}, Status: agent.WavePending}},
		VerifyWindow: time.Minute, HeartbeatSLO: time.Minute}
	if _, err := plan.Advance(time.Now().Add(-2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	var revision int64
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		raw, err := encodeRolloutPlan(plan)
		if err != nil {
			return err
		}
		stored, err := (store.Rollouts{}).Create(ctx, sc, id, raw)
		if err == nil {
			revision = stored.Revision
		}
		return err
	})
	server := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(server.Close)
	result := callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/verify", nil, http.StatusBadRequest)
	if !strings.Contains(string(result), "ROLLOUT HALTED") {
		t.Fatal("the expired verification did not report the halt transition", string(result))
	}
	var view struct {
		Halted     bool     `json:"halted"`
		Stragglers []string `json:"stragglers"`
	}
	result = callSeasonalAPI(t, server, f.tokens[owner], http.MethodGet, path, nil, http.StatusOK)
	if err := json.Unmarshal(result, &view); err != nil || !view.Halted || len(view.Stragglers) != 1 {
		t.Fatal("the recorded halt and straggler did not survive the request", view, err)
	}
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/advance", nil, http.StatusBadRequest)
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/verify", nil, http.StatusBadRequest)
	callSeasonalAPI(t, server, f.tokens[sibling], http.MethodGet, path, nil, http.StatusNotFound)
	callSeasonalAPI(t, server, f.tokens[sibling], http.MethodPost, path+"/resume", map[string]string{"reason": "fixture sibling"}, http.StatusNotFound)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var events, audit int
			if err := sc.Q.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM rollout_events WHERE rollout_id=$1 AND action='rollout.verify'),
				(SELECT count(*) FROM audit_events WHERE target=$1 AND action='rollout.verify' AND data->>'outcome'='failure')`, id).Scan(&events, &audit); err != nil {
				return err
			}
			if tenant == owner {
				stored, err := (store.Rollouts{}).Get(ctx, sc, id)
				if err != nil {
					return err
				}
				reloaded, err := decodeRolloutPlan(stored)
				if err != nil || stored.Revision != revision+1 || !reloaded.Halted || len(reloaded.Waves) != 1 ||
					reloaded.Waves[0].Status != agent.WaveHalted || events != 1 || audit != 1 {
					t.Fatal("expected exactly one persisted halt and its audit event", stored.Revision, reloaded, events, audit, err)
				}
			} else if events != 0 || audit != 0 {
				t.Fatal("the sibling could see the rollout event or tenant audit record", events, audit)
			}
			return nil
		})
	}
	callSeasonalAPI(t, server, f.tokens[owner], http.MethodPost, path+"/resume", map[string]string{"reason": "fixture operator checked the agent"}, http.StatusOK)
}
