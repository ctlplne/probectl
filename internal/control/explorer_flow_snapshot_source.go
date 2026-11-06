// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// FlowSnapshotStorage uses the deployment's existing stores, router, fence and
// envelope. No memory result cache, private signing key or edition gate is added.
type FlowSnapshotStorage struct {
	Pool                    *pgxpool.Pool
	Objects                 objectstore.Store
	Router                  tenancy.Router
	Fence                   tenancy.WriterFence
	DeploymentRetentionDays int
	Cache                   flowsnapshot.Config
}

func (s *Server) WithFlowSnapshotStorage(options FlowSnapshotStorage) *Server {
	lifetime := options.Cache.Lifetime
	if lifetime <= 0 {
		lifetime = flowsnapshot.DefaultLifetime
	}
	exportBytes := options.Cache.ExportBytes
	if exportBytes <= 0 {
		exportBytes = flowsnapshot.DefaultExportBytes
	}
	source := &flowSnapshotSource{server: s, deploymentDays: options.DeploymentRetentionDays, lifetime: lifetime, now: time.Now, tempDir: options.Cache.TempDir, exportBytes: exportBytes, pool: options.Pool}
	service := flowsnapshot.New(options.Pool, options.Objects, options.Router, options.Fence, source.validate, options.Cache)
	s.flowSnapshots = service
	s.flowSnapshotSource = source
	if engine, ok := s.tenantLife.(*tenantlife.Engine); ok {
		engine.WithFlowSnapshots(service)
	}
	return s
}

type flowSnapshotSource struct {
	server         *Server
	deploymentDays int
	lifetime       time.Duration
	now            func() time.Time
	tempDir        string
	exportBytes    int64
	pool           *pgxpool.Pool
}

func (source *flowSnapshotSource) expiry(ctx context.Context, scope flowsnapshot.Scope, clock flowstore.SnapshotInputs) (time.Time, error) {
	if scope.TenantID == "" {
		return time.Time{}, tenancy.ErrNoTenant
	}
	if source.server.tenantLife == nil {
		return time.Time{}, apierror.Unavailable("flow snapshot retention policy is unavailable")
	}
	policy, err := source.server.tenantLife.RetentionFor(ctx, scope.TenantID)
	if err != nil || policy.TenantID != scope.TenantID {
		return time.Time{}, apierror.Unavailable("flow snapshot retention policy could not be validated")
	}
	expiry, err := clock.ExpiresAt(source.deploymentDays, policy.FlowRetentionDays)
	if err != nil {
		return time.Time{}, flowExplorerStoreError(err)
	}
	if !expiry.IsZero() && !source.now().Before(expiry) {
		return time.Time{}, flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	return expiry, nil
}

type flowSnapshotValidity struct {
	Inputs           []flowstore.SnapshotInputs `json:"inputs"`
	TagAuthorization string                     `json:"tag_authorization,omitempty"`
	RoleDigest       string                     `json:"role_digest,omitempty"`
}

func (source *flowSnapshotSource) receipt(ctx context.Context, scope flowsnapshot.Scope, results ...flowstore.PlanResult) (json.RawMessage, time.Time, error) {
	if len(results) < 1 || len(results) > 2 {
		return nil, time.Time{}, flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	until := source.now().Add(source.lifetime)
	proof := flowSnapshotValidity{}
	for _, result := range results {
		clock, err := flowstore.SnapshotInputsForTenant(ctx, scope.TenantID, result)
		if err != nil {
			return nil, time.Time{}, flowExplorerStoreError(err)
		}
		if clock.TagLookup {
			data, err := flowTagQueryFromContext(ctx, scope.TenantID)
			if err != nil || data == nil {
				return nil, time.Time{}, apierror.Unavailable("tag authorization receipt is unavailable")
			}
			revision, err := data.Revision(scope.TenantID)
			if err != nil || revision != result.TagRevision {
				return nil, time.Time{}, apierror.Unavailable("tag authorization revision is unavailable")
			}
			digest, err := data.ContextAuthorization(scope.TenantID)
			if err != nil || (proof.TagAuthorization != "" && proof.TagAuthorization != digest) {
				return nil, time.Time{}, apierror.Unavailable("tag authorization receipt is unavailable")
			}
			proof.TagAuthorization = digest
		}
		if flowstore.PlanUsesInterfaceRoles(result.Query) {
			if result.RoleTenantID != scope.TenantID || len(result.RoleDigest) != 64 || proof.RoleDigest != "" && proof.RoleDigest != result.RoleDigest {
				return nil, time.Time{}, apierror.Unavailable("current role source receipt is unavailable")
			}
			proof.RoleDigest = result.RoleDigest
		}
		expiry, err := source.expiry(ctx, scope, clock)
		if err != nil {
			return nil, time.Time{}, err
		}
		if !expiry.IsZero() && expiry.Before(until) {
			until = expiry
		}
		proof.Inputs = append(proof.Inputs, clock)
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return nil, time.Time{}, apierror.Unavailable("flow snapshot source receipt unavailable")
	}
	return encoded, until, nil
}

func (source *flowSnapshotSource) validate(ctx context.Context, scope flowsnapshot.Scope, proof json.RawMessage) error {
	if len(proof) > 8192 {
		return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	var receipt flowSnapshotValidity
	decoder := json.NewDecoder(bytes.NewReader(proof))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	if len(receipt.Inputs) < 1 || len(receipt.Inputs) > 2 {
		return flowExplorerStoreError(flowstore.ErrSnapshotInputs)
	}
	if err := source.validateTagAuthorization(ctx, scope, receipt); err != nil {
		return err
	}
	if err := source.validateRoleAuthorization(ctx, scope, receipt); err != nil {
		return err
	}
	verifier, ok := flowstore.SnapshotInputVerifierOf(source.server.flowStore)
	if !ok {
		return apierror.Unavailable("flow snapshot source coverage cannot be validated")
	}
	for _, clock := range receipt.Inputs {
		if _, err := source.expiry(ctx, scope, clock); err != nil {
			return err
		}
		if err := verifier.VerifySnapshotInputs(ctx, scope.TenantID, clock); err != nil {
			return flowExplorerStoreError(err)
		}
	}
	return nil
}

func (source *flowSnapshotSource) validateRoleAuthorization(ctx context.Context, scope flowsnapshot.Scope, receipt flowSnapshotValidity) error {
	roles := false
	for _, input := range receipt.Inputs {
		roles = roles || slices.Contains(input.Fields, "in_if_role") || slices.Contains(input.Fields, "out_if_role")
	}
	if !roles && receipt.RoleDigest == "" {
		return nil
	}
	p := auth.PrincipalFrom(ctx)
	if !roles || len(receipt.RoleDigest) != 64 || p == nil || p.TenantID != scope.TenantID || p.UserID != scope.Owner {
		return apierror.Forbidden("current interface role authority is required; run a fresh query")
	}
	current, err := source.server.loadFlowRoleSnapshot(ctx, p, flowstore.ExplorerOperationBudget(ctx, source.server.flowStore))
	if err != nil {
		return err
	}
	digest, err := current.data.Digest(ctx, scope.TenantID, source.now().UTC())
	if err != nil || digest != receipt.RoleDigest {
		return apierror.Forbidden("interface role authority changed; run a fresh query")
	}
	return nil
}

func (source *flowSnapshotSource) validateTagAuthorization(ctx context.Context, scope flowsnapshot.Scope, receipt flowSnapshotValidity) error {
	tagged := false
	var subjects []string
	for _, clock := range receipt.Inputs {
		tagged = tagged || clock.TagLookup
		subjects = append(subjects, clock.TagSubjects...)
	}
	if !tagged && receipt.TagAuthorization == "" {
		return nil
	}
	p := auth.PrincipalFrom(ctx)
	if !tagged || receipt.TagAuthorization == "" || p == nil || p.TenantID != scope.TenantID || p.UserID != scope.Owner {
		return apierror.Forbidden("current tag authorization is required for these results; run a fresh query")
	}
	slices.Sort(subjects)
	subjects = slices.Compact(subjects)
	data, err := source.server.loadFlowTagQueryPolicy(ctx, p, subjects)
	if err != nil {
		return err
	}
	digest, err := data.ContextAuthorization(scope.TenantID)
	if err != nil || digest != receipt.TagAuthorization {
		return apierror.Forbidden("tag context authorization changed; run a fresh query")
	}
	return nil
}
