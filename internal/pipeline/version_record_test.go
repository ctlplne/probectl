// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"errors"
	"testing"
)

// recordingBinding verifies every pair and remembers reported versions.
type recordingBinding struct {
	refuse   bool
	verified int
	versions []string // "tenant/agent@version"
}

func (b *recordingBinding) Verify(context.Context, string, string) error {
	b.verified++
	if b.refuse {
		return ErrTenantNotBound
	}
	return nil
}

func (b *recordingBinding) RecordVersion(_ context.Context, tenant, agent, version string) {
	b.versions = append(b.versions, tenant+"/"+agent+"@"+version)
}

// plainBinding verifies but cannot record versions (older bindings).
type plainBinding struct{}

func (plainBinding) Verify(context.Context, string, string) error { return nil }

// TestVerifiedBatchRecordsItsProducerVersion (DPR-093): bus collectors never
// carried a version at registration, so the fleet view showed none and the
// staged rollout could never verify a wave containing one. A batch whose
// envelope names the producer's version now records it — after verification,
// on both the namespaced and the shared lane — and only then.
func TestVerifiedBatchRecordsItsProducerVersion(t *testing.T) {
	ctx := context.Background()
	ids := []Identity{{Tenant: "t1", Agent: "a1", Version: "0.6.1"}, {Tenant: "t1", Agent: "a1", Version: "0.6.1"}}

	b := &recordingBinding{}
	if _, _, err := VerifyBatchTenantStrict(ctx, b, "t1", true, ids); err != nil {
		t.Fatalf("namespaced lane: %v", err)
	}
	if _, _, err := VerifyBatchTenantStrict(ctx, b, "", false, ids); err != nil {
		t.Fatalf("shared lane: %v", err)
	}
	if len(b.versions) != 2 || b.versions[0] != "t1/a1@0.6.1" || b.versions[1] != "t1/a1@0.6.1" {
		t.Fatalf("both verified batches must report the version, got %v", b.versions)
	}

	// A refused batch reports nothing: an unverified producer never writes.
	refusing := &recordingBinding{refuse: true}
	if _, _, err := VerifyBatchTenantStrict(ctx, refusing, "t1", true, ids); !errors.Is(err, ErrTenantNotBound) {
		t.Fatalf("expected refusal, got %v", err)
	}
	if len(refusing.versions) != 0 {
		t.Fatalf("a refused batch must not record a version: %v", refusing.versions)
	}

	// No version on the envelope: nothing recorded (older producers).
	silent := &recordingBinding{}
	if _, _, err := VerifyBatchTenantStrict(ctx, silent, "t1", true, []Identity{{Tenant: "t1", Agent: "a1"}}); err != nil {
		t.Fatal(err)
	}
	if len(silent.versions) != 0 {
		t.Fatalf("no envelope version must record nothing: %v", silent.versions)
	}

	// A binding without a recorder keeps working unchanged.
	if _, _, err := VerifyBatchTenantStrict(ctx, plainBinding{}, "t1", true, ids); err != nil {
		t.Fatalf("plain binding: %v", err)
	}

	// The version is part of the identity: two versions in one batch is a
	// heterogeneous batch and is rejected like a mixed tenant or agent.
	mixed := []Identity{{Tenant: "t1", Agent: "a1", Version: "0.6.1"}, {Tenant: "t1", Agent: "a1", Version: "0.6.0"}}
	if _, _, err := VerifyBatchTenantStrict(ctx, b, "t1", true, mixed); !errors.Is(err, ErrMixedBatch) {
		t.Fatalf("mixed versions must be rejected, got %v", err)
	}
}
