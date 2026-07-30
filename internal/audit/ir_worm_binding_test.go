// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
)

type recordingIRWORMDurability struct {
	failPersistOnce bool
	persistCalls    int
	coverage        int64
	segments        []verifiedWORMSegment
}

func (d *recordingIRWORMDurability) PersistWORMCompanion(
	_ context.Context,
	_ objectstore.Store,
	segment verifiedWORMSegment,
) error {
	d.persistCalls++
	d.segments = append(d.segments, segment)
	if d.failPersistOnce {
		d.failPersistOnce = false
		return errors.New("injected IR companion finalization failure")
	}
	d.coverage = segment.segment.ToSeq
	return nil
}

func (*recordingIRWORMDurability) VerifyIRStages(context.Context) error {
	return nil
}

func (d *recordingIRWORMDurability) CoverageWatermark(
	context.Context,
	objectstore.Store,
	irWORMSegmentVerifier,
) (int64, error) {
	return d.coverage, nil
}

func TestIRWORMExporterRepairsSignedSegmentBeforeAdvancing(t *testing.T) {
	ctx := context.Background()
	objects := objectstore.NewMemory()
	ir := &recordingIRWORMDurability{failPersistOnce: true}
	worm, err := NewWormExporterEphemeralForTest(
		sourceOf(chainedEvents(2)),
		objects,
		testLog(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worm.WithIRWORMDurability(ir)

	if n, err := worm.ExportOnce(ctx); err == nil || n != 0 ||
		!strings.Contains(err.Error(), "IR companion") {
		t.Fatalf("half-finished IR export = (%d, %v), want (0, companion error)", n, err)
	}
	segmentKey := wormPrefix + "segment-000000000001-000000000002.json"
	if _, err := objects.Get(ctx, segmentKey); err != nil {
		t.Fatalf("signed WORM JSON was not durable at crash boundary: %v", err)
	}
	if _, err := objects.Get(ctx, segmentKey+".sig"); err != nil {
		t.Fatalf("signed WORM signature was not durable at crash boundary: %v", err)
	}

	// A retry must reconcile the already-signed segment before it asks the
	// source for anything beyond sequence two. It must not rewrite the JSON.
	before, err := objects.Get(ctx, segmentKey)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := worm.ExportOnce(ctx); err != nil || n != 0 {
		t.Fatalf("IR reconciliation retry = (%d, %v), want (0, nil)", n, err)
	}
	after, err := objects.Get(ctx, segmentKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("IR reconciliation rewrote immutable WORM bytes")
	}
	if ir.persistCalls != 2 || ir.coverage != 2 {
		t.Fatalf(
			"IR persist calls/coverage = %d/%d, want 2/2",
			ir.persistCalls,
			ir.coverage,
		)
	}
	if len(ir.segments) != 2 ||
		ir.segments[0].hash != ir.segments[1].hash ||
		!bytes.Equal(ir.segments[0].raw, ir.segments[1].raw) {
		t.Fatal("IR crash retry did not bind the exact same verified WORM bytes")
	}
	proof, err := worm.RetentionProof(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.verified || !proof.irVerified || proof.watermark != 2 {
		t.Fatalf("retention proof = %#v, want verified IR sequence 2", proof)
	}
}

func TestIRWORMExporterUsesWORMKeyBeforeIRBinding(t *testing.T) {
	ctx := context.Background()
	objects := objectstore.NewMemory()
	ir := &recordingIRWORMDurability{failPersistOnce: true}
	worm, err := NewWormExporterEphemeralForTest(
		sourceOf(chainedEvents(1)),
		objects,
		testLog(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worm.WithIRWORMDurability(ir)
	if _, err := worm.ExportOnce(ctx); err == nil {
		t.Fatal("injected first IR finalization failure was not observed")
	}

	segmentKey := wormPrefix + "segment-000000000001-000000000001.json"
	if err := objects.Put(
		ctx,
		segmentKey+".sig",
		"application/octet-stream",
		bytes.Repeat([]byte{0x5a}, crypto.Ed25519SignatureSize),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.ExportOnce(ctx); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("tampered WORM signature reached IR binder: %v", err)
	}
	if ir.persistCalls != 1 {
		t.Fatalf("IR binder calls after WORM signature tamper = %d, want 1", ir.persistCalls)
	}
}

func TestIRWORMRetentionUsesLowerVerifiedWatermark(t *testing.T) {
	ctx := context.Background()
	objects := objectstore.NewMemory()
	ir := &recordingIRWORMDurability{}
	worm, err := NewWormExporterEphemeralForTest(
		sourceOf(chainedEvents(3)),
		objects,
		testLog(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worm.WithIRWORMDurability(ir)
	if n, err := worm.ExportOnce(ctx); err != nil || n != 3 {
		t.Fatalf("export = (%d, %v), want (3, nil)", n, err)
	}
	ir.coverage = 2
	if got, err := worm.RetentionWatermark(ctx); err != nil || got != 2 {
		t.Fatalf("minimum WORM/IR watermark = (%d, %v), want (2, nil)", got, err)
	}
	if err := worm.VerifyWORMChain(ctx); err == nil {
		t.Fatal("full verification accepted a lagging IR coverage chain")
	}
	ir.coverage = 4
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("IR coverage above the signed WORM chain was accepted")
	}
}

func TestIRWORMActionClassifierFailsClosed(t *testing.T) {
	for _, action := range []string{
		"breakglass.grant",
		"break_glass.access",
		"provider.breakglass.future",
		"provider.break-glass-access",
	} {
		if protected, err := classifyIRWORMAction(action); err == nil || protected {
			t.Fatalf("legacy/unknown action %q classified as (%v, %v)", action, protected, err)
		}
	}
	if protected, err := classifyIRWORMAction(
		"provider.breakglass_access",
	); err != nil || !protected {
		t.Fatalf("current protected action classified as (%v, %v)", protected, err)
	}
	if protected, err := classifyIRWORMAction(
		"provider.tenant_create",
	); err != nil || protected {
		t.Fatalf("ordinary provider action classified as (%v, %v)", protected, err)
	}
}
