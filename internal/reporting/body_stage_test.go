// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportBodyStageCopiesExactBytesAndSealsIntegrity(t *testing.T) {
	for _, tenant := range []string{"red", "blue"} {
		t.Run(tenant, func(t *testing.T) {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			stage, err := NewBodyStage(ctx, tenant, DefaultBodyStageLimits())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stage.Close() })
			if reader, err := stage.Open(ctx); err == nil || reader != nil {
				t.Fatal("unsealed bytes became readable")
			}
			input := []byte("abc")
			if n, err := stage.Write(input); err != nil || n != 3 {
				t.Fatal(n, err)
			}
			input[0] = 'X'
			receipt, err := stage.Seal()
			if err != nil || receipt.Bytes != 3 || receipt.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || receipt.AllocatedBytes > stage.limits.MemoryBytes {
				t.Fatal("staged original bytes or independent SHA256 vector changed", receipt, err)
			}
			foreign := tenancy.WithTenant(t.Context(), tenancy.ID(tenant+"-other"))
			for _, denied := range []context.Context{t.Context(), foreign} {
				if reader, err := stage.Open(denied); !errors.Is(err, ErrBodyStageScope) || reader != nil {
					t.Fatal("staged bytes escaped bound tenant scope", err)
				}
			}
			reader, err := stage.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if second, err := stage.Open(ctx); err == nil || second != nil {
				t.Fatal("staging allocated an overlapping reader")
			}
			got, err := io.ReadAll(reader)
			if err != nil || string(got) != "abc" {
				t.Fatal("stage borrowed caller memory or changed sealed bytes", err)
			}
			_ = reader.Close()
			second, err := stage.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = reader.Close() // must not release the newer reader's reservation
			if third, err := stage.Open(ctx); err == nil || third != nil {
				t.Fatal("repeated old Close released another active reader")
			}
			retained := append([][]byte(nil), stage.chunks...)
			_ = stage.Close()
			if n, err := second.Read(make([]byte, 8)); err == nil || n != 0 {
				t.Fatal("closed body remained readable")
			}
			_ = second.Close()
			for _, chunk := range retained {
				if bytes.Count(chunk, []byte{0}) != len(chunk) {
					t.Fatal("closed staging retained rendered bytes")
				}
			}
		})
	}
}

func TestReportBodyStageRefusesPartialOverBudgetAndCanceledOutput(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), "red")
	for _, denied := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), "blue")} {
		if stage, err := NewBodyStage(denied, "red", DefaultBodyStageLimits()); !errors.Is(err, ErrBodyStageScope) || stage != nil {
			t.Fatal("unbound or foreign staging admission succeeded", err)
		}
	}
	for _, limits := range []BodyStageLimits{{}, {Bytes: math.MaxInt64, MemoryBytes: math.MaxInt64}, {Bytes: 3, MemoryBytes: 1}} {
		if stage, err := NewBodyStage(ctx, "red", limits); err == nil || stage != nil {
			t.Fatal("invalid staging budget accepted")
		}
	}
	empty, err := NewBodyStage(ctx, "red", DefaultBodyStageLimits())
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := empty.Seal(); err == nil || receipt != (BodyStageReceipt{}) {
		t.Fatal("empty stage was sealed")
	}
	if _, err := empty.Write([]byte("later")); err == nil {
		t.Fatal("failed empty seal resumed writing")
	}
	_ = empty.Close()
	closed, cancel := context.WithCancel(ctx)
	cancel()
	if stage, err := NewBodyStage(closed, "red", DefaultBodyStageLimits()); !errors.Is(err, context.Canceled) || stage != nil {
		t.Fatal("canceled staging admission succeeded", err)
	}
	for _, tc := range []struct {
		name   string
		limits BodyStageLimits
	}{
		{"output_limit", BodyStageLimits{Bytes: 3, MemoryBytes: 1 << 20}},
		{"allocation_limit", BodyStageLimits{Bytes: BodyChunkBytes, MemoryBytes: 3 * BodyChunkBytes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, err := NewBodyStage(ctx, "red", tc.limits)
			if err != nil {
				t.Fatal("positive staging admission did not reach the intended refusal", err)
			}
			defer func() { _ = stage.Close() }()
			if n, err := stage.Write([]byte("four")); !errors.Is(err, ErrBodyStageLimit) || n != 0 {
				t.Fatal("staging ignored output or allocation limit", n, err)
			}
			if n, err := stage.Write([]byte("x")); !errors.Is(err, ErrBodyStageLimit) || n != 0 {
				t.Fatal("failed staging resumed writing", n, err)
			}
			if receipt, err := stage.Seal(); err == nil || receipt != (BodyStageReceipt{}) {
				t.Fatal("failed staging produced a receipt")
			}
			if reader, err := stage.Open(ctx); err == nil || reader != nil {
				t.Fatal("failed staging exposed partial output")
			}
		})
	}
	for _, when := range []string{"before_seal", "after_seal"} {
		t.Run(when, func(t *testing.T) {
			origin, cancel := context.WithCancel(ctx)
			stage, err := NewBodyStage(origin, "red", DefaultBodyStageLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stage.Close() }()
			if _, err := stage.Write([]byte("whole")); err != nil {
				t.Fatal(err)
			}
			if when == "after_seal" {
				if _, err := stage.Seal(); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			if when == "before_seal" {
				if receipt, err := stage.Seal(); err == nil || receipt != (BodyStageReceipt{}) {
					t.Fatal("canceled stage sealed successfully")
				}
			}
			if reader, err := stage.Open(ctx); err == nil || reader != nil {
				t.Fatal("new context revived a canceled origin")
			}
		})
	}
	failure := errors.New("source failed after partial output")
	var partial *BodyStage
	var held [][]byte
	stage, receipt, err := StageBody(ctx, "red", DefaultBodyStageLimits(), func(target io.Writer) error {
		partial = target.(*BodyStage)
		if _, err := target.Write([]byte("partial")); err != nil {
			return err
		}
		held = append(held, partial.chunks...)
		return failure
	})
	if !errors.Is(err, failure) || stage != nil || receipt != (BodyStageReceipt{}) || partial.state != "closed" {
		t.Fatal("failed renderer returned publishable staging", err)
	}
	for _, chunk := range held {
		if bytes.Count(chunk, []byte{0}) != len(chunk) {
			t.Fatal("failed renderer left staging bytes alive")
		}
	}
}

type failingBodyStageHasher struct{ crypto.Provider }

func (failingBodyStageHasher) HashReader(io.Reader) ([]byte, error) {
	return make([]byte, 32), io.ErrUnexpectedEOF
}

func TestReportBodyStageHashFailureNeverReturnsPartialDigest(t *testing.T) {
	original := crypto.Default
	crypto.Default = failingBodyStageHasher{original}
	defer func() { crypto.Default = original }()
	ctx := tenancy.WithTenant(t.Context(), "red")
	stage, receipt, err := StageBody(ctx, "red", DefaultBodyStageLimits(), func(target io.Writer) error {
		_, err := target.Write([]byte("complete bytes, failed hash"))
		return err
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) || stage != nil || receipt != (BodyStageReceipt{}) {
		t.Fatal("failed hash exposed a body or partial digest", receipt, err)
	}
}
