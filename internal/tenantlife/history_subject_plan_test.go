// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

func subjectDirectoryCodec(t *testing.T) (context.Context, *flowconversation.Codec, string, subjectDirectoryWire) {
	t.Helper()
	ids := make([]string, 4)
	for i := range ids {
		var err error
		ids[i], err = crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("owned-subject-directory", base64.StdEncoding.EncodeToString(key))
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	codec, err := flowconversation.NewCodec(flowconversation.DefaultCodecBudget())
	if err != nil {
		t.Fatal(err)
	}
	w := subjectDirectoryWire{Version: 1, Tenant: ids[0], Subject: "owned@example.test", Kind: "user", ID: ids[1], DirectoryAliases: []string{ids[1], "owned@example.test"}, SessionIDs: []string{ids[2]}}
	slices.Sort(w.DirectoryAliases)
	w.Aliases = append(slices.Clone(w.DirectoryAliases), ids[2])
	slices.Sort(w.Aliases)
	return tenancy.WithTenant(t.Context(), tenancy.ID(ids[0])), codec, ids[3], w
}

func TestHistorySubjectDirectorySnapshotStrictPrivateDecode(t *testing.T) {
	ctx, codec, operation, value := subjectDirectoryCodec(t)
	app, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := codec.PrepareSubjectErasurePlan(ctx, operation, value.Subject, value.Aliases, app)
	clear(app)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Release()
	snapshot, err := decodeSubjectDirectory(ctx, value.Tenant, plan, 1<<20)
	if err != nil || snapshot.value.ID != value.ID || snapshot.value.Kind != "user" || !slices.Equal(snapshot.value.SessionIDs, value.SessionIDs) {
		t.Fatal("typed identity snapshot did not decode", err)
	}
	if _, err := json.Marshal(snapshot); !errors.Is(err, errSubjectDirectoryPlan) {
		t.Fatal("private snapshot crossed JSON", err)
	}
	if text := fmt.Sprintf("%#v", snapshot); strings.Contains(text, value.ID) || strings.Contains(text, value.Subject) {
		t.Fatal("private snapshot leaked through formatting")
	}
	snapshot.release()
	if snapshot.value.ID != "" || snapshot.value.Subject != "" || len(snapshot.value.Aliases) != 0 {
		t.Fatal("private snapshot survived release")
	}
	if _, err := decodeSubjectDirectory(ctx, value.Tenant, plan, 1); !errors.Is(err, flowconversation.ErrMessageBudget) {
		t.Fatal("application bypassed explicit resource budget", err)
	}
	legacy, err := codec.PrepareSubjectErasurePlan(ctx, operation, value.Subject, value.Aliases)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Release()
	if _, err := decodeSubjectDirectory(ctx, value.Tenant, legacy, 1<<20); !errors.Is(err, errSubjectDirectoryPlan) {
		t.Fatal("legacy alias plan fabricated typed directory proof", err)
	}
}

func TestHistorySubjectDirectorySnapshotRefusesForgedBindingsAndFields(t *testing.T) {
	ctx, codec, operation, original := subjectDirectoryCodec(t)
	for _, fault := range []string{"version", "tenant", "kind", "identity", "extra_alias", "subject_not_directory", "missing_credential_alias", "unsorted", "unknown_field", "duplicate_field"} {
		t.Run(fault, func(t *testing.T) {
			value := original
			value.Aliases, value.DirectoryAliases = slices.Clone(original.Aliases), slices.Clone(original.DirectoryAliases)
			value.SessionIDs = slices.Clone(original.SessionIDs)
			switch fault {
			case "version":
				value.Version = 2
			case "tenant":
				value.Tenant = operation
			case "kind":
				value.Kind = "provider"
			case "identity":
				value.ID = "caller-chosen"
			case "extra_alias":
				value.Aliases = append(value.Aliases, "replacement@example.test")
				slices.Sort(value.Aliases)
			case "subject_not_directory":
				value.DirectoryAliases = []string{value.ID}
			case "missing_credential_alias":
				value.SessionIDs = []string{operation}
			case "unsorted":
				slices.Reverse(value.DirectoryAliases)
			}
			app, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "unknown_field" {
				app = append(bytes.TrimSuffix(app, []byte("}")), []byte(`,"complete":true}`)...)
			}
			if fault == "duplicate_field" {
				app = append(bytes.TrimSuffix(app, []byte("}")), []byte(`,"version":1}`)...)
			}
			plan, err := codec.PrepareSubjectErasurePlan(ctx, operation, value.Subject, value.Aliases, app)
			clear(app)
			if err != nil {
				t.Fatal(err)
			}
			defer plan.Release()
			if snapshot, err := decodeSubjectDirectory(ctx, original.Tenant, plan, 1<<20); snapshot.value != nil || !errors.Is(err, errSubjectDirectoryPlan) {
				t.Fatal("forged directory/application binding was accepted", err)
			}
		})
	}
}

func TestHistorySubjectPreparationRequiresIndependentAuthority(t *testing.T) {
	ctx, _, operation, wire := subjectDirectoryCodec(t)
	var engine *Engine
	current := func(context.Context, string) error { return nil }
	for _, invalid := range []context.Context{t.Context(), auth.WithPrincipal(ctx, &auth.Principal{TenantID: wire.Tenant}), tenancy.WithTenant(ctx, tenancy.ID(operation))} {
		if _, err := engine.prepareHistorySubject(invalid, wire.Tenant, operation, wire.Subject, flowconversation.DefaultCodecBudget(), current); !errors.Is(err, flowconversation.ErrMessageDenied) {
			t.Fatal("request or foreign preparation reached storage", err)
		}
	}
	if _, err := engine.prepareHistorySubject(ctx, wire.Tenant, operation, wire.Subject, flowconversation.DefaultCodecBudget(), nil); !errors.Is(err, flowconversation.ErrMessageDenied) {
		t.Fatal("missing current authority reached storage", err)
	}
}
