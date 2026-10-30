// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	workerTenant = "00000000-0000-0000-0000-000000000101"
	workerOwner  = "00000000-0000-0000-0000-000000000201"
	workerID     = "00000000-0000-0000-0000-000000000301"
	workerOther  = "00000000-0000-0000-0000-000000000401"
)

func workerTestReference(t *testing.T, kind WorkerCredentialKind) (WorkerCredentialRef, []byte) {
	t.Helper()
	hash := crypto.Hash([]byte("owned accepted credential hash input"))
	ref, err := CaptureWorkerCredential(kind, workerTenant, workerOwner, workerID, hash)
	if err != nil {
		t.Fatal(err)
	}
	return ref, hash
}

func TestWorkerCredentialMatchesExactOriginAndRejectsSuccessor(t *testing.T) {
	for _, kind := range []WorkerCredentialKind{WorkerCredentialSession, WorkerCredentialMCP} {
		ref, hash := workerTestReference(t, kind)
		if !ref.MatchesStored(kind, workerTenant, workerOwner, workerID, hash) {
			t.Fatal("exact accepted credential did not match")
		}
		successor := crypto.Hash([]byte("same row rotated to a different accepted credential"))
		if ref.MatchesStored(kind, workerTenant, workerOwner, workerID, successor) {
			t.Fatal("stable row ID borrowed a successor credential")
		}
		for _, change := range []struct {
			kind              WorkerCredentialKind
			tenant, owner, id string
		}{
			{kind, workerOther, workerOwner, workerID},
			{kind, workerTenant, workerOther, workerID},
			{kind, workerTenant, workerOwner, workerOther},
			{0, workerTenant, workerOwner, workerID},
			{3 - kind, workerTenant, workerOwner, workerID},
		} {
			if ref.MatchesStored(change.kind, change.tenant, change.owner, change.id, hash) {
				t.Fatal("different kind/tenant/owner/row matched the same hash")
			}
		}
		for _, wrong := range [][]byte{nil, hash[:31], append(append([]byte{}, hash...), 0)} {
			if ref.MatchesStored(kind, workerTenant, workerOwner, workerID, wrong) {
				t.Fatal("malformed stored hash matched")
			}
		}
		if _, _, err := ref.ScopedID(workerOther, workerOwner); !errors.Is(err, ErrWorkerCredentialInvalid) {
			t.Fatal("foreign tenant obtained credential metadata", err)
		}
		if _, _, err := ref.ScopedID(workerTenant, workerOther); !errors.Is(err, ErrWorkerCredentialInvalid) {
			t.Fatal("foreign owner obtained credential metadata", err)
		}
	}
}

func TestWorkerCredentialPrivateEncodingRoundTripAndScopeTampering(t *testing.T) {
	ref, hash := workerTestReference(t, WorkerCredentialSession)
	encoded, err := ref.MarshalBinary()
	if err != nil || len(encoded) != workerCredentialBytes || bytes.Contains(encoded, hash) {
		t.Fatal("private encoding failed or retained the stored token hash", err)
	}
	decoded, err := DecodeWorkerCredentialRef(encoded)
	if err != nil || !decoded.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, hash) {
		t.Fatal("private reference did not survive envelope codec", err)
	}
	encoded[len(encoded)-1] ^= 1
	if !decoded.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, hash) {
		t.Fatal("decoder retained a mutable alias into ciphertext input")
	}
	tampered, err := DecodeWorkerCredentialRef(encoded)
	if err != nil || tampered.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, hash) {
		t.Fatal("syntax decoding granted authority to a changed fingerprint", err)
	}
	for _, offset := range []int{5, 41, 77} {
		wire, _ := ref.MarshalBinary()
		copy(wire[offset:offset+36], workerOther)
		changed, err := DecodeWorkerCredentialRef(wire)
		if err != nil {
			t.Fatal("scope mutation is syntactically valid for this negative proof", err)
		}
		tenant, owner, id := workerTenant, workerOwner, workerID
		switch offset {
		case 5:
			tenant = workerOther
		case 41:
			owner = workerOther
		case 77:
			id = workerOther
		}
		if changed.MatchesStored(WorkerCredentialSession, tenant, owner, id, hash) {
			t.Fatal("fingerprint was not bound to its authoritative scope")
		}
	}
	wire, _ := ref.MarshalBinary()
	for _, bad := range [][]byte{nil, wire[:len(wire)-1], append(append([]byte{}, wire...), 0), append([]byte("PWC1"), wire[4:]...), append([]byte("PWC3"), wire[4:]...)} {
		if _, err := DecodeWorkerCredentialRef(bad); !errors.Is(err, ErrWorkerCredentialInvalid) {
			t.Fatal("unknown/truncated/extended encoding accepted", err)
		}
	}
	wire[4] = 255
	if _, err := DecodeWorkerCredentialRef(wire); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("unknown credential kind accepted", err)
	}
}

func TestWorkerCredentialNeverPublishesJSONOrFormattedPrivateValues(t *testing.T) {
	ref, hash := workerTestReference(t, WorkerCredentialMCP)
	if _, err := json.Marshal(ref); err == nil {
		t.Fatal("private reference was serialized by a public JSON encoder")
	}
	if err := json.Unmarshal([]byte(`{"tenant":"`+workerTenant+`","owner":"`+workerOwner+`"}`), &ref); err == nil {
		t.Fatal("JSON payload supplied a private worker reference")
	}
	for _, formatted := range []string{fmt.Sprintf("%v", ref), fmt.Sprintf("%+v", &ref), fmt.Sprintf("%#v", ref), fmt.Sprintf("%x", ref), fmt.Sprintf("%+v", struct{ Ref WorkerCredentialRef }{ref}), fmt.Sprintf("%#v", struct{ private *WorkerCredentialRef }{&ref}), fmt.Sprintf("%#v", struct{ private WorkerCredentialRef }{ref})} {
		for _, private := range []string{workerTenant, workerOwner, workerID, hex.EncodeToString(hash), hex.EncodeToString(ref.binding.fingerprint[:])} {
			if strings.Contains(formatted, private) {
				t.Fatal("formatted output disclosed private credential metadata")
			}
		}
	}
	if !ref.MatchesStored(WorkerCredentialMCP, workerTenant, workerOwner, workerID, hash) {
		t.Fatal("failed JSON decoding mutated an admitted reference")
	}
}

func TestWorkerCredentialZeroAndMalformedBindingsFailClosed(t *testing.T) {
	var zero WorkerCredentialRef
	if _, _, err := zero.ScopedID(workerTenant, workerOwner); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("zero reference obtained an identity", err)
	}
	if _, err := zero.MarshalBinary(); !errors.Is(err, ErrWorkerCredentialInvalid) {
		t.Fatal("zero reference became a durable identity", err)
	}
	hash := crypto.Hash([]byte("owned accepted hash"))
	for _, test := range []struct {
		kind              WorkerCredentialKind
		tenant, owner, id string
		hash              []byte
	}{
		{0, workerTenant, workerOwner, workerID, hash},
		{WorkerCredentialSession, "", workerOwner, workerID, hash},
		{WorkerCredentialSession, workerTenant, "", workerID, hash},
		{WorkerCredentialSession, workerTenant, workerOwner, "", hash},
		{WorkerCredentialSession, " " + workerTenant, workerOwner, workerID, hash},
		{WorkerCredentialSession, strings.Replace(workerTenant, "-", ":", 1), workerOwner, workerID, hash},
		{WorkerCredentialSession, workerTenant, workerOwner, workerID, nil},
		{WorkerCredentialSession, workerTenant, workerOwner, workerID, hash[:31]},
	} {
		if _, err := CaptureWorkerCredential(test.kind, test.tenant, test.owner, test.id, test.hash); !errors.Is(err, ErrWorkerCredentialInvalid) {
			t.Fatal("malformed admitted identity accepted", err)
		}
	}
}
