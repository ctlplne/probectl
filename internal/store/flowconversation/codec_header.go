// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"encoding/binary"
	"math"

	"github.com/ctlplne/probectl/internal/auth"
)

func encodeMessageHeader(origin auth.WorkerCredentialRef, requirements []string, budget int) ([]byte, error) {
	canonical, err := canonicalMessageRequirements(requirements, budget)
	if err != nil {
		return nil, err
	}
	if uint64(len(canonical)) > math.MaxUint32 {
		return nil, ErrMessageBudget
	}
	credential, err := origin.MarshalBinary()
	if err != nil {
		return nil, ErrMessageIntegrity
	}
	defer clear(credential)
	size := 4 + 4 + len(credential) + 4 + 32
	if size > budget {
		return nil, ErrMessageBudget
	}
	for _, requirement := range canonical {
		if uint64(len(requirement)) > math.MaxUint32 || budget-size < 4 || len(requirement) > budget-size-4 {
			return nil, ErrMessageBudget
		}
		size += 4 + len(requirement)
	}
	out := make([]byte, 0, size)
	out = append(out, "PCH1"...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(credential)))
	out = append(out, credential...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(canonical)))
	for _, requirement := range canonical {
		out = binary.BigEndian.AppendUint32(out, uint32(len(requirement)))
		out = append(out, requirement...)
	}
	return append(out, make([]byte, 32)...), nil
}

type messageHeaderReader struct{ body []byte }

func (r *messageHeaderReader) take(size uint32) ([]byte, bool) {
	if uint64(size) > uint64(len(r.body)) {
		return nil, false
	}
	value := r.body[:int(size)]
	r.body = r.body[int(size):]
	return value, true
}

func (r *messageHeaderReader) number() (uint32, bool) {
	value, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(value), true
}

func decodeMessageHeader(body []byte) (auth.WorkerCredentialRef, []string, []byte, error) {
	r := messageHeaderReader{body}
	magic, ok := r.take(4)
	if !ok || string(magic) != "PCH1" {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	credentialBytes, ok := r.number()
	if !ok {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	credential, ok := r.take(credentialBytes)
	if !ok {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	origin, err := auth.DecodeWorkerCredentialRef(credential)
	if err != nil {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	count, ok := r.number()
	if !ok || count == 0 || uint64(count) > uint64(len(r.body))/5 {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	requirements := make([]string, 0, int(count))
	last := ""
	for range count {
		size, ok := r.number()
		if !ok {
			return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
		}
		value, ok := r.take(size)
		if !ok || !messageRequirement(string(value)) || string(value) <= last {
			return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
		}
		last = string(value)
		requirements = append(requirements, last)
	}
	digest, ok := r.take(32)
	if !ok || len(r.body) != 0 {
		return auth.WorkerCredentialRef{}, nil, nil, ErrMessageIntegrity
	}
	return origin, requirements, digest, nil
}
