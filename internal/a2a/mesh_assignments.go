// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"bytes"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type meshReporter struct {
	key          [MeshResultKeyBytes]byte
	issued       atomic.Pointer[issuedMeshTask]
	registeredAt time.Time
}

type issuedMeshTask struct {
	at     time.Time
	target string
}

// A mesh assignment lives in the broker until tasks expire and in the mesh
// scheduler for its bounded report window. Only PollFor discloses a key.
type meshAssignment struct {
	initiator meshReporter
	responder meshReporter
}

func newMeshAssignment() (*meshAssignment, error) {
	wire, err := crypto.Random(2 * MeshResultKeyBytes)
	if err != nil {
		return nil, err
	}
	assignment := &meshAssignment{}
	copy(assignment.initiator.key[:], wire[:MeshResultKeyBytes])
	copy(assignment.responder.key[:], wire[MeshResultKeyBytes:])
	return assignment, nil
}

func (a *meshAssignment) issue(task Task, at time.Time) []byte {
	reporter := a.reporter(task.Role)
	target := task.PeerAgentID
	if task.Role == RoleInitiator {
		target = net.JoinHostPort(task.ResponderHost, strconv.FormatUint(uint64(task.ResponderPort), 10))
	}
	reporter.issued.CompareAndSwap(nil, &issuedMeshTask{at: at, target: target})
	return bytes.Clone(reporter.key[:])
}

func (a *meshAssignment) reporter(role Role) *meshReporter {
	if role == RoleResponder {
		return &a.responder
	}
	return &a.initiator
}

// reserveMeshCapacity holds responder queue capacity for the whole operation.
// No task is visible until the caller's tenant audit transaction commits.
func (b *Broker) reserveMeshCapacity(tenant string, count int) (func(), error) {
	b.mu.Lock()
	b.gcLocked()
	if !b.hasPendingCapacityLocked(tenant, count) {
		b.mu.Unlock()
		return nil, ErrPendingFull
	}
	b.reservedByTenant[tenant] += count
	b.mu.Unlock()
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.reservedByTenant[tenant] -= count
		if b.reservedByTenant[tenant] == 0 {
			delete(b.reservedByTenant, tenant)
		}
	}, nil
}
