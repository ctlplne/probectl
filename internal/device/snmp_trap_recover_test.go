// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"strings"
	"testing"
)

// ING-05 defense in depth: a panic inside gosnmp's read loop runs on the device
// agent's listener goroutine and would otherwise crash the whole agent.
// listenWithRecover must convert it into an error so only the listener stops.
func TestListenWithRecover(t *testing.T) {
	err := listenWithRecover(func() error { panic("gosnmp exploded") })
	if err == nil || !strings.Contains(err.Error(), "recovered") {
		t.Fatalf("a panicking listener must be recovered into an error; got %v", err)
	}

	sentinel := errors.New("listener stopped normally")
	if got := listenWithRecover(func() error { return sentinel }); !errors.Is(got, sentinel) {
		t.Fatalf("a non-panicking listener must return its own error unchanged; got %v", got)
	}
}
