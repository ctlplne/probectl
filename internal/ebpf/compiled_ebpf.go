// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build ebpf

package ebpf

// liveCompiled is true when built with -tags ebpf: the cilium/ebpf live source
// is linked in (see source_live_linux.go).
const liveCompiled = true
