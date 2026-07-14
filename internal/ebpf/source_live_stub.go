// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build !linux || !ebpf

package ebpf

import "errors"

// newLiveSource is unavailable on builds without the eBPF loader: the default
// build, macOS/Windows, or Linux built without -tags ebpf. Set a fixture_path
// (PROBECTL_EBPF_FIXTURE_PATH) for the no-kernel path, or rebuild with -tags ebpf
// on a Linux host with clang + libbpf headers. See docs/ebpf-agent.md. The real
// implementation lives in source_live_linux.go (//go:build linux && ebpf).
func newLiveSource(*Config) (Source, error) {
	return nil, errors.New("ebpf: live source not compiled in (build -tags ebpf on Linux with clang, or set fixture_path)")
}
