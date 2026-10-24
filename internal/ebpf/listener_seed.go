// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import "fmt"

// Ways the agent can learn who owns a listening socket that predates it
// (ING-24). The startup log names the one that ran.
const (
	// ListenerSeedTaskFileIterator: the l4flow task_file BPF iterator walked
	// every task's open files once at start and recorded each TCP (or MPTCP)
	// socket in LISTEN with its owning process.
	ListenerSeedTaskFileIterator = "bpf task_file iterator"
	// ListenerSeedNone: nothing was seeded. A server started before the agent
	// is attributed only when one of its connections closes (close() runs in
	// the owner's context); one started after the agent is unaffected.
	ListenerSeedNone = "none"
)

// ListenerSeed is what the start-time listener seed did, stage by stage
// (files visited, socket files, TCP/MPTCP listeners, owners recorded), so a
// start that attributes no pre-existing listener names the stage that dropped
// them.
type ListenerSeed struct {
	Method         string
	Reason         string // why nothing was seeded; empty when Method is the iterator
	FilesVisited   uint64
	SocketFiles    uint64
	TCPListeners   uint64
	OwnersRecorded uint64
}

// Attributed reports whether listeners that predate the agent are attributed
// to their process from the first connection.
func (s ListenerSeed) Attributed() bool { return s.Method == ListenerSeedTaskFileIterator }

// stats is the seed's stage counters in their historical order.
func (s ListenerSeed) stats() [4]uint64 {
	return [4]uint64{s.FilesVisited, s.SocketFiles, s.TCPListeners, s.OwnersRecorded}
}

// judgeListenerSeed decides what a seed run achieved. loaded is false when the
// kernel refused the iterator program (no bpf_sock_from_file before 5.11);
// runErr is the attach/open/read failure. A walk that read to the end but
// never saw a single open file did not seed anything — the agent's own
// descriptors alone guarantee at least one file in any walk that ran — so it
// is reported as not seeded, never as success.
func judgeListenerSeed(loaded bool, runErr error, stats [4]uint64) ListenerSeed {
	s := ListenerSeed{Method: ListenerSeedNone, FilesVisited: stats[0], SocketFiles: stats[1], TCPListeners: stats[2], OwnersRecorded: stats[3]}
	switch {
	case !loaded:
		s.Reason = "the kernel refused the task_file iterator program (it needs bpf_sock_from_file, kernel >= 5.11)"
	case runErr != nil:
		s.Reason = fmt.Sprintf("the task_file iterator failed: %v", runErr)
	case s.FilesVisited == 0:
		s.Reason = "the task_file iterator ran but was never handed an open file, not even the agent's own"
	default:
		s.Method = ListenerSeedTaskFileIterator
	}
	return s
}

// listenerSeedLogAttrs is the startup log record for a seed.
func listenerSeedLogAttrs(s ListenerSeed) []any {
	attrs := []any{"method", s.Method, "preexisting_listeners_attributed", s.Attributed()}
	if s.Reason != "" {
		attrs = append(attrs, "reason", s.Reason)
	}
	return append(attrs, "files_visited", s.FilesVisited, "socket_files", s.SocketFiles,
		"tcp_listeners", s.TCPListeners, "owners_recorded", s.OwnersRecorded)
}
