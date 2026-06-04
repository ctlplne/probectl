// Package agent is the probectl agent runtime (S5): a plugin host that runs
// compiled-in canaries on a schedule into a disk-backed, bounded store-and-forward
// buffer, plus a forwarder that registers, heartbeats, and drains the buffer to
// the control plane over mTLS (S4), reconnecting with backoff.
//
// Probing runs independently of connectivity, so results accumulate during an
// outage and drain on reconnect (at-least-once). The agent is tenant-bound: its
// identity comes from its client certificate's SPIFFE id, and every result it
// buffers/emits is stamped with that tenant + agent id (F50). It holds no database
// connection — it is a thin, dependency-light client.
package agent
