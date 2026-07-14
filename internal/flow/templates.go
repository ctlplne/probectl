// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"sync"
	"time"
)

// templateField is one field spec inside a v9/IPFIX template: which information
// element, how many bytes it occupies in a data record, and (IPFIX only) the
// private enterprise number when the element is vendor-specific.
type templateField struct {
	ID         uint16
	Length     uint16 // 0xFFFF in IPFIX means variable-length
	Enterprise uint32 // 0 = IANA
}

// templateRecord is a cached (options) template: the ordered field list plus
// the fixed record width (variable-length fields make Width 0 = "walk fields").
type templateRecord struct {
	Fields   []templateField
	Options  bool // options template (sampling state, not flow data)
	ScopeLen int  // options: number of leading scope fields
	variable bool
	width    int
	added    time.Time
}

// fixedWidth returns the fixed data-record width, or 0 when any field is
// variable-length (IPFIX RFC 7011 §7).
func (t templateRecord) fixedWidth() int {
	if t.variable {
		return 0
	}
	return t.width
}

type templateKey struct {
	exporter string
	domain   uint32
	id       uint16
}

// templateCache holds v9/IPFIX templates per (exporter, observation domain,
// template ID) with a TTL and a hard size cap: templates come from untrusted
// datagrams, so an exporter must not be able to grow collector memory without
// bound (CLAUDE.md §7 guardrail 12). Exceeding the cap evicts the oldest entry.
type templateCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[templateKey]templateRecord
}

func newTemplateCache(ttl time.Duration, maxEntries int) *templateCache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &templateCache{ttl: ttl, max: maxEntries, m: make(map[templateKey]templateRecord)}
}

func (c *templateCache) put(k templateKey, t templateRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t.added = time.Now()
	t.variable = false
	t.width = 0
	for _, f := range t.Fields {
		if f.Length == 0xFFFF {
			t.variable = true
			continue
		}
		t.width += int(f.Length)
	}
	if _, exists := c.m[k]; !exists && len(c.m) >= c.max {
		c.evictOldestLocked()
	}
	c.m[k] = t
}

func (c *templateCache) get(k templateKey) (templateRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[k]
	if !ok {
		return templateRecord{}, false
	}
	if time.Since(t.added) > c.ttl {
		delete(c.m, k)
		return templateRecord{}, false
	}
	return t, true
}

func (c *templateCache) evictOldestLocked() {
	var oldest templateKey
	var oldestAt time.Time
	first := true
	for k, t := range c.m {
		if first || t.added.Before(oldestAt) {
			oldest, oldestAt, first = k, t.added, false
		}
	}
	if !first {
		delete(c.m, oldest)
	}
}

// len reports the number of cached templates (tests + stats).
func (c *templateCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// samplingState remembers the per-(exporter, domain) sampling rate learned from
// v9/IPFIX options data records, applied to subsequent flow records that do not
// carry an inline sampling element.
type samplingState struct {
	mu sync.Mutex
	m  map[string]uint64 // "exporter|domain" -> rate
}

func newSamplingState() *samplingState {
	return &samplingState{m: make(map[string]uint64)}
}

func samplingKey(exporter string, domain uint32) string {
	return exporter + "|" + itoa32(domain)
}

func (s *samplingState) set(exporter string, domain uint32, rate uint64) {
	if rate == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) > 65536 { // hard bound — untrusted input
		s.m = make(map[string]uint64)
	}
	s.m[samplingKey(exporter, domain)] = rate
}

func (s *samplingState) get(exporter string, domain uint32) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[samplingKey(exporter, domain)]
}

// itoa32 is a tiny allocation-light uint32 formatter for map keys.
func itoa32(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
