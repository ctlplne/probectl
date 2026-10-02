// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"encoding/json"
	"io"
	"strings"
)

type subjectRecord struct {
	AgentID string     `json:"agent_id"`
	Result  ResultView `json:"result"`
}

// ExportSubject writes subject-matching endpoint latest-view records for one
// tenant as JSONL. This store is a bounded derived cache; source telemetry
// remains owned by TSDB/OTLP/flow lifecycle paths.
func (s *SnapshotStore) ExportSubject(tenant, subject string, w io.Writer) (int64, error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if tenant == "" || subject == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(w)
	var rows int64
	for agent, st := range s.tenants[tenant] {
		agentMatch := strings.ToLower(agent) == subject
		for _, rv := range st.byType {
			if !agentMatch && !resultMatchesSubject(rv, subject) {
				continue
			}
			if err := enc.Encode(subjectRecord{AgentID: agent, Result: rv}); err != nil {
				return rows, err
			}
			rows++
		}
		for _, rv := range st.sessions {
			if !agentMatch && !resultMatchesSubject(rv, subject) {
				continue
			}
			if err := enc.Encode(subjectRecord{AgentID: agent, Result: rv}); err != nil {
				return rows, err
			}
			rows++
		}
	}
	return rows, nil
}

// DeleteSubject removes subject-matching endpoint latest-view records for one
// tenant. If the endpoint agent id itself matches, the whole endpoint view is
// removed to avoid preserving the subject as a map key.
func (s *SnapshotStore) DeleteSubject(tenant, subject string) (deleted, remaining int64) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if tenant == "" || subject == "" {
		return 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	part := s.tenants[tenant]
	for agent, st := range part {
		if strings.ToLower(agent) == subject {
			deleted += int64(len(st.byType) + len(st.sessions))
			delete(part, agent)
			continue
		}
		for typ, rv := range st.byType {
			if resultMatchesSubject(rv, subject) {
				delete(st.byType, typ)
				deleted++
			}
		}
		for target, rv := range st.sessions {
			if resultMatchesSubject(rv, subject) {
				delete(st.sessions, target)
				deleted++
			}
		}
		st.lastSeen = latestAgentObservation(st)
		if len(st.byType) == 0 && len(st.sessions) == 0 {
			delete(part, agent)
		}
	}
	for agent, st := range part {
		agentMatch := strings.ToLower(agent) == subject
		for _, rv := range st.byType {
			if agentMatch || resultMatchesSubject(rv, subject) {
				remaining++
			}
		}
		for _, rv := range st.sessions {
			if agentMatch || resultMatchesSubject(rv, subject) {
				remaining++
			}
		}
	}
	if len(part) == 0 {
		delete(s.tenants, tenant)
	}
	return deleted, remaining
}

// resultMatchesSubject reports whether one endpoint latest-view record is about
// the subject, by EXACT field-typed equality (TEN-05). The subject identifies
// one endpoint target or attribute value, never a substring of one, so the
// previous strings.Contains match — which let "alice" erase "alice-laptop" and
// "alice.service.example" alike — is replaced by equality. Type is a signal
// category and Error is a free-text message, so neither is subject-bearing;
// attribute keys are column names, so only attribute VALUES are compared.
// subject is already trimmed and lower-cased by the caller.
func resultMatchesSubject(rv ResultView, subject string) bool {
	if strings.ToLower(rv.Target) == subject {
		return true
	}
	for _, v := range rv.Attributes {
		if strings.ToLower(v) == subject {
			return true
		}
	}
	return false
}
