// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
		agentMatch := strings.Contains(strings.ToLower(agent), subject)
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
		if strings.Contains(strings.ToLower(agent), subject) {
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
		agentMatch := strings.Contains(strings.ToLower(agent), subject)
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

func resultMatchesSubject(rv ResultView, subject string) bool {
	if subjectTextContains(subject, rv.Type, rv.Target, rv.Error) {
		return true
	}
	for k, v := range rv.Attributes {
		if subjectTextContains(subject, k, v) {
			return true
		}
	}
	return false
}

func subjectTextContains(subject string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), subject) {
			return true
		}
	}
	return false
}
