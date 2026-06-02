package ai

import (
	"regexp"
	"strings"
	"time"
)

// Planner turns a natural-language Question into a set of typed S23 queries. It
// is DELIBERATELY deterministic netctl code, not the model: the model never
// decides what to fetch, so untrusted question or evidence text can never widen
// the query scope. The planned queries still run through the S23 engine, which
// enforces the tenant boundary first, then RBAC — the planner cannot bypass it.
type Planner interface {
	Plan(q Question) []Query
}

// Question is a natural-language RCA request. Subject optionally pins the entity
// (target host/IP/URL, prefix, node); when empty the planner extracts one from
// the text. Range bounds the evidence window (default: the last hour).
type Question struct {
	Text    string
	Subject map[string]string
	Range   TimeRange
}

// HeuristicPlanner is the PR1 deterministic planner: it pins the subject and a
// time window, then selects which planes to gather from based on the question's
// language. PR2+ may add model-assisted planning behind the same S23 boundary.
type HeuristicPlanner struct{}

var (
	reCIDR = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b`)
	reIP   = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reURL  = regexp.MustCompile(`https?://[^\s]+`)
	reHost = regexp.MustCompile(`\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\b`)
)

// Plan extracts the subject + window, picks the relevant planes, and emits one
// query per plane (topology only when there's a subject to anchor it, so an
// answer never dumps the whole graph).
func (HeuristicPlanner) Plan(q Question) []Query {
	subject := extractSubject(q)
	r := planRange(q.Range)
	want := selectDomains(strings.ToLower(q.Text))

	queries := make([]Query, 0, len(want))
	for _, d := range allDomains {
		if !want[d] {
			continue
		}
		query := Query{Domain: d, Selector: subject, Range: r, Limit: 50}
		if d == DomainTopology {
			query.NodeID = subject["node"]
			if query.NodeID == "" && subject["target"] != "" {
				query.NodeID = "service:" + subject["target"]
			}
			if query.NodeID == "" {
				continue // no anchor — skip rather than dump every node
			}
		}
		queries = append(queries, query)
	}
	return queries
}

// extractSubject prefers an explicit subject, else pulls the first URL / CIDR /
// IP / hostname out of the question text.
func extractSubject(q Question) map[string]string {
	subj := map[string]string{}
	for k, v := range q.Subject {
		if v != "" {
			subj[k] = v
		}
	}
	if subj["target"] == "" && subj["prefix"] == "" && subj["node"] == "" {
		text := q.Text
		switch {
		case reURL.FindString(text) != "":
			subj["target"] = reURL.FindString(text)
		case reCIDR.FindString(text) != "":
			subj["prefix"] = reCIDR.FindString(text)
		case reIP.FindString(text) != "":
			subj["target"] = reIP.FindString(text)
		case reHost.FindString(strings.ToLower(text)) != "":
			subj["target"] = reHost.FindString(strings.ToLower(text))
		}
	}
	return subj
}

// planRange defaults to the last hour ending now, with the topology snapshot at
// "now", unless the caller bounded the window explicitly.
func planRange(r TimeRange) TimeRange {
	now := time.Now()
	if r.At.IsZero() {
		r.At = now
	}
	if r.Start.IsZero() && r.End.IsZero() {
		r.End = now
		r.Start = now.Add(-time.Hour)
	}
	return r
}

// selectDomains picks the planes to gather from based on the question's language.
// Entities (incidents) are always included — they are the richest RCA evidence —
// and an unspecific question broadens across planes.
func selectDomains(text string) map[Domain]bool {
	want := map[Domain]bool{DomainEntities: true}
	if containsAny(text, "slow", "latency", "loss", "jitter", "throughput", "degrad", "timeout", "down", "unreachable", "perf", "packet") {
		want[DomainMetrics] = true
		want[DomainTopology] = true
	}
	if containsAny(text, "route", "routing", "bgp", "hijack", "withdraw", "origin", "peer", "announce", "prefix") {
		want[DomainEvents] = true
		want[DomainTopology] = true
	}
	if containsAny(text, "change", "deploy", "release", "rollout", "config", "commit", "push") {
		want[DomainEvents] = true
	}
	if containsAny(text, "threat", "tls", "cert", "security", "anomal", "scan", "exfil", "malware") {
		want[DomainEvents] = true
	}
	if containsAny(text, "topolog", "path", "depend", "upstream", "downstream", "neighbor", "reach") {
		want[DomainTopology] = true
	}
	if len(want) == 1 { // only entities matched → broaden
		want[DomainMetrics] = true
		want[DomainEvents] = true
		want[DomainTopology] = true
	}
	return want
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
