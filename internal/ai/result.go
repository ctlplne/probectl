package ai

import "time"

// Row is one normalized result record.
type Row map[string]any

// Result is the normalized envelope every query returns, with provenance.
type Result struct {
	Tenant    string   // the principal's tenant — the scope of this result
	Domains   []Domain // which domains contributed (provenance)
	Rows      []Row
	Truncated bool // a cost guard capped the rows
	Elapsed   time.Duration
}
