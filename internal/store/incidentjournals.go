// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// MaxIncidentJournalEntries bounds one incident-room read. A journal that
// reaches the cap remains honest through the response's truncated marker.
const MaxIncidentJournalEntries = 200

// IncidentJournals persists inert, tenant-owned investigation notes. Forced
// RLS is the outer boundary, and every statement also binds tenant_id.
type IncidentJournals struct{}

type IncidentJournalInput struct {
	ID                 string
	IncidentID         string
	Kind               string
	Body               string
	CitationShareID    *string
	CitationEvidenceID *string
	CreatedBy          string
	ExpiresAt          time.Time
}

type IncidentJournalEntry struct {
	ID                 string
	IncidentID         string
	Kind               string
	Body               string
	CitationShareID    *string
	CitationEvidenceID *string
	CreatedBy          string
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

func scanIncidentJournalEntry(row interface{ Scan(...any) error }, out *IncidentJournalEntry) error {
	return row.Scan(&out.ID, &out.IncidentID, &out.Kind, &out.Body,
		&out.CitationShareID, &out.CitationEvidenceID, &out.CreatedBy,
		&out.CreatedAt, &out.ExpiresAt)
}

func (IncidentJournals) Append(ctx context.Context, s tenancy.Scope, in IncidentJournalInput) (*IncidentJournalEntry, error) {
	var out IncidentJournalEntry
	err := scanIncidentJournalEntry(s.Q.QueryRow(ctx, `
		INSERT INTO incident_journal_entries
		       (tenant_id, id, incident_id, entry_kind, body, citation_share_id,
		        citation_evidence_id, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, incident_id::text, entry_kind, body, citation_share_id,
		          citation_evidence_id, created_by, created_at, expires_at`,
		s.Tenant.String(), in.ID, in.IncidentID, in.Kind, in.Body,
		in.CitationShareID, in.CitationEvidenceID, in.CreatedBy, in.ExpiresAt), &out)
	if err != nil {
		return nil, mapWriteErr("incident journal entry", err)
	}
	return &out, nil
}

// List returns live entries oldest-first so the result reads as an investigation
// narrative. One extra row is fetched only to compute the honest truncation bit.
func (IncidentJournals) List(ctx context.Context, s tenancy.Scope, incidentID string) ([]IncidentJournalEntry, bool, error) {
	rows, err := s.Q.Query(ctx, `
		SELECT id, incident_id::text, entry_kind, body, citation_share_id,
		       citation_evidence_id, created_by, created_at, expires_at
		  FROM incident_journal_entries
		 WHERE tenant_id = $1 AND incident_id = $2
		   AND expires_at > clock_timestamp()
		 ORDER BY created_at, id
		 LIMIT $3`,
		s.Tenant.String(), incidentID, MaxIncidentJournalEntries+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]IncidentJournalEntry, 0, MaxIncidentJournalEntries)
	truncated := false
	for rows.Next() {
		if len(out) == MaxIncidentJournalEntries {
			truncated = true
			break
		}
		var entry IncidentJournalEntry
		if err := scanIncidentJournalEntry(rows, &entry); err != nil {
			return nil, false, err
		}
		out = append(out, entry)
	}
	return out, truncated, rows.Err()
}

// Prune removes entries after their tenant-bounded retention deadline.
func (IncidentJournals) Prune(ctx context.Context, s tenancy.Scope) (int64, error) {
	tag, err := s.Q.Exec(ctx, `
		DELETE FROM incident_journal_entries
		 WHERE tenant_id = $1 AND expires_at <= clock_timestamp()`,
		s.Tenant.String())
	if err != nil {
		return 0, mapWriteErr("incident journal entry", err)
	}
	return tag.RowsAffected(), nil
}
