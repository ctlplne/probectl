// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import "github.com/ctlplne/probectl/internal/auth"

// Selection omits only recognized structural references from version1 alert
// documents. Portable exports still contain the complete original row. Owners,
// criteria and unknown/invalid fields remain subject-bearing; a field name
// alone must never conceal personal data in a retained legacy document.
func alertSubjectDocumentSQL(column string) string {
	document := "subject_row." + pgIdent(column)
	trimmed := document
	var projection string
	switch column {
	case "query_source":
		trimmed = alertSubjectWithoutUUIDReference(document, "view_id")
		projection = alertSubjectReadGrantsSQL(document)
	case "dependency_policy":
		trimmed = alertSubjectWithoutUUIDReference(document, "context_id")
		projection = alertSubjectReadGrantsSQL(document)
	case "tag_filter":
		projection = alertSubjectTagBindingsSQL(document)
	default:
		return document
	}
	return `(CASE WHEN jsonb_typeof(` + document + `)='object' AND ` + document + `->'version'='1'::jsonb
 THEN (` + trimmed + `) || (` + projection + `) ELSE ` + document + ` END)`
}

func alertSubjectReadGrantsSQL(document string) string {
	return `(CASE WHEN jsonb_typeof(` + document + `->'read_grants')='array'
 THEN jsonb_build_object('read_grants',(
 SELECT COALESCE(jsonb_agg(CASE
  WHEN jsonb_typeof(subject_grant.value)='object'
   AND subject_grant.value->>'scope_type' IN ('` + string(auth.ScopeOrganization) + `','` + string(auth.ScopeTeam) + `','` + string(auth.ScopeProject) + `')
   AND ` + alertSubjectUUIDReference(`subject_grant.value`, "scope_id") + `
  THEN subject_grant.value-'scope_id' ELSE subject_grant.value END ORDER BY subject_grant.ordinal), '[]'::jsonb)
 FROM jsonb_array_elements(` + document + `->'read_grants') WITH ORDINALITY AS subject_grant(value,ordinal)))
 ELSE '{}'::jsonb END)`
}

func alertSubjectTagBindingsSQL(document string) string {
	return `(CASE WHEN jsonb_typeof(` + document + `->'tag_ids')='object'
 THEN jsonb_build_object('tag_ids',(
 SELECT COALESCE(jsonb_object_agg(subject_tag.key, CASE
  WHEN left(subject_tag.key,4)='tag.' AND length(subject_tag.key)>4
   AND ` + alertSubjectUUIDValueSQL(`subject_tag.value`) + `
  THEN 'null'::jsonb ELSE subject_tag.value END), '{}'::jsonb)
 FROM jsonb_each(` + document + `->'tag_ids') AS subject_tag(key,value)))
 ELSE '{}'::jsonb END)`
}

func alertSubjectWithoutUUIDReference(document, field string) string {
	return `(CASE WHEN ` + alertSubjectUUIDReference(document, field) + ` THEN ` + document + `-'` + field + `' ELSE ` + document + ` END)`
}

func alertSubjectUUIDReference(document, field string) string {
	// Both names are internal constants, never request or configuration text.
	return alertSubjectUUIDValueSQL(document + `->'` + field + `'`)
}

func alertSubjectUUIDValueSQL(value string) string {
	return `(jsonb_typeof(` + value + `)='string' AND ((` + value + `)#>>'{}') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')`
}
