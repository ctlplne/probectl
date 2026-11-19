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
		projection = `(` + alertSubjectReadGrantsSQL(document) + `) || (` + alertSubjectDependencyGraphSQL(document) + `)`
	case "path_health_source":
		trimmed = alertSubjectWithoutUUIDReference(document, "test_id")
		trimmed = alertSubjectWithoutUUIDReference(trimmed, "interface_id")
		projection = alertSubjectReadGrantsSQL(document)
	case "seasonal_source":
		projection = `(` + alertSubjectReadGrantsSQL(document) + `) || (` + alertSubjectSeasonalBindingsSQL(document) + `)`
	case "tag_filter":
		projection = alertSubjectTagBindingsSQL(document)
	default:
		return document
	}
	return `(CASE WHEN jsonb_typeof(` + document + `)='object' AND ` + document + `->'version'='1'::jsonb
 THEN (` + trimmed + `) || (` + projection + `) ELSE ` + document + ` END)`
}

func alertSubjectSeasonalBindingsSQL(document string) string {
	config := `(` + document + `->'config')`
	flowSource := `(` + config + `->'flow')`
	selection := alertSubjectWithoutUUIDReference(config, "test_id")
	nested := `(CASE WHEN jsonb_typeof(` + flowSource + `)='object'
 THEN jsonb_build_object('flow', ` + alertSubjectWithoutUUIDReference(flowSource, "view_id") + `)
 ELSE '{}'::jsonb END)`
	return `(CASE WHEN jsonb_typeof(` + config + `)='object' THEN
 jsonb_build_object('config', (` + selection + `) || ` + nested + `)
 ELSE '{}'::jsonb END)`
}

func alertSubjectDependencyGraphSQL(document string) string {
	node := `subject_dependency_node.value`
	trimmed := node
	for _, field := range []string{"entity_id", "agent_id", "test_id"} {
		trimmed = alertSubjectWithoutUUIDReference(trimmed, field)
	}
	return `(CASE WHEN jsonb_typeof(` + document + `->'graph')='object'
 AND jsonb_typeof(` + document + `->'graph'->'nodes')='array'
 THEN jsonb_build_object('graph', (` + document + `->'graph') || jsonb_build_object('nodes',(
 SELECT COALESCE(jsonb_agg(CASE WHEN jsonb_typeof(` + node + `)='object'
 THEN (` + trimmed + `) || (CASE WHEN jsonb_typeof(` + node + `->'parents')='array'
   THEN jsonb_build_object('parents', (SELECT COALESCE(jsonb_agg(CASE
      WHEN ` + alertSubjectUUIDValueSQL(`subject_dependency_parent.value`) + `
      THEN 'null'::jsonb ELSE subject_dependency_parent.value END ORDER BY subject_dependency_parent.ordinal),'[]'::jsonb)
     FROM jsonb_array_elements(` + node + `->'parents') WITH ORDINALITY AS subject_dependency_parent(value,ordinal)))
   ELSE '{}'::jsonb END)
 ELSE ` + node + ` END ORDER BY subject_dependency_node.ordinal),'[]'::jsonb)
 FROM jsonb_array_elements(` + document + `->'graph'->'nodes') WITH ORDINALITY AS subject_dependency_node(value,ordinal))))
 ELSE '{}'::jsonb END)`
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

// The flow closure is a server-encoded UTF-8 requirements document. Keep
// structural tenant, context, filter and saved view references out of matching
// while retaining all source labels, sender names and original endpoint IPs.
func seasonalFlowReceiptSubjectSQL() string {
	const document = `(convert_from(subject_row.seasonal_flow_scope,'UTF8')::jsonb)`
	return `(CASE WHEN ` + document + `->'version' IN ('1'::jsonb,'2'::jsonb) THEN (
 jsonb_path_query_array(` + document + `,'$.contexts[*].resource.site_label') ||
 jsonb_path_query_array(` + document + `,'$.contexts[*].resource.vrf_label') ||
 jsonb_path_query_array(` + document + `,'$.inputs[*].routing.captures[*].sender') ||
 jsonb_path_query_array(` + document + `,'$.inputs[*].routing.captures[*].exporter') ||
 jsonb_path_query_array(` + document + `,'$.inputs[*].routing.captures[*].src') ||
 jsonb_path_query_array(` + document + `,'$.inputs[*].routing.captures[*].dst') ||
 jsonb_path_query_array(` + document + `,'$.timeline.periods[*].routing.captures[*].sender') ||
 jsonb_path_query_array(` + document + `,'$.timeline.periods[*].routing.captures[*].exporter') ||
 jsonb_path_query_array(` + document + `,'$.timeline.periods[*].routing.captures[*].src') ||
 jsonb_path_query_array(` + document + `,'$.timeline.periods[*].routing.captures[*].dst')
 )::text ELSE COALESCE(` + document + `::text,'') END)`
}
