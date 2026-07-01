// SPDX-License-Identifier: LicenseRef-probectl-TBD

package govern

import (
	"fmt"
	"sort"
	"strings"
)

// DataInventoryEntry is one maintained row in probectl's data map
// (COMPETE-012). ELI5: every store is a labeled box; this record says who owns
// the box, what sensitivity labels may be inside it, how long it lives, which
// processors touch it, and how export/delete handles it.
type DataInventoryEntry struct {
	ID             string     `json:"id"`
	Store          string     `json:"store"`
	Plane          string     `json:"plane"`
	Owner          string     `json:"owner"`
	Home           string     `json:"home"`
	Categories     []Category `json:"categories"`
	DataClasses    []Class    `json:"data_classes"`
	Retention      string     `json:"retention"`
	RetentionOwner string     `json:"retention_owner"`
	Processors     []string   `json:"processors"`
	ExportBehavior string     `json:"export_behavior"`
	TenantDelete   string     `json:"tenant_delete"`
	SubjectDelete  string     `json:"subject_delete"`
}

var dataInventory = []DataInventoryEntry{
	{
		ID:             "probe-results",
		Store:          "Synthetic/canary probe results and metric series",
		Plane:          "active-testing",
		Owner:          "internal/canary, internal/store/tsdb, internal/tenantlife",
		Home:           "TSDB series, result views, and tenant-tagged bus payloads",
		Categories:     []Category{CatIPAddress, CatDNSName, CatAttributeMap},
		DataClasses:    []Class{ClassPII, ClassInternal},
		Retention:      "PROBECTL_TSDB_MEMORY_RETENTION in memory mode; remote Prometheus/VictoriaMetrics policy otherwise",
		RetentionOwner: "internal/store/tsdb",
		Processors: []string{
			"tenant label validation before write",
			"result-to-OTel schema mapping",
			"govern redaction during governed export",
		},
		ExportBehavior: "tenant-scoped lifecycle/support exports include result evidence; redacted mode masks target, DNS, and attribute values",
		TenantDelete:   "tenantlife calls TSDB DeleteTenant or records the Prometheus admin-delete manual receipt",
		SubjectDelete:  "not directly subject-addressable except attributes; subject lifecycle records explicit not-subject-addressable coverage",
	},
	{
		ID:             "flow-telemetry",
		Store:          "Flow telemetry raw rows and hourly rollups",
		Plane:          "flow",
		Owner:          "internal/store/flowstore, internal/flow, internal/tenantlife",
		Home:           "ClickHouse probectl_flows plus probectl_flow_rollups_hour, or in-memory flow store",
		Categories:     []Category{CatIPAddress, CatASN, CatAttributeMap},
		DataClasses:    []Class{ClassPII, ClassConfidential, ClassPublic},
		Retention:      "PROBECTL_FLOW_RETENTION_DAYS raw-row TTL; per-tenant flow_retention_days may tighten it; rollups remain until lifecycle deletion",
		RetentionOwner: "internal/store/flowstore",
		Processors: []string{
			"collector normalization and row-id dedup",
			"ClickHouse tenant row policy",
			"hourly rollup materialized view and backfill",
			"govern redaction during portability export",
		},
		ExportBehavior: "tenant and subject exports stream JSONL through govern.RedactJSONL when redaction is requested or forced",
		TenantDelete:   "DeleteTenant removes raw and rollup rows for the tenant and verifies remaining count is zero",
		SubjectDelete:  "DeleteSubject removes tenant-scoped src/dst/exporter matches from raw rows and rollups",
	},
	{
		ID:             "ebpf-telemetry",
		Store:          "eBPF host, process, and L7 aggregate telemetry",
		Plane:          "ebpf",
		Owner:          "internal/ebpf, internal/store/ebpfstore, internal/tenantlife",
		Home:           "ClickHouse eBPF tables or in-memory eBPF aggregate store",
		Categories:     []Category{CatIPAddress, CatHostname, CatWorkload, CatAttributeMap},
		DataClasses:    []Class{ClassPII, ClassConfidential, ClassInternal},
		Retention:      "PROBECTL_EBPF_RETENTION_DAYS ClickHouse TTL; 0 disables age TTL",
		RetentionOwner: "internal/store/ebpfstore",
		Processors: []string{
			"observe-only eBPF event normalization",
			"L7 privacy policy/redaction before persistence where configured",
			"tenant-scoped ClickHouse or memory writes",
		},
		ExportBehavior: "tenant support/export bundles include only tenant-scoped aggregates and honor governed redaction",
		TenantDelete:   "DeleteTenant removes every tenant aggregate and verifies no tenant rows remain",
		SubjectDelete:  "not directly subject-addressable today; host/process labels are covered by tenant erasure and L7 redaction policy",
	},
	{
		ID:             "path-topology",
		Store:          "Path/traceroute evidence and topology graph labels",
		Plane:          "path-topology",
		Owner:          "internal/store/pathstore, internal/topology, internal/tenantlife",
		Home:           "ClickHouse path hop/link tables plus hourly rollups and topology memory/index stores",
		Categories:     []Category{CatIPAddress, CatHostname, CatWorkload, CatAttributeMap},
		DataClasses:    []Class{ClassPII, ClassConfidential, ClassInternal},
		Retention:      "PROBECTL_PATH_RETENTION_DAYS raw path TTL; hourly rollups remain until lifecycle deletion; topology memory rebuilds from fresh observations",
		RetentionOwner: "internal/store/pathstore and internal/topology",
		Processors: []string{
			"path normalization",
			"tenant-scoped ClickHouse row policies",
			"topology graph builder",
			"govern redaction during export",
		},
		ExportBehavior: "tenant exports include path/topology evidence only after tenant scope; redacted mode masks hop IPs and labels",
		TenantDelete:   "tenantlife calls pathstore.DeleteTenant and topology.DeleteTenant",
		SubjectDelete:  "not directly subject-addressable; tenant erase is the deletion control for path/topology labels",
	},
	{
		ID:             "otlp-traces-logs",
		Store:          "OTLP traces, logs, resources, and attributes",
		Plane:          "otel",
		Owner:          "internal/otel/otlp, internal/pipeline, internal/store/otelstore, internal/tenantlife",
		Home:           "ClickHouse OTLP spans/logs or memory store",
		Categories:     []Category{CatAttributeMap, CatFreeText, CatSubjectID, CatCredential, CatIPAddress, CatURLPath, CatUserAgent},
		DataClasses:    []Class{ClassPII, ClassRestricted, ClassInternal},
		Retention:      "PROBECTL_OTEL_RETENTION_DAYS ClickHouse TTL; 0 disables age TTL",
		RetentionOwner: "internal/store/otelstore",
		Processors: []string{
			"tenant resource-attribute verification",
			"govern.TelemetryPIIPolicy redaction before persistence",
			"attribute/body size bounds",
			"subject export/erase predicates",
		},
		ExportBehavior: "subject export streams tenant-scoped span/log JSONL; tenant export honors redacted mode",
		TenantDelete:   "tenantlife removes OTLP rows through the tenant-scoped store deleter",
		SubjectDelete:  "EraseSubject deletes only this tenant's spans/logs whose names or attrs mention the subject",
	},
	{
		ID:             "device-endpoint-state",
		Store:          "Device telemetry, endpoint/DEM metrics, SNMP/gNMI attributes, and inventory state",
		Plane:          "device-endpoint",
		Owner:          "internal/device, internal/endpoint, internal/store, internal/tenantlife",
		Home:           "TSDB series, Postgres tenant tables, device/endpoint stores, and tenant-scoped API views",
		Categories:     []Category{CatIPAddress, CatHostname, CatMAC, CatSubjectID, CatAttributeMap},
		DataClasses:    []Class{ClassPII, ClassConfidential, ClassInternal},
		Retention:      "metric samples follow TSDB retention; durable inventory rows live while the tenant/identity is active",
		RetentionOwner: "internal/store/tsdb and Postgres tenant tables",
		Processors: []string{
			"SNMP/gNMI/syslog/trap normalization",
			"tenant-scoped inventory upserts",
			"govern column/category redaction during export",
		},
		ExportBehavior: "tenant lifecycle export includes tenant-scoped inventory and endpoint state; redacted mode masks management IPs and subject fields",
		TenantDelete:   "tenantlife deletes tenant Postgres rows and TSDB series or records manual TSDB deletion requirements",
		SubjectDelete:  "subject lifecycle removes identity/endpoint rows that match the subject and records non-subject-addressable device-only planes",
	},
	{
		ID:             "identity-rbac-scim",
		Store:          "User directory attributes, RBAC/ABAC, SCIM, sessions, and tenant membership",
		Plane:          "identity",
		Owner:          "internal/auth, internal/scim, internal/store, internal/tenantlife",
		Home:           "Postgres tenant tables with RLS and sealed/hash-only secrets where applicable",
		Categories:     []Category{CatEmail, CatSubjectID, CatCredential, CatOrgUnit},
		DataClasses:    []Class{ClassPII, ClassRestricted, ClassConfidential},
		Retention:      "kept while the identity or tenant is active; no independent age TTL for directory rows",
		RetentionOwner: "internal/store and internal/tenantlife",
		Processors: []string{
			"RLS-scoped store access",
			"credential hashing/envelope sealing",
			"govern redaction during export",
		},
		ExportBehavior: "tenant and subject exports include scoped identity rows; restricted fields are dropped or redacted",
		TenantDelete:   "tenant offboarding deletes tenant identity/RBAC/SCIM rows under RLS and verifies counts",
		SubjectDelete:  "subject lifecycle deletes or exports matching identity rows before recording the erasure receipt",
	},
	{
		ID:             "audit-evidence",
		Store:          "Tenant audit, provider audit, break-glass records, and signed WORM segments",
		Plane:          "audit",
		Owner:          "internal/audit, internal/siem, internal/objectstore, internal/tenantlife",
		Home:           "Postgres hash chains plus optional signed WORM object segments and SIEM cursor state",
		Categories:     []Category{CatSubjectID, CatFreeText, CatCredential, CatObjectKey},
		DataClasses:    []Class{ClassConfidential, ClassRestricted, ClassPII},
		Retention:      "PROBECTL_AUDIT_RETENTION can prune only older events that were durably exported; 0 keeps forever",
		RetentionOwner: "internal/audit",
		Processors: []string{
			"tamper-evident hash chaining",
			"WORM signature/export gate",
			"SIEM redaction before forwarding",
			"append-only subject-erasure projection",
		},
		ExportBehavior: "audit export projects erased subjects and minimizes raw personal fields before WORM/SIEM copies",
		TenantDelete:   "tenant offboarding records audit/export receipts; provider audit remains in the separate provider stream",
		SubjectDelete:  "RecordSubjectErasure appends a privacy.subject_erase marker and future reads/exports project the subject",
	},
	{
		ID:             "ai-artifacts",
		Store:          "AI prompts, persisted answers, feedback, citations, and model/config hashes",
		Plane:          "ai",
		Owner:          "internal/ai, internal/govern, internal/tenantlife",
		Home:           "optional privacy-minimized Postgres answer artifacts and feedback rows; remote model side only with explicit consent",
		Categories:     []Category{CatFreeText, CatAttributeMap, CatSubjectID, CatCredential},
		DataClasses:    []Class{ClassPII, ClassRestricted, ClassConfidential},
		Retention:      "PROBECTL_AI_PERSIST_ANSWERS=false by default; PROBECTL_AI_ANSWER_RETENTION prunes persisted answers when enabled",
		RetentionOwner: "internal/ai and internal/tenantlife",
		Processors: []string{
			"tenant-first AI/MCP authorization",
			"prompt/evidence minimization",
			"remote-AI egress consent gate",
			"answer retention prune on write",
		},
		ExportBehavior: "tenant and subject lifecycle export privacy-minimized answer artifacts and citations",
		TenantDelete:   "tenant offboarding removes persisted AI artifacts for the tenant",
		SubjectDelete:  "subject lifecycle deletes persisted answers/feedback that mention the subject",
	},
	{
		ID:             "object-artifacts",
		Store:          "Support bundles, lifecycle exports, browser artifacts, backup/WORM files, and test bundles",
		Plane:          "object",
		Owner:          "internal/objectstore, internal/support, internal/audit, internal/tenantlife",
		Home:           "filesystem, S3, or MinIO object store under tenant prefixes/buckets",
		Categories:     []Category{CatObjectKey, CatFreeText, CatCredential, CatAttributeMap},
		DataClasses:    []Class{ClassConfidential, ClassRestricted, ClassPII},
		Retention:      "no FSStore age TTL; backups follow PROBECTL_BACKUP_RETENTION_DAYS and operator bucket/object-lock policy",
		RetentionOwner: "internal/objectstore plus operator backup policy",
		Processors: []string{
			"tenant-prefix object keys",
			"support-bundle redaction/minimization",
			"WORM signing for audit segments",
		},
		ExportBehavior: "lifecycle/support exports are tenant-prefixed and may be redacted before object write",
		TenantDelete:   "tenantlife calls objectstore.DeletePrefix and records backup-retention attestation",
		SubjectDelete:  "subject lifecycle records object-plane coverage; tenant-prefixed artifacts are removed by tenant erase or explicit prefix delete",
	},
	{
		ID:             "shared-open-data",
		Store:          "Open-data and threat-intel shared feed caches",
		Plane:          "opendata-threat",
		Owner:          "internal/opendata, internal/threat",
		Home:           "shared read-only feed caches plus tenant-scoped derived matches/events",
		Categories:     []Category{CatASN, CatDNSName, CatIPAddress},
		DataClasses:    []Class{ClassPublic, ClassPII},
		Retention:      "source-specific cache TTL and AUP/provenance; tenant-derived matches follow their owning event store",
		RetentionOwner: "internal/opendata and internal/threat",
		Processors: []string{
			"TLS-validated read-only fetch",
			"shared ingest once, then tenant-scoped joins",
			"graceful degradation on source outage",
		},
		ExportBehavior: "shared feeds are not tenant telemetry; tenant exports include only the tenant-scoped derived findings",
		TenantDelete:   "shared cache is retained; derived tenant rows/events are removed by the owning tenant store deletion path",
		SubjectDelete:  "not subject-owned; subject lifecycle applies only to tenant-derived rows that contain the subject",
	},
	{
		ID:             "siem-cursors",
		Store:          "SIEM exported copies, delivery cursors, and outbound event payloads",
		Plane:          "siem",
		Owner:          "internal/siem, internal/audit",
		Home:           "customer SIEM plus probectl per-tenant delivery cursor/state",
		Categories:     []Category{CatFreeText, CatSubjectID, CatIPAddress, CatCredential},
		DataClasses:    []Class{ClassConfidential, ClassPII, ClassRestricted},
		Retention:      "destination SIEM owns exported-copy retention; probectl keeps only the tenant-scoped resume cursor",
		RetentionOwner: "customer SIEM policy and internal/siem cursor store",
		Processors: []string{
			"govern redaction before forwarding",
			"tenant-scoped cursor updates",
			"TLS-authenticated outbound delivery",
		},
		ExportBehavior: "SIEM copy is an external controlled copy; probectl can export cursor state and redacted event payloads",
		TenantDelete:   "tenant offboarding removes local cursor/state; destination deletion is an operator/customer SIEM step",
		SubjectDelete:  "future exports project erased subjects; already-exported SIEM copies follow the customer SIEM policy",
	},
	{
		ID:             "backups-snapshots",
		Store:          "Database/object-store backups, snapshots, and restore artifacts",
		Plane:          "backup",
		Owner:          "deploy/backup, internal/backup, operator backup policy, internal/tenantlife",
		Home:           "operator backup system, sealed backups, database snapshots, and object-store snapshots",
		Categories:     []Category{CatObjectKey, CatFreeText, CatCredential, CatAttributeMap},
		DataClasses:    []Class{ClassRestricted, ClassConfidential, ClassPII},
		Retention:      "PROBECTL_BACKUP_RETENTION_DAYS/NOTE records the backup-erasure deadline; actual backup lifecycle is operator-controlled",
		RetentionOwner: "operator backup policy",
		Processors: []string{
			"sealed backup generation",
			"restore drill validation",
			"deletion-attestation backup deadline",
		},
		ExportBehavior: "backup contents are not portability exports; restore evidence may be included in support bundles after redaction",
		TenantDelete:   "live-store erase records the concrete backup-retention deadline instead of claiming immediate snapshot purge",
		SubjectDelete:  "subject erasure applies to live stores; historical backup expiry follows the recorded backup policy",
	},
}

// RequiredDataInventoryIDs is the privacy-gate denominator for the maintained
// store map. Adding a new core privacy-relevant store means appending it here
// and in dataInventory with full lifecycle semantics.
func RequiredDataInventoryIDs() []string {
	out := make([]string, 0, len(dataInventory))
	for _, e := range dataInventory {
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return out
}

// DataInventory returns a sorted, defensive copy of the maintained data map.
func DataInventory() []DataInventoryEntry {
	out := make([]DataInventoryEntry, 0, len(dataInventory))
	for _, e := range dataInventory {
		out = append(out, cloneDataInventoryEntry(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ValidateDataInventory is the privacy gate for the inventory. It is exported
// so docs/tests can assert the same rules the governance surface depends on.
func ValidateDataInventory(entries []DataInventoryEntry) []error {
	var errs []error
	if len(entries) == 0 {
		return []error{fmt.Errorf("data inventory is empty")}
	}
	seen := map[string]struct{}{}
	for _, e := range entries {
		if strings.TrimSpace(e.ID) == "" {
			errs = append(errs, fmt.Errorf("data inventory entry has empty id"))
			continue
		}
		if _, ok := seen[e.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: duplicate inventory id", e.ID))
		}
		seen[e.ID] = struct{}{}
		if strings.TrimSpace(e.Store) == "" {
			errs = append(errs, fmt.Errorf("%s: missing store", e.ID))
		}
		if strings.TrimSpace(e.Plane) == "" {
			errs = append(errs, fmt.Errorf("%s: missing plane", e.ID))
		}
		if strings.TrimSpace(e.Owner) == "" {
			errs = append(errs, fmt.Errorf("%s: missing owner", e.ID))
		}
		if strings.TrimSpace(e.Home) == "" {
			errs = append(errs, fmt.Errorf("%s: missing home", e.ID))
		}
		if len(e.Categories) == 0 {
			errs = append(errs, fmt.Errorf("%s: missing categories", e.ID))
		}
		for _, cat := range e.Categories {
			if _, ok := defaultClass[cat]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown category %q", e.ID, cat))
			}
		}
		if len(e.DataClasses) == 0 {
			errs = append(errs, fmt.Errorf("%s: missing data classes", e.ID))
		}
		for _, class := range e.DataClasses {
			if class < ClassPublic || class > ClassRestricted {
				errs = append(errs, fmt.Errorf("%s: invalid data class %q", e.ID, class))
			}
		}
		if strings.TrimSpace(e.Retention) == "" {
			errs = append(errs, fmt.Errorf("%s: missing retention", e.ID))
		}
		if strings.TrimSpace(e.RetentionOwner) == "" {
			errs = append(errs, fmt.Errorf("%s: missing retention owner", e.ID))
		}
		if len(e.Processors) == 0 {
			errs = append(errs, fmt.Errorf("%s: missing processors", e.ID))
		}
		for i, processor := range e.Processors {
			if strings.TrimSpace(processor) == "" {
				errs = append(errs, fmt.Errorf("%s: empty processor %d", e.ID, i))
			}
		}
		if strings.TrimSpace(e.ExportBehavior) == "" {
			errs = append(errs, fmt.Errorf("%s: missing export behavior", e.ID))
		}
		if strings.TrimSpace(e.TenantDelete) == "" {
			errs = append(errs, fmt.Errorf("%s: missing tenant deletion semantics", e.ID))
		}
		if strings.TrimSpace(e.SubjectDelete) == "" {
			errs = append(errs, fmt.Errorf("%s: missing subject deletion semantics", e.ID))
		}
	}
	return errs
}

func cloneDataInventoryEntry(e DataInventoryEntry) DataInventoryEntry {
	e.Categories = append([]Category(nil), e.Categories...)
	e.DataClasses = append([]Class(nil), e.DataClasses...)
	e.Processors = append([]string(nil), e.Processors...)
	return e
}
