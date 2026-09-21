// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

// Package pricing implements the offline, assumption-first commercial and
// self-hosted TCO worksheet. It deliberately has no network or telemetry
// dependency: operators supply a versioned JSON document and receive a traced
// result.
package pricing

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const SchemaV1 = "probectl-tco-input/v1"

// Input is one editable worksheet cell. Value is nil when the value has not
// been measured or supplied. Provenance is carried into every dependent line.
type Input struct {
	Value      *float64 `json:"value"`
	Unit       string   `json:"unit"`
	Provenance string   `json:"provenance"`
	AsOf       string   `json:"as_of,omitempty"`
	Source     string   `json:"source,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// Model is the complete offline input document.
type Model struct {
	Schema        string        `json:"schema"`
	Revision      string        `json:"revision"`
	Currency      string        `json:"currency"`
	Disclaimer    string        `json:"disclaimer"`
	Prices        Prices        `json:"prices"`
	Packages      []Package     `json:"packages"`
	Sensitivities []Sensitivity `json:"sensitivities"`
	Scenarios     []Scenario    `json:"scenarios"`
}

type Prices struct {
	VCPUMonth         Input `json:"vcpu_month"`
	RAMGiBMonth       Input `json:"ram_gib_month"`
	HotStorageTBMonth Input `json:"hot_storage_tb_month"`
	BackupTBMonth     Input `json:"backup_tb_month"`
	OperatorHour      Input `json:"operator_hour"`
	SupportHour       Input `json:"support_hour"`
	MigrationHour     Input `json:"migration_hour"`
}

// Package is a candidate packaging hypothesis, not an executable entitlement
// table and not an offer. Runtime features remain owned by internal/license.
type Package struct {
	Name                    string   `json:"name"`
	PricingModel            string   `json:"pricing_model"`
	BaseAnnualUSD           Input    `json:"base_annual_usd"`
	PerPeakAgentMonthlyUSD  Input    `json:"per_peak_agent_monthly_usd"`
	TenantCap               *int     `json:"tenant_cap"`
	CapMeaning              string   `json:"cap_meaning"`
	IncludedFeatures        []string `json:"included_features"`
	UnavailableCapabilities []string `json:"unavailable_capabilities"`
	ReviewState             string   `json:"review_state"`
}

// Sensitivity changes the four highest-leverage infrastructure dimensions.
// A multiplier of 1 is the baseline.
type Sensitivity struct {
	Name                  string  `json:"name"`
	RetentionMultiplier   float64 `json:"retention_multiplier"`
	SamplingMultiplier    float64 `json:"sampling_multiplier"`
	ReplicationMultiplier float64 `json:"replication_multiplier"`
	QueryLoadMultiplier   float64 `json:"query_load_multiplier"`
}

type Scenario struct {
	Name                        string `json:"name"`
	Tenants                     Input  `json:"tenants"`
	SitesPerTenant              Input  `json:"sites_per_tenant"`
	AgentsPerSite               Input  `json:"agents_per_site"`
	TestsPerAgent               Input  `json:"tests_per_agent"`
	RawIngestGBPerAgentDay      Input  `json:"raw_ingest_gb_per_agent_day"`
	RetentionDays               Input  `json:"retention_days"`
	SamplingFraction            Input  `json:"sampling_fraction"`
	CompressionRatio            Input  `json:"compression_ratio"`
	HotReplication              Input  `json:"hot_replication"`
	BackupReplication           Input  `json:"backup_replication"`
	QueryRPS                    Input  `json:"query_rps"`
	CPUSecondsPerQuery          Input  `json:"cpu_seconds_per_query"`
	TargetCPUUtilization        Input  `json:"target_cpu_utilization"`
	BaseVCPU                    Input  `json:"base_vcpu"`
	RAMGiB                      Input  `json:"ram_gib"`
	OperatorHoursBaseMonth      Input  `json:"operator_hours_base_month"`
	OperatorMinutesTenantMonth  Input  `json:"operator_minutes_tenant_month"`
	SupportHoursTenantMonth     Input  `json:"support_hours_tenant_month"`
	MigrationHours              Input  `json:"migration_hours"`
	MigrationAmortizationMonths Input  `json:"migration_amortization_months"`
	MeasuredOperatorHoursMonth  Input  `json:"measured_operator_hours_month"`
}

type Report struct {
	Schema          string           `json:"schema"`
	InputSchema     string           `json:"input_schema"`
	InputRevision   string           `json:"input_revision"`
	Currency        string           `json:"currency"`
	Disclaimer      string           `json:"disclaimer"`
	Offline         bool             `json:"offline"`
	ScenarioResults []ScenarioResult `json:"scenario_results"`
}

type ScenarioResult struct {
	Scenario    string          `json:"scenario"`
	Sensitivity string          `json:"sensitivity"`
	Lines       []Line          `json:"lines"`
	Packages    []PackageResult `json:"packages"`
}

type Line struct {
	Name          string           `json:"name"`
	Unit          string           `json:"unit"`
	Formula       string           `json:"formula"`
	Value         *float64         `json:"value"`
	Inputs        map[string]Input `json:"inputs"`
	UnknownInputs []string         `json:"unknown_inputs,omitempty"`
}

type PackageResult struct {
	Name                    string   `json:"name"`
	PricingModel            string   `json:"pricing_model"`
	MonthlyLicenseUSD       Line     `json:"monthly_license_usd"`
	MonthlyTCOUSD           Line     `json:"monthly_tco_usd"`
	EffectiveTenantMonthUSD Line     `json:"effective_tenant_month_usd"`
	TenantCap               *int     `json:"tenant_cap"`
	CapStatus               string   `json:"cap_status"`
	IncludedFeatures        []string `json:"included_features"`
	UnavailableCapabilities []string `json:"unavailable_capabilities"`
	ReviewState             string   `json:"review_state"`
}

// Validate rejects ambiguous or silently-zero worksheet cells.
func (m Model) Validate() error {
	if m.Schema != SchemaV1 {
		return fmt.Errorf("pricing: schema %q is not %q", m.Schema, SchemaV1)
	}
	if strings.TrimSpace(m.Revision) == "" {
		return errors.New("pricing: revision is required")
	}
	if m.Currency != "USD" {
		return fmt.Errorf("pricing: currency must be USD, got %q", m.Currency)
	}
	if len(m.Packages) == 0 || len(m.Scenarios) == 0 || len(m.Sensitivities) == 0 {
		return errors.New("pricing: packages, scenarios, and sensitivities are required")
	}
	var inputs []namedInput
	add := func(prefix string, in Input) { inputs = append(inputs, namedInput{prefix, in}) }
	add("prices.vcpu_month", m.Prices.VCPUMonth)
	add("prices.ram_gib_month", m.Prices.RAMGiBMonth)
	add("prices.hot_storage_tb_month", m.Prices.HotStorageTBMonth)
	add("prices.backup_tb_month", m.Prices.BackupTBMonth)
	add("prices.operator_hour", m.Prices.OperatorHour)
	add("prices.support_hour", m.Prices.SupportHour)
	add("prices.migration_hour", m.Prices.MigrationHour)

	seenPackages := map[string]bool{}
	for i, p := range m.Packages {
		if p.Name == "" || seenPackages[p.Name] {
			return fmt.Errorf("pricing: package %d has empty or duplicate name", i)
		}
		seenPackages[p.Name] = true
		if p.PricingModel != "free" && p.PricingModel != "flat" && p.PricingModel != "consumption" && p.PricingModel != "undecided" {
			return fmt.Errorf("pricing: package %s has unsupported pricing_model %q", p.Name, p.PricingModel)
		}
		if p.TenantCap != nil && *p.TenantCap <= 0 {
			return fmt.Errorf("pricing: package %s tenant_cap must be positive or null", p.Name)
		}
		add("packages."+p.Name+".base_annual_usd", p.BaseAnnualUSD)
		add("packages."+p.Name+".per_peak_agent_monthly_usd", p.PerPeakAgentMonthlyUSD)
	}

	seenScenarios := map[string]bool{}
	for i, s := range m.Scenarios {
		if s.Name == "" || seenScenarios[s.Name] {
			return fmt.Errorf("pricing: scenario %d has empty or duplicate name", i)
		}
		seenScenarios[s.Name] = true
		for name, in := range scenarioInputs(s) {
			add("scenarios."+s.Name+"."+name, in)
		}
	}
	for _, n := range inputs {
		if err := validateInput(n.name, n.input); err != nil {
			return err
		}
	}
	for _, s := range m.Sensitivities {
		if s.Name == "" || s.RetentionMultiplier <= 0 || s.SamplingMultiplier <= 0 || s.ReplicationMultiplier <= 0 || s.QueryLoadMultiplier <= 0 {
			return fmt.Errorf("pricing: sensitivity %q requires positive multipliers", s.Name)
		}
	}
	return nil
}

type namedInput struct {
	name  string
	input Input
}

func validateInput(name string, in Input) error {
	if in.Unit == "" || in.Provenance == "" {
		return fmt.Errorf("pricing: %s requires unit and provenance", name)
	}
	if in.Value == nil {
		if in.Provenance != "unknown" {
			return fmt.Errorf("pricing: %s has null value but provenance %q, want unknown", name, in.Provenance)
		}
		return nil
	}
	if math.IsNaN(*in.Value) || math.IsInf(*in.Value, 0) || *in.Value < 0 {
		return fmt.Errorf("pricing: %s must be a finite non-negative number", name)
	}
	if in.Provenance == "unknown" {
		return fmt.Errorf("pricing: %s has a value but unknown provenance", name)
	}
	if in.Provenance != "derived" && (in.AsOf == "" || in.Source == "") {
		return fmt.Errorf("pricing: %s known value requires as_of and source", name)
	}
	return nil
}

// Calculate produces a fully traced report. It performs no I/O.
func Calculate(m Model) (Report, error) {
	if err := m.Validate(); err != nil {
		return Report{}, err
	}
	report := Report{
		Schema:          "probectl-tco-report/v1",
		InputSchema:     m.Schema,
		InputRevision:   m.Revision,
		Currency:        m.Currency,
		Disclaimer:      m.Disclaimer,
		Offline:         true,
		ScenarioResults: make([]ScenarioResult, 0, len(m.Scenarios)*len(m.Sensitivities)),
	}
	for _, s := range m.Scenarios {
		for _, sensitivity := range m.Sensitivities {
			report.ScenarioResults = append(report.ScenarioResults, calculateScenario(m, s, sensitivity))
		}
	}
	return report, nil
}

func calculateScenario(m Model, s Scenario, sensitivity Sensitivity) ScenarioResult {
	base := scenarioInputs(s)
	base["retention_multiplier"] = derivedInput(sensitivity.RetentionMultiplier, "ratio", "sensitivity "+sensitivity.Name)
	base["sampling_multiplier"] = derivedInput(sensitivity.SamplingMultiplier, "ratio", "sensitivity "+sensitivity.Name)
	base["replication_multiplier"] = derivedInput(sensitivity.ReplicationMultiplier, "ratio", "sensitivity "+sensitivity.Name)
	base["query_load_multiplier"] = derivedInput(sensitivity.QueryLoadMultiplier, "ratio", "sensitivity "+sensitivity.Name)

	lines := make([]Line, 0, 14)
	agents := evaluate("agents", "count", "tenants * sites_per_tenant * agents_per_site", pick(base, "tenants", "sites_per_tenant", "agents_per_site"), func(v map[string]float64) float64 {
		return v["tenants"] * v["sites_per_tenant"] * v["agents_per_site"]
	})
	lines = append(lines, agents)
	tests := evaluate("tests", "count", "agents * tests_per_agent", merge(map[string]Input{"agents": lineInput(agents)}, pick(base, "tests_per_agent")), func(v map[string]float64) float64 {
		return v["agents"] * v["tests_per_agent"]
	})
	lines = append(lines, tests)
	rawDay := evaluate("sampled_raw_ingest", "GB/day", "agents * raw_ingest_gb_per_agent_day * sampling_fraction * sampling_multiplier", merge(map[string]Input{"agents": lineInput(agents)}, pick(base, "raw_ingest_gb_per_agent_day", "sampling_fraction", "sampling_multiplier")), func(v map[string]float64) float64 {
		return v["agents"] * v["raw_ingest_gb_per_agent_day"] * v["sampling_fraction"] * v["sampling_multiplier"]
	})
	lines = append(lines, rawDay)
	logicalTB := evaluate("logical_retained", "TB", "sampled_raw_ingest * retention_days * retention_multiplier / compression_ratio / 1000", merge(map[string]Input{"sampled_raw_ingest": lineInput(rawDay)}, pick(base, "retention_days", "retention_multiplier", "compression_ratio")), func(v map[string]float64) float64 {
		return v["sampled_raw_ingest"] * v["retention_days"] * v["retention_multiplier"] / v["compression_ratio"] / 1000
	})
	lines = append(lines, logicalTB)
	hotTB := evaluate("hot_retained", "TB", "logical_retained * hot_replication * replication_multiplier", merge(map[string]Input{"logical_retained": lineInput(logicalTB)}, pick(base, "hot_replication", "replication_multiplier")), func(v map[string]float64) float64 {
		return v["logical_retained"] * v["hot_replication"] * v["replication_multiplier"]
	})
	lines = append(lines, hotTB)
	backupTB := evaluate("backup_retained", "TB", "logical_retained * backup_replication", merge(map[string]Input{"logical_retained": lineInput(logicalTB)}, pick(base, "backup_replication")), func(v map[string]float64) float64 {
		return v["logical_retained"] * v["backup_replication"]
	})
	lines = append(lines, backupTB)
	queryVCPU := evaluate("query_vcpu", "vCPU", "query_rps * query_load_multiplier * cpu_seconds_per_query / target_cpu_utilization", pick(base, "query_rps", "query_load_multiplier", "cpu_seconds_per_query", "target_cpu_utilization"), func(v map[string]float64) float64 {
		return v["query_rps"] * v["query_load_multiplier"] * v["cpu_seconds_per_query"] / v["target_cpu_utilization"]
	})
	lines = append(lines, queryVCPU)
	compute := evaluate("compute", "USD/month", "(base_vcpu + query_vcpu) * vcpu_month + ram_gib * ram_gib_month", merge(map[string]Input{"query_vcpu": lineInput(queryVCPU), "vcpu_month": m.Prices.VCPUMonth, "ram_gib_month": m.Prices.RAMGiBMonth}, pick(base, "base_vcpu", "ram_gib")), func(v map[string]float64) float64 {
		return (v["base_vcpu"]+v["query_vcpu"])*v["vcpu_month"] + v["ram_gib"]*v["ram_gib_month"]
	})
	lines = append(lines, compute)
	hotCost := evaluate("hot_storage", "USD/month", "hot_retained * hot_storage_tb_month", map[string]Input{"hot_retained": lineInput(hotTB), "hot_storage_tb_month": m.Prices.HotStorageTBMonth}, func(v map[string]float64) float64 {
		return v["hot_retained"] * v["hot_storage_tb_month"]
	})
	lines = append(lines, hotCost)
	backupCost := evaluate("backup_storage", "USD/month", "backup_retained * backup_tb_month", map[string]Input{"backup_retained": lineInput(backupTB), "backup_tb_month": m.Prices.BackupTBMonth}, func(v map[string]float64) float64 {
		return v["backup_retained"] * v["backup_tb_month"]
	})
	lines = append(lines, backupCost)
	operatorLabor := evaluate("operator_labor", "USD/month", "(operator_hours_base_month + tenants * operator_minutes_tenant_month / 60) * operator_hour", merge(map[string]Input{"operator_hour": m.Prices.OperatorHour}, pick(base, "operator_hours_base_month", "tenants", "operator_minutes_tenant_month")), func(v map[string]float64) float64 {
		return (v["operator_hours_base_month"] + v["tenants"]*v["operator_minutes_tenant_month"]/60) * v["operator_hour"]
	})
	lines = append(lines, operatorLabor)
	measuredOperatorLabor := evaluate("measured_operator_labor", "USD/month", "measured_operator_hours_month * operator_hour", merge(map[string]Input{"operator_hour": m.Prices.OperatorHour}, pick(base, "measured_operator_hours_month")), func(v map[string]float64) float64 {
		return v["measured_operator_hours_month"] * v["operator_hour"]
	})
	lines = append(lines, measuredOperatorLabor)
	supportLabor := evaluate("support_labor", "USD/month", "tenants * support_hours_tenant_month * support_hour", merge(map[string]Input{"support_hour": m.Prices.SupportHour}, pick(base, "tenants", "support_hours_tenant_month")), func(v map[string]float64) float64 {
		return v["tenants"] * v["support_hours_tenant_month"] * v["support_hour"]
	})
	lines = append(lines, supportLabor)
	migration := evaluate("migration_amortized", "USD/month", "migration_hours * migration_hour / migration_amortization_months", merge(map[string]Input{"migration_hour": m.Prices.MigrationHour}, pick(base, "migration_hours", "migration_amortization_months")), func(v map[string]float64) float64 {
		return v["migration_hours"] * v["migration_hour"] / v["migration_amortization_months"]
	})
	lines = append(lines, migration)
	infrastructure := evaluate("infrastructure", "USD/month", "compute + hot_storage + backup_storage", map[string]Input{"compute": lineInput(compute), "hot_storage": lineInput(hotCost), "backup_storage": lineInput(backupCost)}, sumInputs)
	lines = append(lines, infrastructure)
	selfHosted := evaluate("self_hosted_tco_before_license", "USD/month", "infrastructure + operator_labor + support_labor + migration_amortized", map[string]Input{"infrastructure": lineInput(infrastructure), "operator_labor": lineInput(operatorLabor), "support_labor": lineInput(supportLabor), "migration_amortized": lineInput(migration)}, sumInputs)
	lines = append(lines, selfHosted)
	costPerTB := evaluate("infrastructure_per_logical_retained_tb", "USD/TB-month", "infrastructure / logical_retained", map[string]Input{"infrastructure": lineInput(infrastructure), "logical_retained": lineInput(logicalTB)}, func(v map[string]float64) float64 {
		return v["infrastructure"] / v["logical_retained"]
	})
	lines = append(lines, costPerTB)

	packages := make([]PackageResult, 0, len(m.Packages))
	for _, p := range m.Packages {
		license := evaluate("monthly_license", "USD/month", "base_annual_usd / 12 + agents * per_peak_agent_monthly_usd", map[string]Input{"base_annual_usd": p.BaseAnnualUSD, "agents": lineInput(agents), "per_peak_agent_monthly_usd": p.PerPeakAgentMonthlyUSD}, func(v map[string]float64) float64 {
			return v["base_annual_usd"]/12 + v["agents"]*v["per_peak_agent_monthly_usd"]
		})
		total := evaluate("monthly_tco", "USD/month", "self_hosted_tco_before_license + monthly_license", map[string]Input{"self_hosted_tco_before_license": lineInput(selfHosted), "monthly_license": lineInput(license)}, sumInputs)
		perTenant := evaluate("effective_tenant_month", "USD/tenant-month", "monthly_tco / tenants", map[string]Input{"monthly_tco": lineInput(total), "tenants": s.Tenants}, func(v map[string]float64) float64 {
			return v["monthly_tco"] / v["tenants"]
		})
		capStatus := "unlimited"
		if p.TenantCap != nil {
			capStatus = "unknown"
			if s.Tenants.Value != nil {
				if *s.Tenants.Value <= float64(*p.TenantCap) {
					capStatus = "within_cap"
				} else {
					capStatus = "exceeds_cap"
				}
			}
		}
		packages = append(packages, PackageResult{
			Name: p.Name, PricingModel: p.PricingModel, MonthlyLicenseUSD: license,
			MonthlyTCOUSD: total, EffectiveTenantMonthUSD: perTenant,
			TenantCap: p.TenantCap, CapStatus: capStatus,
			IncludedFeatures:        append([]string(nil), p.IncludedFeatures...),
			UnavailableCapabilities: append([]string(nil), p.UnavailableCapabilities...),
			ReviewState:             p.ReviewState,
		})
	}
	return ScenarioResult{Scenario: s.Name, Sensitivity: sensitivity.Name, Lines: lines, Packages: packages}
}

func scenarioInputs(s Scenario) map[string]Input {
	return map[string]Input{
		"tenants": s.Tenants, "sites_per_tenant": s.SitesPerTenant,
		"agents_per_site": s.AgentsPerSite, "tests_per_agent": s.TestsPerAgent,
		"raw_ingest_gb_per_agent_day": s.RawIngestGBPerAgentDay,
		"retention_days":              s.RetentionDays, "sampling_fraction": s.SamplingFraction,
		"compression_ratio": s.CompressionRatio, "hot_replication": s.HotReplication,
		"backup_replication": s.BackupReplication, "query_rps": s.QueryRPS,
		"cpu_seconds_per_query":  s.CPUSecondsPerQuery,
		"target_cpu_utilization": s.TargetCPUUtilization, "base_vcpu": s.BaseVCPU,
		"ram_gib": s.RAMGiB, "operator_hours_base_month": s.OperatorHoursBaseMonth,
		"operator_minutes_tenant_month": s.OperatorMinutesTenantMonth,
		"support_hours_tenant_month":    s.SupportHoursTenantMonth,
		"migration_hours":               s.MigrationHours,
		"migration_amortization_months": s.MigrationAmortizationMonths,
		"measured_operator_hours_month": s.MeasuredOperatorHoursMonth,
	}
}

func evaluate(name, unit, formula string, inputs map[string]Input, calculate func(map[string]float64) float64) Line {
	values := make(map[string]float64, len(inputs))
	unknown := make([]string, 0)
	for inputName, input := range inputs {
		if input.Value == nil {
			unknown = append(unknown, inputName)
			continue
		}
		values[inputName] = *input.Value
	}
	sort.Strings(unknown)
	line := Line{Name: name, Unit: unit, Formula: formula, Inputs: inputs, UnknownInputs: unknown}
	if len(unknown) == 0 {
		value := calculate(values)
		if !math.IsNaN(value) && !math.IsInf(value, 0) {
			line.Value = &value
		} else {
			line.UnknownInputs = []string{"non_finite_result"}
		}
	}
	return line
}

func lineInput(line Line) Input {
	return Input{Value: line.Value, Unit: line.Unit, Provenance: provenanceForLine(line), Source: "formula:" + line.Name, Note: strings.Join(line.UnknownInputs, ",")}
}

func provenanceForLine(line Line) string {
	if line.Value == nil {
		return "unknown"
	}
	return "derived"
}

func derivedInput(value float64, unit, source string) Input {
	return Input{Value: &value, Unit: unit, Provenance: "derived", Source: source}
}

func pick(all map[string]Input, names ...string) map[string]Input {
	selected := make(map[string]Input, len(names))
	for _, name := range names {
		selected[name] = all[name]
	}
	return selected
}

func merge(groups ...map[string]Input) map[string]Input {
	merged := map[string]Input{}
	for _, group := range groups {
		for name, value := range group {
			merged[name] = value
		}
	}
	return merged
}

func sumInputs(values map[string]float64) float64 {
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total
}
