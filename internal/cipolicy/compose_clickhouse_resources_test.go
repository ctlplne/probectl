// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const clickhouseResourceFile = "deploy/compose/prod/clickhouse/resources.xml"
const clickhouseResourceMount = "./prod/clickhouse/resources.xml:/etc/clickhouse-server/config.d/probectl-resources.xml:ro"

type clickhouseMaintenanceConfig struct {
	XMLName xml.Name
	Pool    int    `xml:"background_pool_size"`
	Ratio   int    `xml:"background_merges_mutations_concurrency_ratio"`
	Memory  uint64 `xml:"merges_mutations_memory_usage_soft_limit"`
	Tree    struct {
		Block    int `xml:"merge_max_block_size"`
		Lower    int `xml:"number_of_free_entries_in_pool_to_lower_max_size_of_merge"`
		Mutation int `xml:"number_of_free_entries_in_pool_to_execute_mutation"`
		Optimize int `xml:"number_of_free_entries_in_pool_to_execute_optimize_entire_partition"`
	} `xml:"merge_tree"`
}

// The four-GiB profile must reserve room for foreground readers and avoid the
// upstream 16-thread/8192-row maintenance defaults. Threshold validation also
// catches configurations that 24.8 rejects at boot or that cannot run mutations.
func clickhouseMaintenanceProblems(mounted bool, body string) []string {
	if !mounted {
		return []string{"bounded ClickHouse maintenance config is not mounted read-only"}
	}
	var c clickhouseMaintenanceConfig
	if err := xml.Unmarshal([]byte(body), &c); err != nil {
		return []string{"invalid ClickHouse maintenance XML"}
	}
	var problems []string
	if c.XMLName.Local != "clickhouse" || c.XMLName.Space != "" {
		problems = append(problems, "invalid ClickHouse config root")
	}
	if c.Pool < 1 || c.Pool > 2 || c.Ratio < 1 || c.Ratio > 2 {
		problems = append(problems, "unbounded or oversized maintenance concurrency")
	}
	if c.Memory == 0 || c.Memory > 1<<30 {
		problems = append(problems, "unbounded or oversized maintenance memory admission")
	}
	if c.Tree.Block < 1 || c.Tree.Block > 1024 {
		problems = append(problems, "unbounded or oversized merge blocks")
	}
	capacity := c.Pool * c.Ratio
	for _, threshold := range []int{c.Tree.Lower, c.Tree.Mutation, c.Tree.Optimize} {
		if threshold < 1 || threshold > capacity {
			problems = append(problems, "maintenance thresholds cannot reserve workers or boot safely")
		}
	}
	return problems
}

func TestDurableClickHouseBackgroundWorkFitsMemoryProfile(t *testing.T) {
	var file struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, composeDurable)), &file); err != nil {
		t.Fatal(err)
	}
	mounted := slices.Contains(file.Services["clickhouse"].Volumes, clickhouseResourceMount)
	if !mounted {
		t.Fatal("bounded ClickHouse maintenance config is not mounted read-only")
	}
	if problems := clickhouseMaintenanceProblems(mounted, readRepoFile(t, clickhouseResourceFile)); len(problems) != 0 {
		t.Fatalf("durable ClickHouse background resources: %v", problems)
	}
}

func TestDurableClickHouseMaintenanceJudgeRejectsUnsafeSettings(t *testing.T) {
	body := readRepoFile(t, clickhouseResourceFile)
	cases := []struct {
		name, old, replacement string
		unmounted              bool
	}{
		{name: "missing mount", unmounted: true},
		{name: "unbounded pool", old: "<background_pool_size>2", replacement: "<background_pool_size>0"},
		{name: "upstream pool", old: "<background_pool_size>2", replacement: "<background_pool_size>16"},
		{name: "unbounded memory", old: "<merges_mutations_memory_usage_soft_limit>1073741824", replacement: "<merges_mutations_memory_usage_soft_limit>0"},
		{name: "oversized memory", old: "<merges_mutations_memory_usage_soft_limit>1073741824", replacement: "<merges_mutations_memory_usage_soft_limit>4294967296"},
		{name: "upstream wide blocks", old: "<merge_max_block_size>1024", replacement: "<merge_max_block_size>8192"},
		{name: "mutation startup failure", old: "<number_of_free_entries_in_pool_to_execute_mutation>1", replacement: "<number_of_free_entries_in_pool_to_execute_mutation>20"},
		{name: "optimize startup failure", old: "<number_of_free_entries_in_pool_to_execute_optimize_entire_partition>1", replacement: "<number_of_free_entries_in_pool_to_execute_optimize_entire_partition>25"},
		{name: "missing mutation threshold", old: "<number_of_free_entries_in_pool_to_execute_mutation>1</number_of_free_entries_in_pool_to_execute_mutation>", replacement: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := body
			if tc.old != "" {
				if !strings.Contains(changed, tc.old) {
					t.Fatal("mutation did not apply")
				}
				changed = strings.Replace(changed, tc.old, tc.replacement, 1)
			}
			if problems := clickhouseMaintenanceProblems(!tc.unmounted, changed); len(problems) == 0 {
				t.Fatal("unsafe ClickHouse maintenance configuration passed")
			}
		})
	}
}
