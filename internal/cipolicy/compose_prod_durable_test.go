// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/config"
)

// Beta gate G2 (decision of record D-26): deploy/compose/probectl.prod.yml is
// THE durable production Compose path. Layered over probectl.yml it must keep
// every telemetry plane on a real, durable backing service reached over
// verified TLS (docs/guardrails.md G7-12), keep that service's data on a named
// volume, never publish a backing service to the host, and never reach for the
// volatile acknowledgment. The judge runs on the merged service model so an
// overlay cannot quietly undo the base, and the planted regression in testdata
// proves the judge itself still bites (fail-before).

const (
	composeBase       = "deploy/compose/probectl.yml"
	composeDurable    = "deploy/compose/probectl.prod.yml"
	plantedVolatile   = "internal/cipolicy/testdata/compose-prod-volatile.yml"
	volatileAckEnvKey = "PROBECTL_ALLOW_VOLATILE"
)

// durableModes is every plane the control plane would otherwise keep in
// memory (config.VolatileStores) and the only durable modes this profile ships.
var durableModes = map[string][]string{
	"PROBECTL_BUS_MODE":           {"nats", "kafka"},
	"PROBECTL_TSDB_MODE":          {"prometheus"},
	"PROBECTL_PATHSTORE_MODE":     {"clickhouse"},
	"PROBECTL_FLOWSTORE_MODE":     {"clickhouse"},
	"PROBECTL_OTELSTORE_MODE":     {"clickhouse"},
	"PROBECTL_EBPFSTORE_MODE":     {"clickhouse"},
	"PROBECTL_ENDPOINTSTORE_MODE": {"clickhouse"},
}

// durableURLs names each backing-service URL and the scheme it must use.
var durableURLs = map[string]string{
	"PROBECTL_BUS_BROKERS":        "tls://",
	"PROBECTL_TSDB_URL":           "https://",
	"PROBECTL_PATHSTORE_URL":      "https://",
	"PROBECTL_FLOWSTORE_URL":      "https://",
	"PROBECTL_OTELSTORE_URL":      "https://",
	"PROBECTL_EBPFSTORE_URL":      "https://",
	"PROBECTL_ENDPOINTSTORE_URL":  "https://",
	"PROBECTL_BUS_TLS_ENABLED":    "",
	"PROBECTL_DEPLOYMENT_PROFILE": "",
}

// durableDataPaths is where each backing service keeps the data that must
// survive a restart.
var durableDataPaths = map[string]string{
	"nats":       "/data",
	"clickhouse": "/var/lib/clickhouse",
	"prometheus": "/prometheus",
}

type composeModel struct {
	services map[string]*composeServiceModel
	volumes  map[string]bool // top-level named volumes
	raw      []string        // every source file, for whole-text rules
}

type composeServiceModel struct {
	env     map[string]string
	mounts  map[string]composeMount // by container target
	ports   []string
	present bool
}

type composeMount struct {
	kind   string // volume, bind, tmpfs
	source string
}

type composeFileYAML struct {
	Services map[string]struct {
		Environment yaml.Node   `yaml:"environment"`
		Volumes     []yaml.Node `yaml:"volumes"`
		Ports       []yaml.Node `yaml:"ports"`
	} `yaml:"services"`
	Volumes map[string]yaml.Node `yaml:"volumes"`
}

// loadComposeModel merges compose files the way `docker compose -f a -f b`
// does for the fields the gate judges: environment keys and mounts (by
// target) are overridden by later files, ports accumulate, named volumes union.
func loadComposeModel(t *testing.T, files ...string) composeModel {
	t.Helper()
	m := composeModel{services: map[string]*composeServiceModel{}, volumes: map[string]bool{}}
	for _, f := range files {
		raw := readRepoFile(t, f)
		m.raw = append(m.raw, raw)
		var doc composeFileYAML
		if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for name := range doc.Volumes {
			m.volumes[name] = true
		}
		for name, svc := range doc.Services {
			s := m.services[name]
			if s == nil {
				s = &composeServiceModel{env: map[string]string{}, mounts: map[string]composeMount{}}
				m.services[name] = s
			}
			s.present = true
			mergeComposeEnv(t, f, name, &svc.Environment, s.env)
			for i := range svc.Volumes {
				target, mount := parseComposeMount(t, f, name, &svc.Volumes[i])
				s.mounts[target] = mount
			}
			for i := range svc.Ports {
				s.ports = append(s.ports, nodeText(&svc.Ports[i]))
			}
		}
	}
	return m
}

func mergeComposeEnv(t *testing.T, file, svc string, n *yaml.Node, into map[string]string) {
	t.Helper()
	switch n.Kind {
	case 0:
		return
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			into[n.Content[i].Value] = n.Content[i+1].Value
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			k, v, _ := strings.Cut(item.Value, "=")
			into[k] = v
		}
	default:
		t.Fatalf("%s: service %s has an environment block the gate cannot read", file, svc)
	}
}

func parseComposeMount(t *testing.T, file, svc string, n *yaml.Node) (string, composeMount) {
	t.Helper()
	if n.Kind == yaml.ScalarNode {
		parts := strings.Split(n.Value, ":")
		if len(parts) < 2 {
			t.Fatalf("%s: service %s has an anonymous volume %q the gate cannot judge", file, svc, n.Value)
		}
		src := parts[0]
		kind := "volume"
		if strings.HasPrefix(src, ".") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") {
			kind = "bind"
		}
		return parts[1], composeMount{kind: kind, source: src}
	}
	var long struct {
		Type   string `yaml:"type"`
		Source string `yaml:"source"`
		Target string `yaml:"target"`
	}
	if err := n.Decode(&long); err != nil || long.Target == "" {
		t.Fatalf("%s: service %s has a volume entry the gate cannot read: %v", file, svc, err)
	}
	return long.Target, composeMount{kind: long.Type, source: long.Source}
}

func nodeText(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	out, _ := yaml.Marshal(n)
	return strings.TrimSpace(string(out))
}

// durableComposeViolations is the judge. Each returned line names one broken
// promise of the durable production profile.
func durableComposeViolations(m composeModel) []string {
	var out []string
	for _, raw := range m.raw {
		if strings.Contains(raw, volatileAckEnvKey) {
			out = append(out, volatileAckEnvKey+" appears in the durable profile; it must refuse memory modes, never acknowledge them")
			break
		}
	}
	control := m.services["control"]
	if control == nil {
		return append(out, "no control service in the merged durable profile")
	}
	for key, allowed := range durableModes {
		v := strings.TrimSpace(control.env[key])
		switch {
		case v == "":
			out = append(out, key+" is missing: the plane falls back to the volatile memory default")
		case v == "memory":
			out = append(out, key+"=memory is volatile")
		case !containsString(allowed, v):
			out = append(out, key+"="+v+" is not a durable mode ("+strings.Join(allowed, "|")+")")
		}
	}
	out = append(out, durableURLViolations(control.env)...)
	out = append(out, durableServiceViolations(m)...)
	sort.Strings(out)
	return out
}

func durableURLViolations(env map[string]string) []string {
	var out []string
	for key, scheme := range durableURLs {
		v := strings.TrimSpace(env[key])
		switch key {
		case "PROBECTL_BUS_TLS_ENABLED":
			if v != "true" {
				out = append(out, key+" must be true (docs/guardrails.md G7-12)")
			}
			continue
		case "PROBECTL_DEPLOYMENT_PROFILE":
			if v != "multi-tenant" && v != "regulated" {
				out = append(out, key+"="+v+" is not a production-like profile that refuses memory modes")
			}
			continue
		}
		if v == "" {
			out = append(out, key+" is missing")
			continue
		}
		for _, u := range strings.Split(v, ",") {
			if !strings.HasPrefix(strings.TrimSpace(u), scheme) {
				out = append(out, key+"="+u+" is not "+scheme+" (docs/guardrails.md G7-12)")
			}
		}
	}
	return out
}

func durableServiceViolations(m composeModel) []string {
	var out []string
	for svc, dataPath := range durableDataPaths {
		s := m.services[svc]
		if s == nil || !s.present {
			out = append(out, svc+" service is missing from the durable profile")
			continue
		}
		mount, ok := s.mounts[dataPath]
		switch {
		case !ok:
			out = append(out, svc+" has no volume at "+dataPath+": its data would die with the container")
		case mount.kind != "volume" || !m.volumes[mount.source]:
			out = append(out, svc+" keeps "+dataPath+" on "+strings.TrimSpace(mount.kind+" "+mount.source)+", not a declared named volume")
		}
		if len(s.ports) > 0 {
			out = append(out, svc+" publishes host ports "+strings.Join(s.ports, ", ")+"; only the control plane's HTTPS API may be published")
		}
	}
	return out
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func TestDurableComposeProfileKeepsEveryPlaneDurable(t *testing.T) {
	m := loadComposeModel(t, composeBase, composeDurable)
	if v := durableComposeViolations(m); len(v) > 0 {
		t.Fatalf("%s over %s is not a durable production profile:\n  %s", composeDurable, composeBase, strings.Join(v, "\n  "))
	}
}

func TestDurableComposeGateCatchesPlantedVolatileOverlay(t *testing.T) {
	m := loadComposeModel(t, composeBase, composeDurable, plantedVolatile)
	got := strings.Join(durableComposeViolations(m), "\n")
	for _, want := range []string{
		volatileAckEnvKey + " appears",
		"PROBECTL_PATHSTORE_MODE=memory is volatile",
		"PROBECTL_OTELSTORE_MODE is missing",
		"PROBECTL_TSDB_URL=http://prometheus:9090 is not https://",
		"PROBECTL_FLOWSTORE_URL=http://clickhouse:8123 is not https://",
		"PROBECTL_BUS_BROKERS=nats://nats:4222 is not tls://",
		"nats keeps /data on bind ./nats-data, not a declared named volume",
		"prometheus keeps /prometheus on tmpfs",
		"clickhouse publishes host ports",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("planted volatile overlay: the judge missed %q; it reported:\n%s", want, got)
		}
	}
}

// TestDurableComposeControlEnvPassesConfigValidation feeds the merged control
// environment (render-only placeholders for the operator's secrets) through
// the real config loader: the production profile must accept it with no
// volatile plane and complete tenant scoping, and must refuse the planted
// volatile overlay — the semantic half of the structural judge above.
func TestDurableComposeControlEnvPassesConfigValidation(t *testing.T) {
	cfg, err := config.Load(composeControlGetenv(t, loadComposeModel(t, composeBase, composeDurable)))
	if err != nil {
		t.Fatalf("the durable profile's control environment fails config validation:\n%v", err)
	}
	if v := cfg.VolatileStores(); len(v) > 0 {
		t.Fatalf("durable profile still has volatile planes: %v", v)
	}
	if cfg.DeploymentProfile != "multi-tenant" || !cfg.TenantScopingComplete() {
		t.Fatalf("durable profile = %q, tenant scoping complete = %v; want multi-tenant with every lane scoped",
			cfg.DeploymentProfile, cfg.TenantScopingComplete())
	}

	planted := loadComposeModel(t, composeBase, composeDurable, plantedVolatile)
	if _, err := config.Load(composeControlGetenv(t, planted)); err == nil ||
		!strings.Contains(err.Error(), "volatile lightweight modes are not allowed") {
		t.Fatalf("the planted volatile overlay must fail config validation under the production profile, got %v", err)
	}
}

// TestComposeMigrateOneShotPassesConfigValidation: the migrate one-shot runs the
// control binary's configured path, so the real config loader must accept its
// environment, in the shipped stack and under the durable overlay. Since TEN-01
// split migrations out of the serving container, the one-shot carried no session
// HMAC key, the default session auth mode then refused to load, and the shipped
// quickstart stopped at its first one-shot.
func TestComposeMigrateOneShotPassesConfigValidation(t *testing.T) {
	for name, m := range map[string]composeModel{
		"probectl.yml":                     loadComposeModel(t, composeBase),
		"probectl.yml + probectl.prod.yml": loadComposeModel(t, composeBase, composeDurable),
	} {
		if _, err := config.Load(composeServiceGetenv(t, m, "migrate")); err != nil {
			t.Errorf("%s: the migrate one-shot's environment fails config validation, so the stack cannot migrate:\n%v", name, err)
		}
		// The envelope key is resolved after config load and fails closed, so
		// the one-shot must name the control service's key and mount its volume.
		migrate, control := m.services["migrate"], m.services["control"]
		for _, k := range []string{"PROBECTL_ENVELOPE_KEY", "PROBECTL_ENVELOPE_KEY_FILE", "PROBECTL_REQUIRE_AT_REST_ENCRYPTION"} {
			if migrate.env[k] != control.env[k] {
				t.Errorf("%s: migrate's %s = %q, control's = %q; the one-shot cannot resolve the envelope key", name, k, migrate.env[k], control.env[k])
			}
		}
		if migrate.mounts["/var/lib/probectl"] != control.mounts["/var/lib/probectl"] {
			t.Errorf("%s: migrate does not mount the control service's /var/lib/probectl volume, where the envelope key lives", name)
		}
	}
}

// TestDurableComposeOverlayStaysRendered keeps the CI render gate and the
// make target pointed at the overlay, so a rename cannot drop it silently.
func TestDurableComposeOverlayStaysRendered(t *testing.T) {
	if ci := readRepoFile(t, ".github/workflows/ci.yml"); !strings.Contains(ci, "[probectl.prod.yml]=probectl.yml") {
		t.Error("compose-render must render probectl.prod.yml merged over probectl.yml")
	}
	if mk := readRepoFile(t, "Makefile"); !strings.Contains(mk, "-f deploy/compose/probectl.prod.yml") {
		t.Error("Makefile compose-prod-durable-up must layer deploy/compose/probectl.prod.yml")
	}
	for _, f := range []string{"secrets-init.sh", "clickhouse-init.sh", "nats.conf", "prometheus.yml"} {
		if _, err := os.Stat(filepath.Join(repoRoot(t), "deploy", "compose", "prod", f)); err != nil {
			t.Errorf("durable profile file deploy/compose/prod/%s: %v", f, err)
		}
	}
}

var composeInterpolation = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::?([-?])([^}]*))?\}`)

// composeControlGetenv resolves the merged control environment the way
// Compose interpolates it: ${VAR:-default} takes its default, a required
// ${VAR:?...} takes a render-only placeholder (never a real secret).
func composeControlGetenv(t *testing.T, m composeModel) func(string) string {
	t.Helper()
	return composeServiceGetenv(t, m, "control")
}

// composeServiceGetenv is composeControlGetenv for any service of the stack.
func composeServiceGetenv(t *testing.T, m composeModel, svc string) func(string) string {
	t.Helper()
	control := m.services[svc]
	if control == nil {
		t.Fatalf("no %s service", svc)
	}
	placeholder := map[string]string{
		// A 32-byte key the loader can parse, built at run time so no
		// key-shaped literal lives in the repository.
		"PROBECTL_SESSION_HMAC_KEY": strings.Repeat("0f", 32),
		"PROBECTL_SIEM_ENDPOINT":    "https://siem.example/ingest",
		"PROBECTL_IMAGE":            "probectl-control:render-only",
	}
	env := map[string]string{}
	for k, v := range control.env {
		v = composeInterpolation.ReplaceAllStringFunc(v, func(ref string) string {
			sub := composeInterpolation.FindStringSubmatch(ref)
			name, op, arg := sub[1], sub[2], sub[3]
			switch {
			case op == "-":
				return arg
			case placeholder[name] != "":
				return placeholder[name]
			default:
				return "render-only"
			}
		})
		env[k] = strings.ReplaceAll(v, "$$", "$")
	}
	return func(k string) string { return env[k] }
}
