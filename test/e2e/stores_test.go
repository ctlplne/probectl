// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The e2e's backing services run the way a production deployment runs them
// (docs/guardrails.md G7-12, beta gate G6): Postgres over verify-full TLS,
// Kafka over SASL_SSL on every listener, and ClickHouse over HTTPS with the
// least-privilege reader login every tenant read runs as (DPR-285). No
// plaintext bus flag exists anywhere in this package; internal/cipolicy's
// TestE2EStoresRunTheProductionTLSShape keeps it that way.

// kafkaInternalBroker is the broker's in-network SASL_SSL listener: the
// control-plane container and the admin tools run inside the kafka container
// use it. The host-facing SASL_SSL listener advertises the run's free
// loopback port (localhost:<port>), which does not exist inside a container.
// Both listeners present the run's certgen certificate, whose SANs carry
// `kafka` and `localhost`, so every client verifies chain and hostname.
const kafkaInternalBroker = "kafka:19093"

// kafkaClientConfig is the admin tools' SASL_SSL client configuration, written
// per run by the kafka-secrets one-shot into the broker's secrets volume.
const kafkaClientConfig = "/etc/kafka/secrets/client.properties"

// kafkaSASLUser is the SASL/PLAIN login the control plane and the collectors
// authenticate to the broker as (its password is generated per run).
const kafkaSASLUser = "probectl"

// clickhouseURL is the store endpoint every ClickHouse-backed lane uses:
// HTTPS only, hostname-verified against the certgen CA, exactly as
// deploy/compose/probectl.prod.yml points the control plane at it.
const clickhouseURL = "https://clickhouse:8443"

// clickhouseReaderUser is the SELECT-only login the shipped
// prod/clickhouse-init.sh provisions and every lane's row policy binds.
const clickhouseReaderUser = "probectl_reader"

// clickhousePlanes are the telemetry planes the release image puts on
// ClickHouse, each tenant-scoped through the reader login.
var clickhousePlanes = []string{"pathstore", "flowstore", "otelstore", "ebpfstore", "endpointstore"}

// storeSecrets are the run's throwaway backing-service credentials. Each is
// generated per run from the kernel's random source (never a literal), only
// ever reaches the disposable loopback stack, and dies with it.
type storeSecrets struct {
	kafkaStore, kafkaSASL                                string
	clickhouseAdmin, clickhouseControl, clickhouseReader string
}

func newStoreSecrets(t *testing.T) storeSecrets {
	t.Helper()
	return storeSecrets{
		kafkaStore: randomHex(t, 24), kafkaSASL: randomHex(t, 24),
		clickhouseAdmin: randomHex(t, 24), clickhouseControl: randomHex(t, 24), clickhouseReader: randomHex(t, 24),
	}
}

// composeEnv is what the override interpolates; it reaches only the docker
// compose process, never a command line.
func (s storeSecrets) composeEnv() []string {
	return []string{
		"PROBECTL_E2E_KAFKA_STORE_PASSWORD=" + s.kafkaStore,
		"PROBECTL_E2E_KAFKA_SASL_PASSWORD=" + s.kafkaSASL,
		"PROBECTL_E2E_CLICKHOUSE_ADMIN_PASSWORD=" + s.clickhouseAdmin,
		"PROBECTL_E2E_CLICKHOUSE_CONTROL_PASSWORD=" + s.clickhouseControl,
		"PROBECTL_E2E_CLICKHOUSE_READER_PASSWORD=" + s.clickhouseReader,
	}
}

// storeEnv returns the control plane's bus and ClickHouse configuration, the
// production shape of deploy/compose/probectl.prod.yml and the Helm
// multi-tenant table: Kafka over TLS (CA-verified, SASL-authenticated), every
// telemetry store on ClickHouse over HTTPS, each lane tenant-scoped with its
// reader login, and both ClickHouse credentials as owner-only 0600 files the
// way secrets-init writes them.
func storeEnv(t *testing.T, ctl *controlImage, secretsDir, serverCA string, s storeSecrets) map[string]string {
	t.Helper()
	controlAuth := writeBasicAuthFile(t, filepath.Join(secretsDir, "clickhouse-basic-auth.json"), "probectl", s.clickhouseControl)
	readerAuth := writeBasicAuthFile(t, filepath.Join(secretsDir, "clickhouse-reader-basic-auth.json"), clickhouseReaderUser, s.clickhouseReader)
	env := map[string]string{
		// The certgen CA verifies the HTTPS ClickHouse hop (SSL_CERT_FILE, as
		// probectl.prod.yml sets it); the IdP keeps its own CA file.
		"SSL_CERT_FILE": ctl.path(t, serverCA),

		"PROBECTL_BUS_MODE":           "kafka",
		"PROBECTL_BUS_BROKERS":        kafkaInternalBroker,
		"PROBECTL_BUS_TLS_ENABLED":    "true",
		"PROBECTL_BUS_TLS_CA_FILE":    ctl.path(t, serverCA),
		"PROBECTL_BUS_SASL_MECHANISM": "plain",
		"PROBECTL_BUS_SASL_USER":      kafkaSASLUser,
		"PROBECTL_BUS_SASL_PASSWORD":  s.kafkaSASL,

		"PROBECTL_CLICKHOUSE_BASIC_AUTH_FILE":        ctl.path(t, controlAuth),
		"PROBECTL_CLICKHOUSE_READER_BASIC_AUTH_FILE": ctl.path(t, readerAuth),
	}
	for _, plane := range clickhousePlanes {
		key := "PROBECTL_" + strings.ToUpper(plane)
		env[key+"_MODE"] = "clickhouse"
		env[key+"_URL"] = clickhouseURL
		env[key+"_TENANT_SCOPING"] = "true"
		env[key+"_READER_USER"] = clickhouseReaderUser
	}
	return env
}

// collectorBusEnv is a fixture collector's broker configuration: TLS with
// the certgen CA (hostname `localhost`, the advertised host listener) and
// SASL, the env shape the probectl-agent Helm chart renders.
func collectorBusEnv(prefix, caFile string, s storeSecrets) []string {
	return []string{
		prefix + "_BUS_TLS_ENABLED=true",
		prefix + "_BUS_TLS_CA_FILE=" + caFile,
		prefix + "_BUS_SASL_MECHANISM=plain",
		prefix + "_BUS_SASL_USER=" + kafkaSASLUser,
		prefix + "_BUS_SASL_PASSWORD=" + s.kafkaSASL,
	}
}

// writeBasicAuthFile writes one owner-only ClickHouse credential file in the
// shape secrets-init writes it.
func writeBasicAuthFile(t *testing.T, path, username, password string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(raw)+"\n")
	return path
}

// provisionClickHouseLogins runs the SHIPPED deploy/compose/prod/clickhouse-init.sh
// one-shot: the `probectl` control login and the SELECT-only
// `probectl_reader`, over the strictly verified secure native port.
func provisionClickHouseLogins(t *testing.T, root string, stack composeStack) {
	t.Helper()
	out := runCmdOutput(t, root, stack.env, "docker", stack.args("run", "--rm", "-T", "clickhouse-init")...)
	if !strings.Contains(out, "probectl + probectl_reader provisioned") {
		t.Fatalf("clickhouse-init did not provision the control and reader logins:\n%s", out)
	}
}

// serviceMapFromStore reads the tenant's eBPF service map, which the release
// image serves from ClickHouse through the reader lane, and fails unless the
// answer really came from the store.
func serviceMapFromStore(t *testing.T, a api) string {
	t.Helper()
	body := a.get(t, "/v1/ebpf/service-map?limit=500")
	var resp struct {
		Source  string `json:"source"`
		Running bool   `json:"ebpf_running"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode /v1/ebpf/service-map: %v: %s", err, body)
	}
	if resp.Source != "store" || !resp.Running {
		t.Fatalf("/v1/ebpf/service-map is not served from the ClickHouse store (source %q, running %t): %s",
			resp.Source, resp.Running, body)
	}
	return body
}

// assertClickHouseReads proves the ClickHouse-backed eBPF read works for each
// tenant through the reader login and shows nothing of the other tenant.
func assertClickHouseReads(t *testing.T, a, b api) {
	t.Helper()
	for _, c := range []struct {
		name         string
		reader       api
		own, foreign string
	}{{tenantA, a, ipOnlyA, ipOnlyB}, {tenantB, b, ipOnlyB, ipOnlyA}} {
		waitFor(t, "tenant "+c.name+"'s edge in the ClickHouse-backed /v1/ebpf/service-map", 60*time.Second, func() bool {
			return strings.Contains(serviceMapFromStore(t, c.reader), c.own)
		})
		if body := serviceMapFromStore(t, c.reader); strings.Contains(body, c.foreign) {
			t.Fatalf("CROSS-TENANT LEAK: tenant %s's ClickHouse-backed /v1/ebpf/service-map shows the other tenant's %s:\n%s",
				c.name, c.foreign, body)
		}
	}
}

// restartAndReverify restarts the control plane once telemetry rows exist,
// so its boot self-check (DPR-285) runs against non-empty tables: on every
// lane the reader must authenticate as the policy-bound login, be refused
// INSERT and CREATE, and see no row under a tenant that owns none. Any
// failure refuses startup, and /readyz never answers.
func restartAndReverify(t *testing.T, ctl *controlImage, anon api, controlRunning func()) {
	t.Helper()
	name := ctl.project + "-control"
	before := readerLaneVerifications(t, name)
	if out, err := exec.Command("docker", "restart", name).CombinedOutput(); err != nil {
		t.Fatalf("restart the control plane: %v\n%s", err, out)
	}
	waitFor(t, "control plane /readyz after the restart", 120*time.Second, func() bool {
		controlRunning()
		code, _ := anon.doQuiet(http.MethodGet, "/readyz")
		return code == http.StatusOK
	})
	after := readerLaneVerifications(t, name)
	for _, plane := range clickhousePlanes {
		if before[plane] < 1 || after[plane] <= before[plane] {
			t.Fatalf("the restarted control plane did not verify its %s reader lane at both boots (%d verifications before the restart, %d after)",
				plane, before[plane], after[plane])
		}
	}
}

// readerLaneVerifications counts, per plane, the boot log lines the control
// plane writes only after a lane's reader self-check passed. Counting the
// whole log needs no clock shared between this host and the daemon.
func readerLaneVerifications(t *testing.T, container string) map[string]int {
	t.Helper()
	out, err := exec.Command("docker", "logs", container).CombinedOutput()
	if err != nil {
		t.Fatalf("read the control plane's log: %v\n%s", err, out)
	}
	counts := map[string]int{}
	for _, plane := range clickhousePlanes {
		counts[plane] = strings.Count(string(out), plane+": ClickHouse tenant reads run as the policy-bound reader login")
	}
	return counts
}

// composeOverride runs the backing services the way production runs them.
// Published ports are pinned to loopback (the stack's credentials are
// throwaway, so it never listens on a LAN interface).
//
//   - Postgres serves TLS with the run's certgen bundle, the way
//     deploy/compose/probectl.yml does: the key is installed postgres-owned
//     0600 as the server requires.
//   - Kafka serves SASL_SSL on both client listeners and SSL on its loopback
//     controller listener; the kafka-secrets one-shot builds the broker's
//     PKCS12 key and trust stores from the certgen bundle per run.
//   - ClickHouse is the durable profile's service (deploy/compose/probectl.prod.yml):
//     the shipped prod/clickhouse/tls.xml removes every plaintext listener,
//     users.xml gives the tenant setting its fail-closed default, and the
//     shipped prod/clickhouse-init.sh provisions the control and reader
//     logins. The clickhouse-secrets one-shot installs the bundle 101:101 the
//     way secrets-init does. Relative paths resolve against deploy/compose,
//     the directory of the stack's first Compose file.
const composeOverride = `services:
  postgres:
    ports: !override
      - "127.0.0.1:${PROBECTL_DEV_POSTGRES_PORT}:5432"
    command: >
      bash -c "install -o postgres -g postgres -m 600 /certs/tls.key /var/lib/postgresql/server.key
      && install -o postgres -g postgres -m 644 /certs/tls.crt /var/lib/postgresql/server.crt
      && exec docker-entrypoint.sh postgres -c ssl=on
      -c ssl_cert_file=/var/lib/postgresql/server.crt
      -c ssl_key_file=/var/lib/postgresql/server.key"
    volumes:
      - ${PROBECTL_E2E_TLS_DIR}:/certs:ro

  kafka-secrets:
    image: apache/kafka:3.9.0@sha256:fbc7d7c428e3755cf36518d4976596002477e4c052d1f80b5b9eafd06d0fff2f # digest-pinned (U-061)
    user: "0:0"
    network_mode: none
    entrypoint: ["/bin/bash", "-ec"]
    command:
      - |
        umask 077
        openssl pkcs12 -export -in /certs/tls.crt -inkey /certs/tls.key -certfile /certs/ca.crt \
          -name kafka -out /out/kafka.keystore.p12 -passout env:KAFKA_STORE_PASSWORD
        rm -f /out/kafka.truststore.p12
        keytool -importcert -noprompt -storetype PKCS12 -alias e2e-ca -file /certs/ca.crt \
          -keystore /out/kafka.truststore.p12 -storepass "$$KAFKA_STORE_PASSWORD"
        {
          printf '%s\n' 'security.protocol=SASL_SSL'
          printf '%s\n' 'ssl.truststore.location=/etc/kafka/secrets/kafka.truststore.p12'
          printf '%s\n' 'ssl.truststore.type=PKCS12'
          printf 'ssl.truststore.password=%s\n' "$$KAFKA_STORE_PASSWORD"
          printf '%s\n' 'ssl.endpoint.identification.algorithm=https'
          printf '%s\n' 'sasl.mechanism=PLAIN'
          printf 'sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="probectl" password="%s";\n' "$$KAFKA_SASL_PASSWORD"
        } > /out/client.properties
        chown -R 1000:1000 /out
        chmod 0700 /out
        find /out -type f -exec chmod 0600 {} +
    environment:
      KAFKA_STORE_PASSWORD: ${PROBECTL_E2E_KAFKA_STORE_PASSWORD:?}
      KAFKA_SASL_PASSWORD: ${PROBECTL_E2E_KAFKA_SASL_PASSWORD:?}
    volumes:
      - ${PROBECTL_E2E_TLS_DIR}:/certs:ro
      - kafkasecrets:/out
    restart: "no"

  kafka:
    depends_on:
      kafka-secrets:
        condition: service_completed_successfully
    ports: !override
      - "127.0.0.1:${PROBECTL_DEV_KAFKA_PORT}:9092"
    environment: !override
      KAFKA_NODE_ID: 1
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@localhost:9093
      KAFKA_LISTENERS: EXTERNAL://0.0.0.0:9092,CONTROLLER://localhost:9093,INTERNAL://0.0.0.0:19093
      KAFKA_ADVERTISED_LISTENERS: EXTERNAL://localhost:${PROBECTL_DEV_KAFKA_PORT},INTERNAL://kafka:19093
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:SSL,EXTERNAL:SASL_SSL,INTERNAL:SASL_SSL
      KAFKA_INTER_BROKER_LISTENER_NAME: INTERNAL
      KAFKA_SASL_ENABLED_MECHANISMS: PLAIN
      KAFKA_SASL_MECHANISM_INTER_BROKER_PROTOCOL: PLAIN
      KAFKA_LISTENER_NAME_INTERNAL_PLAIN_SASL_JAAS_CONFIG: org.apache.kafka.common.security.plain.PlainLoginModule required username="probectl" password="${PROBECTL_E2E_KAFKA_SASL_PASSWORD:?}" user_probectl="${PROBECTL_E2E_KAFKA_SASL_PASSWORD:?}";
      KAFKA_LISTENER_NAME_EXTERNAL_PLAIN_SASL_JAAS_CONFIG: org.apache.kafka.common.security.plain.PlainLoginModule required user_probectl="${PROBECTL_E2E_KAFKA_SASL_PASSWORD:?}";
      KAFKA_SSL_KEYSTORE_LOCATION: /etc/kafka/secrets/kafka.keystore.p12
      KAFKA_SSL_KEYSTORE_TYPE: PKCS12
      KAFKA_SSL_KEYSTORE_PASSWORD: ${PROBECTL_E2E_KAFKA_STORE_PASSWORD:?}
      KAFKA_SSL_KEY_PASSWORD: ${PROBECTL_E2E_KAFKA_STORE_PASSWORD:?}
      KAFKA_SSL_TRUSTSTORE_LOCATION: /etc/kafka/secrets/kafka.truststore.p12
      KAFKA_SSL_TRUSTSTORE_TYPE: PKCS12
      KAFKA_SSL_TRUSTSTORE_PASSWORD: ${PROBECTL_E2E_KAFKA_STORE_PASSWORD:?}
      KAFKA_SSL_CLIENT_AUTH: none
      KAFKA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM: https
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR: 1
      KAFKA_TRANSACTION_STATE_LOG_MIN_ISR: 1
      KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS: 0
      KAFKA_NUM_PARTITIONS: 3
    volumes:
      - kafkasecrets:/etc/kafka/secrets:ro
    healthcheck:
      test: ["CMD-SHELL", "/opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server kafka:19093 --command-config /etc/kafka/secrets/client.properties >/dev/null 2>&1 || exit 1"]

  clickhouse-secrets:
    image: clickhouse/clickhouse-server:24.8@sha256:1ffa82edee000a42c09313bd9f1293d94c570aee74babc1b3ca9983a35fa597b # digest-pinned (U-061)
    user: "0:0"
    network_mode: none
    entrypoint: ["bash", "-ec"]
    command:
      - |
        install -d /out
        chown 101:101 /out
        chmod 0700 /out
        install -o 101 -g 101 -m 0644 /certs/tls.crt /out/tls.crt
        install -o 101 -g 101 -m 0644 /certs/ca.crt /out/ca.crt
        install -o 101 -g 101 -m 0600 /certs/tls.key /out/tls.key
    volumes:
      - ${PROBECTL_E2E_TLS_DIR}:/certs:ro
      - chsecrets:/out
    restart: "no"

  clickhouse:
    depends_on:
      clickhouse-secrets:
        condition: service_completed_successfully
    ports: !reset []
    environment: !override
      CLICKHOUSE_USER: probectl_admin
      CLICKHOUSE_PASSWORD: ${PROBECTL_E2E_CLICKHOUSE_ADMIN_PASSWORD:?}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"
    volumes: !override
      - chdata:/var/lib/clickhouse
      - chsecrets:/run/probectl-clickhouse:ro
      - ./prod/clickhouse/tls.xml:/etc/clickhouse-server/config.d/probectl-tls.xml:ro
      - ./prod/clickhouse/users.xml:/etc/clickhouse-server/users.d/probectl-tenant-setting.xml:ro
      - ./prod/clickhouse/client.xml:/etc/clickhouse-client/config.xml:ro
    healthcheck:
      test: ["CMD-SHELL", "clickhouse-client --secure --host clickhouse --port 9440 --user probectl_admin --password \"$$CLICKHOUSE_PASSWORD\" --query 'SELECT 1' >/dev/null 2>&1 || exit 1"]
      interval: 5s
      timeout: 5s
      retries: 40
      start_period: 15s

  clickhouse-init:
    image: clickhouse/clickhouse-server:24.8@sha256:1ffa82edee000a42c09313bd9f1293d94c570aee74babc1b3ca9983a35fa597b # digest-pinned (U-061)
    user: "101:101"
    depends_on:
      clickhouse:
        condition: service_healthy
    entrypoint: ["bash", "/prod/clickhouse-init.sh"]
    environment:
      CLICKHOUSE_ADMIN_PASSWORD: ${PROBECTL_E2E_CLICKHOUSE_ADMIN_PASSWORD:?}
      CLICKHOUSE_CONTROL_PASSWORD: ${PROBECTL_E2E_CLICKHOUSE_CONTROL_PASSWORD:?}
      CLICKHOUSE_READER_PASSWORD: ${PROBECTL_E2E_CLICKHOUSE_READER_PASSWORD:?}
    volumes:
      - ./prod/clickhouse-init.sh:/prod/clickhouse-init.sh:ro
      - ./prod/clickhouse/client.xml:/etc/clickhouse-client/config.xml:ro
      - chsecrets:/run/probectl-clickhouse:ro
    networks: [probectl]
    read_only: true
    tmpfs:
      - /tmp:size=16m,mode=1777
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    restart: "no"

volumes:
  kafkasecrets: {}
  chsecrets: {}
`

// e2eRuntimePassword is the disposable serve login's password: a throwaway
// value on a loopback-only, per-run database, deliberately not key-shaped.
const e2eRuntimePassword = "e2e-runtime-login-throwaway"

// createKafkaTopics creates the tenant lanes over the authenticated,
// certificate-verified SASL_SSL listener.
func createKafkaTopics(t *testing.T, root string, stack composeStack, topics ...string) {
	t.Helper()
	for _, topic := range topics {
		runCmd(t, root, stack.env, "docker", stack.args("exec", "-T", "kafka",
			"/opt/kafka/bin/kafka-topics.sh",
			"--bootstrap-server", kafkaInternalBroker,
			"--command-config", kafkaClientConfig,
			"--create",
			"--if-not-exists",
			"--topic", topic,
			"--partitions", "3",
			"--replication-factor", "1")...)
	}
}

func dumpKafkaDiagnostics(t *testing.T, root string, stack composeStack) {
	t.Helper()
	admin := func(tool string, args ...string) []string {
		return append([]string{"/opt/kafka/bin/" + tool, "--bootstrap-server", kafkaInternalBroker, "--command-config", kafkaClientConfig}, args...)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "topics", args: admin("kafka-topics.sh", "--list")},
		{name: "consumer-groups", args: admin("kafka-consumer-groups.sh", "--all-groups", "--describe")},
		{name: "tenant-a-ebpf-offsets", args: admin("kafka-get-offsets.sh", "--topic", "probectl."+laneA+".ebpf.flows")},
		{name: "tenant-b-ebpf-offsets", args: admin("kafka-get-offsets.sh", "--topic", "probectl."+laneB+".ebpf.flows")},
		{name: "tenant-a-result-offsets", args: admin("kafka-get-offsets.sh", "--topic", "probectl."+laneA+".network.results")},
		{name: "tenant-b-result-offsets", args: admin("kafka-get-offsets.sh", "--topic", "probectl."+laneB+".network.results")},
	} {
		args := stack.args(append([]string{"exec", "-T", "kafka"}, tc.args...)...)
		cmd := exec.Command("docker", args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), stack.env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("---- kafka %s failed ----\n%v\n%s", tc.name, err, out)
			continue
		}
		t.Logf("---- kafka %s ----\n%s", tc.name, out)
	}
}
