#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Start and remove the exact disposable NetBox CI source, never a remote one.

The source application, PostgreSQL and cache use TLS with a per-run CA.
Credentials, raw source data and keys never enter the receipt or command argv.
"""

import copy
from http.client import HTTPSConnection, HTTPException
import ipaddress
import json
import io
import os
import re
from pathlib import Path
import secrets
import shutil
import ssl
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "test/netbox/compose.yml"
RUNTIME = Path("/tmp/probectl-qa-beta-netbox")
PROJECT = "probectl-qa-beta-netbox"
ORIGIN = "https://localhost:18443"

NETBOX_CONFIG = """import os
SECRET_KEY = os.environ["SECRET_KEY"]
DATABASES = {"default": {
    "NAME": "netbox", "USER": "netbox", "PASSWORD": os.environ["DB_PASSWORD"],
    "HOST": "netbox-db", "PORT": "5432", "CONN_MAX_AGE": 0,
    "OPTIONS": {"sslmode": "verify-full", "sslrootcert": "/opt/netbox/ci-ca.crt"},
}}
REDIS = {kind: {
    "HOST": "netbox-cache", "PORT": 6379, "DATABASE": index,
    "PASSWORD": os.environ["CACHE_PASSWORD"], "SSL": True,
    "INSECURE_SKIP_TLS_VERIFY": False, "CA_CERT_PATH": "/opt/netbox/ci-ca.crt",
} for kind, index in [("tasks", 0), ("caching", 1)]}
REDIS["caching"]["URL"] = "rediss://netbox-cache:6379/1?ssl_check_hostname=True"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "netbox"]
CENSUS_REPORTING_ENABLED = False
ISOLATED_DEPLOYMENT = True
RELEASE_CHECK_URL = None
GRAPHQL_ENABLED = False
WEBHOOKS_ENABLED = False
DEBUG = False
"""


def private_file(name: str, data: str) -> None:
    descriptor = os.open(RUNTIME / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)


def command(
    args: list[str], stage: str, *, data: bytes | None = None, timeout: int = 120
) -> bytes:
    try:
        result = subprocess.run(
            args, input=data, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"NetBox fixture {stage} timed out") from None
    if result.returncode:
        # Never echo a source response, bootstrap input, environment or logs.
        detail = bootstrap_failure(result.stderr) if stage == "compose exec" else ""
        raise RuntimeError(
            f"NetBox fixture {stage} failed (exit {result.returncode})" + detail
        )
    return result.stdout


def bootstrap_failure(raw: bytes) -> str:
    """Admit only fixed stage/class enums from the owned bootstrap protocol."""
    stages = {
        "django_setup",
        "input",
        "models",
        "cache_tls",
        "task_tls",
        "reader_user",
        "read_permission",
        "read_token",
        "device_type",
        "source_tenants",
        "source_addresses",
        "ownership_move",
    }
    classes = {
        "ImportError",
        "ModuleNotFoundError",
        "ImproperlyConfigured",
        "OperationalError",
        "IntegrityError",
        "ProgrammingError",
        "DataError",
        "ConnectionError",
        "AuthenticationError",
        "SSLError",
        "TimeoutError",
        "ValueError",
        "TypeError",
        "AttributeError",
        "KeyError",
        "RuntimeError",
        "other",
    }
    prefix = b"PROBECTL_NETBOX_BOOTSTRAP_FAILURE "
    for line in raw[-16384:].splitlines():
        _, marker, payload = line.partition(prefix)
        if not marker:
            continue
        try:
            value = json.loads(payload)
        except (ValueError, UnicodeError):
            continue
        if (
            isinstance(value, dict)
            and set(value) == {"stage", "error_class"}
            and isinstance(value["stage"], str)
            and isinstance(value["error_class"], str)
            and value["stage"] in stages
            and value["error_class"] in classes
        ):
            return (
                " bootstrap stage="
                + value["stage"]
                + " error_class="
                + value["error_class"]
            )
    return ""


def compose(*args: str, data: bytes | None = None, timeout: int = 120) -> bytes:
    return command(
        [
            "docker",
            "compose",
            "--project-name",
            PROJECT,
            "--env-file",
            str(RUNTIME / ".env"),
            "-f",
            str(COMPOSE),
            *args,
        ],
        "compose " + args[0],
        data=data,
        timeout=timeout,
    )


def tls_config() -> dict:
    return {
        "listeners": {
            "0.0.0.0:8443": {
                "pass": "applications/netbox",
                "tls": {
                    "certificate": "fixture",
                    "conf_commands": {"minprotocol": "TLSv1.2"},
                },
            }
        },
        "applications": {
            "netbox": {
                "type": "python 3",
                "path": "/opt/netbox/netbox/",
                "module": "netbox.wsgi",
                "home": "/opt/netbox/venv",
                "user": "unit",
                "group": "root",
                "processes": {"max": 1, "spare": 1},
            }
        },
    }


def verify_tls_config(config: dict) -> None:
    if set(config.get("listeners", {})) != {"0.0.0.0:8443"}:
        raise ValueError("fixture must have exactly one native TLS listener")
    listener = config["listeners"]["0.0.0.0:8443"]
    if listener.get("tls") != {
        "certificate": "fixture",
        "conf_commands": {"minprotocol": "TLSv1.2"},
    }:
        raise ValueError("fixture listener lost its TLS minimum or certificate")


def certificates() -> None:
    command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-keyout",
            str(RUNTIME / "ca.key"),
            "-out",
            str(RUNTIME / "ca.crt"),
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-subj",
            "/CN=probectl-netbox-fixture-ca",
        ],
        "test CA",
    )
    for name, (names, hostname) in {
        "db": ("DNS:netbox-db", "netbox-db"),
        "cache": ("DNS:netbox-cache", "netbox-cache"),
        "netbox": ("DNS:localhost,DNS:netbox,IP:127.0.0.1", "localhost"),
    }.items():
        private_file(
            name + ".ext",
            "\n".join(
                [
                    "subjectAltName=" + names,
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "subjectKeyIdentifier=hash",
                    "authorityKeyIdentifier=keyid,issuer",
                    "",
                ]
            ),
        )
        command(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(RUNTIME / (name + ".key")),
                "-out",
                str(RUNTIME / (name + ".csr")),
                "-subj",
                "/CN=" + name,
            ],
            "test source key",
        )
        command(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(RUNTIME / (name + ".csr")),
                "-CA",
                str(RUNTIME / "ca.crt"),
                "-CAkey",
                str(RUNTIME / "ca.key"),
                "-CAcreateserial",
                "-out",
                str(RUNTIME / (name + ".crt")),
                "-days",
                "2",
                "-extfile",
                str(RUNTIME / (name + ".ext")),
            ],
            "test source certificate",
        )
        command(
            [
                "openssl",
                "verify",
                "-x509_strict",
                "-purpose",
                "sslserver",
                "-verify_hostname",
                hostname,
                "-CAfile",
                str(RUNTIME / "ca.crt"),
                str(RUNTIME / (name + ".crt")),
            ],
            "strict server certificate profile",
        )
    private_file(
        "netbox.bundle",
        (RUNTIME / "netbox.crt").read_text() + (RUNTIME / "netbox.key").read_text(),
    )


def validate_source_endpoint(endpoint: dict) -> tuple[str, int]:
    address = ipaddress.ip_address(endpoint.get("host", ""))
    if (
        endpoint.get("port") != 8443
        or address.version != 4
        or not any(
            address in ipaddress.ip_network(network)
            for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
    ):
        raise ValueError("NetBox fixture endpoint is not its private IPv4 TLS listener")
    return str(address), 8443


def source_endpoint() -> tuple[str, int]:
    return validate_source_endpoint(json.loads((RUNTIME / "endpoint.json").read_text()))


def discover_source_endpoint() -> None:
    container = compose("ps", "--quiet", "netbox").decode().strip()
    if not 12 <= len(container) <= 64 or any(
        char not in "0123456789abcdef" for char in container
    ):
        raise RuntimeError(
            "NetBox fixture did not identify exactly one owned container"
        )
    template = '{"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .NetworkSettings.Ports}}}'
    state = json.loads(
        command(
            ["docker", "inspect", container, "--format", template],
            "owned endpoint inspection",
        )
    )
    if (
        state["project"] != PROJECT
        or state["service"] != "netbox"
        or set(state["networks"]) != {PROJECT + "_source"}
    ):
        raise RuntimeError(
            "NetBox fixture container is not isolated on its owned source network"
        )
    internal = command(
        [
            "docker",
            "network",
            "inspect",
            PROJECT + "_source",
            "--format",
            "{{json .Internal}}",
        ],
        "owned network isolation",
    ).strip()
    if internal != b"true":
        raise RuntimeError("NetBox fixture source network lost outbound isolation")
    endpoint = {
        "host": state["networks"][PROJECT + "_source"]["IPAddress"],
        "port": 8443,
    }
    validate_source_endpoint(endpoint)
    private_file("endpoint.json", json.dumps(endpoint) + "\n")
    print(
        "NetBox fixture host port published: "
        + str(bool((state["ports"] or {}).get("8443/tcp"))).lower()
    )


class FixtureHTTPSConnection(HTTPSConnection):
    """Route only this owned source; retain localhost SNI/hostname checking."""

    def __init__(self, context: ssl.SSLContext):
        super().__init__("localhost", 18443, timeout=8, context=context)
        self.fixture_context = context

    def connect(self) -> None:
        peer = socket.create_connection(source_endpoint(), timeout=8)
        try:
            self.sock = self.fixture_context.wrap_socket(
                peer, server_hostname="localhost"
            )
        except BaseException:
            peer.close()
            raise


def request(
    path: str, *, token: str = "", method: str = "GET", body: bytes | None = None
) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Token " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    context = ssl.create_default_context(cafile=str(RUNTIME / "ca.crt"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = FixtureHTTPSConnection(context)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read((4 << 20) + 1)
        if len(raw) > 4 << 20:
            raise RuntimeError("NetBox fixture response exceeds the source bound")
        if response.status >= 500:
            diagnose_http_error(response.status, raw)
        return response.status, raw if response.status < 400 else b""
    finally:
        connection.close()


def diagnose_http_error(status: int, raw: bytes) -> None:
    """NetBox CoreMiddleware catches API exceptions before Django logs them.

    Admit its exception class enum and fixed signal booleans only. Its error
    field can contain credentials or SQL and must never leave this function.
    """
    category, error = "other", ""
    try:
        document = json.loads(raw)
        if isinstance(document, dict):
            value = document.get("exception")
            if value in {
                "ImportError",
                "ModuleNotFoundError",
                "ImproperlyConfigured",
                "OperationalError",
                "IntegrityError",
                "ProgrammingError",
                "DataError",
                "ConnectionError",
                "AuthenticationError",
                "SSLError",
                "TimeoutError",
                "ValueError",
                "TypeError",
                "AttributeError",
                "KeyError",
                "RuntimeError",
                "PermissionError",
                "NotImplementedError",
                "AssertionError",
            }:
                category = value
            if isinstance(document.get("error"), str):
                error = document["error"]
    except (ValueError, UnicodeError, TypeError):
        pass
    signals = {
        name: marker in error
        for name, marker in {
            "tls_verification": "CERTIFICATE_VERIFY_FAILED",
            "authentication_required": "Authentication required",
            "connection_refused": "Connection refused",
            "permission_denied": "Permission denied",
            "tls_minimum_option": "ssl_min_version",
            "task_configuration": "RQ_QUEUES",
            "settings_module": "DJANGO_SETTINGS_MODULE",
        }.items()
    }
    print(
        "NetBox fixture HTTP failure: "
        + json.dumps(
            {
                "http_status": status
                if type(status) is int and 500 <= status <= 599
                else None,
                "exception_class": category,
                "signals": signals,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def verify_source_tls() -> None:
    for wrong_ca in [True, False]:
        context = (
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if wrong_ca
            else ssl.create_default_context(cafile=str(RUNTIME / "ca.crt"))
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        hostname = "localhost" if wrong_ca else "wrong-netbox.test"
        try:
            with socket.create_connection(source_endpoint(), timeout=8) as connection:
                with context.wrap_socket(connection, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            continue
        raise RuntimeError("NetBox source TLS accepted a wrong CA or hostname")


def verify_application_version(status: int, raw: bytes) -> None:
    version = None
    try:
        document = json.loads(raw)
        if isinstance(document, dict):
            value = document.get("netbox-version")
            if isinstance(value, str) and re.fullmatch(
                r"[0-9]{1,3}(?:\.[0-9]{1,3}){2}", value
            ):
                version = value
    except (ValueError, UnicodeError):
        pass
    if status == 200 and version == "4.4.5":
        return
    # Numeric status and a bounded numeric version only; never an error body,
    # source-supplied string, hostname, URL or credential.
    print(
        "NetBox fixture version check: "
        + json.dumps(
            {
                "http_status": status
                if type(status) is int and 100 <= status <= 599
                else None,
                "numeric_version": version,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    raise RuntimeError("NetBox fixture did not report its pinned application version")


def bootstrap(spec: dict) -> dict:
    script = (ROOT / "test/netbox/seed.py").read_text()
    raw = compose(
        "exec",
        "-T",
        "--workdir",
        "/opt/netbox/netbox",
        "netbox",
        "/opt/netbox/venv/bin/python",
        "-c",
        script,
        data=json.dumps(spec).encode(),
    )
    return json.loads(raw)


def startup_diagnostics() -> None:
    """Print only enum/boolean state, never raw container output or errors."""
    allowed_services = {"netbox", "netbox-db", "netbox-cache"}
    states = {"created", "running", "restarting", "exited", "dead", "paused"}
    try:
        raw = compose("ps", "--all", "--format", "json").decode()
        rows = (
            json.loads(raw)
            if raw.lstrip().startswith("[")
            else [json.loads(line) for line in raw.splitlines() if line.strip()]
        )
        for row in rows:
            if row.get("Service") not in allowed_services:
                continue
            state = row.get("State")
            health = row.get("Health")
            print(
                json.dumps(
                    {
                        "source_service": row["Service"],
                        "state": state if state in states else "unknown",
                        "health": health
                        if health in {"healthy", "unhealthy", "starting", ""}
                        else "unknown",
                        "exit_code": row.get("ExitCode")
                        if isinstance(row.get("ExitCode"), int)
                        else None,
                    },
                    sort_keys=True,
                )
            )
        stage = (
            compose("exec", "-T", "netbox", "cat", "/tmp/probectl-netbox-stage")
            .decode()
            .strip()
        )
        if stage in {
            "configuration",
            "migrations",
            "unit-start",
            "unit-certificate",
            "unit-configuration",
            "serving",
        }:
            print("NetBox fixture startup stage: " + stage)
    except (RuntimeError, ValueError, OSError):
        print("NetBox fixture startup state unavailable")
    try:
        raw = compose("logs", "--no-color", "--tail", "100", "netbox")
        safe_failure = bootstrap_failure(raw)
        if safe_failure:
            print("NetBox fixture request failure:" + safe_failure)
        # Fixed signals help distinguish startup failures without allowing log
        # strings, tokens, URLs, environment or Python tracebacks into CI output.
        signals = {
            label: marker in raw
            for label, marker in {
                "database_migrations_started": b"Applying database migrations",
                "database_wait": b"Waiting on DB",
                "initialisation_completed": b"Initialisation is done",
                "permission_error": b"Permission denied",
                "configuration_error": b"ImproperlyConfigured",
                "tls_verification_error": b"CERTIFICATE_VERIFY_FAILED",
                "task_authentication_error": b"AuthenticationError",
                "source_type_error": b"TypeError",
                "source_attribute_error": b"AttributeError",
                "memory_error": b"MemoryError",
                "unit_error": b"[alert]",
            }.items()
        }
        print("NetBox fixture startup signals: " + json.dumps(signals, sort_keys=True))
    except (RuntimeError, OSError):
        print("NetBox fixture startup signals unavailable")


def start() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError(
            "NetBox source startup is CI-only; local heavy work needs host admission"
        )
    os.umask(0o077)
    RUNTIME.mkdir(mode=0o700)
    db_password, cache_password = secrets.token_hex(24), secrets.token_hex(24)
    token = secrets.token_hex(20)
    private_file("token", token + "\n")
    private_file(
        ".env",
        "\n".join(
            [
                "PROBECTL_TEST_NETBOX_RUNTIME_DIR=" + str(RUNTIME),
                "DB_PASSWORD=" + db_password,
                "CACHE_PASSWORD=" + cache_password,
                "SECRET_KEY=" + secrets.token_urlsafe(64),
                "",
            ]
        ),
    )
    private_file("netbox_config.py", NETBOX_CONFIG)
    private_file("netbox_settings.py", (ROOT / "test/netbox/settings.py").read_text())
    private_file(
        "pg_hba.conf",
        "local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n",
    )
    private_file(
        "valkey.conf",
        "\n".join(
            [
                "port 0",
                "tls-port 6379",
                "bind 0.0.0.0",
                "protected-mode yes",
                "tls-cert-file /tmp/cache.crt",
                "tls-key-file /tmp/cache.key",
                "tls-ca-cert-file /tmp/ca.crt",
                "tls-auth-clients no",
                'tls-protocols "TLSv1.2 TLSv1.3"',
                "requirepass " + cache_password,
                'save ""',
                "appendonly no",
                "maxmemory 96mb",
                "maxmemory-policy noeviction",
                "",
            ]
        ),
    )
    config = tls_config()
    verify_tls_config(config)
    private_file("unit.json", json.dumps(config))
    certificates()
    compose("config", "--quiet")
    compose("pull", timeout=300)
    compose("up", "-d", "--no-build", timeout=180)
    discover_source_endpoint()
    deadline = time.monotonic() + 240
    readiness = {
        "last_http_status": None,
        "transport": "not_attempted",
        "certificate_verify_code": None,
    }
    while True:
        try:
            status, _ = request("/login/")
            readiness = {
                "last_http_status": status,
                "transport": "verified_tls",
                "certificate_verify_code": None,
            }
            if status == 200:
                break
        except (OSError, HTTPException) as reason:
            if isinstance(reason, ssl.SSLCertVerificationError):
                readiness = {
                    "last_http_status": None,
                    "transport": "certificate_verification_refused",
                    "certificate_verify_code": reason.verify_code,
                }
            else:
                readiness = {
                    "last_http_status": None,
                    "transport": "tls_or_connection_unavailable",
                    "certificate_verify_code": None,
                }
        if time.monotonic() >= deadline:
            print(
                "NetBox fixture client readiness: "
                + json.dumps(readiness, sort_keys=True)
            )
            startup_diagnostics()
            raise RuntimeError("NetBox fixture verified-TLS readiness timed out")
        time.sleep(2)
    verify_source_tls()
    print("NetBox fixture source transport verified", flush=True)
    manifest = bootstrap({"action": "seed", "token": token})
    print("NetBox fixture ORM bootstrap verified", flush=True)
    manifest.update(
        {
            "origin": ORIGIN,
            "ca_file": str(RUNTIME / "ca.crt"),
            "token_file": str(RUNTIME / "token"),
            "dial_address": "%s:%d" % source_endpoint(),
        }
    )
    private_file("manifest.json", json.dumps(manifest, sort_keys=True) + "\n")
    status, raw = request("/api/status/", token=token)
    try:
        verify_application_version(status, raw)
    except RuntimeError:
        startup_diagnostics()
        raise
    status, _ = request("/api/tenancy/tenants/", token=token, method="POST", body=b"{}")
    if status != 403:
        raise RuntimeError("NetBox fixture API credential was not read-only")
    images = []
    for image in compose("config", "--images").decode().splitlines():
        if "@sha256:" not in image:
            raise RuntimeError("NetBox fixture image is not digest-pinned")
        identifier = (
            command(
                ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
                "image identity",
            )
            .decode()
            .strip()
        )
        images.append({"image": image, "id": identifier})
    private_file(
        "receipt.json",
        json.dumps(
            {
                "source": "real NetBox",
                "version": "4.4.5",
                "tested_checkout": command(
                    ["git", "-C", str(ROOT), "rev-parse", "HEAD"], "tested checkout"
                )
                .decode()
                .strip(),
                "scope": "source/provider component; full FX-3 release receipt remains required",
                "images": images,
                "api_credential": "read-only",
                "tls": "verified source, PostgreSQL and cache",
                "network": "internal-only; verified owned container dial with localhost SNI",
            },
            indent=2,
        )
        + "\n",
    )
    github_env = os.environ.get("GITHUB_ENV")
    if github_env:
        with open(github_env, "a", encoding="utf-8") as handle:
            handle.write(
                "PROBECTL_TEST_NETBOX_FIXTURE=" + str(RUNTIME / "manifest.json") + "\n"
            )
    print(
        "Real NetBox source is ready with verified TLS and a read-only runtime credential"
    )


def move_ip(source: str, destination: str) -> None:
    if (
        source not in {"a", "b"}
        or destination not in {"a", "b"}
        or source == destination
    ):
        raise ValueError("fixture move needs distinct a/b lanes")
    manifest = json.loads((RUNTIME / "manifest.json").read_text())
    bootstrap(
        {
            "action": "move-ip",
            "ip_id": manifest["ips"][source],
            "from_tenant": manifest["tenants"][source],
            "to_tenant": manifest["tenants"][destination],
        }
    )


def restore_ip(source: str) -> None:
    if source not in {"a", "b"}:
        raise ValueError("fixture restore needs an a/b lane")
    destination = "b" if source == "a" else "a"
    manifest = json.loads((RUNTIME / "manifest.json").read_text())
    bootstrap(
        {
            "action": "restore-ip",
            "ip_id": manifest["ips"][source],
            "from_tenant": manifest["tenants"][destination],
            "to_tenant": manifest["tenants"][source],
        }
    )


def cleanup() -> None:
    if (RUNTIME / ".env").exists():
        compose("down", "--volumes", "--remove-orphans", timeout=120)
    shutil.rmtree(RUNTIME, ignore_errors=True)


def selftest() -> None:
    verify_tls_config(tls_config())
    verify_application_version(200, b'{"netbox-version":"4.4.5"}')
    for raw in [
        b'{"exception":"TypeError","error":"untrusted-detail ssl_min_version"}',
        b'{"exception":"untrusted-detail","error":"untrusted-detail"}',
        b'{"exception":["untrusted-detail"]}',
        b"untrusted-detail",
    ]:
        diagnostic = io.StringIO()
        with patch("sys.stdout", diagnostic):
            diagnose_http_error(500, raw)
        if "untrusted-detail" in diagnostic.getvalue():
            raise RuntimeError("fixture HTTP diagnostic leaked source text")
        if b'"exception":"TypeError"' in raw and (
            '"exception_class": "TypeError"' not in diagnostic.getvalue()
            or '"tls_minimum_option": true' not in diagnostic.getvalue()
        ):
            raise RuntimeError(
                "fixture HTTP diagnostic lost its admitted class or signal"
            )
    for status, raw in [
        (500, b"untrusted-detail"),
        (200, b'{"netbox-version":"4.4.50"}'),
        (200, b'{"netbox-version":"untrusted-detail"}'),
        (200, b"[]"),
    ]:
        diagnostic = io.StringIO()
        with patch("sys.stdout", diagnostic):
            try:
                verify_application_version(status, raw)
            except RuntimeError:
                pass
            else:
                raise RuntimeError(
                    "fixture version check accepted an error or unpinned version"
                )
        if "untrusted-detail" in diagnostic.getvalue():
            raise RuntimeError("fixture version diagnostic leaked source text")
    diagnostic = b'PROBECTL_NETBOX_BOOTSTRAP_FAILURE {"stage":"cache_tls","error_class":"ConnectionError"}'
    if (
        bootstrap_failure(diagnostic)
        != " bootstrap stage=cache_tls error_class=ConnectionError"
    ):
        raise RuntimeError("fixture bootstrap enum diagnostic was lost")
    for unsafe in [
        diagnostic.replace(b"cache_tls", b"untrusted-detail"),
        diagnostic.replace(b"ConnectionError", b"untrusted-detail"),
        diagnostic[:-1] + b',"token":"untrusted-detail"}',
        b"raw traceback or source error: untrusted-detail",
        b'PROBECTL_NETBOX_BOOTSTRAP_FAILURE {"stage":[],"error_class":"other"}',
    ]:
        if bootstrap_failure(unsafe):
            raise RuntimeError("fixture bootstrap diagnostic admitted untrusted text")

    def refused_setup():
        raise RuntimeError("untrusted-detail must never reach the diagnostic")

    errors = io.StringIO()
    with (
        patch.dict(sys.modules, {"django": SimpleNamespace(setup=refused_setup)}),
        patch.dict(os.environ),
        patch("sys.stderr", errors),
    ):
        try:
            exec((ROOT / "test/netbox/seed.py").read_text(), {"__name__": "__main__"})
        except SystemExit as refused:
            if refused.code != 1:
                raise RuntimeError(
                    "fixture bootstrap failure lost its refusal"
                ) from None
        else:
            raise RuntimeError("fixture bootstrap accepted failed Django setup")
    if (
        "untrusted-detail" in errors.getvalue()
        or bootstrap_failure(errors.getvalue().encode())
        != " bootstrap stage=django_setup error_class=RuntimeError"
    ):
        raise RuntimeError(
            "fixture bootstrap leaked exception text or lost its safe class"
        )
    for bad in [
        {"host": "127.0.0.1", "port": 8443},
        {"host": "1.1.1.1", "port": 8443},
        {"host": "172.18.0.2", "port": 8080},
    ]:
        try:
            validate_source_endpoint(bad)
        except ValueError:
            continue
        raise RuntimeError("fixture accepted an unowned or non-TLS dial target")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with patch.dict(globals(), {"source_endpoint": lambda: ("172.18.0.2", 8443)}):
        with patch.object(socket, "create_connection") as dial:
            with patch.object(context, "wrap_socket") as wrap:
                connection = FixtureHTTPSConnection(context)
                connection.connect()
                dial.assert_called_once_with(("172.18.0.2", 8443), timeout=8)
                wrap.assert_called_once_with(
                    dial.return_value, server_hostname="localhost"
                )
                connection.close()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise RuntimeError(
            "fixture dial disabled TLS certificate/hostname verification"
        )
    config = {}
    with patch.dict(
        os.environ,
        {
            key: "fixture-selftest-only"
            for key in ["SECRET_KEY", "DB_PASSWORD", "CACHE_PASSWORD"]
        },
    ):
        exec(NETBOX_CONFIG, config)
    if config["DATABASES"]["default"]["OPTIONS"] != {
        "sslmode": "verify-full",
        "sslrootcert": "/opt/netbox/ci-ca.crt",
    }:
        raise RuntimeError("fixture database configuration lost TLS verification")
    for kind, connection in config["REDIS"].items():
        if (
            not connection["SSL"]
            or connection["INSECURE_SKIP_TLS_VERIFY"]
            or connection["CA_CERT_PATH"] != "/opt/netbox/ci-ca.crt"
            or not connection["PASSWORD"]
            or (kind == "tasks" and "URL" in connection)
            or (
                kind == "caching"
                and connection.get("URL")
                != "rediss://netbox-cache:6379/1?ssl_check_hostname=True"
            )
        ):
            raise RuntimeError("fixture cache/task configuration lost TLS verification")
    base_queue = {
        "HOST": "netbox-cache",
        "PORT": 6379,
        "PASSWORD": "fixture-selftest-only",
        "SSL": True,
        "SSL_CERT_REQS": "required",
        "REDIS_CLIENT_KWARGS": {"ssl_ca_certs": "/opt/netbox/ci-ca.crt"},
    }
    settings_script = (ROOT / "test/netbox/settings.py").read_text()
    for bad_override in [
        None,
        {"URL": "rediss://netbox-cache:6379/0"},
        {"PASSWORD": ""},
        {"SSL": False},
        {"SSL_CERT_REQS": "none"},
        {"REDIS_CLIENT_KWARGS": {}},
    ]:
        queue = copy.deepcopy(base_queue)
        queue.update(bad_override or {})
        base = SimpleNamespace(
            __all__=["RQ_QUEUES", "PRESERVED_SETTING"],
            RQ_QUEUES={"default": queue, "high": queue},
            PRESERVED_SETTING="base",
        )
        derived = {}
        with patch.dict(
            sys.modules,
            {"netbox": SimpleNamespace(settings=base), "netbox.settings": base},
        ):
            try:
                exec(settings_script, derived)
            except RuntimeError:
                if bad_override is None:
                    raise RuntimeError(
                        "fixture settings refused valid base task parameters"
                    ) from None
                continue
        if bad_override is not None:
            raise RuntimeError("fixture settings accepted unsafe task parameters")
        if (
            derived["PRESERVED_SETTING"] != "base"
            or queue["PASSWORD"] != base_queue["PASSWORD"]
            or queue["REDIS_CLIENT_KWARGS"]
            != {
                "ssl_ca_certs": "/opt/netbox/ci-ca.crt",
                "ssl_check_hostname": True,
                "ssl_min_version": ssl.TLSVersion.TLSv1_2,
            }
        ):
            raise RuntimeError(
                "fixture settings lost base settings, credentials or explicit TLS checks"
            )
    if (
        config["CENSUS_REPORTING_ENABLED"]
        or not config["ISOLATED_DEPLOYMENT"]
        or config["RELEASE_CHECK_URL"]
    ):
        raise RuntimeError("fixture configuration enabled outbound reporting/checks")
    bad = copy.deepcopy(tls_config())
    del bad["listeners"]["0.0.0.0:8443"]["tls"]
    try:
        verify_tls_config(bad)
    except ValueError:
        print("NetBox fixture rejects a planted plaintext listener")
        return
    raise RuntimeError("NetBox fixture accepted a plaintext listener")


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["start"]:
            start()
        elif sys.argv[1:] == ["cleanup"]:
            cleanup()
        elif sys.argv[1:] == ["selftest"]:
            selftest()
        elif len(sys.argv) == 4 and sys.argv[1] == "move-ip":
            move_ip(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 3 and sys.argv[1] == "restore-ip":
            restore_ip(sys.argv[2])
        else:
            raise ValueError(
                "usage: ci_netbox.py start|cleanup|selftest|move-ip a b|restore-ip a"
            )
    except (RuntimeError, ValueError, OSError) as error:
        # Errors above contain stage names only; never dump captured processes.
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
