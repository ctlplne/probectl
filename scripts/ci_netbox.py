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
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
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
    "URL": f"rediss://netbox-cache:6379/{index}?ssl_check_hostname=True",
} for kind, index in [("tasks", 0), ("caching", 1)]}
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
        raise RuntimeError(f"NetBox fixture {stage} failed (exit {result.returncode})")
    return result.stdout


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
    req = Request(ORIGIN + path, data=body, headers=headers, method=method)
    try:
        with urlopen(req, context=context, timeout=8) as response:
            raw = response.read((4 << 20) + 1)
            if len(raw) > 4 << 20:
                raise RuntimeError("NetBox fixture response exceeds the source bound")
            return response.status, raw
    except HTTPError as exc:
        return exc.code, b""


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
            with socket.create_connection(
                ("127.0.0.1", 18443), timeout=8
            ) as connection:
                with context.wrap_socket(connection, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            continue
        raise RuntimeError("NetBox source TLS accepted a wrong CA or hostname")


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
        except (URLError, TimeoutError) as error:
            reason = error.reason if isinstance(error, URLError) else error
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
    manifest = bootstrap({"action": "seed", "token": token})
    manifest.update(
        {
            "origin": ORIGIN,
            "ca_file": str(RUNTIME / "ca.crt"),
            "token_file": str(RUNTIME / "token"),
        }
    )
    private_file("manifest.json", json.dumps(manifest, sort_keys=True) + "\n")
    status, raw = request("/api/status/", token=token)
    if status != 200 or not json.loads(raw).get("netbox-version", "").startswith(
        "4.4.5"
    ):
        raise RuntimeError(
            "NetBox fixture did not report its pinned application version"
        )
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
                "network": "internal; loopback TLS endpoint",
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
    for connection in config["REDIS"].values():
        if (
            not connection["SSL"]
            or connection["INSECURE_SKIP_TLS_VERIFY"]
            or connection["CA_CERT_PATH"] != "/opt/netbox/ci-ca.crt"
            or not connection["URL"].startswith("rediss://")
            or not connection["URL"].endswith("?ssl_check_hostname=True")
        ):
            raise RuntimeError("fixture cache/task configuration lost TLS verification")
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
