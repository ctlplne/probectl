#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Seed short-lived, digest-pinned LibreNMS and Zabbix CI fixtures.

Only normalized test assertions and image metadata survive in the CI artifact.
Raw vendor exports and one-time credentials remain in an owner-only tmpdir and
are removed by the workflow's unconditional cleanup step.
"""

import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "test/nmsvendor/compose.yml"
RUNTIME = Path("/tmp/probectl-nms-vendor-fixture")
PROJECT = "probectl-nms-vendor-fixture"
LIBRENMS = "http://librenms:8000"
ZABBIX = "http://zabbix-web:8080/api_jsonrpc.php"

# The Compose network has no host interface or outbound gateway. The pinned
# LibreNMS image includes Python 3, so one static bridge reads request data on
# stdin and calls both vendor web servers from inside that network. No token or
# database password is placed in argv, a URL, the workflow log, or an artifact.
CONTAINER_HTTP = r"""
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

spec = json.load(sys.stdin)
headers = {"Accept": "application/json"}
if spec.get("token"):
    headers["Authorization"] = "Bearer " + spec["token"]
body = spec.get("body")
data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
if data is not None:
    headers["Content-Type"] = spec["content_type"]
try:
    with urlopen(Request(spec["url"], data=data, headers=headers), timeout=spec["timeout"]) as response:
        raw = response.read((64 << 20) + 1)
        if len(raw) > 64 << 20:
            sys.exit(2)
        sys.stdout.buffer.write(raw)
except HTTPError as exc:
    print("HTTP " + str(exc.code), file=sys.stderr)
    sys.exit(1)
except (URLError, TimeoutError):
    sys.exit(1)
"""

# Invoke the pinned LibreNMS user command through its Laravel kernel. Its CLI
# --password option would expose the fixture password in the process argv;
# ArrayInput keeps the same command validation while reading the value on stdin.
CREATE_LIBRENMS_USER = r"""
require '/opt/librenms/vendor/autoload.php';
$app = require '/opt/librenms/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$password = stream_get_contents(STDIN, 4096);
if ($password === false || strlen($password) < 20 || strlen($password) > 128) {
    exit(2);
}
$input = new Symfony\Component\Console\Input\ArrayInput([
    'command' => 'user:add',
    'username' => 'fixture-admin',
    '--password' => $password,
    '--role' => ['admin'],
]);
$status = $kernel->handle($input, new Symfony\Component\Console\Output\NullOutput());
$kernel->terminate($input, $status);
exit($status);
"""


def docker(*args: str) -> str:
    command = [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(RUNTIME / ".env"),
        "-f",
        str(COMPOSE),
        *args,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(
            f"vendor Compose {args[0]} failed (exit {result.returncode})"
        )
    return result.stdout


def vendor_http(
    url: str,
    *,
    token: str = "",
    body: dict | None = None,
    content_type: str = "application/json",
    timeout: int = 12,
) -> bytes:
    command = [
        "docker",
        "compose",
        "--project-name",
        PROJECT,
        "--env-file",
        str(RUNTIME / ".env"),
        "-f",
        str(COMPOSE),
        "exec",
        "-T",
        "librenms",
        "python3",
        "-c",
        CONTAINER_HTTP,
    ]
    spec = {
        "url": url,
        "token": token,
        "body": body,
        "content_type": content_type,
        "timeout": timeout,
    }
    result = subprocess.run(
        command, input=json.dumps(spec).encode(), capture_output=True, check=False
    )
    if result.returncode:
        status = result.stderr.decode(errors="replace").strip()
        if not re.fullmatch(r"HTTP [1-5][0-9][0-9]", status):
            status = "unavailable"
        raise RuntimeError(f"vendor API {status}")
    if len(result.stdout) > 64 << 20:
        raise RuntimeError("vendor response exceeds one bounded page")
    return result.stdout


def private_file(path: Path, data: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)


def request_json(
    url: str, *, token: str = "", body: dict | None = None
) -> tuple[dict | list, bytes]:
    raw = vendor_http(url, token=token, body=body)
    return json.loads(raw), raw


def ready(url: str, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    last_error = "unavailable"
    while time.monotonic() < deadline:
        try:
            vendor_http(url, timeout=3)
            return
        except RuntimeError as exc:
            last_error = str(exc)
        time.sleep(3)
    # Compose state and HTTP status are safe to log. Container logs and raw
    # vendor responses may include credentials or configuration, so omit them.
    states = []
    try:
        raw = docker("ps", "--format", "json")
        records = (
            json.loads(raw)
            if raw.lstrip().startswith("[")
            else [json.loads(line) for line in raw.splitlines() if line.strip()]
        )
        if isinstance(records, dict):
            records = [records]
        for item in records:
            states.append(
                f"{item.get('Service', '?')}:{item.get('State', '?')}:"
                f"{item.get('Health', '?')}"
            )
    except (RuntimeError, ValueError, KeyError):
        states.append("status-unavailable")
    raise RuntimeError(
        "vendor web frontend did not become ready; "
        + "container states="
        + ",".join(sorted(states))
        + "; last request="
        + last_error
    )


def seed_librenms() -> dict:
    password = secrets.token_urlsafe(24)
    deadline = time.monotonic() + 180
    while True:
        command = [
            "docker",
            "compose",
            "--project-name",
            PROJECT,
            "--env-file",
            str(RUNTIME / ".env"),
            "-f",
            str(COMPOSE),
            "exec",
            "-T",
            "librenms",
            "php",
            "-r",
            CREATE_LIBRENMS_USER,
        ]
        result = subprocess.run(
            command, input=password.encode(), capture_output=True, check=False
        )
        if result.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("LibreNMS fixture administrator unavailable")
        time.sleep(5)
    output = docker(
        "exec", "-T", "librenms", "lnms", "api:token-create", "fixture-admin"
    )
    match = re.search(r"(?m)^(\d+\|[A-Za-z0-9]+)$", output)
    if not match:
        raise RuntimeError("LibreNMS one-time API token unavailable")
    token = match.group(1)

    def call(path: str, body: dict | None = None) -> tuple[dict | list, bytes]:
        value, raw = request_json(LIBRENMS + path, token=token, body=body)
        if not isinstance(value, dict) or value.get("status") != "ok":
            raise RuntimeError(f"LibreNMS {path} did not return status ok")
        return value, raw

    call("/api/v0/locations", {"location": "Fixture East"})
    locations, _ = call("/api/v0/resources/locations")
    found = [x for x in locations["locations"] if x.get("location") == "Fixture East"]
    if len(found) != 1:
        raise RuntimeError("LibreNMS fixture location was not listed exactly once")
    location_id = str(found[0]["id"])
    device, _ = call(
        "/api/v0/devices",
        {
            "hostname": "192.0.2.40",
            "force_add": True,
            "snmp_disable": True,
            "location_id": location_id,
            "override_sysLocation": True,
        },
    )
    device_id = str(device["devices"][0]["device_id"])
    group, _ = call(
        "/api/v0/devicegroups",
        {
            "name": "Fixture WAN",
            "type": "static",
            "devices": [int(device_id)],
        },
    )
    group_id = str(group["id"])
    call(
        "/api/v0/rules",
        {
            "devices": [int(device_id)],
            "groups": [],
            "locations": [],
            "invert_map": False,
            "name": "Fixture port down",
            "severity": "critical",
            "disabled": 1,
            "alert_operation_id": None,
            "builder": {
                "condition": "AND",
                "rules": [
                    {
                        "id": "ports.ifOperStatus",
                        "field": "ports.ifOperStatus",
                        "type": "string",
                        "input": "text",
                        "operator": "not_equal",
                        "value": "up",
                    }
                ],
                "valid": True,
            },
        },
    )
    paths = {
        "devices": "/api/v0/devices",
        "locations": "/api/v0/resources/locations",
        "groups": "/api/v0/devicegroups",
        "members": "/api/v0/devicegroups/Fixture%20WAN",
        "rules": "/api/v0/rules",
    }
    for name, path in paths.items():
        value, raw = request_json(LIBRENMS + path, token=token)
        if name in ("groups", "members"):
            if (
                not isinstance(value, list)
                or len(value) != 1
                or value[0].get("status") != "ok"
            ):
                raise RuntimeError(f"LibreNMS {name} envelope changed")
        elif not isinstance(value, dict) or value.get("status") != "ok":
            raise RuntimeError(f"LibreNMS {name} envelope changed")
        (RUNTIME / f"librenms-{name}.json").write_bytes(raw)
    return {
        "device_id": device_id,
        "location_id": location_id,
        "group_id": group_id,
        "group_name": "Fixture WAN",
    }


def seed_zabbix() -> dict:
    def call(method: str, params: dict, token: str = ""):
        result = json.loads(
            vendor_http(
                ZABBIX,
                token=token,
                content_type="application/json-rpc",
                body={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            )
        )
        if "error" in result or "result" not in result:
            raise RuntimeError(f"Zabbix {method} returned an API error")
        return result["result"]

    deadline = time.monotonic() + 180
    while True:
        try:
            # This published fixture-image bootstrap credential is used only
            # inside the isolated network and immediately replaced below.
            token = call("user.login", {"username": "Admin", "password": "zabbix"})
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
    admins = call(
        "user.get", {"filter": {"username": "Admin"}, "output": ["userid"]}, token
    )
    if len(admins) != 1:
        raise RuntimeError("Zabbix fixture administrator identity changed")
    rotated_password = secrets.token_urlsafe(32)
    call(
        "user.update",
        {
            "userid": admins[0]["userid"],
            "current_passwd": "zabbix",
            "passwd": rotated_password,
        },
        token,
    )
    token = call("user.login", {"username": "Admin", "password": rotated_password})
    group_id = call("hostgroup.create", {"name": "Fixture WAN"}, token)["groupids"][0]
    host_id = call(
        "host.create",
        {
            "host": "edge-r1",
            "name": "Fixture Edge R1",
            "groups": [{"groupid": group_id}],
            "interfaces": [
                {
                    "type": 2,
                    "main": 1,
                    "useip": 1,
                    "ip": "192.0.2.40",
                    "dns": "",
                    "port": "161",
                    "details": {
                        "version": 2,
                        "bulk": 1,
                        "community": "{$SNMP_COMMUNITY}",
                    },
                }
            ],
        },
        token,
    )["hostids"][0]
    interfaces = call(
        "hostinterface.get", {"hostids": [host_id], "output": ["interfaceid"]}, token
    )
    if len(interfaces) != 1:
        raise RuntimeError("Zabbix fixture host interface unavailable")
    call(
        "item.create",
        {
            "hostid": host_id,
            "interfaceid": interfaces[0]["interfaceid"],
            "name": "Fixture ifOperStatus",
            "key_": "ifOperStatus.1",
            "type": 20,
            "value_type": 3,
            "snmp_oid": "1.3.6.1.2.1.2.2.1.8.1",
            "delay": "15s",
        },
        token,
    )
    call(
        "trigger.create",
        {
            "description": "Fixture interface down",
            "expression": "last(/edge-r1/ifOperStatus.1)=2",
            "priority": 4,
            "status": 1,
        },
        token,
    )
    exported = call(
        "configuration.export",
        {
            "format": "json",
            "options": {"hosts": [host_id], "host_groups": [group_id]},
        },
        token,
    )
    value = json.loads(exported)
    if len(value.get("zabbix_export", {}).get("hosts", [])) != 1:
        raise RuntimeError("Zabbix exported host count changed")
    (RUNTIME / "zabbix-hosts.json").write_text(exported, encoding="utf-8")
    return {"host_key": "edge-r1", "group_name": "Fixture WAN"}


def image_receipt() -> list[dict]:
    images = [
        "librenms/librenms:26.10.2@sha256:66f586a84355b6c80758e373aaa7c0b230284d1d22588b29b3706540041e2806",
        "zabbix/zabbix-server-pgsql:7.4.16-alpine@sha256:546f7cae8f04b287ab4ffd3cc81193f2ea99f2da1d0564217b65d93438f44454",
        "zabbix/zabbix-web-nginx-pgsql:7.4.16-alpine@sha256:62ffffb395b9ecd63e9260263dcd9bb4038668fd691e0be1e396bc0182bf77ba",
        "postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94",
        "mariadb:11.8.3@sha256:ae6119716edac6998ae85508431b3d2e666530ddf4e94c61a10710caec9b0f71",
    ]
    receipts = []
    for image in images:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=True,
        )
        actual = json.loads(result.stdout)[0]
        receipts.append(
            {
                "reference": image,
                "image_id": actual["Id"],
                "os": actual["Os"],
                "architecture": actual["Architecture"],
            }
        )
    return receipts


def start() -> None:
    if RUNTIME.exists():
        raise RuntimeError("owned vendor fixture directory already exists")
    RUNTIME.mkdir(mode=0o700)
    private_file(
        RUNTIME / ".env",
        "LIBRENMS_DB_ROOT_PASSWORD="
        + secrets.token_hex(24)
        + "\nLIBRENMS_DB_PASSWORD="
        + secrets.token_hex(24)
        + "\nZABBIX_DB_PASSWORD="
        + secrets.token_hex(24)
        + "\n",
    )
    docker("config", "--quiet")
    docker("pull")
    # Record the actual pulled binaries before the first vendor process starts.
    private_file(
        RUNTIME / "receipt.json",
        json.dumps(
            {
                "fixture": PROJECT,
                "source": "live vendor containers",
                "images": image_receipt(),
                "licenses": {
                    "librenms": "GPL-3.0-or-later with listed exceptions; Docker packaging MIT",
                    "zabbix": "AGPL-3.0-or-later",
                },
            },
            sort_keys=True,
            indent=2,
        )
        + "\n",
    )
    docker("up", "-d", "--no-build")
    ready(LIBRENMS + "/login", 300)
    ready("http://zabbix-web:8080/", 300)
    sources = {"librenms": seed_librenms(), "zabbix": seed_zabbix()}
    private_file(RUNTIME / "manifest.json", json.dumps(sources, sort_keys=True) + "\n")
    print("Live LibreNMS and Zabbix export fixtures are ready")


def cleanup() -> None:
    try:
        if (RUNTIME / ".env").exists():
            docker("down", "--volumes", "--remove-orphans")
    finally:
        shutil.rmtree(RUNTIME, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "cleanup"}:
        raise SystemExit("usage: ci_nms_vendor.py start|cleanup")
    if sys.argv[1] == "start":
        start()
    else:
        cleanup()
