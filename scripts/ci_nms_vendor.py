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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "test/nmsvendor/compose.yml"
RUNTIME = Path("/tmp/probectl-nms-vendor-fixture")
PROJECT = "probectl-nms-vendor-fixture"
LIBRENMS = "http://127.0.0.1:18880"
ZABBIX = "http://127.0.0.1:18881/api_jsonrpc.php"


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


def private_file(path: Path, data: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)


def request_json(
    url: str, *, token: str = "", body: dict | None = None
) -> tuple[dict | list, bytes]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode()
    request = Request(url, data=data, headers=headers)
    try:
        with urlopen(request, timeout=12) as response:
            raw = response.read(64 << 20)
            if response.read(1):
                raise RuntimeError("vendor response exceeds one bounded page")
    except HTTPError as exc:
        raise RuntimeError(f"vendor API returned HTTP {exc.code}") from None
    except URLError as exc:
        raise RuntimeError("vendor API unavailable") from exc
    return json.loads(raw), raw


def ready(url: str, seconds: int) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return
        except (HTTPError, URLError, TimeoutError):
            pass
        time.sleep(3)
    raise RuntimeError("vendor web frontend did not become ready")


def seed_librenms() -> dict:
    password = secrets.token_urlsafe(24)
    deadline = time.monotonic() + 180
    while True:
        try:
            docker(
                "exec",
                "-T",
                "librenms",
                "lnms",
                "user:add",
                "fixture-admin",
                "--password",
                password,
                "--role",
                "admin",
            )
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
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
        headers = {"Content-Type": "application/json-rpc", "Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(
            ZABBIX,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": 1,
                }
            ).encode(),
            headers=headers,
        )
        try:
            with urlopen(request, timeout=12) as response:
                result = json.load(response)
        except (HTTPError, URLError) as exc:
            raise RuntimeError(f"Zabbix {method} unavailable") from exc
        if "error" in result or "result" not in result:
            raise RuntimeError(f"Zabbix {method} returned an API error")
        return result["result"]

    deadline = time.monotonic() + 180
    while True:
        try:
            # The vendor image's isolated bootstrap credential is used once.
            # It is never put in an export, artifact, log, or product config.
            token = call("user.login", {"username": "Admin", "password": "zabbix"})
            break
        except RuntimeError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
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
    ready("http://127.0.0.1:18881/", 300)
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
