# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Run inside the disposable NetBox application; never against a remote source.

Bootstrap administration uses the local ORM. The API credential given to
probectl belongs to a normal user, is view-only, and expires after two hours.
Input arrives on stdin; output contains only nonsecret fixture identifiers.
"""

import json
import os
import pwd
import ssl
import sys
from datetime import timedelta

import django

BOOTSTRAP_STAGE = "django_setup"


def worker_tls_proof():
    global BOOTSTRAP_STAGE
    from django.db import connection

    BOOTSTRAP_STAGE = "worker_identity"
    if (
        os.geteuid() == 0
        or os.geteuid() != pwd.getpwnam("unit").pw_uid
        or os.getegid() != 0
    ):
        raise RuntimeError("database proof must use the exact nonroot worker identity")
    parameters = connection.get_connection_params()
    parameters["connect_timeout"] = 8
    if (
        parameters.get("sslmode") != "verify-full"
        or parameters.get("sslrootcert") != "/opt/netbox/ci-ca.crt"
        or parameters.get("sslcert") != "/opt/netbox/ci-no-client-cert.pem"
        or os.path.lexists(parameters["sslcert"])
    ):
        raise RuntimeError(
            "worker database configuration lost its explicit TLS profile"
        )

    def refuse_profile(candidate):
        try:
            with connection.Database.connect(**candidate):
                raise RuntimeError("inaccessible client profile was accepted")
        except connection.Database.OperationalError as error:
            # Never emit driver text, which can contain credentials or SQL.
            if "could not open certificate file" not in str(
                error
            ) or "Permission denied" not in str(error):
                raise RuntimeError(
                    "worker client-profile refusal did not reproduce"
                ) from None

    # This exec shares the web UID/GID, but is a separate process with its own
    # inherited environment. Observe its defaults without treating them as the
    # original protected HTTP request's profile.
    BOOTSTRAP_STAGE = "worker_db_default"
    implicit = {key: value for key, value in parameters.items() if key != "sslcert"}
    try:
        with connection.Database.connect(**implicit):
            default_outcome = "connected"
    except connection.Database.OperationalError as error:
        default_outcome = (
            "certificate_permission_refused"
            if "could not open certificate file" in str(error)
            and "Permission denied" in str(error)
            else "other_operational_error"
        )
    BOOTSTRAP_STAGE = "worker_db_negative"
    denied = {**parameters, "sslcert": "/opt/netbox/ci-blocked-profile/client.crt"}
    refuse_profile(denied)
    BOOTSTRAP_STAGE = "worker_db_positive"
    with connection.Database.connect(**parameters) as connected:
        with connected.cursor() as cursor:
            cursor.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            if cursor.fetchone() != (True,):
                raise RuntimeError("worker database connection did not use TLS")
    return {
        "default_profile_outcome": default_outcome,
        "denied_profile_reproduced": True,
        "verified_worker_database": True,
    }


def seed(spec):
    global BOOTSTRAP_STAGE
    BOOTSTRAP_STAGE = "models"
    from django.core.cache import cache
    from django_rq import get_connection
    from django.contrib.contenttypes.models import ContentType
    from django.db import transaction
    from django.utils import timezone
    from dcim.models import (
        Device,
        DeviceRole,
        DeviceType,
        Interface,
        Manufacturer,
        Site,
    )
    from ipam.models import IPAddress, Prefix, Role, VRF
    from tenancy.models import Tenant
    from users.models import ObjectPermission, Token, User

    BOOTSTRAP_STAGE = "cache_tls"
    cache.set("probectl-fixture-tls", "verified", timeout=30)
    if cache.get("probectl-fixture-tls") != "verified":
        raise RuntimeError("fixture cache TLS channel is unavailable")
    BOOTSTRAP_STAGE = "task_tls"
    task = get_connection("default")
    options = task.connection_pool.connection_kwargs
    effective = task.connection_pool.connection_class(**options)
    if (
        effective.host != "netbox-cache"
        or effective.password != os.environ["CACHE_PASSWORD"]
        or effective.cert_reqs != ssl.CERT_REQUIRED
        or effective.ca_certs != "/opt/netbox/ci-ca.crt"
        or effective.check_hostname is not True
        or effective.ssl_min_version != ssl.TLSVersion.TLSv1_2
    ):
        raise RuntimeError(
            "fixture task connection lost authentication or verified TLS"
        )
    effective.disconnect()
    if not task.ping():
        raise RuntimeError("fixture task TLS channel is unavailable")
    with transaction.atomic():
        BOOTSTRAP_STAGE = "reader_user"
        user = User.objects.create(username="probectl-fixture-reader", is_active=True)
        user.set_unusable_password()
        user.save()
        BOOTSTRAP_STAGE = "read_permission"
        permission = ObjectPermission.objects.create(
            name="probectl fixture read-only", actions=["view"]
        )
        permission.object_types.set(
            ContentType.objects.filter(
                app_label__in=["dcim", "ipam", "tenancy", "virtualization"]
            )
        )
        permission.users.add(user)
        BOOTSTRAP_STAGE = "read_token"
        Token.objects.create(
            user=user,
            key=spec["token"],
            write_enabled=False,
            expires=timezone.now() + timedelta(hours=2),
        )
        BOOTSTRAP_STAGE = "device_type"
        manufacturer = Manufacturer.objects.create(name="Fixture", slug="fixture")
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer, model="Fixture router", slug="fixture-router"
        )
        result = {
            "tenants": {},
            "devices": {},
            "roles": {},
            "sites": {},
            "ips": {},
            "prefixes": {},
            "prefixes_v6": {},
            "prefix_alternates": {},
            "prefix_vrfs": {},
            "prefix_next_vrfs": {},
        }
        for index, lane in enumerate(["a", "b"], start=1):
            BOOTSTRAP_STAGE = "source_tenants"
            tenant = Tenant.objects.create(
                name="Fixture " + lane, slug="fixture-" + lane
            )
            site = Site.objects.create(
                name="site-" + lane, slug="site-" + lane, tenant=tenant
            )
            role = DeviceRole.objects.create(name="role-" + lane, slug="role-" + lane)
            device = Device.objects.create(
                name="shared-edge",
                site=site,
                role=role,
                device_type=device_type,
                tenant=tenant,
            )
            interface = Interface.objects.create(
                device=device, name="eth0", type="1000base-t"
            )
            vrf = VRF.objects.create(
                name="shared-vrf",
                rd=f"64512:{index}",
                tenant=tenant,
                enforce_unique=True,
            )
            BOOTSTRAP_STAGE = "source_addresses"
            address = IPAddress.objects.create(
                address="192.0.2.10/32",
                tenant=tenant,
                vrf=vrf,
                assigned_object_type=ContentType.objects.get_for_model(Interface),
                assigned_object_id=interface.pk,
            )
            BOOTSTRAP_STAGE = "source_prefixes"
            ipam_role = Role.objects.create(
                name="ipam-role-" + lane, slug="ipam-role-" + lane
            )
            prefix = Prefix.objects.create(
                prefix="192.0.2.0/24",
                tenant=tenant,
                vrf=vrf,
                role=ipam_role,
                scope_type=ContentType.objects.get_for_model(Site),
                scope_id=site.pk,
            )
            ipv6 = Prefix.objects.create(
                prefix="2001:db8::/32",
                tenant=tenant,
                vrf=vrf,
                role=ipam_role,
                scope_type=ContentType.objects.get_for_model(Site),
                scope_id=site.pk,
            )
            if lane == "a":
                alternate = VRF.objects.create(
                    name="overlapping-vrf",
                    rd="64512:101",
                    tenant=tenant,
                    enforce_unique=True,
                )
                other = Prefix.objects.create(
                    prefix="192.0.2.0/24",
                    tenant=tenant,
                    vrf=alternate,
                    role=ipam_role,
                    scope_type=ContentType.objects.get_for_model(Site),
                    scope_id=site.pk,
                )
                result["prefix_alternates"][lane] = str(other.pk)
            next_vrf = VRF.objects.create(
                name="review-next-vrf-" + lane,
                rd=f"64512:{index + 200}",
                tenant=tenant,
                enforce_unique=True,
            )
            result["prefix_vrfs"][lane] = str(vrf.pk)
            result["prefix_next_vrfs"][lane] = str(next_vrf.pk)
            result["prefixes"][lane] = str(prefix.pk)
            result["prefixes_v6"][lane] = str(ipv6.pk)
            result["tenants"][lane] = str(tenant.pk)
            result["devices"][lane] = str(device.pk)
            result["roles"][lane] = str(role.pk)
            result["sites"][lane] = str(site.pk)
            result["ips"][lane] = str(address.pk)
        return result


def main():
    global BOOTSTRAP_STAGE
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    django.setup()
    BOOTSTRAP_STAGE = "input"
    spec = json.load(sys.stdin)
    if spec.get("action") == "seed":
        print(json.dumps(seed(spec)))
    elif spec.get("action") == "worker-tls-proof":
        print(json.dumps(worker_tls_proof()))
    elif spec.get("action") == "prefix-vrf":
        BOOTSTRAP_STAGE = "prefix_metadata_update"
        from django.db import transaction
        from ipam.models import Prefix, VRF

        with transaction.atomic():
            prefix = Prefix.objects.select_for_update().get(pk=spec["prefix_id"])
            vrf = VRF.objects.get(pk=spec["vrf_id"])
            if (
                str(prefix.tenant_id) != spec["tenant_id"]
                or vrf.tenant_id != prefix.tenant_id
            ):
                raise RuntimeError("fixture prefix metadata crossed tenant ownership")
            prefix.vrf = vrf
            prefix.full_clean()
            prefix.save()
        print(json.dumps({"updated": True}))
    elif spec.get("action") in {"move-ip", "restore-ip"}:
        BOOTSTRAP_STAGE = "ownership_move"
        from django.db import transaction
        from ipam.models import IPAddress

        with transaction.atomic():
            address = IPAddress.objects.select_for_update().get(pk=spec["ip_id"])
            current = str(address.tenant_id)
            restoring = spec["action"] == "restore-ip"
            if current != spec["from_tenant"] and not (
                restoring and current == spec["to_tenant"]
            ):
                raise RuntimeError("fixture ownership changed before mutation")
            address.tenant_id = spec["to_tenant"]
            address.save()
        print(json.dumps({"moved": True}))
    else:
        raise RuntimeError("unsupported fixture action")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never expose exception text, traceback, SQL, input, URL or credential.
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
        }
        category = type(error).__name__
        if category not in classes:
            category = "other"
        print(
            "PROBECTL_NETBOX_BOOTSTRAP_FAILURE "
            + json.dumps(
                {
                    "stage": BOOTSTRAP_STAGE,
                    "error_class": category,
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None
