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
import sys
from datetime import timedelta

import django


def seed(spec):
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
    from ipam.models import IPAddress, VRF
    from tenancy.models import Tenant
    from users.models import ObjectPermission, Token, User

    cache.set("probectl-fixture-tls", "verified", timeout=30)
    if (
        cache.get("probectl-fixture-tls") != "verified"
        or not get_connection("default").ping()
    ):
        raise RuntimeError("fixture cache/task TLS channels are unavailable")
    with transaction.atomic():
        user = User.objects.create(username="probectl-fixture-reader", is_active=True)
        user.set_unusable_password()
        user.save()
        permission = ObjectPermission.objects.create(
            name="probectl fixture read-only", actions=["view"]
        )
        permission.object_types.set(
            ContentType.objects.filter(
                app_label__in=["dcim", "ipam", "tenancy", "virtualization"]
            )
        )
        permission.users.add(user)
        Token.objects.create(
            user=user,
            key=spec["token"],
            write_enabled=False,
            expires=timezone.now() + timedelta(hours=2),
        )
        manufacturer = Manufacturer.objects.create(name="Fixture", slug="fixture")
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer, model="Fixture router", slug="fixture-router"
        )
        result = {"tenants": {}, "devices": {}, "ips": {}}
        for index, lane in enumerate(["a", "b"], start=1):
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
            address = IPAddress.objects.create(
                address="192.0.2.10/32",
                tenant=tenant,
                vrf=vrf,
                assigned_object_type=ContentType.objects.get_for_model(Interface),
                assigned_object_id=interface.pk,
            )
            result["tenants"][lane] = str(tenant.pk)
            result["devices"][lane] = str(device.pk)
            result["ips"][lane] = str(address.pk)
        return result


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")
    django.setup()
    spec = json.load(sys.stdin)
    if spec.get("action") == "seed":
        print(json.dumps(seed(spec)))
    elif spec.get("action") in {"move-ip", "restore-ip"}:
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
