# SPDX-License-Identifier: BUSL-1.1
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Fixture-only extension of NetBox's settings; task credentials stay off URLs."""

import ssl

from netbox.settings import *  # noqa: F403

# django-rq3.1's URL branch drops PASSWORD and REDIS_CLIENT_KWARGS. Its
# host/port branch forwards both. Make hostname/minimum verification explicit
# for every task client, independent of the installed redis-py defaults.
for _queue in RQ_QUEUES.values():  # noqa: F405
    if (
        "URL" in _queue
        or _queue.get("HOST") != "netbox-cache"
        or _queue.get("PORT") != 6379
        or not _queue.get("PASSWORD")
        or _queue.get("SSL") is not True
        or _queue.get("SSL_CERT_REQS") != "required"
        or _queue.get("REDIS_CLIENT_KWARGS", {}).get("ssl_ca_certs")
        != "/opt/netbox/ci-ca.crt"
    ):
        raise RuntimeError(
            "fixture task parameters lost authentication or verified TLS"
        )
    _queue["REDIS_CLIENT_KWARGS"] = {
        **_queue["REDIS_CLIENT_KWARGS"],
        "ssl_check_hostname": True,
        "ssl_min_version": ssl.TLSVersion.TLSv1_2,
    }
