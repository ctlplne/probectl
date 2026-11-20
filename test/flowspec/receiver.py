#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Check one documented prefix on a pinned receiver in an internal network."""

from contextlib import ExitStack
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid

IMAGE = 'quay.io/frrouting/frr:10.7.1@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2'
PREFIX = '192.0.2.0/24'
PORT = 18443
ASN = 64520
FAMILY = struct.pack('!HB', 1, 133)
MARKER = bytes([255]) * 16


def fixture_route():
    input_data = json.loads(sys.stdin.buffer.read(2049))
    if not isinstance(input_data, dict) or set(input_data) - {'template', 'expires_at'}:
        raise ValueError('Unexpected fixture authorization.')
    expires = input_data.get('expires_at')
    if expires:
        expiry = datetime.fromisoformat(expires.replace('Z', '+00:00')).timestamp()
        if not 0 < expiry - datetime.now(timezone.utc).timestamp() <= 45:
            raise ValueError('The fixture requires a short-lived authorization.')
    else:
        expiry = None
    template = input_data['template']
    expected = {
        'afi': 1, 'safi': 133, 'action': 'discard',
        'components': [
            {'type': 1, 'field': 'destination_prefix', 'value': PREFIX},
            {'type': 3, 'field': 'ip_protocol', 'value': '6'},
            {'type': 5, 'field': 'destination_port', 'value': str(PORT)},
        ],
    }
    if template != expected:
        raise ValueError('The fixture accepts only its fixed documentation-prefix template.')
    prefix = ipaddress.IPv4Network(template['components'][0]['value'])
    destination = bytes((1, prefix.prefixlen)) + prefix.network_address.packed[:3]
    protocol = bytes((3, 0x81, int(template['components'][1]['value'])))
    port = bytes((5, 0x91)) + struct.pack('!H', int(template['components'][2]['value']))
    components = destination + protocol + port
    return bytes((len(components),)) + components, expiry


def docker(*args, check=True):
    return subprocess.run(
        ('docker', *args), capture_output=True, text=True, check=check, timeout=40,
    )


def wait_for(description, poll, timeout=25):
    finish = time.monotonic() + timeout
    while time.monotonic() < finish:
        result = poll()
        if result:
            return result
        time.sleep(0.25)
    raise RuntimeError('Timed out waiting for ' + description)


def address(container, network):
    result = docker(
        'inspect', container, '--format',
        '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}',
    )
    return str(ipaddress.IPv4Address(result.stdout.strip()))


def frame(kind, payload=b''):
    return MARKER + struct.pack('!HB', 19 + len(payload), kind) + payload


def attr(flags, kind, value):
    return bytes((flags, kind, len(value))) + value


def update(route, withdraw):
    if withdraw:
        attributes = attr(0x80, 15, FAMILY + route)
    else:
        attributes = (
            attr(0x40, 1, bytes(1))
            + attr(0x40, 2, b'')
            + attr(0x40, 5, struct.pack('!I', 100))
            + attr(0x80, 14, FAMILY + bytes(2) + route)
            + attr(0xc0, 16, bytes((0x80, 6)) + bytes(6))
        )
    return frame(2, struct.pack('!HH', 0, len(attributes)) + attributes)


def read_exact(fd, size):
    data = bytearray()
    finish = time.monotonic() + 15
    while len(data) < size:
        remaining = finish - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise RuntimeError('Owned peer timed out before the expected BGP message.')
        chunk = os.read(fd, size - len(data))
        if not chunk:
            raise RuntimeError('Owned peer closed before the expected BGP message.')
        data.extend(chunk)
    return bytes(data)


def read_frame(proc):
    fd = proc.stdout.fileno()
    header = read_exact(fd, 19)
    length, kind = struct.unpack('!HB', header[16:])
    if header[:16] != MARKER or length < 19 or length > 4096:
        raise RuntimeError('Unexpected frame in the isolated BGP fixture.')
    return kind, read_exact(fd, length - 19)


def send(proc, payload):
    proc.stdin.write(payload)
    proc.stdin.flush()


def configure(receiver, sender_ip, directory):
    files = {
        'daemons': (
            'zebra=yes\nbgpd=yes\nvtysh_enable=yes\n'
            'zebra_options="-A 127.0.0.1"\nbgpd_options="-A 127.0.0.1"\n'
        ),
        'vtysh.conf': 'service integrated-vtysh-config\n',
        'frr.conf': f"""frr defaults traditional
hostname flowspec-receiver
!
router bgp {ASN}
 bgp router-id 192.0.2.1
 no bgp default ipv4-unicast
 neighbor {sender_ip} remote-as {ASN}
 neighbor {sender_ip} passive
 address-family ipv4 flowspec
  neighbor {sender_ip} activate
 exit-address-family
!
""",
    }
    for name, contents in files.items():
        path = directory / name
        path.write_text(contents)
        docker('cp', str(path), receiver + ':/etc/frr/' + name)


def check_session(proc, router, neighbor, route, expiry):
    capability = bytes((1, 4, 0, 1, 0, 133))
    options = bytes((2, len(capability))) + capability
    opening = struct.pack('!BHH4sB', 4, ASN, 90, bytes((192, 0, 2, 2)), len(options))
    send(proc, frame(1, opening + options))
    kind, data = read_frame(proc)
    if kind != 1 or len(data) < 10 or data[0] != 4:
        raise RuntimeError('FRRouting did not send the expected OPEN.')
    send(proc, frame(4))
    if read_frame(proc) != (4, b''):
        raise RuntimeError('FRRouting did not send the expected KEEPALIVE.')
    if expiry is not None and expiry <= time.time():
        raise RuntimeError('Authorization expired before the fixture announced the template.')
    send(proc, update(route, withdraw=False))

    def present():
        table = router('show bgp ipv4 flowspec detail')
        expected = (
            'Destination Address ' + PREFIX,
            'IP Protocol = 6',
            'Destination Port = ' + str(PORT),
            'FS:rate 0.000000',
            'Displayed 1 flowspec entries',
        )
        return table if all(line in table for line in expected) else None

    print(wait_for('the exact template in the receiver RIB', present), flush=True)
    if expiry is not None:
        while time.time() < expiry:
            time.sleep(min(0.25, max(0, expiry - time.time())))
        print('The recorded authorization reached its expiry.', flush=True)
    send(proc, update(route, withdraw=True))
    wait_for('withdrawal of the exact template', lambda: PREFIX not in router('show bgp ipv4 flowspec detail'))
    if 'BGP state = Established' not in neighbor():
        raise RuntimeError('An established session is required to prove withdrawal.')
    print('FRRouting accepted and withdrew the exact template with the session still up.', flush=True)


def run(route, expiry):
    base = 'probectl-qa-beta-flowspec-rib-' + uuid.uuid4().hex[:10]
    network, receiver, sender = base + '-net', base + '-receiver', base + '-sender'
    with ExitStack() as stack:
        docker('network', 'create', '--internal', network)
        stack.callback(docker, 'network', 'rm', network, check=False)
        docker('create', '--pull=never', '--name', sender, '--network', network,
               '--entrypoint', '/bin/sh', IMAGE, '-c', 'sleep 180')
        stack.callback(docker, 'rm', '-f', sender, check=False)
        docker('start', sender)
        sender_ip = address(sender, network)
        docker('create', '--pull=never', '--name', receiver, '--network', network,
               '--cap-add', 'NET_ADMIN', '--cap-add', 'SYS_ADMIN', '--ulimit', 'nofile=4096:4096', IMAGE)
        stack.callback(docker, 'rm', '-f', receiver, check=False)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=base + '-')))
        configure(receiver, sender_ip, directory)
        docker('start', receiver)
        receiver_ip = address(receiver, network)

        def router(command):
            return docker('exec', receiver, 'vtysh', '-c', command).stdout

        def neighbor():
            return router('show bgp neighbors ' + sender_ip)

        def active():
            try:
                return 'BGP state = Active (passive)' in neighbor()
            except subprocess.CalledProcessError:
                return False

        try:
            wait_for('passive BGP neighbor readiness', active)
            proc = subprocess.Popen(
                ('docker', 'exec', '-i', sender, 'nc', receiver_ip, '179'),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            with proc:
                try:
                    check_session(proc, router, neighbor, route, expiry)
                finally:
                    proc.stdin.close()
                    try:
                        proc.wait(timeout=6)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=6)
        except Exception:
            log = docker('logs', '--tail', '25', receiver, check=False)
            print(log.stdout + log.stderr, file=sys.stderr, flush=True)
            raise


def stop(_signum, _frame):
    raise SystemExit('The isolated receiver test was stopped.')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    run(*fixture_route())
