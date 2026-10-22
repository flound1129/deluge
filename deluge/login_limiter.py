#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

"""Limit failed logins per client address."""

import ipaddress
import math
import time

# Failed logins a client may make before its first block.
MAX_FAILURES = 5
# The first block in seconds. Each further failure doubles it, up to MAX_DELAY.
BASE_DELAY = 30
MAX_DELAY = 15 * 60
# A client with no failed login for this long starts again from zero.
FORGET_AFTER = 60 * 60
# The most clients tracked at one time, so the table cannot fill memory.
MAX_CLIENTS = 10000


def client_key(host):
    """Return the key a client is tracked by: its IPv4 address or its IPv6 /64.

    One host or user usually has a whole IPv6 /64, so all addresses in it count
    as one client.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return str(host)
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((address, 64), strict=False))
    return str(address)


class LoginLimiter:
    """Block a client address after too many failed logins.

    After MAX_FAILURES failed logins a client is blocked for BASE_DELAY seconds,
    and each further failure blocks it for twice as long, up to MAX_DELAY. The
    caller refuses a login during a block without checking the password. A good
    login resets the count.

    Args:
        clock: Returns the current time in seconds (for tests).
    """

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        # key: [failures, blocked_until, last_failure]
        self._clients = {}

    def check(self, host) -> int:
        """Return the seconds left in the client's block, or 0 if it can log in."""
        now = self._clock()
        entry = self._get(client_key(host), now)
        if entry is None or entry[1] <= now:
            return 0
        return math.ceil(entry[1] - now)

    def failure(self, host) -> None:
        """Record a failed login from the client."""
        now = self._clock()
        key = client_key(host)
        entry = self._get(key, now)
        if entry is None:
            self._make_room(now)
            entry = [0, 0.0, now]
        else:
            # Move it to the end, so the oldest client is evicted first.
            del self._clients[key]
        self._clients[key] = entry
        entry[0] += 1
        entry[2] = now
        if entry[0] >= MAX_FAILURES:
            doublings = min(entry[0] - MAX_FAILURES, 16)
            entry[1] = now + min(BASE_DELAY * 2**doublings, MAX_DELAY)

    def success(self, host) -> None:
        """Record a good login from the client, which resets its count."""
        self._clients.pop(client_key(host), None)

    def _get(self, key, now):
        entry = self._clients.get(key)
        if entry is not None and self._expired(entry, now):
            del self._clients[key]
            return None
        return entry

    @staticmethod
    def _expired(entry, now):
        return entry[1] <= now and now - entry[2] >= FORGET_AFTER

    def _make_room(self, now):
        if len(self._clients) < MAX_CLIENTS:
            return
        for key in [k for k, e in self._clients.items() if self._expired(e, now)]:
            del self._clients[key]
        while len(self._clients) >= MAX_CLIENTS:
            del self._clients[next(iter(self._clients))]
