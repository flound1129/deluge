#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import pytest

from deluge import login_limiter
from deluge.login_limiter import (
    BASE_DELAY,
    FORGET_AFTER,
    MAX_DELAY,
    MAX_FAILURES,
    LoginLimiter,
    client_key,
)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def limiter(clock):
    return LoginLimiter(clock=clock)


def fail(limiter, host, times):
    for _ in range(times):
        limiter.failure(host)


def test_failures_below_limit_are_allowed(limiter):
    fail(limiter, '192.0.2.1', MAX_FAILURES - 1)
    assert limiter.check('192.0.2.1') == 0


def test_block_after_limit(limiter, clock):
    fail(limiter, '192.0.2.1', MAX_FAILURES)
    assert limiter.check('192.0.2.1') == BASE_DELAY
    assert limiter.check('192.0.2.2') == 0
    clock.now += BASE_DELAY
    assert limiter.check('192.0.2.1') == 0


def test_block_doubles_up_to_max(limiter, clock):
    fail(limiter, '192.0.2.1', MAX_FAILURES)
    delays = []
    for _ in range(10):
        delay = limiter.check('192.0.2.1')
        delays.append(delay)
        clock.now += delay
        limiter.failure('192.0.2.1')
    assert delays[:3] == [BASE_DELAY, BASE_DELAY * 2, BASE_DELAY * 4]
    assert delays[-1] == MAX_DELAY
    assert max(delays) == MAX_DELAY


def test_success_resets_count(limiter):
    fail(limiter, '192.0.2.1', MAX_FAILURES - 1)
    limiter.success('192.0.2.1')
    fail(limiter, '192.0.2.1', MAX_FAILURES - 1)
    assert limiter.check('192.0.2.1') == 0


def test_count_forgotten_after_quiet_period(limiter, clock):
    fail(limiter, '192.0.2.1', MAX_FAILURES - 1)
    clock.now += FORGET_AFTER
    limiter.failure('192.0.2.1')
    assert limiter.check('192.0.2.1') == 0


def test_ipv6_counted_per_64(limiter):
    for i in range(MAX_FAILURES):
        limiter.failure(f'2001:db8:1:2::{i + 1}')
    assert limiter.check('2001:db8:1:2:ffff::1') == BASE_DELAY
    assert limiter.check('2001:db8:1:3::1') == 0


def test_client_key():
    assert client_key('::ffff:192.0.2.1') == '192.0.2.1'
    assert client_key('192.0.2.1') == '192.0.2.1'
    assert client_key('2001:db8::1') == '2001:db8::/64'
    assert client_key(None) == 'None'


def test_tracked_clients_are_capped(limiter, monkeypatch):
    monkeypatch.setattr(login_limiter, 'MAX_CLIENTS', 3)
    for i in range(10):
        limiter.failure(f'192.0.2.{i}')
    assert len(limiter._clients) == 3
