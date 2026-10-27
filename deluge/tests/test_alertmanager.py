#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#
import gc
import sys
from dataclasses import dataclass

import pytest
from twisted.internet import defer, reactor, task

from deluge import configmanager
from deluge.core import alertmanager
from deluge.core.core import Core


class LtSessionMock:
    def __init__(self):
        self.alerts = []

    def push_alerts(self, alerts):
        self.alerts.extend(alerts)

    def wait_for_alert(self, timeout):
        return self.alerts[0] if len(self.alerts) > 0 else None

    def pop_alerts(self):
        alerts = self.alerts
        self.alerts = []
        return alerts


class ManualDelayedCall:
    def __init__(self, delay, function, args, kwargs):
        self.delay = delay
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.called = False
        self.cancelled = False

    def active(self):
        return not self.called and not self.cancelled

    def cancel(self):
        self.cancelled = True

    def run(self):
        self.called = True
        self.function(*self.args, **self.kwargs)


class ManualReactor:
    """Small callLater scheduler that advances one reactor turn at a time."""

    def __init__(self):
        self.calls = []

    def callLater(self, delay, function, *args, **kwargs):  # NOQA: N802
        call = ManualDelayedCall(delay, function, args, kwargs)
        self.calls.append(call)
        return call

    def callFromThread(self, function, *args, **kwargs):  # NOQA: N802
        function(*args, **kwargs)

    def active_calls(self, delay=None):
        return [
            call
            for call in self.calls
            if call.active() and (delay is None or call.delay == delay)
        ]

    def run_next(self, delay=0):
        call = self.active_calls(delay)[0]
        call.run()


@dataclass
class LtAlertMock:
    type: int
    name: str
    message: str

    def message(self):
        return self.message

    def what(self):
        return self.name


@pytest.fixture
def mock_alert1():
    return LtAlertMock(type=1, name='mock_alert1', message='Alert 1')


@pytest.fixture
def mock_alert2():
    return LtAlertMock(type=2, name='mock_alert2', message='Alert 2')


class TestAlertManager:
    @pytest.fixture
    def free_core(self):
        yield
        # set_up requests this before component, so it runs after the component
        # fixture shuts the Core down. Free the Core and its libtorrent session
        # (about 110 fds) now. Otherwise a later GC frees them at a random point
        # in another test, which can break the fd list Twisted uses to spawn the
        # test daemon (macOS). Until then the Core is held by the alert-poller
        # thread (until it sees the stop), by the core.conf callbacks and by its
        # own reference cycles.
        alert_thread = self.am._thread
        del self.am
        del self.core
        alert_thread.join(timeout=5)
        configmanager.close('core.conf')
        gc.collect()

    @pytest.fixture(autouse=True)
    def set_up(self, free_core, component):
        self.core = Core()
        self.core.config.config['lsd'] = False
        self.am = component.get('AlertManager')
        self.am.session = LtSessionMock()

        component.start(['AlertManager'])

    def test_register_handler(self):
        def handler(alert): ...

        self.am.register_handler('dummy1', handler)
        self.am.register_handler('dummy2_alert', handler)
        assert self.am.handlers['dummy1'] == [handler]
        assert self.am.handlers['dummy2'] == [handler]

    def test_alert_queue_uses_native_default_bound(self):
        assert self.am.alert_queue_size == 2000

    def test_alert_burst_is_processed_under_per_turn_budget(self, monkeypatch):
        manual_reactor = ManualReactor()
        monkeypatch.setattr(alertmanager, 'reactor', manual_reactor)
        self.am._event.clear()

        handled = []
        self.am.register_handler('burst', lambda alert: handled.append(alert.type))
        alerts = [
            LtAlertMock(type=i, name='burst', message='burst') for i in range(250)
        ]
        self.am.session.push_alerts(alerts)

        self.am.handle_alerts()

        assert handled == []
        assert 0 < len(self.am.delayed_calls) <= self.am.alert_work_per_turn

        while manual_reactor.active_calls(delay=0):
            handled_before_turn = len(handled)
            manual_reactor.run_next()
            assert len(handled) - handled_before_turn <= self.am.alert_work_per_turn

        assert handled == list(range(250))

    def test_new_burst_stays_native_until_existing_drain_finishes(self, monkeypatch):
        manual_reactor = ManualReactor()
        monkeypatch.setattr(alertmanager, 'reactor', manual_reactor)
        self.am._event.clear()

        handled = []
        self.am.register_handler('burst', lambda alert: handled.append(alert.type))
        first_burst = [
            LtAlertMock(type=i, name='burst', message='burst') for i in range(120)
        ]
        second_burst = [
            LtAlertMock(type=i, name='burst', message='burst') for i in range(120, 240)
        ]

        self.am.session.push_alerts(first_burst)
        self.am.handle_alerts()
        scheduled_calls = len(manual_reactor.active_calls(delay=0))
        self.am.session.push_alerts(second_burst)
        self.am.handle_alerts()

        assert len(manual_reactor.active_calls(delay=0)) == scheduled_calls
        assert self.am.session.alerts == second_burst
        while manual_reactor.active_calls(delay=0):
            manual_reactor.run_next()

        assert handled == list(range(120))
        self.am.handle_alerts()
        while manual_reactor.active_calls(delay=0):
            manual_reactor.run_next()

        assert handled == list(range(240))

    def test_repeated_bursts_do_not_expand_pending_queue_when_handlers_stall(
        self, monkeypatch
    ):
        manual_reactor = ManualReactor()
        monkeypatch.setattr(alertmanager, 'reactor', manual_reactor)
        self.am._event.clear()
        self.am.max_pending_alerts = 6
        self.am.alert_work_per_turn = 4
        self.am.max_pending_handlers = 2

        handler_results = []

        def handler(alert):
            result = defer.Deferred()
            handler_results.append(result)
            return result

        self.am.register_handler('burst', handler)
        self.am.session.push_alerts(
            [LtAlertMock(type=i, name='burst', message='burst') for i in range(6)]
        )
        self.am.handle_alerts()

        pending_after_first_burst = len(self.am._pending_alerts)
        for first_type in (6, 8, 10):
            self.am.session.push_alerts(
                [
                    LtAlertMock(type=i, name='burst', message='burst')
                    for i in range(first_type, first_type + 2)
                ]
            )
            self.am.handle_alerts()

        while manual_reactor.active_calls(delay=0):
            manual_reactor.run_next()

        assert len(self.am._pending_alerts) == pending_after_first_burst
        assert len(self.am._pending_alerts) <= self.am.max_pending_alerts
        assert len(self.am.delayed_calls) == self.am.max_pending_handlers
        assert [alert.type for alert in self.am.session.alerts] == list(range(6, 12))

        self.am.handle_alerts()
        assert [alert.type for alert in self.am.session.alerts] == list(range(6, 12))

    def test_oversized_native_batch_keeps_oldest_alerts(self, monkeypatch):
        manual_reactor = ManualReactor()
        monkeypatch.setattr(alertmanager, 'reactor', manual_reactor)
        self.am._event.clear()
        self.am.max_pending_alerts = 3
        warnings = []
        monkeypatch.setattr(
            alertmanager.log,
            'warning',
            lambda message, *args: warnings.append(message % args),
        )

        handled = []
        self.am.register_handler('burst', lambda alert: handled.append(alert.type))
        self.am.session.push_alerts(
            [LtAlertMock(type=i, name='burst', message='burst') for i in range(5)]
        )

        self.am.handle_alerts()
        while manual_reactor.active_calls(delay=0):
            manual_reactor.run_next()

        assert handled == [0, 1, 2]
        assert warnings == ['Dropping 2 newest alerts from oversized native batch']

    def test_unresolved_handlers_apply_backpressure(self, monkeypatch):
        manual_reactor = ManualReactor()
        monkeypatch.setattr(alertmanager, 'reactor', manual_reactor)
        self.am._event.clear()

        handler_results = []

        def handler(alert):
            result = defer.Deferred()
            handler_results.append(result)
            return result

        self.am.register_handler('burst', handler)
        alert_count = self.am.max_pending_handlers + 50
        self.am.session.push_alerts(
            [
                LtAlertMock(type=i, name='burst', message='burst')
                for i in range(alert_count)
            ]
        )

        self.am.handle_alerts()
        while manual_reactor.active_calls(delay=0):
            manual_reactor.run_next()

        assert len(handler_results) == self.am.max_pending_handlers
        assert len(self.am.delayed_calls) == self.am.max_pending_handlers
        assert self.am._has_pending_alert_work()

        handler_results[0].callback(None)

        assert len(manual_reactor.active_calls(delay=0)) == 1
        manual_reactor.run_next()
        assert len(handler_results) == self.am.max_pending_handlers
        assert len(manual_reactor.active_calls(delay=0)) == 1
        manual_reactor.run_next()
        assert len(handler_results) == self.am.max_pending_handlers + 1

    async def test_pop_alert(self, mock_callback, mock_alert1, mock_alert2):
        self.am.register_handler('mock_alert1', mock_callback)

        self.am.session.push_alerts([mock_alert1, mock_alert2])

        await mock_callback.deferred

        mock_callback.assert_called_once_with(mock_alert1)

    @pytest.mark.xfail(
        sys.platform == 'win32',
        reason='Issue under Windows where mock is already called.',
    )
    async def test_pause_not_pop_alert(
        self, component, mock_alert1, mock_alert2, mock_callback
    ):
        await component.pause(['AlertManager'])

        self.am.register_handler('mock_alert1', mock_callback)
        self.am.session.push_alerts([mock_alert1, mock_alert2])

        await mock_callback.deferred

        mock_callback.assert_not_called()
        assert not self.am._event.is_set()
        assert len(self.am.session.alerts) == 2

    async def test_stop_while_paused_exits_thread(self, component, mock_alert1):
        """Test alert-poller thread exits when component stopped while paused with pending alert.

        Regression test: _event.wait() without a timeout blocked the alert-poller
        thread indefinitely when paused, preventing clean shutdown.
        """
        alert_thread = self.am._thread
        assert alert_thread.is_alive()

        await component.pause(['AlertManager'])
        self.am.session.push_alerts([mock_alert1])

        # Let the alert-poller thread reach _event.wait() before stopping.
        await task.deferLater(reactor, 0.1, lambda: None)

        await component.stop(['AlertManager'])

        alert_thread.join(timeout=2)
        assert not alert_thread.is_alive(), (
            'Alert-poller thread is still running after stop'
        )

    def test_deregister_handler(self):
        def handler(alert): ...

        self.am.register_handler('dummy1', handler)
        self.am.register_handler('dummy2_alert', handler)
        self.am.deregister_handler(handler)
        assert self.am.handlers['dummy1'] == []
        assert self.am.handlers['dummy2'] == []
