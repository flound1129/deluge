#
# Copyright (C) 2007-2009 Andrew Resch <andrewresch@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

"""

The AlertManager handles all the libtorrent alerts.

This should typically only be used by the Core. Plugins should utilize the
`:mod:EventManager` for similar functionality.

"""

import contextlib
import logging
import threading
import time
from collections import defaultdict, deque
from functools import partial
from typing import Any, Callable

from twisted.internet import reactor, task, threads

import deluge.component as component
from deluge._libtorrent import lt
from deluge.common import decode_bytes
from deluge.core.network_policy import sanitize_log_value

log = logging.getLogger(__name__)


class AlertManager(component.Component):
    """AlertManager fetches and processes libtorrent alerts"""

    alert_queue_size = 2000
    max_pending_alerts = 2000
    alert_work_per_turn = 100
    max_pending_handlers = 100

    def __init__(self):
        log.debug('AlertManager init...')
        component.Component.__init__(self, 'AlertManager')
        self.session = component.get('Core').session

        # Keep the native queue bounded. Alert processing below yields between
        # batches, so a larger queue would allow a burst to retain substantially
        # more native and Python state without improving reactor responsiveness.
        self.set_alert_queue_size(self.alert_queue_size)

        alert_mask = (
            lt.alert.category_t.error_notification
            | lt.alert.category_t.port_mapping_notification
            | lt.alert.category_t.storage_notification
            | lt.alert.category_t.tracker_notification
            | lt.alert.category_t.status_notification
            | lt.alert.category_t.ip_block_notification
            | lt.alert.category_t.performance_warning
            | lt.alert.category_t.file_progress_notification
            | lt.alert.category_t.peer_notification
            | lt.alert.category_t.connect_notification
        )

        self.session.apply_settings({'alert_mask': alert_mask})

        # handlers is a dictionary of lists {"alert_type": [handler1,h2,..]}
        self.handlers = defaultdict(list)
        self.handlers_timeout_secs = 2
        self.delayed_calls = []
        self._pending_alerts = deque()
        self._current_alert = None
        self._current_alert_type = None
        self._current_handlers = ()
        self._current_handler_index = 0
        self._alert_drain_call = None
        self._event = threading.Event()

    def update(self):
        pass

    def start(self):
        self._thread = threading.Thread(
            target=self.wait_for_alert_in_thread, name='alert-poller', daemon=True
        )
        self._thread.start()
        self._event.set()

    def stop(self):
        self.cancel_delayed_calls()

    def pause(self):
        self._event.clear()

    def resume(self):
        self._event.set()

    def wait_for_alert_in_thread(self):
        while self._component_state not in ('Stopping', 'Stopped'):
            if self.check_delayed_calls():
                time.sleep(0.05)
                continue

            if not self._event.wait(timeout=1):
                continue

            if self.session.wait_for_alert(1000) is None:
                continue

            threads.blockingCallFromThread(reactor, self.maybe_handle_alerts)

    def on_delayed_call_timeout(self, result, timeout, **kwargs):
        log.warning('Alert handler timed out %s', kwargs)

    def cancel_delayed_calls(self):
        """Cancel all delayed handlers."""
        if self._alert_drain_call is not None and self._alert_drain_call.active():
            self._alert_drain_call.cancel()
        self._alert_drain_call = None
        self._pending_alerts.clear()
        self._clear_current_alert()

        delayed_calls = self.delayed_calls
        self.delayed_calls = []
        for delayed_call in delayed_calls:
            delayed_call.cancel()

    def check_delayed_calls(self) -> bool:
        """Returns True if any handler calls are delayed."""
        return bool(
            self.delayed_calls
            or self._pending_alerts
            or self._current_alert is not None
            or self._alert_drain_call is not None
        )

    def maybe_handle_alerts(self) -> None:
        if self._component_state != 'Started' or not self._event.is_set():
            return

        self.handle_alerts()

    def register_handler(self, alert_type: str, handler: Callable[[Any], None]) -> None:
        """
        Registers a function that will be called when 'alert_type' is pop'd
        in handle_alerts.  The handler function should look like: handler(alert)
        Where 'alert' is the actual alert object from libtorrent.

        Args:
            alert_type: String representation of the libtorrent alert name.
                Can be supplied with or without `_alert` suffix.
            handler: Callback function when the alert is raised.
        """
        if alert_type and alert_type.endswith('_alert'):
            alert_type = alert_type[: -len('_alert')]

        self.handlers[alert_type].append(handler)
        log.debug('Registered handler for alert %s', alert_type)

    def deregister_handler(self, handler: Callable[[Any], None]):
        """
        De-registers the `handler` function from all alert types.

        Args:
            handler: The handler function to deregister.
        """
        for alert_type_handlers in self.handlers.values():
            with contextlib.suppress(ValueError):
                alert_type_handlers.remove(handler)

    def handle_alerts(self):
        """
        Move libtorrent alerts into the bounded, incremental reactor work queue.
        """
        # libtorrent only exposes an all-at-once pop. Leave its bounded queue
        # untouched until the current Python batch and its handlers have made
        # progress, rather than accumulating successive native batches here.
        if self._has_pending_alert_work() or self.delayed_calls:
            log.debug('Deferring native alert pop while local work is pending')
            return

        alerts = self.session.pop_alerts()
        if not alerts:
            return

        num_alerts = len(alerts)
        if log.isEnabledFor(logging.DEBUG):
            log.debug('Alerts queued: %s', num_alerts)
        if num_alerts > 0.9 * self.alert_queue_size:
            log.warning(
                'Warning total alerts queued, %s, passes 90%% of queue size.',
                num_alerts,
            )

        if num_alerts > self.max_pending_alerts:
            dropped_alerts = num_alerts - self.max_pending_alerts
            log.warning(
                'Dropping %s newest alerts from oversized native batch',
                dropped_alerts,
            )
            alerts = alerts[: self.max_pending_alerts]

        self._pending_alerts.extend(alerts)
        self._drain_alerts()

    def _has_pending_alert_work(self):
        return bool(
            self._pending_alerts
            or self._current_alert is not None
            or self._alert_drain_call is not None
        )

    def _clear_current_alert(self):
        self._current_alert = None
        self._current_alert_type = None
        self._current_handlers = ()
        self._current_handler_index = 0

    def _schedule_alert_drain(self):
        if self._alert_drain_call is None and self._has_pending_alert_work():
            self._alert_drain_call = reactor.callLater(0, self._drain_alerts)

    def _handler_finished(self, result, delayed_call):
        with contextlib.suppress(ValueError):
            self.delayed_calls.remove(delayed_call)
        if len(self.delayed_calls) < self.max_pending_handlers:
            self._schedule_alert_drain()
        return result

    def _drain_alerts(self):
        """Process a bounded amount of alert work in one reactor turn."""
        self._alert_drain_call = None
        work_done = 0

        while work_done < self.alert_work_per_turn:
            if self._current_alert is None:
                if not self._pending_alerts:
                    break

                self._current_alert = self._pending_alerts.popleft()
                self._current_alert_type = self._current_alert.what()
                self._current_handlers = tuple(
                    self.handlers.get(self._current_alert_type, ())
                )
                self._current_handler_index = 0
                work_done += 1

                if log.isEnabledFor(logging.DEBUG):
                    log.debug(
                        '%s: %s',
                        self._current_alert_type,
                        sanitize_log_value(decode_bytes(self._current_alert.message())),
                    )

                if not self._current_handlers:
                    self._clear_current_alert()
                    continue

            if len(self.delayed_calls) >= self.max_pending_handlers:
                break

            handler = self._current_handlers[self._current_handler_index]
            self._current_handler_index += 1
            work_done += 1

            if log.isEnabledFor(logging.DEBUG):
                log.debug('Handling alert: %s', self._current_alert_type)
            # Defer invocation itself so alert inspection never calls a slow
            # synchronous handler inline in the same reactor turn.
            d = task.deferLater(reactor, 0, handler, self._current_alert)
            on_handler_timeout = partial(
                self.on_delayed_call_timeout,
                handler=handler.__qualname__,
                alert_type=self._current_alert_type,
            )
            d.addTimeout(
                self.handlers_timeout_secs,
                reactor,
                onTimeoutCancel=on_handler_timeout,
            )
            self.delayed_calls.append(d)
            d.addBoth(self._handler_finished, d)

            if self._current_handler_index == len(self._current_handlers):
                self._clear_current_alert()

        if (
            self._has_pending_alert_work()
            and len(self.delayed_calls) < self.max_pending_handlers
        ):
            self._schedule_alert_drain()

    def set_alert_queue_size(self, queue_size):
        """Sets the maximum size of the libtorrent alert queue"""
        log.info('Alert Queue Size set to %s', queue_size)
        self.alert_queue_size = queue_size
        component.get('Core').apply_session_setting(
            'alert_queue_size', self.alert_queue_size
        )
