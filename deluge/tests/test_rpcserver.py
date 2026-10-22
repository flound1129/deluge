#
# Copyright (C) 2013 Bro <bro.development@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import struct
import zlib
from unittest import mock

import rencode
from twisted.internet import task
from twisted.internet.address import IPv4Address

import deluge.component as component
import deluge.error
from deluge.common import get_localhost_auth
from deluge.conftest import BaseTestCase
from deluge.core import rpcserver
from deluge.core.authmanager import AuthManager
from deluge.core.rpcserver import RPCServer, SquallRPCProtocol
from deluge.log import setup_logger
from deluge.login_limiter import MAX_FAILURES

setup_logger('none')


class SquallRPCProtocolTester(SquallRPCProtocol):
    messages = []

    def transfer_message(self, data):
        self.messages.append(data)

    def getPeer(self):  # NOQA: N802
        # The tests use the protocol as its own transport.
        return IPv4Address('TCP', '192.0.2.1', 54321)


class TestRPCServer(BaseTestCase):
    def set_up(self):
        self.rpcserver = RPCServer(listen=False)
        self.rpcserver.factory.protocol = SquallRPCProtocolTester
        self.factory = self.rpcserver.factory
        self.session_id = '0'
        self.request_id = 11
        self.protocol = self.rpcserver.factory.protocol()
        self.protocol.factory = self.factory
        self.protocol.transport = self.protocol
        self.factory.session_protocols[self.session_id] = self.protocol
        self.factory.authorized_sessions[self.session_id] = None
        self.factory.interested_events[self.session_id] = ['TorrentFolderRenamedEvent']
        self.protocol.sessionno = self.session_id
        return component.start()

    def tear_down(self):
        def on_shutdown(result):
            del self.rpcserver

        return component.shutdown().addCallback(on_shutdown)

    def test_emit_event_for_session_id(self):
        torrent_id = '12'
        from deluge.event import TorrentFolderRenamedEvent

        data = [torrent_id, 'new name', 'old name']
        e = TorrentFolderRenamedEvent(*data)
        self.rpcserver.emit_event_for_session_id(self.session_id, e)
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_EVENT, str(msg)
        assert msg[1] == 'TorrentFolderRenamedEvent', str(msg)
        assert msg[2] == data, str(msg)

    def test_invalid_client_login(self):
        self.protocol.dispatch(self.request_id, 'daemon.login', [1], {})
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_ERROR
        assert msg[1] == self.request_id

    def test_valid_client_login(self):
        self.authmanager = AuthManager()
        auth = get_localhost_auth()
        self.protocol.dispatch(
            self.request_id, 'daemon.login', auth, {'client_version': 'Test'}
        )
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_RESPONSE, str(msg)
        assert msg[1] == self.request_id, str(msg)
        assert msg[2] == rpcserver.AUTH_LEVEL_ADMIN, str(msg)

    def login(self, username, password):
        self.protocol.dispatch(
            self.request_id,
            'daemon.login',
            [username, password],
            {'client_version': 'Test'},
        )
        return self.protocol.messages.pop()

    def test_login_blocked_after_failed_logins(self):
        self.authmanager = AuthManager()
        username, password = get_localhost_auth()
        for _ in range(MAX_FAILURES):
            msg = self.login(username, 'wrong')
            assert msg[0] == rpcserver.RPC_ERROR
            assert msg[2] == 'BadLoginError'

        # A correct password is refused too, and is not checked.
        with mock.patch.object(
            self.authmanager, 'authorize', wraps=self.authmanager.authorize
        ) as authorize:
            msg = self.login(username, password)
        assert msg[0] == rpcserver.RPC_ERROR
        assert msg[2] == 'BadLoginError'
        assert msg[3][0].startswith('Too many failed logins.')
        authorize.assert_not_called()

    def test_good_login_resets_failed_logins(self):
        self.authmanager = AuthManager()
        username, password = get_localhost_auth()
        for _ in range(2):
            for _ in range(MAX_FAILURES - 1):
                assert self.login(username, 'wrong')[0] == rpcserver.RPC_ERROR
            msg = self.login(username, password)
            assert msg[0] == rpcserver.RPC_RESPONSE, str(msg)

    def send_message(self, body):
        body = zlib.compress(body)
        self.protocol.dataReceived(struct.pack('!BI', 1, len(body)) + body)

    def test_deeply_nested_message_is_dropped(self):
        """S05: deep rencode nesting before login does not crash the daemon."""
        with mock.patch.object(self.protocol, 'message_received') as message_received:
            # 65000 nested lists are under the pre-login size limit, and are
            # about 100 bytes compressed.
            self.send_message(b'\xc1' * 65000 + b'\x00')
            message_received.assert_not_called()

            self.send_message(rencode.dumps(((1, 'daemon.info', [], {}),)))
            message_received.assert_called_once()

    def start_connection(self):
        """Call connectionMade with a test clock. Returns the clock."""
        clock = task.Clock()
        self.patch(rpcserver, 'reactor', clock)
        self.protocol.loseConnection = mock.Mock()
        self.protocol.connectionMade()
        return clock

    def test_login_timeout(self):
        """S05: a client that does not log in is disconnected."""
        clock = self.start_connection()
        clock.advance(rpcserver.LOGIN_TIMEOUT - 1)
        self.protocol.loseConnection.assert_not_called()
        clock.advance(1)
        self.protocol.loseConnection.assert_called_once()

    def test_login_stops_login_timeout(self):
        self.authmanager = AuthManager()
        clock = self.start_connection()
        msg = self.login(*get_localhost_auth())
        assert msg[0] == rpcserver.RPC_RESPONSE, str(msg)
        clock.advance(rpcserver.LOGIN_TIMEOUT)
        self.protocol.loseConnection.assert_not_called()

    def test_client_login_error(self):
        # This test causes error log prints while running the test...
        self.protocol.transport = None  # This should cause AttributeError
        self.authmanager = AuthManager()
        auth = get_localhost_auth()
        self.protocol.dispatch(
            self.request_id, 'daemon.login', auth, {'client_version': 'Test'}
        )
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_ERROR
        assert msg[1] == self.request_id
        assert msg[2] == 'WrappedException'
        assert msg[3][1] == 'AttributeError'

    def test_client_invalid_method_call(self):
        self.authmanager = AuthManager()
        auth = get_localhost_auth()
        self.protocol.dispatch(self.request_id, 'invalid_function', auth, {})
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_ERROR
        assert msg[1] == self.request_id
        assert msg[2] == 'WrappedException'
        assert msg[3][1] == 'AttributeError'

    def test_daemon_info(self):
        self.protocol.dispatch(self.request_id, 'daemon.info', [], {})
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_RESPONSE, str(msg)
        assert msg[1] == self.request_id, str(msg)
        assert msg[2] == deluge.common.get_version(), str(msg)

    def test_set_event_interest_requires_login(self):
        del self.factory.session_protocols[self.session_id]
        self.factory.authorized_sessions[self.session_id] = self.protocol.AuthLevel(
            rpcserver.AUTH_LEVEL_NONE, ''
        )
        self.factory.interested_events.clear()
        self.protocol.dispatch(
            self.request_id,
            'daemon.set_event_interest',
            [['TorrentFolderRenamedEvent']],
            {},
        )
        assert self.session_id not in self.factory.interested_events

    def test_emit_event_skips_session_without_protocol(self):
        from deluge.event import TorrentFolderRenamedEvent

        del self.factory.session_protocols[self.session_id]
        self.rpcserver.emit_event(TorrentFolderRenamedEvent('12', 'new', 'old'))

    def test_max_message_size_before_and_after_login(self):
        self.factory.authorized_sessions[self.session_id] = self.protocol.AuthLevel(
            rpcserver.AUTH_LEVEL_NONE, ''
        )
        assert (
            self.protocol.max_message_size()
            == rpcserver.MAX_UNAUTHENTICATED_MESSAGE_SIZE
        )
        self.factory.authorized_sessions[self.session_id] = self.protocol.AuthLevel(
            rpcserver.AUTH_LEVEL_ADMIN, 'localclient'
        )
        assert self.protocol.max_message_size() == rpcserver.MAX_MESSAGE_SIZE

    def test_set_event_interest_rejects_invalid_names(self):
        """S04: event interest must be a list of event names."""
        self.protocol.dispatch(
            self.request_id, 'daemon.set_event_interest', [[123]], {}
        )
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_ERROR
        assert self.factory.interested_events[self.session_id] == [
            'TorrentFolderRenamedEvent'
        ]

    def test_set_event_interest_deduplicates_and_caps(self):
        """S04: repeated names are stored once and the number of names is capped."""
        self.protocol.dispatch(
            self.request_id,
            'daemon.set_event_interest',
            [['TorrentAddedEvent', 'TorrentAddedEvent', 'TorrentFolderRenamedEvent']],
            {},
        )
        assert self.protocol.messages.pop()[0] == rpcserver.RPC_RESPONSE
        assert self.factory.interested_events[self.session_id] == [
            'TorrentFolderRenamedEvent',
            'TorrentAddedEvent',
        ]

        names = ['Event%d' % i for i in range(rpcserver.MAX_EVENT_INTERESTS)]
        self.protocol.dispatch(
            self.request_id, 'daemon.set_event_interest', [names], {}
        )
        assert self.protocol.messages.pop()[0] == rpcserver.RPC_ERROR
        assert len(self.factory.interested_events[self.session_id]) == 2

    def test_emit_event_failed_recipient_does_not_stop_others(self):
        """S04: an error from one recipient does not stop delivery to another."""
        from deluge.event import TorrentFolderRenamedEvent

        broken = mock.Mock()
        broken.sendData.side_effect = OSError('connection gone')
        self.factory.session_protocols['1'] = broken
        self.factory.interested_events['1'] = ['TorrentFolderRenamedEvent']
        # Put the broken recipient first.
        self.factory.interested_events = {
            '1': self.factory.interested_events['1'],
            self.session_id: self.factory.interested_events[self.session_id],
        }

        self.rpcserver.emit_event(TorrentFolderRenamedEvent('12', 'new', 'old'))
        broken.sendData.assert_called_once()
        msg = self.protocol.messages.pop()
        assert msg[0] == rpcserver.RPC_EVENT
        assert msg[1] == 'TorrentFolderRenamedEvent'

    def test_event_handlers_run_when_client_delivery_fails(self):
        """S04: local handlers, and the operation that emits, survive a delivery error."""
        from deluge.core.eventmanager import EventManager
        from deluge.event import PreTorrentRemovedEvent

        event_manager = EventManager()
        handler = mock.Mock()
        event_manager.register_event_handler('PreTorrentRemovedEvent', handler)
        with mock.patch.object(
            self.rpcserver, 'emit_event', side_effect=KeyError('stale session')
        ):
            event_manager.emit(PreTorrentRemovedEvent('12'))
        handler.assert_called_once_with('12')
