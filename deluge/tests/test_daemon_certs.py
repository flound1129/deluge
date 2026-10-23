#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import multiprocessing
from unittest.mock import Mock

import pytest
from twisted.internet import defer
from twisted.python.failure import Failure

from deluge import error
from deluge.configmanager import set_config_dir
from deluge.ui import daemon_certs
from deluge.ui.client import (
    Client,
    PinnedClientContextFactory,
    SquallRPCClientFactory,
    SquallRPCProtocol,
)
from deluge.ui.hostlist import HostList


def _pin_in_process(config_dir, host, start):
    """Pin one host in a spawned process for the lost-update regression test."""
    set_config_dir(config_dir)
    start.wait()
    daemon_certs.check(host, 58846, f'fingerprint-{host}')


def test_pin_check_and_forget(config_dir):
    assert daemon_certs.check('daemon.example', 58846, 'AA:BB')
    assert daemon_certs.get('daemon.example', 58846) == 'AA:BB'
    assert daemon_certs.check('daemon.example', 58846, 'AA:BB')
    assert not daemon_certs.check('daemon.example', 58846, 'CC:DD')
    assert daemon_certs.get('daemon.example', 58846) == 'AA:BB'

    daemon_certs.forget('daemon.example', 58846)
    assert daemon_certs.get('daemon.example', 58846) is None


def test_concurrent_processes_do_not_lose_pins(config_dir):
    context = multiprocessing.get_context('spawn')
    start = context.Event()
    hosts = [f'daemon-{index}.example' for index in range(4)]
    processes = [
        context.Process(target=_pin_in_process, args=(str(config_dir), host, start))
        for host in hosts
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0

    for host in hosts:
        assert daemon_certs.get(host, 58846) == f'fingerprint-{host}'


def test_remove_last_host_forgets_pin(monkeypatch):
    hostlist = HostList()
    host_id, hostname, port = hostlist.config['hosts'][0][:3]
    forget = Mock()
    monkeypatch.setattr(daemon_certs, 'forget', forget)

    assert hostlist.remove_host(host_id)

    forget.assert_called_once_with(hostname, port)


def test_remove_duplicate_endpoint_keeps_shared_pin(monkeypatch):
    hostlist = HostList()
    first = hostlist.config['hosts'][0]
    # JSON-loaded entries are lists while entries added in this process are
    # tuples, so endpoint matching must not depend on the container type.
    duplicate = ['duplicate', first[1], first[2], 'other-user', 'other-password']
    hostlist.config['hosts'].append(duplicate)
    forget = Mock()
    monkeypatch.setattr(daemon_certs, 'forget', forget)

    assert hostlist.remove_host(first[0])

    forget.assert_not_called()


def test_failed_host_removal_save_keeps_pin(monkeypatch):
    hostlist = HostList()
    host_id = hostlist.config['hosts'][0][0]
    monkeypatch.setattr(hostlist.config, 'save', Mock(return_value=False))
    forget = Mock()
    monkeypatch.setattr(daemon_certs, 'forget', forget)

    assert hostlist.remove_host(host_id)

    forget.assert_not_called()


def test_protocol_reports_connected_only_after_tls_handshake():
    connect_deferred = defer.Deferred()
    daemon = Mock(connect_deferred=connect_deferred, connected=False)
    protocol = SquallRPCProtocol()
    protocol.factory = Mock(daemon=daemon)
    protocol.transport = Mock()
    protocol.transport.getPeer.return_value = Mock(host='daemon.example', port=58846)

    protocol.connectionMade()

    assert not connect_deferred.called
    assert not daemon.connected

    protocol.handshakeCompleted()

    assert connect_deferred.called
    assert daemon.connected

    # TLS renegotiation is reported through the same Twisted callback.
    protocol.handshakeCompleted()


def test_changed_certificate_is_reported_on_connection_failure(monkeypatch):
    certificate_error = error.DaemonCertificateError('certificate changed')
    connect_deferred = defer.Deferred()
    failures = []
    connect_deferred.addErrback(failures.append)
    daemon = Mock(
        certificate_error=certificate_error,
        connect_deferred=connect_deferred,
    )
    factory = SquallRPCClientFactory(daemon, {})

    factory.clientConnectionFailed(
        Mock(host='daemon.example', port=58846), Failure(ConnectionError())
    )

    assert failures[0].value is certificate_error


@pytest.mark.usefixtures('daemon')
def test_changed_certificate_aborts_real_connection(listen_port):
    daemon_certs.check('localhost', listen_port, 'not-the-daemon-certificate')
    test_client = Client()

    connection = test_client.connect('localhost', listen_port, skip_authentication=True)

    def unexpected_success(result):
        pytest.fail(f'Connection unexpectedly succeeded: {result}')

    def expected_failure(failure):
        failure.trap(error.DaemonCertificateError)
        assert not test_client.connected()

    connection.addCallbacks(unexpected_success, expected_failure)
    return connection


def test_certificate_callback_pins_leaf_and_rejects_change(monkeypatch):
    daemon = Mock(certificate_error=None)
    context_factory = PinnedClientContextFactory(daemon, 'daemon.example', 58846)
    certificate = Mock()
    certificate.digest.return_value = b'AA:BB'
    check = Mock(return_value=True)
    monkeypatch.setattr(daemon_certs, 'check', check)

    assert context_factory._verify(None, certificate, 0, 0, False)
    check.assert_called_once_with('daemon.example', 58846, 'AA:BB')
    assert daemon.certificate_error is None

    check.return_value = False
    assert not context_factory._verify(None, certificate, 0, 0, False)
    assert isinstance(daemon.certificate_error, error.DaemonCertificateError)


def test_certificate_callback_fails_closed_on_pin_store_error(monkeypatch):
    daemon = Mock(certificate_error=None)
    context_factory = PinnedClientContextFactory(daemon, 'daemon.example', 58846)
    certificate = Mock()
    certificate.digest.return_value = b'AA:BB'

    def fail_check(*args):
        raise OSError('pin store is not writable')

    monkeypatch.setattr(daemon_certs, 'check', fail_check)

    assert not context_factory._verify(None, certificate, 0, 0, False)
    assert isinstance(daemon.certificate_error, error.DaemonCertificateError)


def test_certificate_callback_ignores_non_leaf_certificate(monkeypatch):
    daemon = Mock(certificate_error=None)
    context_factory = PinnedClientContextFactory(daemon, 'daemon.example', 58846)
    check = Mock()
    monkeypatch.setattr(daemon_certs, 'check', check)

    assert context_factory._verify(None, Mock(), 0, 1, False)
    check.assert_not_called()
