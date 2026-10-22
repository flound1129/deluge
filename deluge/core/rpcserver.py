#
# Copyright (C) 2008,2009 Andrew Resch <andrewresch@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

"""RPCServer Module"""

import logging
import os
import sys
import traceback
from collections import namedtuple
from types import FunctionType
from typing import Callable, TypeVar, overload

from rencode import rencode_orig
from twisted.internet import defer, reactor
from twisted.internet.protocol import Factory, connectionDone

import deluge.component as component
import deluge.configmanager
from deluge.core.authmanager import (
    AUTH_LEVEL_ADMIN,
    AUTH_LEVEL_DEFAULT,
    AUTH_LEVEL_NONE,
)
from deluge.crypto_utils import check_ssl_keys, get_context_factory
from deluge.error import (
    BadLoginError,
    DelugeError,
    IncompatibleClient,
    NotAuthorizedError,
    WrappedException,
    _ClientSideRecreateError,
)
from deluge.event import ClientDisconnectedEvent
from deluge.login_limiter import LoginLimiter
from deluge.transfer import MAX_MESSAGE_SIZE, SquallTransferProtocol

RPC_RESPONSE = 1
RPC_ERROR = 2
RPC_EVENT = 3

# daemon.info and daemon.login requests are tiny.
MAX_UNAUTHENTICATED_MESSAGE_SIZE = 64 * 1024
# Seconds a client has to log in after it connects. Clients log in at once, or
# ask for daemon.info and disconnect.
LOGIN_TIMEOUT = 60

# Core and plugins define a few dozen events with names under 30 characters.
MAX_EVENT_INTERESTS = 256
MAX_EVENT_NAME_LENGTH = 128

log = logging.getLogger(__name__)

TCallable = TypeVar('TCallable', bound=Callable)


@overload
def export(func: TCallable) -> TCallable: ...


@overload
def export(auth_level: int) -> Callable[[TCallable], TCallable]: ...


def export(auth_level=AUTH_LEVEL_DEFAULT):
    """
    Decorator function to register an object's method as an RPC.  The object
    will need to be registered with an :class:`RPCServer` to be effective.

    :param func: the function to export
    :type func: function
    :param auth_level: the auth level required to call this method
    :type auth_level: int

    """

    def wrap(func, *args, **kwargs):
        func._rpcserver_export = True
        func._rpcserver_auth_level = auth_level

        rpc_text = '**RPC exported method** (*Auth level: %s*)' % auth_level

        # Append the RPC text while ensuring correct docstring formatting.
        if func.__doc__:
            if func.__doc__.endswith('    '):
                indent = func.__doc__.split('\n')[-1]
                func.__doc__ += f'\n{indent}'
            else:
                func.__doc__ += '\n\n'
            func.__doc__ += rpc_text
        else:
            func.__doc__ = rpc_text

        return func

    if isinstance(auth_level, FunctionType):
        func = auth_level
        auth_level = AUTH_LEVEL_DEFAULT
        return wrap(func)
    else:
        return wrap


def format_request(call):
    """
    Format the RPCRequest message for debug printing

    :param call: the request
    :type call: a RPCRequest

    :returns: a formatted string for printing
    :rtype: str

    """
    try:
        s = call[1] + '('
        if call[2]:
            s += ', '.join([str(x) for x in call[2]])
        if call[3]:
            if call[2]:
                s += ', '
            s += ', '.join([key + '=' + str(value) for key, value in call[3].items()])
        s += ')'
    except UnicodeEncodeError:
        return 'UnicodeEncodeError, call: %s' % call
    else:
        return s


class SquallRPCProtocol(SquallTransferProtocol):
    def __init__(self):
        super().__init__()
        # namedtuple subclass with auth_level, username for the connected session.
        self.AuthLevel = namedtuple('SessionAuthlevel', 'auth_level, username')
        self._login_timer = None

    def decode_message(self, body):
        # The C decoder of rencode recurses once per nested list or dict, with no
        # depth limit, so one small message from a client that is not logged in
        # could overflow the C stack and crash the daemon. The Python decoder
        # raises RecursionError instead. Requests are small, so its speed is fine.
        return rencode_orig.loads(body, decode_utf8=True)

    def message_received(self, request):
        """
        This method is called whenever a message is received from a client.  The
        only message that a client sends to the server is a RPC Request message.
        If the RPC Request message is valid, then the method is called in
        :meth:`dispatch`.

        :param request: the request from the client.
        :type data: tuple

        """
        if not isinstance(request, tuple):
            log.debug('Received invalid message: type is not tuple')
            return

        if len(request) < 1:
            log.debug('Received invalid message: there are no items')
            return

        for call in request:
            if len(call) != 4:
                log.debug(
                    'Received invalid rpc request: number of items in request is %s',
                    len(call),
                )
                continue
            # log.debug('RPCRequest: %s', format_request(call))
            reactor.callLater(0, self.dispatch, *call)

    def sendData(self, data):  # NOQA: N802
        """
        Sends the data to the client.

        :param data: the object that is to be sent to the client.  This should
            be one of the RPC message types.
        :type data: object

        """
        try:
            self.transfer_message(data)
        except Exception as ex:
            log.warning('Error occurred when sending message: %s.', ex)
            log.exception(ex)
            raise

    def connectionMade(self):  # NOQA: N802
        """
        This method is called when a new client connects.
        """
        peer = self.transport.getPeer()
        log.info('Squall Client connection made from: %s:%s', peer.host, peer.port)
        # Set the initial auth level of this session to AUTH_LEVEL_NONE
        self.factory.authorized_sessions[self.transport.sessionno] = self.AuthLevel(
            AUTH_LEVEL_NONE, ''
        )
        self._login_timer = reactor.callLater(LOGIN_TIMEOUT, self._login_timed_out)

    def _login_timed_out(self):
        peer = self.transport.getPeer()
        log.info(
            'Closing connection from %s:%s: no login in %s seconds',
            peer.host,
            peer.port,
            LOGIN_TIMEOUT,
        )
        self.transport.loseConnection()

    def _stop_login_timer(self):
        if self._login_timer and self._login_timer.active():
            self._login_timer.cancel()

    def connectionLost(self, reason=connectionDone):  # NOQA: N802
        """
        This method is called when the client is disconnected.

        :param reason: the reason the client disconnected.
        :type reason: str

        """
        self._stop_login_timer()

        # We need to remove this session from various dicts
        del self.factory.authorized_sessions[self.transport.sessionno]
        if self.transport.sessionno in self.factory.session_protocols:
            del self.factory.session_protocols[self.transport.sessionno]
        if self.transport.sessionno in self.factory.interested_events:
            del self.factory.interested_events[self.transport.sessionno]

        if self.factory.state == 'running':
            component.get('EventManager').emit(
                ClientDisconnectedEvent(self.factory.session_id)
            )
        log.info('Squall client disconnected: %s', reason.value)

    def valid_session(self):
        return self.transport.sessionno in self.factory.authorized_sessions

    def max_message_size(self):
        # Before login the only requests are daemon.info and daemon.login,
        # so do not let an unauthenticated peer send large messages.
        session = self.factory.authorized_sessions.get(self.transport.sessionno)
        if session and session.auth_level > AUTH_LEVEL_NONE:
            return MAX_MESSAGE_SIZE
        return MAX_UNAUTHENTICATED_MESSAGE_SIZE

    def dispatch(self, request_id, method, args, kwargs):
        """
        This method is run when a RPC Request is made.  It will run the local method
        and will send either a RPC Response or RPC Error back to the client.

        :param request_id: the request_id from the client (sent in the RPC Request)
        :type request_id: int
        :param method: the local method to call. It must be registered with
            the :class:`RPCServer`.
        :type method: str
        :param args: the arguments to pass to `method`
        :type args: list
        :param kwargs: the keyword-arguments to pass to `method`
        :type kwargs: dict

        """

        def send_error():
            """
            Sends an error response with the contents of the exception that was raised.
            """
            exc_type, exc_value, dummy_exc_trace = sys.exc_info()
            formated_tb = traceback.format_exc()
            try:
                self.sendData(
                    (
                        RPC_ERROR,
                        request_id,
                        exc_type.__name__,
                        exc_value._args,
                        exc_value._kwargs,
                        formated_tb,
                    )
                )
            except AttributeError:
                # This is not a deluge exception (object has no attribute '_args), let's wrap it
                log.warning(
                    'An exception occurred while sending RPC_ERROR to '
                    'client. Wrapping it and resending. Error to '
                    'send(causing exception goes next):\n%s',
                    formated_tb,
                )
                try:
                    raise WrappedException(
                        str(exc_value), exc_type.__name__, formated_tb
                    )
                except WrappedException:
                    send_error()
            except Exception as ex:
                log.error(
                    'An exception occurred while sending RPC_ERROR to client: %s', ex
                )

        if method == 'daemon.info':
            # This is a special case and used in the initial connection process
            self.sendData((RPC_RESPONSE, request_id, deluge.common.get_version()))
            return
        elif method == 'daemon.login':
            # This is a special case and used in the initial connection process
            # We need to authenticate the user here
            log.debug('RPC dispatch daemon.login')
            login_limiter = self.factory.login_limiter
            blocked = False
            try:
                client_version = kwargs.pop('client_version', None)
                if client_version is None:
                    raise IncompatibleClient(deluge.common.get_version())
                peer = self.transport.getPeer()
                wait = login_limiter.check(peer.host)
                if wait:
                    # Refuse before the password check, which is slow (scrypt).
                    blocked = True
                    raise BadLoginError(
                        f'Too many failed logins. Try again in {wait} seconds.',
                        args[0] if args else '',
                    )
                ret = component.get('AuthManager').authorize(*args, **kwargs)
                if ret:
                    login_limiter.success(peer.host)
                    self._stop_login_timer()
                    self.factory.authorized_sessions[self.transport.sessionno] = (
                        self.AuthLevel(ret, args[0])
                    )
                    self.factory.session_protocols[self.transport.sessionno] = self
            except Exception as ex:
                send_error()
                if not isinstance(ex, _ClientSideRecreateError):
                    log.exception(ex)
                if isinstance(ex, BadLoginError):
                    if not blocked:
                        login_limiter.failure(peer.host)
                    log.error(
                        'Squall client authentication error made from: %s:%s (%s)',
                        peer.host,
                        peer.port,
                        str(ex),
                    )
            else:
                self.sendData((RPC_RESPONSE, request_id, (ret)))
                if not ret:
                    self.transport.loseConnection()
            return

        # Anything below requires a valid session
        if not self.valid_session():
            return

        if method == 'daemon.set_event_interest':
            log.debug('RPC dispatch daemon.set_event_interest')
            if self.transport.sessionno not in self.factory.session_protocols:
                # Only logged-in sessions have a protocol to send events to.
                return
            # This special case is to allow clients to set which events they are
            # interested in receiving.
            # We are expecting a sequence of event names from the client.
            try:
                names = args[0]
                if not isinstance(names, (list, tuple)) or not all(
                    isinstance(name, str) and len(name) <= MAX_EVENT_NAME_LENGTH
                    for name in names
                ):
                    raise TypeError('Event interest must be a list of event names')
                current = self.factory.interested_events.get(
                    self.transport.sessionno, []
                )
                interest = current + [
                    name for name in dict.fromkeys(names) if name not in current
                ]
                if len(interest) > MAX_EVENT_INTERESTS:
                    raise ValueError(
                        'A session can register at most %d events' % MAX_EVENT_INTERESTS
                    )
                self.factory.interested_events[self.transport.sessionno] = interest
            except Exception:
                send_error()
            else:
                self.sendData((RPC_RESPONSE, request_id, (True)))
            return

        if method not in self.factory.methods:
            try:
                # Raise exception to be sent back to client
                raise AttributeError('RPC call on invalid function: %s' % method)
            except AttributeError:
                send_error()
                return

        log.debug('RPC dispatch %s', method)
        try:
            method_auth_requirement = self.factory.methods[method]._rpcserver_auth_level
            auth_level = self.factory.authorized_sessions[
                self.transport.sessionno
            ].auth_level
            if auth_level < method_auth_requirement:
                # This session is not allowed to call this method
                log.debug(
                    'Session %s is attempting an unauthorized method call!',
                    self.transport.sessionno,
                )
                raise NotAuthorizedError(auth_level, method_auth_requirement)
            # Set the session_id in the factory so that methods can know
            # which session is calling it.
            self.factory.session_id = self.transport.sessionno
            ret = self.factory.methods[method](*args, **kwargs)
        except Exception as ex:
            send_error()
            # Don't bother printing out DelugeErrors, because they are just
            # for the client
            if not isinstance(ex, DelugeError):
                log.exception('Exception calling RPC request: %s', ex)
        else:
            # Check if the return value is a deferred, since we'll need to
            # wait for it to fire before sending the RPC_RESPONSE
            if isinstance(ret, defer.Deferred):

                def on_success(result):
                    try:
                        self.sendData((RPC_RESPONSE, request_id, result))
                    except Exception:
                        send_error()
                    return result

                def on_fail(failure):
                    try:
                        failure.raiseException()
                    except Exception:
                        send_error()
                    return failure

                ret.addCallbacks(on_success, on_fail)
            else:
                self.sendData((RPC_RESPONSE, request_id, ret))


class RPCServer(component.Component):
    """
    This class is used to handle rpc requests from the client.  Objects are
    registered with this class and their methods are exported using the export
    decorator.

    :param port: the port the RPCServer will listen on
    :type port: int
    :param interface: the interface to listen on, this may override the `allow_remote` setting
    :type interface: str
    :param allow_remote: set True if the server should allow remote connections
    :type allow_remote: bool
    :param listen: if False, will not start listening.. This is only useful in Classic Mode
    :type listen: bool
    """

    def __init__(self, port=58846, interface='', allow_remote=False, listen=True):
        component.Component.__init__(self, 'RPCServer')

        self.factory = Factory()
        self.factory.protocol = SquallRPCProtocol
        self.factory.session_id = -1
        self.factory.state = 'running'

        # Holds the registered methods
        self.factory.methods = {}
        # Holds the session_ids and auth levels
        self.factory.authorized_sessions = {}
        # Holds the protocol objects with the session_id as key
        self.factory.session_protocols = {}
        # Holds the interested event list for the sessions
        self.factory.interested_events = {}
        # Counts failed logins per client address
        self.factory.login_limiter = LoginLimiter()

        self.listen = listen
        if not listen:
            return

        if allow_remote:
            hostname = ''
        else:
            hostname = 'localhost'

        if interface:
            hostname = interface

        log.info('Starting SquallRPC server %s:%s', hostname, port)

        # Check for SSL keys and generate some if needed
        check_ssl_keys()

        cert = os.path.join(deluge.configmanager.get_config_dir('ssl'), 'daemon.cert')
        pkey = os.path.join(deluge.configmanager.get_config_dir('ssl'), 'daemon.pkey')

        try:
            reactor.listenSSL(
                port, self.factory, get_context_factory(cert, pkey), interface=hostname
            )
        except Exception as ex:
            log.debug('Daemon already running or port not available.: %s', ex)
            raise

    def register_object(self, obj, name=None):
        """
        Registers an object to export it's rpc methods.  These methods should
        be exported with the export decorator prior to registering the object.

        :param obj: the object that we want to export
        :type obj: object
        :param name: the name to use, if None, it will be the class name of the object
        :type name: str
        """
        if not name:
            name = obj.__class__.__name__.lower()

        for d in dir(obj):
            if d[0] == '_':
                continue
            if getattr(getattr(obj, d), '_rpcserver_export', False):
                log.debug('Registering method: %s', name + '.' + d)
                self.factory.methods[name + '.' + d] = getattr(obj, d)

    def deregister_object(self, obj):
        """
        Deregisters an objects exported rpc methods.

        :param obj: the object that was previously registered

        """
        for key, value in self.factory.methods.items():
            if value.__self__ == obj:
                del self.factory.methods[key]

    def get_object_method(self, name):
        """
        Returns a registered method.

        :param name: the name of the method, usually in the form of 'object.method'
        :type name: str

        :returns: method

        :raises KeyError: if `name` is not registered

        """
        return self.factory.methods[name]

    def get_method_list(self):
        """
        Returns a list of the exported methods.

        :returns: the exported methods
        :rtype: list
        """
        return list(self.factory.methods)

    def get_session_id(self):
        """
        Returns the session id of the current RPC.

        :returns: the session id, this will be -1 if no connections have been made
        :rtype: int

        """
        return self.factory.session_id

    def get_session_user(self):
        """
        Returns the username calling the current RPC.

        :returns: the username of the user calling the current RPC
        :rtype: string

        """
        if not self.listen:
            return 'localclient'
        session_id = self.get_session_id()
        if session_id > -1 and session_id in self.factory.authorized_sessions:
            return self.factory.authorized_sessions[session_id].username
        else:
            # No connections made yet
            return ''

    def end_user_sessions(self, username):
        """End all sessions of ``username``, because its account was removed or
        changed.

        The sessions drop to AUTH_LEVEL_NONE at once, so requests that are
        already queued are refused, and they get no more events. Then they are
        disconnected.
        """
        for session_id, session in list(self.factory.authorized_sessions.items()):
            if not session or session.auth_level == AUTH_LEVEL_NONE:
                continue
            if session.username != username:
                continue
            log.info(
                'Ending session %s of %s: the account changed', session_id, username
            )
            self.factory.authorized_sessions[session_id] = session._replace(
                auth_level=AUTH_LEVEL_NONE, username=''
            )
            self.factory.interested_events.pop(session_id, None)
            protocol = self.factory.session_protocols.pop(session_id, None)
            if protocol:
                protocol.transport.loseConnection()

    def get_session_auth_level(self):
        """
        Returns the auth level of the user calling the current RPC.

        :returns: the auth level
        :rtype: int
        """
        if not self.listen or not self.is_session_valid(self.get_session_id()):
            return AUTH_LEVEL_ADMIN
        return self.factory.authorized_sessions[self.get_session_id()].auth_level

    def get_rpc_auth_level(self, rpc):
        """
        Returns the auth level requirement for an exported rpc.

        :returns: the auth level
        :rtype: int
        """
        return self.factory.methods[rpc]._rpcserver_auth_level

    def is_session_valid(self, session_id):
        """
        Checks if the session is still valid, eg, if the client is still connected.

        :param session_id: the session id
        :type session_id: int

        :returns: True if the session is valid
        :rtype: bool

        """
        return session_id in self.factory.authorized_sessions

    def emit_event(self, event):
        """
        Emits the event to interested clients.

        :param event: the event to emit
        :type event: :class:`deluge.event.DelugeEvent`
        """
        log.debug('intevents: %s', self.factory.interested_events)
        # Use copy of `interested_events` since it can mutate while iterating.
        for session_id, interest in self.factory.interested_events.copy().items():
            protocol = self.factory.session_protocols.get(session_id)
            if protocol and event.name in interest:
                log.debug('Emit Event: %s %s', event.name, event.args)
                # This session is interested so send a RPC_EVENT. One failed
                # recipient must not stop delivery to the others.
                try:
                    protocol.sendData((RPC_EVENT, event.name, event.args))
                except Exception as ex:
                    log.error(
                        'Unable to send event %s to session %s: %s',
                        event.name,
                        session_id,
                        ex,
                    )

    def emit_event_for_session_id(self, session_id, event):
        """
        Emits the event to specified session_id.

        :param session_id: the event to emit
        :type session_id: int
        :param event: the event to emit
        :type event: :class:`deluge.event.DelugeEvent`
        """
        if not self.is_session_valid(session_id):
            log.debug(
                'Session ID %s is not valid. Not sending event "%s".',
                session_id,
                event.name,
            )
            return
        if session_id not in self.factory.interested_events:
            log.debug(
                'Session ID %s is not interested in any events. Not sending event "%s".',
                session_id,
                event.name,
            )
            return
        if event.name not in self.factory.interested_events[session_id]:
            log.debug(
                'Session ID %s is not interested in event "%s". Not sending it.',
                session_id,
                event.name,
            )
            return
        log.debug(
            'Sending event "%s" with args "%s" to session id "%s".',
            event.name,
            event.args,
            session_id,
        )
        self.factory.session_protocols[session_id].sendData(
            (RPC_EVENT, event.name, event.args)
        )

    def stop(self):
        self.factory.state = 'stopping'
