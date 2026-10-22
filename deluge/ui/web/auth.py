#
# Copyright (C) 2009 Damien Churchill <damoxc@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timedelta
from email.utils import formatdate

from twisted.internet.task import LoopingCall

from deluge.common import AUTH_LEVEL_ADMIN, AUTH_LEVEL_NONE
from deluge.error import NotAuthorizedError
from deluge.login_limiter import LoginLimiter
from deluge.ui.web.json_api import JSONComponent, export

log = logging.getLogger(__name__)


def make_checksum(session_id):
    checksum = 0
    for value in [ord(char) for char in session_id]:
        checksum += value
    return checksum


def get_session_id(session_id):
    """
    Checks a session id against its checksum
    """
    if not session_id:
        return None

    try:
        checksum = int(session_id[-4:])
        session_id = session_id[:-4]

        if checksum == make_checksum(session_id):
            return session_id
        return None
    except Exception as ex:
        log.exception(ex)
        return None


def make_expires(timeout):
    dt = timedelta(seconds=timeout)
    expires = time.mktime((datetime.now() + dt).timetuple())
    expires_str = formatdate(timeval=expires, localtime=False, usegmt=True)
    return expires, expires_str


class Auth(JSONComponent):
    """
    The component that implements authentication into the JSON interface.
    """

    def __init__(self, config):
        super().__init__('Auth')
        self.worker = LoopingCall(self._clean_sessions)
        self.config = config
        # Counts failed password checks per client address
        self.login_limiter = LoginLimiter()

    def start(self):
        if not self.worker.running:
            self.worker.start(5)

    def stop(self):
        if self.worker.running:
            self.worker.stop()

    def shutdown(self):
        # DelugeWeb starts the cleaner directly, so the registry may see this
        # component as stopped and not call stop().
        self.stop()

    def _clean_sessions(self):
        now = time.gmtime()
        for session_id in list(self.config['sessions']):
            session = self.config['sessions'][session_id]

            if 'expires' not in session:
                del self.config['sessions'][session_id]
                continue

            if time.gmtime(session['expires']) < now:
                del self.config['sessions'][session_id]
                continue

    def _create_session(self, request, login='admin'):
        """
        Creates a new session.

        :param login: the username of the user logging in, currently \
        only for future use currently.
        :type login: string
        """
        m = hashlib.sha256()
        m.update(os.urandom(32))
        session_id = m.hexdigest()

        expires, expires_str = make_expires(self.config['session_timeout'])
        checksum = str(make_checksum(session_id))

        request.addCookie(
            '_session_id',
            session_id + checksum,
            path=request.base,
            expires=expires_str,
            secure=request.isSecure(),
            httpOnly=True,
            sameSite='lax',
        )

        log.debug('Creating session for %s', login)

        if isinstance(self.config['sessions'], list):
            self.config['sessions'] = {}
        self._clean_sessions()

        self.config['sessions'][session_id] = {
            'login': login,
            'level': AUTH_LEVEL_ADMIN,
            'expires': expires,
        }
        return True

    def check_password(self, password):
        config = self.config
        if 'pwd_sha1' not in config.config:
            log.debug('Failed to find config login details.')
            return False

        s = hashlib.sha1()
        s.update(config['pwd_salt'].encode('utf8'))
        s.update(password.encode('utf8'))
        return hmac.compare_digest(s.hexdigest(), config['pwd_sha1'])

    def has_session(self, request):
        """Return True if the request's session cookie names a current session.

        Unlike check_request, this does not renew the session.
        """
        cookie_sess_id = request.getCookie(b'_session_id')
        if not cookie_sess_id:
            return False
        session_id = get_session_id(cookie_sess_id.decode('utf8', 'replace'))
        if session_id not in self.config['sessions']:
            return False
        return self.config['sessions'][session_id].get('expires', 0) >= time.time()

    def check_request(self, request, method=None, level=None):
        """
        Check to ensure that a request is authorised to call the specified
        method of authentication level.

        :param request: The HTTP request in question
        :type request: twisted.web.http.Request
        :param method: Check the specified method
        :type method: function
        :param level: Check the specified auth level
        :type level: integer

        :raises: Exception
        """
        cookie_sess_id = request.getCookie(b'_session_id')
        if cookie_sess_id:
            session_id = get_session_id(cookie_sess_id.decode())
        else:
            session_id = None

        # _clean_sessions runs only every few seconds, so check expiry here too,
        # before the session is renewed.
        if (
            session_id in self.config['sessions']
            and self.config['sessions'][session_id].get('expires', 0) < time.time()
        ):
            del self.config['sessions'][session_id]

        if session_id not in self.config['sessions']:
            auth_level = AUTH_LEVEL_NONE
            session_id = None
        else:
            session = self.config['sessions'][session_id]
            auth_level = session['level']
            expires, expires_str = make_expires(self.config['session_timeout'])
            session['expires'] = expires

            _session_id = request.getCookie(b'_session_id')
            request.addCookie(
                '_session_id',
                _session_id,
                path=request.base,
                expires=expires_str,
                secure=request.isSecure(),
                httpOnly=True,
                sameSite='lax',
            )

        if method:
            if not hasattr(method, '_json_export'):
                raise Exception('Not an exported method')

            method_level = getattr(method, '_json_auth_level')
            if method_level is None:
                raise Exception('Method has no auth level')

            level = method_level

        if level is None:
            raise Exception('No level specified to check against')

        request.auth_level = auth_level
        request.session_id = session_id

        if auth_level < level:
            raise NotAuthorizedError(auth_level, level)

    def _change_password(self, new_password):
        """
        Change the password. This is to allow the UI to change/reset a
        password.

        :param new_password: the password to change to
        :type new_password: string
        """
        log.debug('Changing password')
        salt = hashlib.sha1(os.urandom(32)).hexdigest()
        s = hashlib.sha1(salt.encode('utf-8'))
        s.update(new_password.encode('utf8'))
        self.config['pwd_salt'] = salt
        self.config['pwd_sha1'] = s.hexdigest()
        return True

    @export
    def change_password(self, old_password, new_password):
        """
        Change the password.

        :param old_password: the current password
        :type old_password: string
        :param new_password: the password to change to
        :type new_password: string
        """
        client_ip = __request__.getClientIP()
        if self.login_limiter.check(client_ip):
            log.error(
                'Password change refused, too many failed tries (ClientIP %s)',
                client_ip,
            )
            return False
        if not self.check_password(old_password):
            self.login_limiter.failure(client_ip)
            return False
        self.login_limiter.success(client_ip)
        # Keep only the caller's session, so an old or stolen cookie stops working.
        for session_id in list(self.config['sessions']):
            if session_id != __request__.session_id:
                del self.config['sessions'][session_id]
        return self._change_password(new_password)

    @export(AUTH_LEVEL_NONE)
    def check_session(self, session_id=None):
        """
        Check a session to see if it's still valid.

        :returns: True if the session is valid, False if not.
        :rtype: booleon
        """
        return __request__.session_id is not None

    @export
    def delete_session(self):
        """
        Removes a session.

        :param session_id: the id for the session to remove
        :type session_id: string
        """
        del self.config['sessions'][__request__.session_id]
        return True

    @export(AUTH_LEVEL_NONE)
    def login(self, password):
        """
        Test a password to see if it's valid.

        :param password: the password to test
        :type password: string
        :returns: a session id or False
        :rtype: string or False
        """
        client_ip = __request__.getClientIP()
        wait = self.login_limiter.check(client_ip)
        if wait:
            # Refuse without checking the password, even a correct one.
            log.error(
                'Login refused, too many failed logins (ClientIP %s, %s seconds left)',
                client_ip,
                wait,
            )
            return False
        if self.check_password(password):
            self.login_limiter.success(client_ip)
            log.info('Login success (ClientIP %s)', client_ip)
            return self._create_session(__request__)
        else:
            self.login_limiter.failure(client_ip)
            log.error('Login failed (ClientIP %s)', client_ip)
            return False
