#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import time
from unittest.mock import Mock, patch

import pytest

from deluge.common import AUTH_LEVEL_ADMIN, AUTH_LEVEL_DEFAULT
from deluge.error import NotAuthorizedError
from deluge.ui.web import auth


class MockConfig:
    def __init__(self, config):
        self.config = config

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, value):
        self.config[key] = value


class TestWebAuth:
    @patch('deluge.ui.web.auth.JSONComponent.__init__', return_value=None)
    def test_change_password(self, mock_json):
        config = MockConfig(
            {
                'pwd_sha1': '8d8ff487626141d2b91025901d3ab57211180b48',
                'pwd_salt': '7555d757710158655bd1646e207dee21a89e9226',
                'sessions': {},
            }
        )
        webauth = auth.Auth(config)
        with patch.object(auth, '__request__', Mock(session_id=None), create=True):
            assert webauth.change_password('deluge', 'deluge_new')

    @patch('deluge.ui.web.auth.JSONComponent.__init__', return_value=None)
    def test_change_password_ends_other_sessions(self, mock_json):
        expires = time.time() + 3600
        config = MockConfig(
            {
                'pwd_sha1': '8d8ff487626141d2b91025901d3ab57211180b48',
                'pwd_salt': '7555d757710158655bd1646e207dee21a89e9226',
                'sessions': {
                    'mine': {'level': AUTH_LEVEL_ADMIN, 'expires': expires},
                    'other': {'level': AUTH_LEVEL_ADMIN, 'expires': expires},
                },
            }
        )
        webauth = auth.Auth(config)
        with patch.object(auth, '__request__', Mock(session_id='mine'), create=True):
            assert webauth.change_password('deluge', 'deluge_new')
        assert list(config['sessions']) == ['mine']

    @patch('deluge.ui.web.auth.JSONComponent.__init__', return_value=None)
    def test_check_request_rejects_expired_session(self, mock_json):
        session_id = 'a' * 64
        config = MockConfig(
            {
                'session_timeout': 3600,
                'sessions': {
                    session_id: {'level': AUTH_LEVEL_ADMIN, 'expires': time.time() - 1}
                },
            }
        )
        webauth = auth.Auth(config)
        cookie = (session_id + str(auth.make_checksum(session_id))).encode()
        request = Mock(base=b'/')
        request.getCookie.return_value = cookie

        with pytest.raises(NotAuthorizedError):
            webauth.check_request(request, level=AUTH_LEVEL_DEFAULT)
        assert session_id not in config['sessions']
        request.addCookie.assert_not_called()
