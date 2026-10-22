#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#
import pytest

from deluge.common import AUTH_LEVEL_ADMIN, AUTH_LEVEL_DEFAULT
from deluge_execute.core import Core


@pytest.mark.parametrize('method', ['add_command', 'save_command', 'remove_command'])
def test_command_changes_need_admin(method):
    # Commands run as the daemon user.
    assert getattr(Core, method)._rpcserver_auth_level == AUTH_LEVEL_ADMIN


def test_get_commands_needs_default_level():
    assert Core.get_commands._rpcserver_auth_level == AUTH_LEVEL_DEFAULT
