#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import time
from types import SimpleNamespace

from twisted.internet import defer

import deluge.ui.console.cmdline.commands.info as info_module
from deluge.ui.console.cmdline.commands.info import Command as InfoCommand
from deluge.ui.console.eventlog import EventLog
from deluge.ui.console.utils import colors
from deluge.ui.console.utils.security import sanitize_console_text


class FakeConsole:
    def __init__(self, torrent_name='torrent'):
        self.events = []
        self.interactive = False
        self.lines = []
        self.torrent_name = torrent_name

    def get_torrent_name(self, torrent_id):
        return self.torrent_name

    def match_torrent(self, _pattern):
        return []

    def set_batch_write(self, enabled):
        pass

    def write(self, line):
        self.lines.append(line)

    def write_event(self, line):
        self.events.append(line)


def test_sanitize_console_text_preserves_unicode_and_neutralizes_controls():
    value = 'safe\n\r\t\x00\x1b[31m\x85\u202e{!error!}雪'

    assert sanitize_console_text(value) == (
        r'safe\n\r\t\x00\x1b[31m\x85\u202e{\!error!\}雪'
    )


def test_info_peer_fields_cannot_inject_terminal_controls_or_color_tags():
    command = InfoCommand()
    command.console = FakeConsole()
    status = {
        'peers': [
            {
                'seed': True,
                'country': 'U\nS',
                'ip': '1.2.3.4:6881\x1b[2J',
                'client': '{!error!}bad\tclient',
                'up_speed': 0,
                'down_speed': 0,
            }
        ]
    }

    command.show_peer_info('a' * 40, status)

    output = command.console.lines[-1]
    assert '\n' not in output
    assert '\x1b' not in output
    assert '{!error!}' not in output
    assert r'U\nS' in output
    assert r'\x1b[2J' in output
    assert r'{\!error!\}bad\tclient' in output
    assert colors.state_color['Seeding'] in output


def test_info_status_file_and_id_fields_are_sanitized():
    command = InfoCommand()
    command.console = FakeConsole()
    status = {
        'name': 'name\n\x1b[2J{!error!}',
        'state': 'Paused',
        'total_done': 0,
        'total_size': 0,
        'all_time_download': 0,
        'total_uploaded': 0,
        'ratio': 0,
        'eta': 0,
        'seeding_time': 0,
        'active_time': 0,
        'time_since_transfer': 0,
        'last_seen_complete': 0,
        'tracker_host': 'tracker\rhost',
        'tracker_status': 'error\n{!success!}',
        'is_finished': True,
        'progress': 0,
        'download_location': '/tmp/\x1b[2J',
        'label': 'label\u202e',
        'files': [{'path': 'dir\n/{!error!}file\x1b[2J', 'size': 1}],
        'file_progress': [0],
        'file_priorities': [1],
    }

    command.show_info('id\n\x1b[2J{!error!}', status, verbose=True)
    command.show_file_info('a' * 40, status)

    output = '\n'.join(command.console.lines)
    assert '\x1b' not in output
    assert '{!error!}file' not in output
    assert r'name\n\x1b[2J{\!error!\}' in output
    assert r'error\n{\!success!\}' in output
    assert r'label\u202e' in output
    assert r'dir\n' in output
    assert r'{\!error!\}file\x1b[2J' in output
    assert r'id\n\x1b[2J{\!error!\}' in output


def test_info_rpc_failure_is_sanitized(monkeypatch):
    command = InfoCommand()
    console = FakeConsole()

    class FailingCore:
        def get_torrents_status(self, status_dict, keys):
            return defer.fail(Exception('failure\n\x1b[2J{!error!}'))

    monkeypatch.setattr(info_module.component, 'get', lambda _name: console)
    monkeypatch.setattr(info_module, 'client', SimpleNamespace(core=FailingCore()))
    options = SimpleNamespace(
        torrent_ids=[], sort='', sort_rev='', state=None, verbose=False, detailed=False
    )

    command.handle(options)

    assert r'failure\n\x1b[2J{\!error!\}' in console.lines[-1]
    assert '\n' not in console.lines[-1]
    assert '\x1b' not in console.lines[-1]


def test_event_log_sanitizes_names_but_preserves_its_color_markup():
    event_log = EventLog.__new__(EventLog)
    event_log.console = FakeConsole('bad\n\x1b[2J{!error!}')
    event_log.date_change_format = 'date'
    event_log.prefix = '{!event!}* '
    event_log.previous_time = time.localtime()

    event_log.on_torrent_state_changed('id\n\x1b[2J{!error!}', 'Downloading')

    output = event_log.console.events[-1]
    assert '\n' not in output
    assert '\x1b' not in output
    assert r'bad\n\x1b[2J{\!error!\}' in output
    assert r'id\n\x1b[2J{\!error!\}' in output
    assert colors.state_color['Downloading'] in output
