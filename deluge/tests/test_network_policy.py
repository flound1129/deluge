from unittest import mock

import pytest

from deluge.common import AUTH_LEVEL_ADMIN, AUTH_LEVEL_NORMAL
from deluge.core.core import Core
from deluge.core.network_policy import (
    MAX_NETWORK_URL_LENGTH,
    MAX_TRACKERS_PER_TORRENT,
    MAX_WEB_SEEDS_PER_TORRENT,
    filter_tracker_tiers,
    network_url_log_label,
    sanitize_log_value,
    sanitize_torrent_metainfo,
    validate_network_url,
    validate_peer_endpoint,
    validate_resolved_network_url,
)
from deluge.core.preferencesmanager import PreferencesManager
from deluge.error import NotAuthorizedError


@pytest.mark.parametrize(
    'url',
    [
        'http://127.0.0.1/announce',
        'https://10.0.0.1/announce',
        'udp://169.254.1.1:80/announce',
        'ws://224.0.0.1/announce',
        'http://0.0.0.0/announce',
        'http://[fec0::1]/announce',
        'http://localhost/announce',
        'http://tracker.local/announce',
    ],
)
def test_validate_network_url_rejects_non_global_destinations(url):
    with pytest.raises(ValueError):
        validate_network_url(url, kind='tracker')


def test_validate_network_url_accepts_public_destination():
    assert (
        validate_network_url('https://8.8.8.8/announce', kind='tracker')
        == 'https://8.8.8.8/announce'
    )


def test_validate_network_url_does_not_block_on_dns():
    with mock.patch(
        'deluge.core.network_policy.socket.getaddrinfo',
        side_effect=AssertionError('synchronous validation must not resolve'),
    ):
        assert validate_network_url('https://tracker.example/announce', kind='tracker')


async def test_validate_resolved_network_url_rejects_private_dns_results():
    with mock.patch(
        'deluge.core.network_policy.socket.getaddrinfo',
        return_value=[(None, None, None, None, ('93.184.216.34', 0))],
    ):
        assert await validate_resolved_network_url(
            'https://tracker.example/announce', kind='tracker'
        )

    with mock.patch(
        'deluge.core.network_policy.socket.getaddrinfo',
        return_value=[(None, None, None, None, ('192.168.1.10', 0))],
    ):
        with pytest.raises(ValueError):
            await validate_resolved_network_url(
                'https://tracker.example/announce', kind='tracker'
            )

    with mock.patch(
        'deluge.core.network_policy.socket.getaddrinfo',
        return_value=[
            (None, None, None, None, ('93.184.216.34', 0)),
            (None, None, None, None, ('127.0.0.1', 0)),
        ],
    ):
        with pytest.raises(ValueError):
            await validate_resolved_network_url(
                'https://tracker.example/announce', kind='tracker'
            )


@pytest.mark.parametrize(
    'url,kind',
    [
        ('file:///etc/passwd', 'web_seed'),
        ('ftp://8.8.8.8/file', 'web_seed'),
        ('http://user:password@8.8.8.8/announce', 'tracker'),
        ('http://8.8.8.8:0/announce', 'tracker'),
        ('http://8.8.8.8/\nannounce', 'tracker'),
        ('http://8.8.8.8/a b', 'tracker'),
        ('http://8.8.8.8/\x00announce', 'tracker'),
        ('http://8.8.8.8/\u202eannounce', 'tracker'),
        ('http://2130706433/announce', 'tracker'),
        ('http://127.1/announce', 'tracker'),
        ('http://0x7f000001/announce', 'tracker'),
        ('http://[fe80::1%25lo0]/announce', 'tracker'),
        ('http://ｅｘａｍｐｌｅ.com/announce', 'tracker'),
        ('http://8.8.8.8/' + 'a' * MAX_NETWORK_URL_LENGTH, 'tracker'),
    ],
)
def test_validate_network_url_rejects_malformed_urls(url, kind):
    with pytest.raises(ValueError):
        validate_network_url(url, kind=kind)


def test_private_tracker_escape_hatch_still_validates_url_shape():
    assert validate_network_url(
        'http://127.0.0.1/announce', kind='tracker', allow_private=True
    )
    with pytest.raises(ValueError):
        validate_network_url('file:///etc/passwd', kind='tracker', allow_private=True)


def test_sanitize_torrent_metainfo_filters_and_caps_network_resources():
    trackers = [f'https://8.8.8.8/{index}'.encode() for index in range(40)]
    metainfo = {
        b'info': {b'name': b'test'},
        b'announce': b'http://127.0.0.1/announce',
        b'announce-list': [[b'http://10.0.0.1/announce'], trackers],
        b'url-list': [
            b'http://127.0.0.1/file',
            *[f'https://8.8.4.4/{index}'.encode() for index in range(20)],
        ],
        b'httpseeds': b'http://[::1]/file',
    }

    sanitize_torrent_metainfo(metainfo, allow_private=False)

    assert len(metainfo[b'announce-list'][0]) == MAX_TRACKERS_PER_TORRENT
    assert metainfo[b'announce'] == trackers[0]
    assert len(metainfo[b'url-list']) == MAX_WEB_SEEDS_PER_TORRENT
    assert b'httpseeds' not in metainfo


def test_sanitize_torrent_metainfo_private_escape_hatch():
    metainfo = {
        b'info': {b'name': b'test'},
        b'announce': b'http://127.0.0.1/announce',
        b'url-list': b'http://10.0.0.1/file',
    }
    sanitize_torrent_metainfo(metainfo, allow_private=True)
    assert metainfo[b'announce'] == b'http://127.0.0.1/announce'
    assert metainfo[b'url-list'] == b'http://10.0.0.1/file'


def test_filter_tracker_tiers_keeps_tiers_aligned():
    trackers, tiers = filter_tracker_tiers(
        ['http://127.0.0.1/a', 'https://8.8.8.8/b'],
        [4, 7],
        allow_private=False,
    )
    assert trackers == ['https://8.8.8.8/b']
    assert tiers == [7]


def test_validate_peer_endpoint():
    assert validate_peer_endpoint('8.8.8.8', '443') == ('8.8.8.8', 443)
    assert validate_peer_endpoint('127.0.0.1', 443) is None
    assert validate_peer_endpoint('224.0.0.1', 443) is None
    assert validate_peer_endpoint('127.0.0.1', 443, allow_private=True) == (
        '127.0.0.1',
        443,
    )
    assert validate_peer_endpoint('tracker.example', 443) is None
    assert validate_peer_endpoint('8.8.8.8', 0) is None
    assert validate_peer_endpoint('8.8.8.8', True) is None
    assert validate_peer_endpoint('8.8.8.8', 443.5) is None
    assert validate_peer_endpoint(0x08080808, 443) is None


@pytest.mark.parametrize(
    'auth_level,allow_private',
    [(AUTH_LEVEL_NORMAL, False), (AUTH_LEVEL_ADMIN, True)],
)
def test_core_connect_peer_only_allows_admin_private_access(auth_level, allow_private):
    torrent = mock.Mock()
    torrent.connect_peer.return_value = True
    core = object.__new__(Core)
    core.torrentmanager = {'torrent-id': torrent}
    rpcserver = mock.Mock()
    rpcserver.get_session_auth_level.return_value = auth_level

    with mock.patch('deluge.core.core.component.get', return_value=rpcserver):
        core.connect_peer('torrent-id', '127.0.0.1', 6881)

    torrent.connect_peer.assert_called_once_with(
        '127.0.0.1', 6881, allow_private=allow_private
    )


def test_private_tracker_escape_hatch_requires_admin():
    core = object.__new__(Core)
    core.config = {}
    core.read_only_config_keys = None
    rpcserver = mock.Mock()
    rpcserver.get_session_auth_level.return_value = AUTH_LEVEL_NORMAL

    with mock.patch('deluge.core.core.component.get', return_value=rpcserver):
        with pytest.raises(NotAuthorizedError):
            core.set_config({'allow_private_trackers': True})

    assert 'allow_private_trackers' not in core.config

    rpcserver.get_session_auth_level.return_value = AUTH_LEVEL_ADMIN
    with mock.patch('deluge.core.core.component.get', return_value=rpcserver):
        core.set_config({'allow_private_trackers': True})
    assert core.config['allow_private_trackers'] is True

    with mock.patch('deluge.core.core.component.get', return_value=rpcserver):
        with pytest.raises(ValueError, match='must be a boolean'):
            core.set_config({'allow_private_trackers': 'false'})


@pytest.mark.parametrize(
    'allow_private,ssrf_mitigation', [(False, True), (True, False)]
)
def test_private_tracker_escape_hatch_updates_libtorrent_policy(
    allow_private, ssrf_mitigation
):
    preferences = object.__new__(PreferencesManager)
    preferences.core = mock.Mock()
    torrentmanager = mock.Mock()
    torrentmanager.torrents = {}
    with mock.patch(
        'deluge.core.preferencesmanager.component.get',
        return_value=torrentmanager,
    ):
        preferences._on_set_allow_private_trackers(
            'allow_private_trackers', allow_private
        )
    preferences.core.apply_session_setting.assert_called_once_with(
        'ssrf_mitigation', ssrf_mitigation
    )


def test_sanitize_log_value_is_bounded_and_single_line():
    value = 'tracker\nforged\tentry\x1b[31m\u202espoof' + 'x' * 300
    sanitized = sanitize_log_value(value)
    assert sanitized.startswith(r'tracker\nforged\tentry\x1b[31m\u202espoof')
    assert sanitized.endswith('...')
    assert '\n' not in sanitized
    assert '\r' not in sanitized


def test_network_url_log_label_omits_sensitive_url_components():
    label = network_url_log_label(
        'https://tracker.example:8443/private-passkey/announce?token=secret'
    )
    assert label == 'https://tracker.example:8443'
