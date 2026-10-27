#
# Copyright (C) 2016 bendikro <bro.devel+deluge@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

import json as json_lib
import os
import socket
import time
from io import BytesIO

import pytest
import twisted.web.client
from twisted.internet import reactor, threads
from twisted.web.client import Agent, FileBodyProducer
from twisted.web.http_headers import Headers

import deluge.ui.web.server
from deluge.ui.web.auth import make_checksum
from deluge.ui.web.server import (
    MAX_BODY,
    MAX_UNAUTHENTICATED_BODY,
    STAGED_FILE_TIMEOUT,
    StagedFiles,
)

from . import common
from .common import get_test_data_file
from .common_web import WebServerMockBase, WebServerTestBase

common.disable_new_release_check()


def send_raw(port, data):
    """Send ``data`` on a new connection and return all of the reply."""
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.sendall(data)
        reply = b''
        while chunk := sock.recv(4096):
            reply += chunk
        return reply


def upload_request(files, cookie=None, length=None):
    """Make a POST /upload request with ``files``. ``length`` replaces the
    real Content-Length and sends no body."""
    body = b''.join(
        b'--xyzzy\r\nContent-Disposition: form-data; name="file"; '
        b'filename="%d.torrent"\r\n\r\n%s\r\n' % (index, data)
        for index, data in enumerate(files)
    )
    body += b'--xyzzy--\r\n'
    headers = [
        b'POST /upload HTTP/1.1',
        b'Host: 127.0.0.1',
        b'Connection: close',
        b'Content-Type: multipart/form-data; boundary=xyzzy',
        b'Content-Length: %d' % (len(body) if length is None else length),
    ]
    if cookie:
        headers.append(b'Cookie: ' + cookie)
    return b'\r\n'.join(headers) + b'\r\n\r\n' + (body if length is None else b'')


class TestStagedFiles:
    def stage(self, staged_files, tmp_path, name):
        tempdir = tmp_path / f'delugeweb-{name}'
        tempdir.mkdir()
        path = tempdir / f'{name}.torrent'
        path.write_bytes(b'data')
        staged_files.add(str(path), 4)
        return path

    def test_remove_after_timeout(self, tmp_path):
        """S03: a staged file and its dir are removed when they expire."""
        now = [0]
        staged_files = StagedFiles(clock=lambda: now[0])
        path = self.stage(staged_files, tmp_path, 'old')
        now[0] = STAGED_FILE_TIMEOUT - 1
        staged_files.remove_expired()
        assert path.exists()
        now[0] = STAGED_FILE_TIMEOUT
        staged_files.remove_expired()
        assert not path.parent.exists()
        assert not staged_files.files

    def test_remove_only_staged_paths(self, tmp_path):
        """S03: a path from the client that was not staged is not removed."""
        staged_files = StagedFiles()
        path = tmp_path / 'user.torrent'
        path.write_bytes(b'data')
        staged_files.remove(str(path))
        assert path.exists()

    def test_stop_removes_all(self, tmp_path):
        """S03: shutdown removes all staged files."""
        staged_files = StagedFiles()
        paths = [self.stage(staged_files, tmp_path, name) for name in ('a', 'b')]
        staged_files.stop()
        assert not any(path.parent.exists() for path in paths)

    def test_has_room(self, monkeypatch):
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_FILES', 2)
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_BYTES', 10)
        staged_files = StagedFiles()
        staged_files.add('/nonexistent/a', 6)
        assert staged_files.has_room(1, 4)
        assert not staged_files.has_room(1, 5)
        assert not staged_files.has_room(2, 0)

    def test_reservation_counts_toward_quota_and_commits(self, monkeypatch, tmp_path):
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_FILES', 2)
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_BYTES', 10)
        staged_files = StagedFiles()
        existing = self.stage(staged_files, tmp_path, 'existing')

        reservation = staged_files.reserve(6)
        assert reservation is not None
        assert staged_files.available_bytes() == 0
        assert not staged_files.has_room(1, 0)

        downloaded = tmp_path / 'downloaded.torrent'
        downloaded.write_bytes(b'data')
        staged_files.commit(reservation, str(downloaded), 4)

        assert reservation not in staged_files.reservations
        assert staged_files.available_bytes() == 2
        assert set(staged_files.files) == {str(existing), str(downloaded)}

    def test_release_reservation_restores_quota(self, monkeypatch):
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_FILES', 1)
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_BYTES', 10)
        staged_files = StagedFiles()

        reservation = staged_files.reserve(10)
        assert reservation is not None
        assert not staged_files.has_room(1, 0)
        staged_files.release(reservation)
        assert staged_files.has_room(1, 10)


class TestWebServer(WebServerTestBase, WebServerMockBase):
    def test_session_cleaner_runs(self):
        """S09: the web server starts and stops the session cleaner."""
        assert self.deluge_web.auth.worker.running
        self.deluge_web.stop()
        assert not self.deluge_web.auth.worker.running

    def session_cookie(self):
        """Add a web session and return its cookie."""
        session_id = 'a' * 64
        self.deluge_web.auth.config['sessions'][session_id] = {
            'login': 'admin',
            'level': 10,
            'expires': time.time() + 3600,
        }
        return b'_session_id=%s%d' % (session_id.encode(), make_checksum(session_id))

    async def send(self, data):
        return await threads.deferToThread(send_raw, self.deluge_web.port, data)

    async def test_body_without_session_refused_before_read(self):
        """S03: a large body without a session is refused before it is sent."""
        reply = await self.send(upload_request([], length=MAX_UNAUTHENTICATED_BODY + 1))
        assert reply.startswith(b'HTTP/1.1 413 ')

    @pytest.mark.parametrize('bare_newline', [b'\r', b'\n'])
    async def test_header_value_rejects_bare_newline(self, bare_newline):
        """CVE-2026-115877: a header value cannot hide a second header."""
        request = (
            b'POST /json HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Test: visible'
            + bare_newline
            + b'Content-Length: 39\r\nConnection: close\r\n\r\n'
            + b'GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
        )
        reply = await self.send(request)
        assert reply.startswith(b'HTTP/1.1 400 ')

    async def test_chunked_body_without_session_refused(self):
        """S03: a chunked body without a session stops at the limit."""
        size = MAX_UNAUTHENTICATED_BODY + 1
        request = (
            b'POST /json HTTP/1.1\r\nHost: 127.0.0.1\r\n'
            b'Transfer-Encoding: chunked\r\n\r\n'
            b'%x\r\n%s\r\n0\r\n\r\n' % (size, b'x' * size)
        )
        reply = await self.send(request)
        assert reply.startswith(b'HTTP/1.1 413 ')

    async def test_body_with_session_limit(self):
        """S03: a logged-in client has the larger limit."""
        cookie = self.session_cookie()
        reply = await self.send(upload_request([], cookie, length=MAX_BODY + 1))
        assert reply.startswith(b'HTTP/1.1 413 ')

    async def test_upload_without_session(self):
        """S03: an upload without a session stages no file."""
        reply = await self.send(upload_request([b'data']))
        assert reply.startswith(b'HTTP/1.1 401 ')
        assert not self.deluge_web.staged_files.files

    async def test_upload_staged_and_used(self):
        """S03: an upload is staged, and web.add_torrents removes it after use."""
        with open(get_test_data_file('test.torrent'), 'rb') as _file:
            data = _file.read()
        reply = await self.send(upload_request([data], self.session_cookie()))
        assert reply.startswith(b'HTTP/1.1 200 ')
        path = json_lib.loads(reply.split(b'\r\n\r\n', 1)[1])['files'][0]
        assert path in self.deluge_web.staged_files.files

        await self.deluge_web.web_api.connect(self.host_id)
        await self.deluge_web.web_api.add_torrents([{'path': path, 'options': {}}])
        assert not self.deluge_web.staged_files.files
        assert not os.path.exists(os.path.dirname(path))

    async def test_upload_too_many_files(self, monkeypatch):
        """S03: an upload over the staged file limit stages no file."""
        monkeypatch.setattr(deluge.ui.web.server, 'MAX_STAGED_FILES', 2)
        cookie = self.session_cookie()
        reply = await self.send(upload_request([b'a', b'b', b'c'], cookie))
        assert reply.startswith(b'HTTP/1.1 413 ')
        assert not self.deluge_web.staged_files.files

        reply = await self.send(upload_request([b'a', b'b'], cookie))
        assert reply.startswith(b'HTTP/1.1 200 ')
        assert len(self.deluge_web.staged_files.files) == 2

    async def test_stop_removes_staged_files(self):
        """S03: stopping the web server removes staged files."""
        reply = await self.send(upload_request([b'data'], self.session_cookie()))
        path = json_lib.loads(reply.split(b'\r\n\r\n', 1)[1])['files'][0]
        assert os.path.exists(path)
        self.deluge_web.stop()
        assert not os.path.exists(path)

    async def test_get_torrent_info(self):
        agent = Agent(reactor)

        self.mock_authentication_ignore(self.deluge_web.auth)

        # This torrent file contains an uncommon field 'filehash' which must be hex
        # encoded to allow dumping the torrent info to json. Otherwise it will fail with:
        # UnicodeDecodeError: 'utf8' codec can't decode byte 0xe5 in position 0: invalid continuation byte
        filename = get_test_data_file('filehash_field.torrent')
        input_file = (
            '{"params": ["%s"], "method": "web.get_torrent_info", "id": 22}'
            % filename.replace('\\', '\\\\')
        )
        headers = {
            b'User-Agent': ['Twisted Web Client Example'],
            b'Content-Type': ['application/json'],
        }
        url = 'http://127.0.0.1:%s/json' % self.deluge_web.port

        response = await agent.request(
            b'POST',
            url.encode(),
            Headers(headers),
            FileBodyProducer(BytesIO(input_file.encode())),
        )
        body = await twisted.web.client.readBody(response)

        json = json_lib.loads(body.decode())
        assert json['error'] is None
        assert 'torrent_filehash' == json['result']['name']

    @pytest.mark.parametrize('base', ['', '/', 'deluge'])
    async def test_base_with_config(self, base):
        agent = Agent(reactor)
        root_url = f'http://127.0.0.1:{self.deluge_web.port}'
        base_url = f'{root_url}/{base}'

        self.deluge_web.base = base

        response = await agent.request(b'GET', root_url.encode())
        assert response.code == 200
        body = await twisted.web.client.readBody(response)
        assert 'Deluge WebUI' in body.decode()

        response = await agent.request(b'GET', base_url.encode())
        assert response.code == 200

    @pytest.mark.parametrize('base', ['/', 'deluge'])
    async def test_base_with_config_recurring_basepath(self, base):
        agent = Agent(reactor)
        base_url = f'http://127.0.0.1:{self.deluge_web.port}/{base}'

        self.deluge_web.base = base

        response = await agent.request(b'GET', base_url.encode())
        assert response.code == 200

        recursive_url = f'{base_url}/{base}'
        response = await agent.request(b'GET', recursive_url.encode())
        assert response.code == 404 if base.strip('/') else 200

        recursive_url = f'{recursive_url}/{base}'
        response = await agent.request(b'GET', recursive_url.encode())
        assert response.code == 404 if base.strip('/') else 200

    async def test_base_with_deluge_header(self):
        """Ensure base path is set and HTML contains path"""
        agent = Agent(reactor)
        base = 'deluge'
        url = f'http://127.0.0.1:{self.deluge_web.port}'
        headers = Headers({'X-Deluge-Base': [base]})

        response = await agent.request(b'GET', url.encode(), headers)
        body = await twisted.web.client.readBody(response)
        assert f'href="/{base}/' in body.decode()

        # Header only changes HTML base path so ensure no resource at server path
        url = f'{url}/{base}'
        response = await agent.request(b'GET', url.encode(), headers)
        assert response.code == 404
