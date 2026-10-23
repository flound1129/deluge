#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#

"""Pinned TLS certificates of the daemons that this UI connects to.

A daemon makes its own self-signed certificate, so no CA can vouch for it. The
UI trusts the certificate that a daemon shows at the first connection to its
host and port, like SSH known_hosts, and refuses a different certificate later.
Removing the last host-list entry for that host and port forgets its certificate.

This trust-on-first-use design cannot detect an attacker who intercepts the
first connection. Users should verify the first fingerprint out of band when
that threat matters. The fingerprint is written to ``daemon_certs.conf`` and
the UI's info log when it is first pinned.
"""

import logging
import os
from contextlib import contextmanager

if os.name == 'nt':  # pragma: no cover - exercised on Windows
    import msvcrt
else:
    import fcntl

from deluge.config import Config
from deluge.configmanager import get_config_dir

log = logging.getLogger(__name__)

CONFIG_FILE = 'daemon_certs.conf'
LOCK_FILE = f'{CONFIG_FILE}.lock'


def _load():
    return Config(CONFIG_FILE, {'certificates': {}}, config_dir=get_config_dir())


def _lock_file(lock_file):
    """Take an exclusive OS lock, released automatically if the process exits."""
    if os.name == 'nt':  # pragma: no cover - exercised on Windows
        # msvcrt.locking locks bytes rather than the file as a whole. Ensure the
        # byte exists, then always lock the first byte.
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b'\0')
            lock_file.flush()
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)


def _unlock_file(lock_file):
    if os.name == 'nt':  # pragma: no cover - exercised on Windows
        lock_file.seek(0)
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextmanager
def _locked_config():
    """Load the latest pin set while holding a cross-process lock."""
    lock_path = get_config_dir(LOCK_FILE)
    with open(lock_path, 'a+b') as lock_file:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        _lock_file(lock_file)
        try:
            # Loading inside the lock makes each update a read-modify-write of
            # the newest file, preventing concurrent UIs from losing pins.
            yield _load()
        finally:
            _unlock_file(lock_file)


def _key(host, port):
    return f'{host}:{port}'


def check(host, port, fingerprint):
    """Check the certificate of the daemon at host:port.

    Args:
        host (str): The host as given to the client.
        port (int): The daemon port.
        fingerprint (str): The SHA-256 fingerprint of the daemon certificate.

    Returns:
        bool: True if ``fingerprint`` is the pinned one. If host:port has no pin
            yet, ``fingerprint`` is pinned and True is returned.
    """
    with _locked_config() as config:
        pinned = config['certificates'].get(_key(host, port))
        if pinned is None:
            log.info(
                'Pinning the certificate of the daemon at %s:%s: SHA-256 %s',
                host,
                port,
                fingerprint,
            )
            config['certificates'][_key(host, port)] = fingerprint
            if not config.save():
                raise OSError('Unable to save daemon certificate pin')
            return True
        return pinned == fingerprint


def get(host, port):
    """Return the pinned fingerprint of host:port, or None."""
    with _locked_config() as config:
        return config['certificates'].get(_key(host, port))


def forget(host, port):
    """Remove the pin of host:port, so the next connection pins again."""
    with _locked_config() as config:
        if config['certificates'].pop(_key(host, port), None) is not None:
            log.info('Forgot the certificate of the daemon at %s:%s', host, port)
            if not config.save():
                raise OSError('Unable to save daemon certificate pins')
