"""Validation helpers for network endpoints supplied by torrent metadata or RPCs."""

import ipaddress
import socket
import unicodedata
from typing import Iterable, List, Sequence, Tuple
from urllib.parse import urlsplit

from twisted.internet import defer, reactor, threads
from twisted.python.failure import Failure
from twisted.python.threadpool import ThreadPool

MAX_TRACKERS_PER_TORRENT = 32
MAX_WEB_SEEDS_PER_TORRENT = 16
MAX_NETWORK_URL_LENGTH = 2048
MAX_MAGNET_URI_LENGTH = 8192
MAX_PREFETCHES = 8
MAX_PREFETCH_WAITERS = 32
MAX_PREFETCH_TIMEOUT = 60

TRACKER_SCHEMES = frozenset({'http', 'https', 'udp', 'ws', 'wss'})
WEB_SEED_SCHEMES = frozenset({'http', 'https'})

_LOCAL_HOST_SUFFIXES = ('.localhost', '.local', '.lan', '.home', '.internal')
_DNS_LOOKUP_LIMIT = 8
_DNS_LOOKUP_TIMEOUT = 5
_DNS_POOL = ThreadPool(
    minthreads=0, maxthreads=_DNS_LOOKUP_LIMIT, name='network-policy-dns'
)
_DNS_POOL_STARTED = False
_DNS_ACTIVE = 0


def sanitize_log_value(value, max_length: int = 256) -> str:
    """Return bounded, single-line text safe to interpolate into a log record."""

    if isinstance(value, bytes):
        text = value.decode('utf8', errors='replace')
    else:
        try:
            text = str(value)
        except Exception:  # pragma: no cover - defensive against extension objects
            return '<unprintable>'
    truncated = len(text) > max_length
    text = text[:max_length]
    escaped = []
    for char in text:
        if (
            char in '\r\n\t'
            or unicodedata.category(char).startswith('C')
            or (char.isspace() and char != ' ')
        ):
            escaped.append(ascii(char)[1:-1])
        else:
            escaped.append(char)
    if truncated:
        escaped.append('...')
    return ''.join(escaped)


def network_url_log_label(value) -> str:
    """Return a URL origin for logs without paths, queries, or credentials."""

    try:
        url = _decode_url(value)
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError):
        return '<invalid-network-url>'
    if not parsed.scheme or not hostname:
        return '<invalid-network-url>'
    if ':' in hostname:
        hostname = f'[{hostname}]'
    origin = f'{parsed.scheme.lower()}://{hostname}'
    if port is not None:
        origin += f':{port}'
    return sanitize_log_value(origin)


def _decode_url(value) -> str:
    if isinstance(value, bytes):
        return value.decode('utf8')
    if isinstance(value, str):
        return value
    raise ValueError('URL must be text')


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    # Python classifies some multicast ranges as globally scoped. They are not
    # valid remote service destinations for this policy.
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not getattr(address, 'is_site_local', False)
    )


def _normalize_hostname(hostname: str) -> str:
    hostname = hostname.rstrip('.').lower()
    if '%' in hostname:
        raise ValueError('Scoped or escaped hostnames are not allowed')
    if not hostname.isascii():
        raise ValueError('Hostname must use ASCII IDNA form')
    try:
        return hostname.encode('idna').decode('ascii')
    except UnicodeError as ex:
        raise ValueError('Hostname is not valid IDNA') from ex


def _literal_address(hostname: str):
    """Parse strict and legacy numeric IP spellings without doing DNS."""

    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    if ':' in hostname:
        return None
    try:
        return ipaddress.ip_address(socket.inet_aton(hostname))
    except OSError:
        return None


def _host_is_allowed(hostname: str, allow_private: bool) -> bool:
    try:
        hostname = _normalize_hostname(hostname)
    except ValueError:
        return False
    if allow_private:
        return True
    if hostname == 'localhost' or hostname.endswith(_LOCAL_HOST_SUFFIXES):
        return False

    address = _literal_address(hostname)
    return _is_public_address(str(address)) if address is not None else True


def _resolved_addresses_are_public(results) -> bool:
    addresses = {result[4][0] for result in results}
    try:
        return bool(addresses) and all(
            _is_public_address(address) for address in addresses
        )
    except ValueError:
        return False


def validate_resolved_network_url(
    value,
    *,
    kind: str,
    allow_private: bool = False,
    include_addresses: bool = False,
):
    """Validate a URL and asynchronously require public DNS results.

    At most eight application DNS checks may be active. Additional checks are
    rejected rather than queued, keeping attacker-selected resolver work
    bounded without blocking the reactor.
    """

    url = validate_network_url(value, kind=kind, allow_private=allow_private)
    hostname = _normalize_hostname(urlsplit(url).hostname)
    literal_address = _literal_address(hostname)

    def result(addresses):
        addresses = tuple(dict.fromkeys(addresses))
        return (url, hostname, addresses) if include_addresses else url

    if literal_address is not None:
        return defer.succeed(result((str(literal_address),)))

    global _DNS_ACTIVE, _DNS_POOL_STARTED
    if _DNS_ACTIVE >= _DNS_LOOKUP_LIMIT:
        return defer.fail(ValueError('Too many network hostname lookups are active'))

    if not _DNS_POOL_STARTED:
        _DNS_POOL.start()
        reactor.addSystemEventTrigger('before', 'shutdown', _DNS_POOL.stop)
        _DNS_POOL_STARTED = True

    _DNS_ACTIVE += 1
    lookup = threads.deferToThreadPool(
        reactor,
        _DNS_POOL,
        socket.getaddrinfo,
        hostname,
        None,
        0,
        socket.SOCK_STREAM,
    )
    outward = defer.Deferred(lambda _deferred: None)
    timeout_call = reactor.callLater(
        _DNS_LOOKUP_TIMEOUT,
        outward.errback,
        ValueError('Network hostname lookup timed out'),
    )

    def stop_timeout(result):
        if timeout_call.active():
            timeout_call.cancel()
        return result

    outward.addBoth(stop_timeout)

    def finish_lookup(outcome):
        global _DNS_ACTIVE
        _DNS_ACTIVE -= 1
        if timeout_call.active():
            timeout_call.cancel()
        if not outward.called:
            if isinstance(outcome, Failure):
                outward.errback(outcome)
            else:
                outward.callback(outcome)
        # Consume failures here; the outward Deferred carries the result.
        return None

    lookup.addBoth(finish_lookup)

    def check_results(results):
        addresses = tuple(dict.fromkeys(item[4][0] for item in results))
        if not addresses or (
            not allow_private and not _resolved_addresses_are_public(results)
        ):
            raise ValueError('Private or unresolved destination is not allowed')
        return result(addresses)

    outward.addCallback(check_results)
    outward.addErrback(
        lambda failure: (
            failure
            if failure.check(ValueError)
            else defer.fail(ValueError('Unable to resolve network destination'))
        )
    )
    return outward


def validate_network_url(value, *, kind: str, allow_private: bool = False) -> str:
    """Return a validated tracker or web-seed URL.

    Literal private, loopback, link-local, multicast, unspecified and reserved
    destinations and conventional local hostnames are denied unless
    ``allow_private`` is explicitly enabled. Hostname resolution is left to
    the asynchronous HTTP policy or libtorrent's connection-time policy.
    """

    url = _decode_url(value)
    try:
        url_length = len(url.encode('utf8'))
    except UnicodeError as ex:
        raise ValueError('URL is not valid UTF-8') from ex
    if not url or url_length > MAX_NETWORK_URL_LENGTH:
        raise ValueError('URL is empty or too long')
    if has_unsafe_url_chars(url):
        raise ValueError('URL contains whitespace or control characters')

    parsed = urlsplit(url)
    if kind == 'tracker':
        schemes = TRACKER_SCHEMES
    elif kind == 'web_seed':
        schemes = WEB_SEED_SCHEMES
    else:
        raise ValueError(f'Unknown network URL kind: {kind}')
    if parsed.scheme.lower() not in schemes:
        raise ValueError(f'Unsupported {kind} URL scheme')
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f'Invalid {kind} URL authority')
    try:
        port = parsed.port
    except ValueError as ex:
        raise ValueError(f'Invalid {kind} URL port') from ex
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f'Invalid {kind} URL port')
    if not _host_is_allowed(parsed.hostname, allow_private):
        raise ValueError(f'Private or invalid {kind} destination is not allowed')
    return url


def has_unsafe_url_chars(value: str) -> bool:
    """Return whether URL-like text contains whitespace or Unicode controls."""

    return any(char.isspace() for char in value) or has_unicode_controls(value)


def has_unicode_controls(value: str) -> bool:
    """Return whether text contains a Unicode control or formatting code."""

    return any(unicodedata.category(char).startswith('C') for char in value)


def filter_network_urls(
    values: Iterable, *, kind: str, allow_private: bool, limit: int
) -> List:
    """Filter and cap URL values, preserving their original text/bytes type."""

    accepted = []
    seen = set()
    for index, value in enumerate(values):
        if len(accepted) >= limit or index >= limit * 4:
            break
        try:
            url = validate_network_url(value, kind=kind, allow_private=allow_private)
        except (UnicodeError, ValueError):
            continue
        if url in seen:
            continue
        seen.add(url)
        accepted.append(value)
    return accepted


def filter_tracker_tiers(
    trackers: Sequence, tiers: Sequence[int], *, allow_private: bool
) -> Tuple[List, List[int]]:
    """Filter parallel tracker/tier arrays while preserving their association."""

    accepted_trackers = []
    accepted_tiers = []
    seen = set()
    for index, value in enumerate(trackers):
        if (
            len(accepted_trackers) >= MAX_TRACKERS_PER_TORRENT
            or index >= MAX_TRACKERS_PER_TORRENT * 4
        ):
            break
        try:
            url = validate_network_url(
                value, kind='tracker', allow_private=allow_private
            )
        except (UnicodeError, ValueError):
            continue
        if url in seen:
            continue
        try:
            tier = int(tiers[index]) if index < len(tiers) else 0
        except (TypeError, ValueError):
            tier = 0
        if not 0 <= tier <= 255:
            tier = 0
        seen.add(url)
        accepted_trackers.append(value)
        accepted_tiers.append(tier)
    return accepted_trackers, accepted_tiers


def sanitize_torrent_metainfo(metainfo: dict, *, allow_private: bool) -> dict:
    """Remove disallowed tracker and web-seed endpoints from decoded metainfo."""

    announce = metainfo.get(b'announce')
    announce_list = metainfo.get(b'announce-list', [])
    tracker_tiers = []
    tracker_count = 0
    tracker_candidates = 0
    seen = set()

    for tier in announce_list if isinstance(announce_list, list) else []:
        if not isinstance(tier, list):
            continue
        accepted_tier = []
        for value in tier:
            if (
                tracker_count >= MAX_TRACKERS_PER_TORRENT
                or tracker_candidates >= MAX_TRACKERS_PER_TORRENT * 4
            ):
                break
            tracker_candidates += 1
            try:
                url = validate_network_url(
                    value, kind='tracker', allow_private=allow_private
                )
            except (UnicodeError, ValueError):
                continue
            if url in seen:
                continue
            seen.add(url)
            accepted_tier.append(value)
            tracker_count += 1
        if accepted_tier:
            tracker_tiers.append(accepted_tier)
        if tracker_candidates >= MAX_TRACKERS_PER_TORRENT * 4:
            break

    if announce is not None and tracker_count < MAX_TRACKERS_PER_TORRENT:
        try:
            announce_url = validate_network_url(
                announce, kind='tracker', allow_private=allow_private
            )
        except (UnicodeError, ValueError):
            announce = None
        else:
            if announce_url not in seen:
                tracker_tiers.insert(0, [announce])
                tracker_count += 1

    if tracker_tiers:
        metainfo[b'announce-list'] = tracker_tiers
        metainfo[b'announce'] = tracker_tiers[0][0]
    else:
        metainfo.pop(b'announce-list', None)
        metainfo.pop(b'announce', None)

    for key in (b'url-list', b'httpseeds'):
        values = metainfo.get(key)
        if values is None:
            continue
        was_scalar = isinstance(values, (bytes, str))
        if was_scalar:
            values = [values]
        if not isinstance(values, list):
            metainfo.pop(key, None)
            continue
        accepted = filter_network_urls(
            values,
            kind='web_seed',
            allow_private=allow_private,
            limit=MAX_WEB_SEEDS_PER_TORRENT,
        )
        if accepted:
            metainfo[key] = accepted[0] if was_scalar else accepted
        else:
            metainfo.pop(key, None)

    return metainfo


def validate_peer_endpoint(host: str, port, *, allow_private: bool = False):
    """Return a validated numeric peer endpoint."""

    if not isinstance(host, str) or isinstance(port, bool):
        return None
    if isinstance(port, str):
        if not port.isascii() or not port.isdecimal():
            return None
    elif not isinstance(port, int):
        return None
    try:
        address = ipaddress.ip_address(host)
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    if not allow_private and not _is_public_address(str(address)):
        return None
    return str(address), port
