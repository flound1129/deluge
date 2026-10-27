# Squall tracker and peer connection security audit

- **Date:** 2026-10-25
- **Updated:** 2026-10-26
- **Repository:** `flound1129/deluge`, branch `squall`
- **Commit audited:** `0fde8ff3c`
- **Related audit:** `REMOTE-SECURITY-AUDIT-2026-10-22.md`
- **Scope:** tracker URLs and responses, redirects, DNS, UDP trackers, inbound and outbound peer connections, DHT/PEX/LSD endpoints, metadata and piece transfer, alert handling, UI/log sinks, filesystem paths, and current dependency vulnerabilities.

## Result

I found no Squall Python path from tracker or peer data to command execution or unsafe deserialization, and no unescaped Web UI sink in the tracker-status and peer-identity fields reviewed here. Tracker response parsing, peer handshakes, extension messages, metadata, piece hashes, Merkle proofs, DHT, PEX and LSD are handled by native libtorrent rather than re-parsed in Python. This makes libtorrent version selection part of Squall's remote security boundary. The related audit's R01 Web sinks and R07 tracker-icon SSRF/cache issue remain applicable outside those reviewed fields.

The current native and application limits prevent a single ordinary tracker response, metadata exchange or peer message from growing without bound. File paths from hostile torrent metadata were also normalized by the required libtorrent version in traversal tests. However, the audit found seven tracker/P2P and adjacent network gaps and one applicable dependency vulnerability:

| ID  | Severity            | Finding                                                                   | Attacker prerequisite                                                  | Confidence |
| --- | ------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------- |
| TP1 | Medium              | libtorrent 2.0.15 lacks the upstream peer-holepunch endpoint SSRF fix     | Malicious peer that negotiates the `ut_holepunch` extension            | Confirmed  |
| TP2 | Medium              | Tracker and web-seed URLs can target internal HTTP or UDP services        | Causes a torrent/magnet to be added, or has a NORMAL daemon account    | Confirmed  |
| TP3 | Medium              | NORMAL `connect_peer` can force a connection to an arbitrary endpoint     | Authenticated NORMAL daemon account and a known torrent ID             | Confirmed  |
| TP4 | Medium              | Magnet metadata prefetch has no concurrency or caller-timeout bounds      | Authenticated NORMAL daemon account                                    | Confirmed  |
| TP5 | Low/Medium          | Tracker-list and alert amplification lack application-level budgets       | Malicious torrent/tracker or authenticated NORMAL daemon account       | Confirmed  |
| TP6 | Low                 | Tracker, peer and torrent text can inject terminal controls and log lines | Victim views console output or logs for malicious tracker/torrent data | Confirmed  |
| TP7 | Medium              | libtorrent 2.0.15 trusts attacker-supplied UPnP SSDP locations            | Malicious responder on the daemon's LAN while UPnP is enabled          | Confirmed  |
| D1  | Medium, conditional | Twisted 26.4 permits HTTP request-parser disagreement behind some proxies | Web UI deployed behind a front end that parses bare CR/LF differently  | Confirmed  |

No peer-originated RCE was found. TP1, TP2 and TP7 are blind connection primitives: they do not return arbitrary internal response bodies to the attacker. Their value is internal reachability, service triggering and port discovery rather than general response extraction.

## Findings

### TP1: peer-holepunch endpoint SSRF in the current libtorrent line

Squall requires `libtorrent>=2.0.15,<2.1` in `requirements.txt:2`; the audited environment has 2.0.15.

Upstream libtorrent pull request [#8530](https://github.com/arvidn/libtorrent/pull/8530) fixed a holepunch handler that accepted a peer-supplied endpoint and called `connect_to_peer()` without rejecting local addresses. A malicious peer can therefore make libtorrent 2.0.15 attempt a BitTorrent connection to a loopback, link-local or private-network endpoint reachable from the daemon. The fix was merged into the 2.1 branch and shipped in 2.1.1; it is absent from 2.0.15.

Libtorrent 2.1.1 lacks the later Merkle validation series shipped in 2.0.15, including [#8802](https://github.com/arvidn/libtorrent/pull/8802), so moving to 2.1.1 would trade one remote-input issue for another. The upstream 2.1.2 release contains both the peer-endpoint fix inherited from 2.1.1 and those later Merkle fixes.

**Recommendation:** move to libtorrent 2.1.2 after full cross-platform validation. Until it is distributable through the project's package source, carry the narrow peer-endpoint half of #8530 in the packaged libtorrent. Disabling Squall's separate `ut_pex` extension is not an established mitigation for `ut_holepunch`.

### TP2: tracker and web-seed URLs remain a deliberate egress capability

Tracker URLs from magnets are decoded and copied into add-torrent parameters without a scheme, host, address or count policy at `deluge/common.py:815-861` and `deluge/core/torrentmanager.py:439-449`. Tracker lists and web seeds from `.torrent` files are accepted by `lt.torrent_info` and passed to the native session at `deluge/core/torrentmanager.py:551-566`. Metadata prefetch also passes the complete magnet to `lt.parse_magnet_uri` at lines 365-371. NORMAL users can replace trackers directly at `deluge/core/torrent.py:608-640`.

Libtorrent 2.0.15 defaults `ssrf_mitigation=True`, but the [documented policy](https://libtorrent.org/reference-Settings.html#ssrf_mitigation) still permits loopback HTTP(S) tracker URLs whose path begins with `/announce`. Web seeds have stronger private-network query and redirect restrictions, but these are limited checks rather than a general egress policy. Private trackers are a legitimate BitTorrent use case, so libtorrent intentionally does not block all private destinations. UDP tracker endpoints likewise have no Squall address or port policy.

The request is constrained: HTTP trackers receive a GET with tracker query parameters, responses must parse as tracker bencoding, and tracker response bodies are not exposed to the caller. Web-seed bytes are consumed as candidate torrent payload and only accepted as file content when piece hashes validate. Both paths can still reach or trigger internal services. Redirect handling and DNS resolution are native; Squall does not revalidate the destination after resolution or redirect.

**Recommendation:** add an optional egress policy for deployments that ingest untrusted torrents. Reject loopback, link-local, multicast and private destinations unless explicitly allowlisted, and apply the same decision after DNS resolution and every redirect. Keep an opt-in for operators who use private trackers.

### TP3: authenticated arbitrary peer connection

`core.connect_peer` is a NORMAL-level RPC at `deluge/core/core.py:665-670`. `Torrent.connect_peer` validates only that the port converts to an integer before forwarding `(ip, port)` to libtorrent at `deluge/core/torrent.py:1312-1327`.

A NORMAL account can use the daemon to attempt BitTorrent handshakes with arbitrary internal or external TCP endpoints. This is blind and protocol-constrained, but it exposes internal reachability and can interact with services that react to unsolicited bytes.

**Recommendation:** either document arbitrary outbound peer connections as part of NORMAL authority or restrict manual peers to globally routable addresses and valid ports. If local peers are required, use an explicit allowlist.

### TP4: unbounded metadata-prefetch population and lifetime

`core.prefetch_magnet_metadata` is NORMAL-level and accepts caller-controlled `timeout` at `deluge/core/core.py:428-447`. Each unique magnet creates a temporary libtorrent torrent handle and a retained queue entry at `deluge/core/torrentmanager.py:353-405`. There is no concurrency limit, total retained-metadata budget or maximum timeout.

Native global connection and metadata limits reduce each item's cost, but a caller can create many unique long-lived prefetches that perform DHT, tracker and peer work and retain session state.

**Recommendation:** cap the timeout, limit concurrent prefetches globally and per account, reject new work when the queue is full, and apply a small returned-metadata limit below libtorrent's native maximum.

### TP5: tracker-list and alert amplification

Magnet parsing, torrent loading, `set_trackers` and tracker merging impose no tracker-count or URL-length budget at `deluge/common.py:815-861` and `deluge/core/torrent.py:608-676`. Native concurrency and response limits prevent all trackers from transferring large responses at once, but the list remains in memory and persisted state and adds scheduling, DNS and alert work.

Squall increases libtorrent's alert queue from 2,000 to 10,000 and schedules a separate Twisted callback for every registered handler at `deluge/core/alertmanager.py:43-60,149-191`. The queue is bounded and older native alerts may be dropped, but a burst can still create thousands of Python Deferreds and event-loop work. Tracker replies missing scrape counts trigger an additional scrape at `deluge/core/torrentmanager.py:1408-1421`.

**Recommendation:** cap tracker count and URL length per torrent, coalesce repeated tracker-status events, and process alert batches under an event-loop work budget.

### TP6: terminal and log control injection

The console interpolates torrent names, filenames, tracker host/status and peer client fields into terminal output without removing control sequences at `deluge/ui/console/cmdline/commands/info.py:213-424` and `deluge/ui/console/eventlog.py:43-71`. Tracker URLs, tracker errors, torrent names and file errors can also introduce newlines or controls into logs at `deluge/core/torrent.py:630-634` and `deluge/core/torrentmanager.py:683-688,1455-1456,1644-1655`.

This can forge terminal or log display but did not provide a command-execution path.

**Recommendation:** escape C0/C1 controls in terminal-facing values and normalize CR/LF in single-line log fields.

### TP7: UPnP SSDP location SSRF in libtorrent 2.0.15

Upstream pull request [#8530](https://github.com/arvidn/libtorrent/pull/8530) also fixed a separate path where libtorrent accepted an SSDP `Location` header from any UPnP responder and fetched it without rejecting loopback, link-local, multicast or unspecified addresses. Squall enables UPnP by default at `deluge/core/preferencesmanager.py:65,310-311`.

A malicious device or responder on the daemon's local network can therefore direct libtorrent 2.0.15 to make an HTTP request to another endpoint reachable from that host. Disabling `ut_pex` does not mitigate this path.

**Recommendation:** upgrade to libtorrent 2.1.2. Until then, disable UPnP where automatic port mapping is unnecessary or carry the UPnP half of #8530 in the packaged libtorrent.

### D1: applicable Twisted HTTP request-smuggling fix

The installed Twisted 26.4.0 has six advisories in the fresh `pip-audit` database. Five affect Twisted IMAP, telnet, XMPP or IRC server components that Squall does not run. The applicable advisory is CVE-2026-115877: Twisted's HTTP server accepted bare CR or LF in a header value, permitting request-framing disagreement with a front-end proxy.

Squall directly uses `twisted.web.server.Site` at `deluge/ui/web/server.py:912` and listens through it at lines 968-981. Direct clients and front ends that reject the malformed headers consistently are not exposed to smuggling, but a differently parsing reverse proxy can be.

Twisted [26.10.0rc1](https://github.com/twisted/twisted/releases/tag/twisted-26.10.0rc1) contains the fix and requires `zope.interface>=8`; Squall currently permits Twisted as old as 18.7 and caps `zope.interface<8` in `requirements.txt:3,16`.

**Recommendation:** update to the stable Twisted 26.10 release when available and lift the zope.interface cap after full CI. Until then, ensure the reverse proxy rejects bare CR/LF and ambiguous headers, or carry the small upstream header-validation patch. The release candidate passed the focused compatibility run described below.

## Protections verified

The libtorrent 2.0.15 runtime defaults and Squall configuration provide these relevant bounds:

| Boundary                       | Effective value |
| ------------------------------ | --------------- |
| Tracker decoded response       | 1 MiB           |
| Concurrent HTTP announces      | 50              |
| Tracker completion/receive     | 30 s / 10 s     |
| Metadata                       | 30 MiB          |
| Per-peer receive buffer        | 2 MiB           |
| Active/paused peer lists       | 3,000 / 1,000   |
| PEX peers per message          | 50              |
| Global peer connections        | 200             |
| Outbound/inbound request queue | 500 / 2,000     |
| Squall alert queue             | 10,000          |

Additional checks:

- HTTPS tracker certificate validation and libtorrent SSRF mitigation are enabled by default.
- Piece hashes, v2 Merkle proofs, peer handshakes, extension messages and malformed wire data remain inside libtorrent. Squall enables `smart_ban` for peers that send bad data at `deluge/core/core.py:133-138`.
- Libtorrent 2.0.15 normalized `../`, `../../` and absolute paths in hostile torrent metadata to safe `_` components in runtime tests. Squall rename inputs also pass through `sanitize_filepath` at `deluge/core/torrent.py:1546-1553`.
- Tracker status is HTML-encoded in `deluge/ui/web/js/deluge-all/details/StatusTab.js:98`; peer client strings are encoded in `PeersTab.js:72-77`. GTK tracker status is XML-escaped and peer cells use plain text properties. The earlier tracker-status stored XSS remains fixed.
- JSON and daemon RPC transports serialize these values as structured data. No transport-level injection was found.

## Dependency check

The current environment contains libtorrent 2.0.15, Twisted 26.4.0 and zope.interface 7.2. `uv pip check` reports that all 53 installed packages are internally compatible. A fresh `pip-audit` found six Twisted advisories; only D1 is reachable in Squall. No other installed package advisory was reported.

`uv pip list --outdated` reports libtorrent 2.1.1 and zope.interface 8.7, but 2.1.1 should not replace 2.0.15 because it lacks the later Merkle validation series. Upstream libtorrent 2.1.2 has both fix sets and publishes Python 3.13 wheels on its [official GitHub release](https://github.com/arvidn/libtorrent/releases/tag/v2.1.2), but it is not currently available through the package index used by `uv`. Squall's `uv.lock` contains no package entries, so the requirements are ranges rather than a reproducible dependency lock.

I tested an isolated candidate with libtorrent 2.1.2 from the official release, Twisted 26.10.0rc1 and zope.interface 8.7:

- 93 focused core, torrent, torrent-manager, alert and common tests passed; three failed for existing host-interface/listen checks that fail identically with libtorrent 2.0.15, with one skip and three expected failures.
- 43 Web server/API/authentication tests passed, with one expected failure.
- A second `pip-audit` found no advisories for the auditable candidate packages. It skipped the GitHub-sourced libtorrent 2.1.2 wheel because that version is not present on PyPI; the upstream review above covers its relevant fixes.

This is strong compatibility evidence for the focused paths, but it is not a substitute for the full cross-platform CI matrix.

## Published Debian package status

The newest published package set checked on 2026-10-26 is prerelease `squall-0.1.0.1793020828`, built from commit `0fde8ff3c6eeebd18c474f7973a0b4c841be4db7`. That is the source commit audited above, so the package does not contain fixes for TP1 through TP7 or D1.

I downloaded and unpacked the published `squall-common` artifacts for Noble and Trixie. Their SHA-256 digests matched the release metadata. Both bundle these relevant versions:

| Dependency     | Noble  | Trixie |
| -------------- | ------ | ------ |
| libtorrent     | 2.0.15 | 2.0.15 |
| Twisted        | 26.4.0 | 26.4.0 |
| zope.interface | 7.2    | 7.2    |

The package therefore remains exposed to TP1 and TP7 in libtorrent and to conditional D1 in Twisted. It also ships the Squall application behavior behind TP2 through TP6 unchanged. The build is not reproducible at the Python-dependency level: `uv.lock` has no package records, `requirements.txt` uses ranges, and `debian/rules` resolves those ranges into the bundled venv during each build.

There are useful deployment safeguards, but they do not close these findings. Remote daemon RPC is disabled by default, and the Web system service is installed without being enabled automatically. Those defaults reduce TP3 through TP5 and D1 until an operator exposes the corresponding service. The P2P listener, tracker/web-seed behavior and UPnP remain active defaults when the daemon runs, so TP1, TP2 and TP7 still apply without enabling remote RPC or Web access.

## Recommended order

1. Prepare a libtorrent 2.1.2 upgrade and run full CI on every packaged platform. Until it can ship, mitigate TP7 by disabling UPnP where it is not required, and carry the relevant halves of the upstream patch for TP1 and TP7.
2. Move to stable Twisted 26.10 plus zope.interface 8 when released and validated; harden the reverse proxy in the interim.
3. Add a configurable tracker and manual-peer egress policy for TP2 and TP3.
4. Bound metadata prefetch concurrency, lifetime and output size (TP4).
5. Cap tracker lists and callback work (TP5), then sanitize terminal/log controls (TP6).

## Limits

- This review did not fuzz native libtorrent parsers or reproduce memory-safety failures. Squall does not contain those parsers.
- No destructive requests were sent to real internal services, trackers or peers.
- Tracker and peer protocol behavior was assessed from Squall's effective settings, libtorrent's public documentation and upstream fixes, plus focused local tests.
- The isolated upgrade used upstream GitHub release artifacts rather than the project's normal package index.
