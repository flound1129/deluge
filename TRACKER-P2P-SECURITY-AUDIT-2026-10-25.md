# Squall tracker and peer connection security audit

- **Date:** 2026-10-25
- **Updated:** 2026-10-27
- **Repository:** `flound1129/deluge`, branch `squall`
- **Commit audited:** `0fde8ff3c`
- **Related audit:** `REMOTE-SECURITY-AUDIT-2026-10-22.md`
- **Scope:** tracker URLs and responses, redirects, DNS, UDP trackers, inbound and outbound peer connections, DHT/PEX/LSD endpoints, metadata and piece transfer, alert handling, UI/log sinks, filesystem paths, and current dependency vulnerabilities.

## Result

I found no Squall Python path from tracker or peer data to command execution or unsafe deserialization, and no unescaped Web UI sink in the tracker-status and peer-identity fields reviewed here. Tracker response parsing, peer handshakes, extension messages, metadata, piece hashes, Merkle proofs, DHT, PEX and LSD are handled by native libtorrent rather than re-parsed in Python. This makes libtorrent version selection part of Squall's remote security boundary. The related audit's R01 Web sinks and R07 tracker-icon SSRF/cache issue remain applicable outside those reviewed fields.

The original audit found seven tracker/P2P and adjacent network gaps and one applicable dependency vulnerability:

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

### Remediation status (2026-10-27)

| ID  | Source status              | Resolution                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| TP1 | Fixed                      | Runtime and package locks require libtorrent 2.1.2, which contains the peer-holepunch endpoint and later Merkle validation fixes.                                                                                                                                                                                                                                                                                                                                                    |
| TP2 | Mitigated; native residual | Squall validates and caps every tracker/web-seed ingress, rejects literal private/local destinations by default and reasserts libtorrent's connection-time SSRF settings. Squall's own torrent-URL downloader also resolves asynchronously, rejects private answers, pins the approved address and revalidates redirects. Libtorrent performs a later independent DNS lookup for hostname trackers/web seeds, so DNS rebinding and tracker redirects remain a native-layer residual. |
| TP3 | Fixed                      | NORMAL accounts may connect only to public numeric peer addresses and valid ports; ADMIN accounts retain local-peer access.                                                                                                                                                                                                                                                                                                                                                          |
| TP4 | Fixed                      | Prefetch timeout, active-prefetch and waiter counts are bounded; malformed and oversized magnets are rejected.                                                                                                                                                                                                                                                                                                                                                                       |
| TP5 | Fixed                      | Tracker/web-seed counts and URL sizes are capped. Native and Python alert queues, handler concurrency and per-reactor-turn work are bounded.                                                                                                                                                                                                                                                                                                                                         |
| TP6 | Fixed in reviewed sinks    | Console and log values render controls and bidirectional formatting visibly; untrusted console color markup is neutralized and URLs are logged without credentials, paths or queries.                                                                                                                                                                                                                                                                                                |
| TP7 | Fixed                      | Runtime and package locks require libtorrent 2.1.2, containing the UPnP SSDP endpoint fix.                                                                                                                                                                                                                                                                                                                                                                                           |
| D1  | Fixed                      | Squall's HTTP channel carries the upstream bare-CR/LF header-value rejection and has raw-socket regression tests.                                                                                                                                                                                                                                                                                                                                                                    |

The source fixes do not harden an already downloaded package. The published-package section below distinguishes the last artifact that was inspected from a package built from these changes.

## Findings

### TP1: peer-holepunch endpoint SSRF in the current libtorrent line

At audit time Squall required `libtorrent>=2.0.15,<2.1` and the environment had 2.0.15.

Upstream libtorrent pull request [#8530](https://github.com/arvidn/libtorrent/pull/8530) fixed a holepunch handler that accepted a peer-supplied endpoint and called `connect_to_peer()` without rejecting local addresses. A malicious peer can therefore make libtorrent 2.0.15 attempt a BitTorrent connection to a loopback, link-local or private-network endpoint reachable from the daemon. The fix was merged into the 2.1 branch and shipped in 2.1.1; it is absent from 2.0.15.

Libtorrent 2.1.1 lacks the later Merkle validation series shipped in 2.0.15, including [#8802](https://github.com/arvidn/libtorrent/pull/8802), so moving to 2.1.1 would trade one remote-input issue for another. The upstream 2.1.2 release contains both the peer-endpoint fix inherited from 2.1.1 and those later Merkle fixes.

**Recommendation:** move to libtorrent 2.1.2 after full cross-platform validation. Until it is distributable through the project's package source, carry the narrow peer-endpoint half of #8530 in the packaged libtorrent. Disabling Squall's separate `ut_pex` extension is not an established mitigation for `ut_holepunch`.

**Resolution:** `requirements.txt` and the Debian/CI locks now require the official libtorrent 2.1.2 wheels.

### TP2: tracker and web-seed URLs remain a deliberate egress capability

Tracker URLs from magnets are decoded and copied into add-torrent parameters without a scheme, host, address or count policy at `deluge/common.py:815-861` and `deluge/core/torrentmanager.py:439-449`. Tracker lists and web seeds from `.torrent` files are accepted by `lt.torrent_info` and passed to the native session at `deluge/core/torrentmanager.py:551-566`. Metadata prefetch also passes the complete magnet to `lt.parse_magnet_uri` at lines 365-371. NORMAL users can replace trackers directly at `deluge/core/torrent.py:608-640`.

Libtorrent 2.0.15 defaults `ssrf_mitigation=True`, but the [documented policy](https://libtorrent.org/reference-Settings.html#ssrf_mitigation) still permits loopback HTTP(S) tracker URLs whose path begins with `/announce`. Web seeds have stronger private-network query and redirect restrictions, but these are limited checks rather than a general egress policy. Private trackers are a legitimate BitTorrent use case, so libtorrent intentionally does not block all private destinations. UDP tracker endpoints likewise have no Squall address or port policy.

The request is constrained: HTTP trackers receive a GET with tracker query parameters, responses must parse as tracker bencoding, and tracker response bodies are not exposed to the caller. Web-seed bytes are consumed as candidate torrent payload and only accepted as file content when piece hashes validate. Both paths can still reach or trigger internal services. Redirect handling and DNS resolution are native; Squall does not revalidate the destination after resolution or redirect.

**Recommendation:** add an optional egress policy for deployments that ingest untrusted torrents. Reject loopback, link-local, multicast and private destinations unless explicitly allowlisted, and apply the same decision after DNS resolution and every redirect. Keep an opt-in for operators who use private trackers.

**Resolution:** Squall now applies a default-on URL policy to `.torrent`, magnet, metadata-prefetch, tracker-edit and native-handle web-seed inputs. It validates schemes, authorities, ports, controls and numeric addresses, caps candidate counts and rejects conventional local hostnames. `allow_private_trackers=True` is an ADMIN-only compatibility escape hatch. Synchronous tracker parsing performs no DNS lookup, avoiding attacker-controlled resolver stalls; libtorrent resolves later with `ssrf_mitigation=True`. Consequently, a hostname that changes from a public to private answer, or a permitted tracker redirect, remains a documented native-layer residual. Squall's separate torrent-URL fetcher closes that gap for its own HTTP traffic by asynchronously resolving and pinning the approved address on every redirect hop.

### TP3: authenticated arbitrary peer connection

`core.connect_peer` is a NORMAL-level RPC at `deluge/core/core.py:665-670`. `Torrent.connect_peer` validates only that the port converts to an integer before forwarding `(ip, port)` to libtorrent at `deluge/core/torrent.py:1312-1327`.

A NORMAL account can use the daemon to attempt BitTorrent handshakes with arbitrary internal or external TCP endpoints. This is blind and protocol-constrained, but it exposes internal reachability and can interact with services that react to unsolicited bytes.

**Recommendation:** either document arbitrary outbound peer connections as part of NORMAL authority or restrict manual peers to globally routable addresses and valid ports. If local peers are required, use an explicit allowlist.

**Resolution:** the RPC now validates numeric address and port types/ranges. NORMAL accounts are limited to globally routable unicast addresses; ADMIN accounts may connect to local peers.

### TP4: unbounded metadata-prefetch population and lifetime

`core.prefetch_magnet_metadata` is NORMAL-level and accepts caller-controlled `timeout` at `deluge/core/core.py:428-447`. Each unique magnet creates a temporary libtorrent torrent handle and a retained queue entry at `deluge/core/torrentmanager.py:353-405`. There is no concurrency limit, total retained-metadata budget or maximum timeout.

Native global connection and metadata limits reduce each item's cost, but a caller can create many unique long-lived prefetches that perform DHT, tracker and peer work and retain session state.

**Recommendation:** cap the timeout, limit concurrent prefetches globally and per account, reject new work when the queue is full, and apply a small returned-metadata limit below libtorrent's native maximum.

**Resolution:** timeout is limited to 1–60 seconds, with at most 8 active prefetches and 32 waiters per info hash. Magnet length and network resources are also capped. Returned metadata remains below libtorrent's native 30 MiB metadata ceiling.

### TP5: tracker-list and alert amplification

Magnet parsing, torrent loading, `set_trackers` and tracker merging impose no tracker-count or URL-length budget at `deluge/common.py:815-861` and `deluge/core/torrent.py:608-676`. Native concurrency and response limits prevent all trackers from transferring large responses at once, but the list remains in memory and persisted state and adds scheduling, DNS and alert work.

Squall increases libtorrent's alert queue from 2,000 to 10,000 and schedules a separate Twisted callback for every registered handler at `deluge/core/alertmanager.py:43-60,149-191`. The queue is bounded and older native alerts may be dropped, but a burst can still create thousands of Python Deferreds and event-loop work. Tracker replies missing scrape counts trigger an additional scrape at `deluge/core/torrentmanager.py:1408-1421`.

**Recommendation:** cap tracker count and URL length per torrent, coalesce repeated tracker-status events, and process alert batches under an event-loop work budget.

**Resolution:** each torrent accepts at most 32 trackers and 16 web seeds, with 2 KiB per URL and bounded candidate inspection. The native alert queue and Python pending queue are each capped at 2,000; at most 100 work units run per reactor turn and 100 unresolved handlers are retained. Handler invocation remains deferred and timed out.

### TP6: terminal and log control injection

The console interpolates torrent names, filenames, tracker host/status and peer client fields into terminal output without removing control sequences at `deluge/ui/console/cmdline/commands/info.py:213-424` and `deluge/ui/console/eventlog.py:43-71`. Tracker URLs, tracker errors, torrent names and file errors can also introduce newlines or controls into logs at `deluge/core/torrent.py:630-634` and `deluge/core/torrentmanager.py:683-688,1455-1456,1644-1655`.

This can forge terminal or log display but did not provide a command-execution path.

**Recommendation:** escape C0/C1 controls in terminal-facing values and normalize CR/LF in single-line log fields.

**Resolution:** console output now escapes C0/C1, ANSI and Unicode bidirectional controls and neutralizes untrusted Squall color tags. Reviewed peer/tracker/torrent log values are bounded and single-line, and URL logging omits credentials, path and query components.

### TP7: UPnP SSDP location SSRF in libtorrent 2.0.15

Upstream pull request [#8530](https://github.com/arvidn/libtorrent/pull/8530) also fixed a separate path where libtorrent accepted an SSDP `Location` header from any UPnP responder and fetched it without rejecting loopback, link-local, multicast or unspecified addresses. Squall enables UPnP by default at `deluge/core/preferencesmanager.py:65,310-311`.

A malicious device or responder on the daemon's local network can therefore direct libtorrent 2.0.15 to make an HTTP request to another endpoint reachable from that host. Disabling `ut_pex` does not mitigate this path.

**Recommendation:** upgrade to libtorrent 2.1.2. Until then, disable UPnP where automatic port mapping is unnecessary or carry the UPnP half of #8530 in the packaged libtorrent.

**Resolution:** libtorrent 2.1.2 is required and hash-locked for package builds.

### D1: applicable Twisted HTTP request-smuggling fix

The installed Twisted 26.4.0 has six advisories in the fresh `pip-audit` database. Five affect Twisted IMAP, telnet, XMPP or IRC server components that Squall does not run. The applicable advisory is CVE-2026-115877: Twisted's HTTP server accepted bare CR or LF in a header value, permitting request-framing disagreement with a front-end proxy.

Squall directly uses `twisted.web.server.Site` at `deluge/ui/web/server.py:912` and listens through it at lines 968-981. Direct clients and front ends that reject the malformed headers consistently are not exposed to smuggling, but a differently parsing reverse proxy can be.

Twisted [26.10.0rc1](https://github.com/twisted/twisted/releases/tag/twisted-26.10.0rc1) contains the fix and requires `zope.interface>=8`; at audit time Squall permitted Twisted as old as 18.7 and capped `zope.interface<8`.

**Recommendation:** update to the stable Twisted 26.10 release when available and lift the zope.interface cap after full CI. Until then, ensure the reverse proxy rejects bare CR/LF and ambiguous headers, or carry the small upstream header-validation patch. The release candidate passed the focused compatibility run described below.

**Resolution:** the package stays on stable Twisted 26.4.0 and Squall's `HardenedHTTPChannel` carries the upstream header-value check. Raw requests containing either a bare CR or bare LF receive HTTP 400. The local patch can be removed after a stable Twisted release containing the fix is adopted.

## Protections verified

The libtorrent 2.1.2 runtime and hardened Squall configuration provide these relevant bounds:

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
| Native/Python alert queues     | 2,000 / 2,000   |

Additional checks:

- HTTPS tracker certificate validation and libtorrent SSRF mitigation are enabled by default.
- Piece hashes, v2 Merkle proofs, peer handshakes, extension messages and malformed wire data remain inside libtorrent. Squall enables `smart_ban` for peers that send bad data at `deluge/core/core.py:133-138`.
- Libtorrent 2.1.2 normalized `../`, `../../` and absolute paths in hostile torrent metadata to safe `_` components in runtime tests. Squall rename inputs also pass through `sanitize_filepath`.
- Tracker status is HTML-encoded in `deluge/ui/web/js/deluge-all/details/StatusTab.js:98`; peer client strings are encoded in `PeersTab.js:72-77`. GTK tracker status is XML-escaped and peer cells use plain text properties. The earlier tracker-status stored XSS remains fixed.
- JSON and daemon RPC transports serialize these values as structured data. No transport-level injection was found.

## Dependency check

Runtime inputs now pin libtorrent 2.1.2, Twisted 26.4.0 and zope.interface 7.2. Platform-specific Python 3.10, 3.12 and 3.13 Linux lock files include all transitive versions and hashes. Debian builds use the Python 3.12 lock on Noble and Python 3.13 lock on Trixie, ignore preinstalled Python packages while installing the lock, and install Squall afterward with `--no-build-isolation --no-deps`. CI follows the same hash-only dependency path. The libtorrent wheel source is its [official 2.1.2 GitHub release](https://github.com/arvidn/libtorrent/releases/tag/v2.1.2), since 2.1.2 is not published on PyPI.

A fresh `pip-audit` of the locked runtime reports six advisories for Twisted 26.4.0 and no other auditable package advisory. Five are in Twisted IMAP, IRC, telnet or XML components Squall does not instantiate. The reachable Web parser advisory, CVE-2026-115877, is covered by Squall's local upstream-equivalent patch. Libtorrent is skipped by PyPI advisory tools because 2.1.2 is GitHub-hosted; the relevant upstream fixes were reviewed directly.

Both Python 3.10 and 3.13 CI locks resolve successfully with `--require-hashes`. The full non-GTK/non-internet suite executed with the official macOS arm64 libtorrent 2.1.2 wheel reports 503 passed, 39 skipped and five expected failures. The only two failures are the previously documented macOS `lo` interface-name checks. Focused private-URL refusal, pinned redirect validation and bare-CR/LF request tests pass. Clean Noble and Trixie amd64 container builds also pass: their `squall-common` packages contain pip 26.2.2, libtorrent 2.1.2, Twisted 26.4.0 and zope.interface 7.2, with no dependency or linkage to a system libtorrent. Linux Python 3.10/3.13 CI remains the release gate.

## Published Debian package status

The newest published package set checked on 2026-10-26 is prerelease `squall-0.1.0.1793020828`, built from commit `0fde8ff3c6eeebd18c474f7973a0b4c841be4db7`. That is the source commit audited above, so the package does not contain fixes for TP1 through TP7 or D1.

I downloaded and unpacked the published `squall-common` artifacts for Noble and Trixie. Their SHA-256 digests matched the release metadata. Both bundle these relevant versions:

| Dependency     | Noble  | Trixie |
| -------------- | ------ | ------ |
| libtorrent     | 2.0.15 | 2.0.15 |
| Twisted        | 26.4.0 | 26.4.0 |
| zope.interface | 7.2    | 7.2    |

That inspected package therefore remains exposed to TP1 and TP7 in libtorrent and to conditional D1 in Twisted. It also ships the original TP2 through TP6 behavior and does not use the new hash locks. Do not describe that already-published artifact as remediated merely because the branch source has changed.

There are useful deployment safeguards, but they do not close these findings. Remote daemon RPC is disabled by default, and the Web system service is installed without being enabled automatically. Those defaults reduce TP3 through TP5 and D1 until an operator exposes the corresponding service. The P2P listener, tracker/web-seed behavior and UPnP remain active defaults when the daemon runs, so TP1, TP2 and TP7 still apply without enabling remote RPC or Web access.

## Remaining work

1. Publish the locally verified Noble and Trixie package builds through the Linux Python 3.10/3.13 CI release gate, then inspect the published artifacts before calling the available package remediated.
2. Move to the stable Twisted release containing CVE-2026-115877 when available and remove the local compatibility patch.
3. Track a strict libtorrent tracker/web-seed egress mode that pins DNS answers and rejects every private redirect. Squall cannot enforce that final connection decision for libtorrent-managed transports from the Python layer; the current application checks and libtorrent mitigation reduce but do not eliminate TP2's DNS-rebinding residual.

## Limits

- This review did not fuzz native libtorrent parsers or reproduce memory-safety failures. Squall does not contain those parsers.
- No destructive requests were sent to real internal services, trackers or peers.
- Tracker and peer protocol behavior was assessed from Squall's effective settings, libtorrent's public documentation and upstream fixes, plus focused local tests.
- Libtorrent 2.1.2 is distributed from upstream GitHub release assets rather than PyPI; the locks include exact wheel hashes.
