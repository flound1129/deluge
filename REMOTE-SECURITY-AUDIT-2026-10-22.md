# Squall whole-codebase remote security audit

- **Date:** 2026-10-22
- **Updated:** 2026-10-23
- **Repository:** `flound1129/deluge`, branch `squall`
- **Commit audited:** `86e66e5ad` (`86e66e5adee6d4b8e5d465d14fedfb617c64fc55`)
- **Previous audit:** `SECURITY-FINDINGS-2026-10-22.md`
- **Scope:** daemon RPC and TLS, Web UI and JavaScript, clients, core and bundled plugins, tracker and HTTP handling, torrent-facing callbacks, filesystem/process boundaries, packaging, services, dependencies and security tests.

## Result

I found no new parser-level pre-authentication remote-code-execution path or authentication bypass in the daemon or Web UI. The framing and decoded-message limits, login timeout and limiter, RPC authorization dispatch, Web request limits, session expiry, staged-file quotas and daemon certificate pinning held up in this review.

I found 13 remotely relevant issues or capabilities. Most require an authenticated NORMAL daemon account or Web UI session; others depend on malicious network content, an enabled plugin or a hostile daemon. Authenticated Web access is equivalent to arbitrary code execution through plugin management. The existing default Web UI exposure (`0.0.0.0:8112`, HTTP, password `deluge`) therefore becomes a practical critical RCE path if an operator has not changed it.

## Findings

| ID  | Severity          | Finding                                                               | Attacker prerequisite                                               | Confidence  |
| --- | ----------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------- |
| R13 | Critical/High     | Web sessions can reach arbitrary Python plugin execution              | Web session plus ADMIN daemon connection or local-daemon bootstrap  | Confirmed   |
| R01 | High              | Hostile daemon data reaches Web UI HTML sinks                         | Controls a connected daemon, or wins the first TOFU connection      | Confirmed   |
| R02 | High              | NORMAL accounts can retrieve proxy and SMTP credentials               | Authenticated NORMAL daemon account or authenticated Web UI session | Confirmed   |
| R03 | High (integrity)  | `core.create_torrent` overwrites an arbitrary daemon-writable path    | Authenticated NORMAL daemon account                                 | Confirmed   |
| R04 | High, conditional | NORMAL account can start an insecure admin-capable Web UI             | Authenticated NORMAL account; WebUi core plugin already enabled     | Confirmed   |
| R05 | High, conditional | Extractor permits caller-controlled extraction destinations           | Extractor enabled and authenticated NORMAL account                  | Confirmed   |
| R06 | Medium            | NORMAL accounts can stop the daemon                                   | Authenticated NORMAL daemon account                                 | Confirmed   |
| R07 | Medium            | Tracker-icon fetching permits SSRF and persistent resource exhaustion | Authenticated Web UI session or attacker-controlled tracker data    | Confirmed   |
| R08 | Medium            | AutoAdd owner filtering is bypassed by its mutating RPCs              | AutoAdd enabled and authenticated NORMAL account                    | Confirmed   |
| R09 | Medium            | Blocklist decompression has no expanded-size or range-count limit     | Blocklist enabled; NORMAL account or compromised configured source  | Conditional |
| R10 | Medium            | Authenticated URL-fetch RPCs can reach internal HTTP services         | Authenticated NORMAL daemon account or Web UI session               | Confirmed   |
| R11 | Low/Medium        | GTK uses attacker-controlled text as Pango markup                     | Malicious torrent/daemon data and a GTK UI action                   | Confirmed   |
| R12 | Low, conditional  | Same-site request forgery can consume the staged-upload quota         | Controls a same-site origin while a Web session is active           | Confirmed   |

### R13: authenticated Web access is an OS code-execution boundary

Arbitrary Python plugins are intentionally executable code. The issue is not a plugin sandbox escape: the Web UI makes plugin installation and daemon bootstrap available to every authenticated Web session, while the default deployment exposes that session behind a public, fixed password. Execution requires either an ADMIN connection to the configured daemon or the ability to start and connect to a local daemon.

- Successful Web login creates an ADMIN-level Web session at `deluge/ui/web/auth.py:129-133,291-314`.
- Authenticated `POST /upload` accepts arbitrary bytes at `deluge/ui/web/server.py:272-321`. For a local daemon, `web.upload_plugin` copies the staged egg into the shared Web plugin directory and asks the daemon to rescan; for a remote daemon it forwards the bytes through `core.upload_plugin` (`deluge/ui/web/json_api.py:933-962`).
- `core.upload_plugin` and `core.enable_plugin` are ADMIN-only at `deluge/core/core.py:924-935,1114-1137`. Plugin loading imports the egg entry point and calls its initialization and enable paths at `deluge/pluginmanagerbase.py:77-83,353-447`. Attacker-supplied Python therefore executes as the daemon account without a restart.
- The normal local Web configuration connects with `localclient`, which is an ADMIN daemon identity. An authenticated Web user can also call `web.start_daemon` at `deluge/ui/web/json_api.py:856-861`, add and connect to that host, and have local blank credentials replaced with `localclient` credentials at `deluge/ui/hostlist.py:136-164`. This bootstrap requires `squalld` to be installed, an available port and a writable configuration directory. A core plugin then executes on the daemon host; local bootstrap makes that the Web host. A matching Web plugin entry point can also execute in the Web process.

This is Critical when the remotely bound Web UI retains the documented default password `deluge`, because anyone who knows the public default can obtain the required session and a typical installation satisfies the local-bootstrap prerequisites. It is High with strong Web credentials because compromise of a Web account can still reach administrator-equivalent code execution. A Web session connected only to a remote NORMAL daemon cannot install or enable a plugin on that daemon. Direct daemon ADMIN plugin installation is an intentional code-execution capability and should be documented as such.

Disabling all plugins is not required to address the remote exposure, but arbitrary Python plugins cannot be made safe for an untrusted administrator. Treat plugin upload and enable, `web.start_daemon`, local-host credential substitution and host management as privileged operations. Either restrict them to a separate administrator role with reauthentication and per-session daemon credentials, or explicitly define every Web login as full OS-code-execution authority and secure it accordingly. Bind new Web installations to loopback, require a unique first-run password, and require TLS or a trusted reverse proxy before remote access. A deployment that does not need remote plugin management can disable those Web methods while retaining preinstalled plugins.

### R01: hostile daemon data reaches Web UI HTML sinks

The Web UI treats several daemon-returned strings as HTML:

- `AboutWindow.js:39-66` concatenates the daemon and libtorrent version strings into `comment`; line 42 calls `setText(comment, false)`, explicitly disabling encoding.
- `StatusTab.js:149-150` assigns fields through `innerHTML`, and lines 152-153 pass attacker-controlled `status.state` as the progress-bar text. `status.seed_rank` is normally numeric, but a hostile daemon can violate that expected type before it reaches the same sink.

A hostile or compromised daemon can return an element with an event handler and execute JavaScript in the Web UI origin when the relevant view opens. The session cookie is HttpOnly, but injected JavaScript can make same-origin JSON and upload requests and act with the victim's Web session. Where R13's local-bootstrap prerequisites hold, it can traverse that path to execute code on the Web host. A first-connection machine in the middle can do the same because TOFU cannot authenticate that first connection.

**Fix:** encode every daemon-returned string before it reaches HTML, and use text nodes or `textContent` for values. Keep static markup separate from dynamic text. Add browser tests with hostile version, state and status values.

Raw plugin metadata is also inserted with `innerHTML` in `PluginsPage.js:23-40,152-155`. This should be encoded too, although an authenticated Web user who can upload and enable a plugin already has a stronger code-execution path through the Web UI's admin daemon session.

### R02: credential-bearing configuration RPCs are NORMAL-accessible

Bare `@export` means `AUTH_LEVEL_DEFAULT`, which is NORMAL (5).

- `core.get_config`, `get_config_value` and `get_config_values` at `deluge/core/core.py:841-854` return `core.conf` values, including `proxy.password`.
- `core.get_proxy` at `deluge/core/core.py:888-917` explicitly returns `proxy_username` and `proxy_password`.
- When the Notifications plugin is enabled, its NORMAL-level `get_config` at `deluge/plugins/Notifications/deluge_notifications/core.py:225-228` returns `smtp_user` and `smtp_pass`.

Any Web UI session can reach daemon RPCs through the Web process's daemon session, so Web authentication is also enough to retrieve these secrets.

**Fix:** redact secret values from general configuration RPCs and add explicit ADMIN-only secret getters only if clients require them. Return a sentinel that lets a preferences UI preserve an existing password without receiving it. Apply the same rule to plugin configuration.

### R03: arbitrary overwrite through `core.create_torrent`

`core.create_torrent` is NORMAL-level at `deluge/core/core.py:1028-1113`. Its worker opens the caller-controlled `target` with `open(target, 'wb')` at lines 1101-1105. It has no allowed-directory restriction, symlink defense or no-clobber behavior.

The output is structured torrent metadata rather than arbitrary bytes, but a remote NORMAL user can truncate and replace any daemon-writable file, corrupt configuration or state, and follow an existing symlink. It can also force hashing of an arbitrary readable path.

This overlaps the documented decision that NORMAL users may choose arbitrary download paths, but it is a direct overwrite primitive and should be explicit in the trust model.

**Fix:** require ADMIN, or restrict output to an approved directory and a new file. Use a no-follow, exclusive temporary file followed by an atomic rename.

### R04: NORMAL can start an insecure Web UI when the WebUi plugin is loaded

The WebUi core plugin is ADMIN-controlled at the plugin enable/disable boundary, but once loaded, `WebUi.set_config` is a NORMAL-level RPC at `deluge/plugins/WebUi/deluge_webui/core.py:90-112`. Setting `enabled=True` calls `start_server`.

The embedded server inherits the Web defaults in `deluge/ui/web/server.py:39-63`: interface `0.0.0.0`, HTTP, port 8112 and password `deluge`. The Web process connects locally to the daemon with an admin-capable session. Thus a NORMAL daemon account can turn a dormant, already-loaded WebUi plugin into a network-exposed admin control plane unless the operator has separately hardened `web.conf` or a firewall blocks the port.

**Fix:** make WebUi configuration ADMIN-only. Refuse a non-loopback bind while the default password is active, and warn or refuse unencrypted remote exposure.

### R05: Extractor destination escape and external archive tools

Extractor's `set_config` is NORMAL-level at `deluge/plugins/Extractor/deluge_extractor/core.py:176-181`, so a NORMAL account can set `extract_path` to any daemon-writable directory.

There is a second path escape: caller-controlled torrent `options['name']` becomes the torrent display name in `deluge/core/torrentmanager.py:477-480` and `deluge/core/torrent.py:991-1004`. Extractor appends that value to its configured base at `deluge/plugins/Extractor/deluge_extractor/core.py:142-145` without normalizing and checking the result. An absolute name or parent components can escape the base. The plugin then invokes external `tar`, `unzip`, `unrar` or `7zr` processes on untrusted torrent content at lines 166-173.

Exact archive traversal and memory-corruption impact depends on the installed external tool. This host has `7zr` 17.05, which is old and should not be treated as a hardened parser for attacker-controlled archives.

**Fix:** require ADMIN for global Extractor configuration; reduce the torrent name to a safe single component; verify the real destination remains under an approved base; and isolate extraction with explicit file-count, expanded-byte and symlink limits. Keep external archive tools patched.

### R06: NORMAL accounts can stop the daemon

`Daemon.shutdown` at `deluge/core/daemon.py:168-171` uses bare `@export()`, so its required level is NORMAL. It schedules `reactor.stop()` immediately. A Web UI session can also reach shutdown through `web.stop_daemon`.

**Fix:** require `AUTH_LEVEL_ADMIN` and add a dispatch-level regression test that rejects NORMAL while allowing ADMIN.

### R07: tracker-icon SSRF and cache exhaustion

The authenticated `/tracker/<name>` Web route treats the path component as a host at `deluge/ui/web/server.py:355-395`. `TrackerIcons` fetches `http://<host>/` at `deluge/ui/tracker_icons.py:246-265`. Redirects are enabled, and favicon links from the returned HTML are resolved with `urljoin` and fetched without scheme, host or destination-IP validation at lines 318-365.

An authenticated Web user can request `127.0.0.1:<port>`, link-local metadata addresses or internal hosts. Separately, a malicious tracker page can redirect or name an internal favicon URL after a victim imports its torrent.

Each page or icon may contain up to the global 256 MiB decoded HTTP limit. Icon files are stored persistently, invalid downloads are not consistently deleted, and there is no cache-wide file or byte budget. Many tracker names can therefore consume disk and memory.

**Fix:** allow only HTTP(S), resolve and reject loopback/private/link-local destinations, revalidate every redirect, and normally require the icon to remain on the tracker origin. Use small page/icon limits, delete invalid files and enforce cache count/byte limits.

### R08: AutoAdd cross-account authorization bypass

AutoAdd's `get_watchdirs` filters entries by owner for non-admin users at `deluge/plugins/AutoAdd/deluge_autoadd/core.py:410-431`. Its mutators do not apply that ownership check:

- `set_options`: lines 118-143
- `enable_watchdir` and `disable_watchdir`: lines 367-394
- `remove`: lines 466-477

`get_config` also returns the complete plugin configuration at lines 405-408, revealing every watchdir ID. A NORMAL user can change, enable, disable or remove another user's watcher and influence its daemon-side filesystem actions.

**Fix:** centralize a watchdir authorization helper used by every read and mutation. Non-admin creation must force `owner` to the current session user rather than accepting a caller-supplied owner.

### R09: Blocklist decompression bomb

Blocklist configuration and import controls are NORMAL-level. ZIP, GZip and BZip2 readers in `deluge/plugins/Blocklist/deluge_blocklist/decompressers.py:15-41` stream decompressed data without an expanded-byte limit. The importer at `deluge/plugins/Blocklist/deluge_blocklist/core.py:393-452` accepts an unlimited number of ranges and adds each to libtorrent.

The downloaded archive is capped at 256 MiB of decoded HTTP content, but archive-internal decompression is not capped. A small compressed bomb or a file containing millions of ranges can consume CPU, memory and disk. This is also reachable if a previously trusted blocklist source is compromised.

**Fix:** cap compressed bytes more tightly for blocklists, count decompressed bytes and ranges, reject multi-entry or suspicious archives, and abort before applying a partial oversized list.

### R10: authenticated URL-fetch SSRF capability

`core.add_torrent_url` is NORMAL-level and fetches a caller-controlled URL and headers at `deluge/core/core.py:506-535`. `web.download_torrent_from_url` does the same at `deluge/ui/web/json_api.py:645-704`. Redirects are followed without private, loopback or link-local destination checks.

The final body must fit the torrent staging or parsing path for the call to succeed, but the outbound HTTP request occurs first. An authenticated attacker can therefore make the daemon or Web host issue GET requests to internal services and follow redirects there.

This is partly intrinsic to a remote torrent client: authenticated users are expected to supply torrent URLs. If NORMAL and Web accounts are not trusted with the host's network position, add an egress policy.

**Fix:** validate schemes and resolved addresses before every connection and redirect, or provide an administrator-controlled policy that disables private-network URL fetches for remote callers.

### R11: GTK Pango markup injection

`deluge/ui/gtk3/removetorrentdialog.py:58-62` passes a torrent name directly to `set_markup`. Filter labels, tracker hosts and owners similarly reach markup in `deluge/ui/gtk3/filtertreeview.py:257-263`, and the Label plugin uses a label name in markup at `deluge/plugins/Label/deluge_label/gtkui/sidebar_menu.py:172-174`.

Attacker-controlled values can spoof the dialog, hide text or cause markup parsing failures. I found no code-execution path.

**Fix:** use `set_text` for untrusted values, or escape them with the GLib/Pango markup escape function before combining them with static markup.

### R12: same-site upload request forgery

`/upload` checks only the session cookie at `deluge/ui/web/server.py:283-315`; it does not validate a CSRF token, `Origin` or `Referer`. The cookie is `SameSite=Lax`, HttpOnly and host-only (`deluge/ui/web/auth.py:104-121`), so normal cross-site POSTs from modern browsers do not carry it. Same-site origins are different: a hostile service on another port of the same host, or a controlled sibling host under the same site, can submit a multipart form with the cookie.

The attacker cannot read the response, but repeated requests can consume the shared 1,000-file/256 MiB staged quota for up to one hour.

**Fix:** require a per-session CSRF token on `/upload`, or enforce a strict `Origin` policy for state-changing Web requests.

## Existing risks still relevant

The earlier report remains authoritative for these items:

- **O2:** private torrent ownership is not an authorization boundary.
- **O3:** the Web password uses one salted SHA-1 round.
- **O4:** daemon RPC errors disclose Python tracebacks before login.
- **O5:** release dependency resolution has no lock file or hashes.
- **O7:** the Web UI defaults to all interfaces, HTTP and password `deluge`.
- **S05 limit:** clients still use the rencode C decoder and a hostile daemon can crash them with deep nesting.
- **S06 limit:** TOFU cannot authenticate the first daemon connection.

The GHSL Deluge issues CVE-2025-46561 through CVE-2025-46564 were fixed upstream in 2.2.0 and their corresponding paths remain fixed here. I found no newer published Deluge advisory in the searches performed for this audit. See the [GitHub Security Lab advisory](https://securitylab.github.com/advisories/GHSL-2024-188_GHSL-2024-191_Deluge/) and the [Deluge 2.2.0 changelog](https://deluge.readthedocs.io/en/deluge-2.2.0/changelog.html).

## Validation and tooling

- Manual review covered 279 Python files (66,324 lines) and 86 JavaScript files (81,961 lines, including vendored and generated bundles), plus service, packaging and shell files.
- Independent focused reviews covered daemon RPC, Web UI, peer/tracker/download paths, plugins/filesystem/process use, clients/dependencies and deployment configuration. A final adversarial pass removed duplicates and downgraded findings whose prerequisites were stronger than first reported.
- A runtime decorator probe confirmed that `daemon.shutdown`, `core.get_config`, `core.get_proxy`, `core.create_torrent`, Notifications `get_config`, WebUi `set_config` and AutoAdd `set_options` all require level 5 (NORMAL), while ADMIN is level 10.
- Bandit scanned the Python tree. Its high findings were SHA-1 uses already explained by BitTorrent protocol hashing or existing O3, plus a development-only plugin generator using the shell. Its pickle findings load local state/config files; no direct unauthenticated network-to-pickle path was found.
- `pip-audit` scanned the installed environment. It reported one Twisted IMAP regular-expression denial of service ([GHSA-8pqf-f4m5-798g](https://github.com/advisories/GHSA-8pqf-f4m5-798g)); Squall does not run Twisted's IMAP server or call the affected wildcard function, so it is not reachable here.
- The repository's opt-in TLS suite was run with `SECURITY_TESTS=1`. It is currently unusable: all 18 daemon cases fail because `deluge/tests/data/testssl.sh` is absent, and all 21 Web cases error because the migrated fixture accesses `self.deluge_web` before initialization. These are validation failures, not evidence of a TLS vulnerability.
- The audited commit passed its GitHub Actions [CI](https://github.com/flound1129/deluge/actions/runs/39885578667), [Linting](https://github.com/flound1129/deluge/actions/runs/39885578661), [Docs](https://github.com/flound1129/deluge/actions/runs/39885578751) and [Debian Packages](https://github.com/flound1129/deluge/actions/runs/39885578677) workflows.

## Limits of this audit

- I did not perform destructive exploitation against real internal services, other users' files or a production daemon.
- The Web XSS findings are static data-flow proofs; there is no browser automation in the repository to execute the payloads end to end.
- Libtorrent's C++ peer, tracker and metadata parsers were treated as an external dependency. The Python alert/status handling around them was reviewed.
- Archive behavior depends on the operating system's `tar`, `unzip`, `unrar` and 7-Zip versions. No archive bomb or memory-corruption payload was executed.
- This was not a coverage-guided fuzzing campaign or a long-running network stress test.

## Recommended order

1. Address R13's trust boundary first. Keep plugins administrator-equivalent, but remove plugin management and daemon bootstrap from ordinary Web sessions, or explicitly secure every Web login as OS-code-execution authority.
2. Fix R01, R02, R04 and R06: they are small authorization/encoding changes with direct security benefit.
3. Decide whether NORMAL accounts remain trusted with arbitrary filesystem and network access. That decision determines the final shape of R03, R05 and R10.
4. Add destination and resource policies for tracker icons and blocklists (R07 and R09).
5. Apply per-owner authorization in AutoAdd (R08), escape GTK markup (R11), and add Web CSRF validation (R12).
6. Repair and make the live TLS suite mandatory in CI.
