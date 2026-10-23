# Squall security findings

- **Date:** 2026-10-22
- **Repository:** flound1129/deluge, branch `squall`
- **Last code commit covered by this report:** `e45647edb`
- **Latest release:** `squall-0.1.0.1792651080` (tag at `d2a45af22`)
- **Latest-release validation:** its Debian-package tests passed on Python 3.10 and 3.13, but the separate Python 3.13 CI test job was cancelled at its 30-minute limit. See section 7.

This file has all the findings from the security work of 2026-10-20 to 2026-10-22. They come from two sources:

1. My own security check of the code (2026-10-20).
2. The Pro agent audit of commit `2c6677f87`, findings S01 to S10. The handoff metadata is preserved in nthdegree message #19403 (mirrored as #19415): `deluge-squall-security-repair-handoff-2026-10-20.md`, 49123 bytes, SHA-256 `23b87e6ae907c9347fc0f3ea389df25497f1b5aa8d3b96b779637b900e596a53`. The original temporary handoff and attached evidence archive are no longer available, so this report and the repository history are now the durable record.

## 1. Status words

| Word                  | Meaning                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------ |
| Fixed                 | The code is changed and pushed. The validation listed for the finding passed.              |
| Fixed, validation gap | The code is changed and pushed, but an important end-to-end test is missing.               |
| Fixed, with limits    | The main problem and its regression tests are fixed. Section 6 gives the remaining limits. |
| Docs only             | By your decision, the code is not changed. The docs tell the risk.                         |
| In progress           | Code is written but not tested or committed.                                               |
| Open                  | Not fixed.                                                                                 |

## 2. Audit findings S01 to S10

The severity is from the audit. It applies when the attacker has the given position.

| ID  | Finding                                                                                                                                | Severity            | Attacker position                                                                         | Status                | Commits                                            |
| --- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------- |
| S01 | Tracker error and warning text went into the Web UI as HTML (stored XSS).                                                              | High                | Controls a tracker of a torrent                                                           | Fixed, validation gap | `62978baad`                                        |
| S02 | A NORMAL account could write files outside the plugins dir, and could install and enable plugins. Plugins run code as the daemon user. | High                | NORMAL daemon account                                                                     | Fixed, with limits    | `62978baad`, `42af0d3da`                           |
| S03 | Web `/upload` had no login check, no size limit and no cleanup.                                                                        | High (availability) | Can reach the Web UI port                                                                 | Fixed, with limits    | `62978baad`, `673474680`, `4cb0e6c0a`, `e45647edb` |
| S04 | An event subscription before login could stop event delivery and torrent removal.                                                      | Medium              | Can reach the daemon port                                                                 | Fixed                 | `62978baad`, `6420a0868`                           |
| S05 | RPC messages and HTTP downloads had no size limits. One small message before login crashed `squalld`.                                  | High (availability) | Can reach the daemon port, or controls a URL that the daemon downloads                    | Fixed, with limits    | `62978baad`, `ac36e6c6e`                           |
| S06 | Clients did not check the TLS certificate of the daemon. A machine in the middle could get the login password.                         | High                | Can intercept a client-to-daemon connection                                               | Fixed, with limits    | `4cb0e6c0a`, `e45647edb`                           |
| S07 | After an account change, the `auth` file (with the plaintext `localclient` admin password) became 0644.                                | High (local)        | Local user who can reach the config dir                                                   | Fixed                 | `62978baad`, `6420a0868`                           |
| S08 | A private torrent is only hidden from lists. Any account that knows its ID can read, change or remove it.                              | High (multi-user)   | NORMAL account; events reveal IDs of newly added torrents                                 | Docs only             | `d2a45af22`                                        |
| S09 | Web sessions stayed valid after they expired and after a password change.                                                              | Medium              | Has an old session cookie                                                                 | Fixed                 | `62978baad`, `6420a0868`                           |
| S10 | A removed or changed account kept its access: after a reload of the `auth` file, and on live connections.                              | Medium              | Authenticated before the account change, or uses old credentials during the reload window | Fixed, with limits    | `62978baad`, `c2f6f1cdd`                           |

### S01: tracker text as HTML in the Web UI

- **Problem:** the Web UI put `tracker_status` into `innerHTML`. A tracker can set this text in its error or warning message.
- **Fix:** the Web UI HTML-encodes tracker status, the tracker host filter, the download folder and the owner. The GTK UI escapes tracker status before Pango markup.
- **Validation:** the trixie deb contains `htmlEncode(status.tracker_status)` in `deluge-all-debug.js`.
- **Not done:** a DOM or browser test.

### S02: plugins and NORMAL accounts

- **Fix in `62978baad`:** `core.upload_plugin` and `web.upload_plugin` use only the base name of the file name, so the file stays in the plugins dir.
- **Fix in `42af0d3da`:**
  - Only ADMIN can call `upload_plugin`, `enable_plugin`, `disable_plugin` and `rescan_plugins`.
  - `set_config` refuses the full request, before it changes a key, when the request has `enabled_plugins` and the caller is below ADMIN.
  - Only ADMIN can add, change or remove Execute plugin commands.
- **Regression coverage:** `test_core.py` and `deluge/plugins/Execute/deluge_execute/tests/test_execute.py` cover the denied plugin RPCs, `enabled_plugins` config changes and Execute command changes.

### S03: Web UI uploads

- **Fix in `62978baad`:** `/upload` needs a login.
- **Fix in `673474680`:**
  - The Web UI refuses a request body over 64 KiB without a session, or over 64 MiB with a session. It checks the length before it reads the body. It sends 413 and closes the connection.
  - Staged files (from `/upload` and `web.download_torrent_from_url`) are limited to 1000 files and 256 MiB in total. Commit `4cb0e6c0a` closes a gap where a completed URL download could take the aggregate above 256 MiB. Commit `e45647edb` reserves file and byte capacity before a URL download starts and gives the downloader that exact size limit, so concurrent downloads cannot exceed the aggregate while they are in flight.
  - Staged files are removed when `web.add_torrents` or `web.upload_plugin` uses them, after 1 hour, and when the Web UI stops. The Web UI never removes a path that it did not stage.
  - A failed `download_torrent_from_url` removes its temp dir.
- **Regression coverage:** `test_httpdownloader.py`, `test_web_api.py` and `test_webserver.py` cover login, request-body limits, per-download and aggregate staged-file limits, in-flight reservations, local write failures, cleanup after use, timeout and shutdown, and failed URL downloads. The login check for `/upload` was already in `62978baad`.
- **Live check:** a real `squall-web` gave 413 for a 1 MiB body without a session. An upload with a session staged a file, and the file was removed at SIGTERM.

### S04: event subscriptions before login

- **Fix in `62978baad`:** the daemon ignores `daemon.set_event_interest` before login. `emit_event` skips a session that has no protocol.
- **Fix in `6420a0868`:**
  - Event names must be strings of 128 characters or less. Each session stores a name once, up to 256 names.
  - A recipient that fails does not stop delivery to other clients.
  - Local event handlers run even if client delivery fails. Thus an operation that sends an event, for example torrent removal, is not stopped.
- **Regression coverage:** `test_rpcserver.py` covers pre-login subscription, interest limits, failed recipients and local handler delivery.

### S05: size limits, crash and timeouts

- **Fix in `62978baad`:**
  - RPC messages are limited to 64 KiB before login and 256 MiB after login. The decompressed size is also limited.
  - HTTP downloads (torrent URLs, tracker pages and icons, blocklists) stop at 256 MiB of decoded data.
- **Fix in `ac36e6c6e`:**
  - **Crash:** the rencode C decoder has no nesting limit. One message of about 91 bytes with 65,000 nested lists, sent before login, crashed `squalld` (SIGSEGV). The daemon now decodes requests with the pure-Python decoder `rencode_orig`, which raises `RecursionError`. The daemon refuses the message and continues.
  - The daemon closes a connection that does not log in within 60 seconds.
  - An HTTP download stops when no data arrives for 60 seconds. It writes no partial file.
- **Regression coverage:** the nesting, login-timeout and HTTP-idle tests exercise the fixed behavior. The hostile nesting input crashed pytest on the old code, so do not run that comparison outside an isolated process.
- **Live check (macOS):** before the fix, the 91-byte message crashed `squalld`. After the fix, the daemon refused it, continued, and a login worked. An idle TLS connection was closed after 60.0 seconds.

### S06: daemon certificate

- **Your decision:** trust on first use (TOFU). At the first connection to a host and port, the client saves the SHA-256 fingerprint of the daemon certificate. Later, it refuses a different certificate during the TLS handshake, before it sends RPC data or a password.
- **Fix in `4cb0e6c0a`:**
  - `deluge/ui/daemon_certs.py` stores pins in `daemon_certs.conf`. An OS file lock serializes read-modify-write operations across UI processes, and a save failure aborts the TLS handshake.
  - `deluge/ui/client.py` reports a connection only after the TLS handshake. A changed certificate produces `DaemonCertificateError` on either Twisted connection-failure path.
  - Removing the last saved connection-manager entry for a host and port forgets its pin. If saving the host-list removal fails, the old pin is kept.
  - The first fingerprint is written to the info log so it can be compared with the daemon through a separate trusted channel.
- **Fix in `e45647edb`:** if deleting a pin fails after the final connection-manager entry was removed, adding the endpoint again retries the pin deletion. Adding another username for an endpoint that is still saved does not clear its shared pin.
- **Regression coverage:** 14 tests in `test_daemon_certs.py` cover pin, mismatch, storage failure, concurrent writers, connection ordering, a real TLS mismatch, host removal, failed saves and pin-reset retry. The focused client, certificate and Web API run passed; see section 7.
- **Limit:** TOFU cannot detect a machine in the middle on the first connection. Squall has no interactive first-fingerprint confirmation. Verify or pre-populate the fingerprint through a trusted channel when this threat matters.
- **Release status:** the latest release at `d2a45af22` predates this fix. Until a release contains `e45647edb`, use a secure tunnel for a daemon on another host.

### S07: `auth` file permissions

- **Fix in `62978baad`:** `auth`, `auth.bak` and `daemon.pkey` are owner-only, independent of the umask. An `auth` file that an older version left readable is made owner-only on load.
- **Fix in `6420a0868`:**
  - `auth` and `auth.bak` are written to a new temp file that is 0600 from creation, then moved into place with `os.replace`. A symlink at `auth` or `auth.bak` is replaced, not followed.
  - An account change that cannot be saved now raises `AuthManagerError` and loads the file again, so memory and disk agree. Before, the change was reported as done, and a removed account could come back after a restart.
  - The mode repair at load does not follow symlinks, and it also covers an old `auth.tmp`.
- **Regression coverage:** `test_authmanager.py` covers private modes, umask 000, account removal, symlinks and failed saves.

### S08: private torrents (docs only)

- **Your decision:** document only. No owner checks.
- **Docs in `d2a45af22`:** the section "Accounts and access levels" in `docs/source/reference/rpc.rst`, and a CHANGELOG line. They say:
  - A torrent that is not shared is only hidden from the torrent lists of accounts below ADMIN.
  - Any account that knows the torrent ID can read the torrent, change it, and remove it with its data.
  - Torrent events go to all logged-in clients that ask for them.
  - A NORMAL account can choose any download folder, so it can write files wherever the daemon user can.
- **ID discovery:** `TorrentAddedEvent` includes the torrent ID and is delivered to every logged-in client that subscribes to it. Thus a NORMAL account can learn the IDs of newly added private torrents; prior knowledge is only a barrier for older torrents whose events it missed.

### S09: Web UI sessions

- **Fix in `62978baad`:** the Web UI rejects an expired session cookie on each request. A password change ends all other sessions.
- **Fix in `6420a0868`:** the web server starts and stops the session cleaner. Before, the cleaner never ran.
- **Regression coverage:** `test_session_cleaner_runs` covers cleaner lifecycle; `62978baad` added expiry and password-change coverage.

### S10: account changes and live sessions

- **Fix in `62978baad`:** a reload of the `auth` file replaces the account list. An account removed from the file can no longer log in.
- **Fix in `c2f6f1cdd`:** when an account is removed, or gets a new password or auth level, its live sessions end. This applies to changes through the RPC API and to edits of the `auth` file (the daemon checks the file every 10 seconds). Each session gets auth level NONE at once (queued requests are refused), loses its event subscriptions and is disconnected.
- **Regression coverage:** `test_rpcserver.py` covers account removal, password and level changes, queued requests and auth-file reload.
- **Live check:** a connected user was disconnected at once after an admin removed the account, and 8 seconds after its line was removed from the `auth` file.

## 3. Other findings from my check (fixed)

| ID  | Finding                                                                                                                                                       | Fix                                                                                                                                                                                  | Commit                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| A1  | No limit on failed logins in the daemon and the Web UI. Each daemon guess ran scrypt on the reactor thread.                                                   | After 5 failed logins, the address is blocked for 30 seconds. Each further failure doubles the block, up to 15 minutes. A blocked login runs no password check. IPv6 counts per /64. | `8dd77c161`              |
| A2  | The Web UI session cookie had no `HttpOnly`, `SameSite` or `Secure` flag.                                                                                     | `HttpOnly`, `SameSite=Lax`, and `Secure` over HTTPS.                                                                                                                                 | `62978baad`              |
| A3  | The Web UI compared the password hash with a normal string compare.                                                                                           | Constant-time compare.                                                                                                                                                               | `62978baad`              |
| A4  | The Web UI used the `X-Deluge-Base` header with no check of its characters.                                                                                   | A value with unsafe characters is ignored.                                                                                                                                           | `62978baad`              |
| A5  | The Web UI debug log wrote JSON request params, which can contain passwords.                                                                                  | The params are not logged.                                                                                                                                                           | `62978baad`              |
| A6  | A `.torrent` copy file name could point outside its dir.                                                                                                      | Only the base name is used.                                                                                                                                                          | `62978baad`              |
| A7  | The `localclient` password came from `random.random()`, which is not a secure random source. The daemon compared plaintext passwords with `==`.               | The password comes from `secrets.token_hex(20)`. Compares use `hmac.compare_digest`.                                                                                                 | `62978baad`              |
| A8  | Plugin dirs were put at the front of `sys.path`. A file in a writable plugin dir could replace another module.                                                | Plugin dirs are added at the end.                                                                                                                                                    | `62978baad`              |
| A9  | Tracker icons: Pillow could use any image decoder on downloaded data.                                                                                         | Only ICO, PNG, GIF, JPEG and BMP.                                                                                                                                                    | `62978baad`              |
| A10 | Notifications plugin: it sent the SMTP password without TLS when the server did not offer STARTTLS. It did not verify the server certificate.                 | It refuses to send, and it verifies the certificate.                                                                                                                                 | `62978baad`              |
| A11 | Data loss: when you unchecked a file of a torrent, the daemon deleted its data, also when the file was complete. This did not occur when you added a torrent. | Only partial data of a file that was wanted before is deleted.                                                                                                                       | `62978baad`              |
| A12 | Old dependencies were allowed. libtorrent 2.0.12 to 2.0.15 fix memory bugs that peers can reach. These have no CVEs, so distros do not backport them.         | libtorrent >= 2.0.15 and < 2.1 (PyPI wheel), Pillow >= 13.0.0 (Python >= 3.11), Twisted >= 18.7, rencode >= 1.0.7 (CVE-2021-40839).                                                  | `62978baad`, `656e7473f` |
| A13 | The open libtorrent pin put libtorrent 2.1.1 into release `squall-0.1.0.1792562665`. Squall is not tested on 2.1, and 2.1.1 is older than the 2.0.15 fixes.   | Pin `< 2.1`. I deleted that release and its tag.                                                                                                                                     | `656e7473f`              |
| A14 | Bug, not security: pyOpenSSL 26.3 removed `X509Req`, so a new install with the bundled pyOpenSSL 26.4 could not start `squalld`.                              | The daemon makes its TLS key and certificate with `cryptography`.                                                                                                                    | `62978baad`              |

## 4. Packaging and CI findings (fixed)

| ID  | Finding                                                                                                                                      | Fix                                                                                                                                                                   | Commit                   |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| P1  | The deb enabled the user `squalld` and `squall-web` units for all users, and enabled and started the system `squall-web` service on install. | Not enabled. You enable them yourself.                                                                                                                                | `62978baad`              |
| P2  | `SQUALLD_OPTS` and `DELUGE_WEB_OPTS` in `/etc/default/squall-*` were not passed to the services.                                             | They are passed.                                                                                                                                                      | `62978baad`              |
| P3  | System services could load Python packages from the user site dir of the service user. The daemon logrotate file had no `su` line.           | `PYTHONNOUSERSITE=1`. logrotate uses `su debian-squall-daemon adm`.                                                                                                   | `62978baad`              |
| P4  | CI workflows had no `permissions` key, kept the checkout credentials, and used actions by tag.                                               | Read-only default token, no kept credentials, actions pinned to commit SHAs, weekly deb rebuild, pip upgraded in the venv.                                            | `62978baad`              |
| P5  | GitHub settings.                                                                                                                             | Changed live: read-only default workflow token. Branch `squall` is protected (no force-push, no delete, rules apply to admins). Actions cannot approve pull requests. | GitHub settings          |
| P6  | A release was published even when the tests failed. The 10-minute test job limit was too short for the suite.                                | The deb workflow runs the tests and publishes only when they pass. The limit is 30 minutes.                                                                           | `1084b46dd`              |
| P7  | `debian/control` required the system `python3-libtorrent`, which Squall does not use.                                                        | Removed. The venv bundles the libtorrent wheel.                                                                                                                       | `1084b46dd`              |
| P8  | Bug: `client.start_daemon` started `deluged`, not `squalld`.                                                                                 | Starts `squalld`.                                                                                                                                                     | `1084b46dd`              |
| P9  | Tests that failed before this work, and lint failures.                                                                                       | Fixed the test harness timeout, rebranded messages, an async test and an internet mark. Fixed a macOS file-descriptor leak in the alertmanager tests. Lint is clean.  | `1084b46dd`, `d74ed00ec` |

## 5. Open items

O1 (S06) was closed by `4cb0e6c0a` and its pin-reset recovery was completed by `e45647edb`; the remaining TOFU limitation is in section 6.

| ID  | Item                                                                                                                 | Severity                    | Attacker position or impact                                 | Where                                       | Note                                                                              |
| --- | -------------------------------------------------------------------------------------------------------------------- | --------------------------- | ----------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------------------- |
| O2  | S08: private torrents have no owner checks.                                                                          | High (multi-user)           | Any NORMAL account; events reveal new torrent IDs           | `deluge/core/`                              | Docs only, by your decision.                                                      |
| O3  | The Web UI password is stored as one salted SHA-1 round. Daemon accounts use scrypt.                                 | Medium                      | Can obtain `web.conf` or another copy of the password hash  | `deluge/ui/web/auth.py:142`, `:236-240`     | Fix: scrypt, and convert the old hash at the next good login.                     |
| O4  | The daemon sends Python tracebacks in RPC errors, also to clients that are not logged in.                            | Low                         | Can reach the daemon port                                   | `deluge/core/rpcserver.py:276`              | Internal paths and implementation details may be disclosed.                       |
| O5  | The deb build uses no lock file with hashes. The weekly rebuild takes the newest allowed version of each dependency. | Medium (supply chain)       | Compromised dependency release, index or maintainer account | `debian/rules`, `requirements.txt`          | Rebuilds are not reproducible.                                                    |
| O6  | The debs are `Architecture: all`, but they contain compiled code. They work only on the build architecture (amd64).  | Low (packaging)             | Installing the package on another architecture              | `debian/control`                            | Availability and packaging correctness, not a direct security boundary.           |
| O7  | Web UI defaults: it listens on `0.0.0.0:8112`, uses HTTP, and the default password is `deluge`.                      | High when network-reachable | Can reach or observe traffic to the Web UI port             | `deluge/ui/web/server.py` (config defaults) | Change the password, restrict the listening interface and add transport security. |
| O8  | Privacy: "Test active port" sends your IP address and port to `deluge-torrent.org`.                                  | Low (privacy)               | The configured external service receives the test           | `deluge/core/core.py:1273`                  | Document the disclosure at the action point.                                      |

## 6. Limits of the fixes

- **S02 and S08:** a NORMAL account can choose any download folder, so it can write files wherever the daemon user can write. This is by your decision, and the docs say it.
- **S02:** the plugin upload does not use `O_NOFOLLOW`. A symlink that is already in the plugins dir is followed. Only ADMIN can upload.
- **S02 and S03:** any user authenticated to the Web UI can give a server file path to `web.add_torrents` and `web.upload_plugin`. The Web UI has one password, not NORMAL and ADMIN roles; daemon-side authorization uses the Web UI process's daemon session. I did not change this.
- **S03:** the staged-file quota is for all sessions together, not for each session. A URL download reserves all currently available byte capacity until it finishes, so another URL download can be refused while the first is in flight. When a client sends a large body, it can get a TCP reset before it reads the 413. Behind a reverse proxy, set a body size limit in the proxy too.
- **S06:** TOFU protects later connections, not the first one. There is no interactive first-fingerprint confirmation. The cross-process lock is tested on macOS; its Windows `msvcrt` branch was reviewed but not executed in this work.
- **S05:**
  - Only the daemon uses the pure-Python decoder. The GTK, console and Web UI clients still use the rencode C decoder. A hostile daemon, or a machine in the middle, can crash them with the same message.
  - I saw the crash on macOS only. I did not test Linux.
  - The pure-Python decoder is about 4 to 6 times slower than the C decoder.
  - After login, a message of up to 256 MiB can still decode into very many objects.
  - There is no idle timeout after login.
  - The HTTP idle timeout does not stop a server that sends data very slowly.
- **S10:**
  - If you change your own account, your own session also ends.
  - `get_session_auth_level` still returns ADMIN when the session is not valid. Ended sessions get level NONE until they disconnect. I did not change the ADMIN fallback.
- **A1 (login limit):**
  - During a block, the Web UI says that the password is incorrect. The server log gives the real cause.
  - Behind a reverse proxy, all Web UI users have the address of the proxy. An attacker can then block all users for up to 15 minutes.
  - A Web UI user who types a wrong daemon password 5 times blocks 127.0.0.1. This also blocks local clients, first for 30 seconds.
  - An attacker with many addresses is not stopped.

## 7. Test and CI results

- **Focused tests through `e45647edb`:** `.venv/bin/pytest -q deluge/tests/test_httpdownloader.py deluge/tests/test_webserver.py deluge/tests/test_web_api.py deluge/tests/test_daemon_certs.py deluge/tests/test_client.py` — 83 passed, 2 expected failures. The configured Ruff, Ruff-format, Prettier, end-of-file, line-ending and trailing-whitespace hooks passed on every changed code file.
- **Broad local run through `e45647edb`:** `.venv/bin/pytest -q -k 'not test_is_interface_name and not test_is_interface' -m 'not (todo or gtkui or security)' deluge/tests` — 432 passed, 1 skipped, 5 expected failures, and 2 failures unrelated to these changes: the listen-port environment check returned `None`, and the live `deluge-torrent.org` tracker-icon fetch returned no icon. The two documented macOS `lo` tests were excluded explicitly.
- **Local full suite (macOS, Python 3.13), after `c2f6f1cdd`:** 413 passed. The 2 failures are the known macOS-only `test_common` tests (macOS has no `lo` interface).
- **Historical CI:** all 4 workflows (CI, Linting, Docs, Debian Packages) passed for [`42af0d3da`](https://github.com/flound1129/deluge/commit/42af0d3dac85cba73a9568eb3f39dc7f199f323f/checks), [`673474680`](https://github.com/flound1129/deluge/commit/67347468080ac052de2a6ae04a6f519a6c288c54/checks), [`ac36e6c6e`](https://github.com/flound1129/deluge/commit/ac36e6c6e45f2ab7f2a58d24f7a986ddd7c9399c/checks) and [`c2f6f1cdd`](https://github.com/flound1129/deluge/commit/c2f6f1cdd86153e27410613a47850daf2f6af3c9/checks).
- **CI for [`d2a45af22`](https://github.com/flound1129/deluge/commit/d2a45af224b8edf4dac267cd81cfe96b38e5aa66/checks):** Docs, Linting and Debian Packages passed. The Debian Packages workflow ran the tests on Python 3.10 and 3.13, and they passed. In the separate CI workflow, the Python 3.13 test job stopped at the 30-minute limit (cancelled). The Python 3.10 job passed. I do not know the cause yet.
- **CI for `4cb0e6c0a` and `e45647edb`:** not run yet at the time this report was updated. Use the checks pages for [`4cb0e6c0a`](https://github.com/flound1129/deluge/commit/4cb0e6c0a248b212cfb5f8c3bb565296f4f77062/checks) and [`e45647edb`](https://github.com/flound1129/deluge/commit/e45647edbe86cd940c3f7ce9c4aaa41df50ebdce/checks) after push.
- **Releases:** `squall-0.1.0.1792638114` (login limit) was later pruned. `squall-0.1.0.1792649251` has the S05 crash fix. `squall-0.1.0.1792649503` has S10. `squall-0.1.0.1792651080` is the latest.

## 8. What you should do

- If you use the Web UI, set a unique Web UI password. The default is `deluge`.
- Bind the Web UI to localhost or a trusted private interface when possible. For remote access, put it behind HTTPS with an authenticated reverse proxy or use a secure tunnel; do not send the Web UI password over untrusted HTTP.
- If other users could read the `auth` file before `62978baad`, change the `localclient` password. On Debian, the daemon dir is 0750, so only members of its group could read the file.
- Give daemon accounts only to people that you trust with the files of the daemon user.
- The latest release predates S06. Until a release contains `e45647edb`, use a secure tunnel (for example SSH) for a connection to a daemon on a different host.
- Behind a reverse proxy, set request body limits in the proxy too.

## 9. Notes

- During the first session, one review agent ran `rm -rf $TMPDIR/delugeweb-*`. This command could also have removed old upload temp dirs from your own local Web UI runs.
- I copied the Pro agent's message #19403 from #nthdegree to #squall as #19415. Message #19403 preserves the full handoff and archive checksums. The attached archive link is now revoked, so the report no longer presents it as a readable source.
- The audit did not test S01 in a browser, and no browser test was added.

## 10. Sources

- GitHub Security Lab, Deluge advisories (fixed in Deluge 2.2.0): https://securitylab.github.com/advisories/GHSL-2024-188_GHSL-2024-191_Deluge/
- Debian security tracker, libtorrent-rasterbar: https://security-tracker.debian.org/tracker/source-package/libtorrent-rasterbar
- libtorrent release notes (v2.0.15, v2.1.1): https://github.com/arvidn/libtorrent/releases
- rencode CVE-2021-40839: https://github.com/advisories/GHSA-gh8j-2pgf-x458
- rencode fix commit and release history: https://github.com/aresch/rencode/commit/572ff74 and https://pypi.org/project/rencode/#history
- pyOpenSSL changelog, 26.3.0 (removed `X509Req`): https://www.pyopenssl.org/en/latest/changelog.html
- Pro audit handoff metadata: nthdegree messages #19403 and #19415. Handoff SHA-256: `23b87e6ae907c9347fc0f3ea389df25497f1b5aa8d3b96b779637b900e596a53`. The now-revoked evidence archive was 38709 bytes with SHA-256 `57fcc7abe2c4a125bf4b8520b745c8d1662d8523a0cc77a12669a620f7cdd177`.
