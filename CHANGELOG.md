# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Intended Effort Versioning (EffVer)](https://jacobtomlinson.dev/effver/).

## [Unreleased]

### Security

- Web UI: HTML-encode tracker status, tracker host filter, download folder and owner. A malicious tracker's failure or warning message could run script in the Web UI session.
- Web UI: require a login for `/upload`, which let anyone write files to the temp dir.
- Web UI: set `HttpOnly`, `SameSite=Lax` and (over HTTPS) `Secure` on the session cookie, compare the password hash in constant time, and ignore an `X-Deluge-Base` header with unsafe characters.
- Web UI: reject an expired session cookie on each request, start the session cleaner with the web server (it never ran), and end all other sessions when the password changes.
- Web UI: do not write JSON request params to the debug log, because they can contain passwords. Keep `upload_plugin` file names inside the plugins dir.
- Daemon: limit RPC message size (64 KiB before login, 256 MiB after) and decompressed size, so a client cannot exhaust memory with a large message or a zlib bomb.
- Daemon: ignore `daemon.set_event_interest` before login. It could stop all event delivery. Event names must be strings; each session stores a name once, up to 256 names. A recipient that fails no longer stops delivery to other clients or to local event handlers.
- Daemon: keep `upload_plugin` file names and `.torrent` copies inside their directories.
- Daemon: only an ADMIN account can upload, enable, disable or rescan plugins, set `enabled_plugins` with `set_config`, or add, change or remove Execute plugin commands. Plugins and commands run as the daemon user. A `set_config` call from a lower account that includes `enabled_plugins` changes no key. A NORMAL account can still choose any download folder, so it can write files wherever the daemon user can. Give daemon accounts only to users you trust with the daemon user's files.
- Daemon: write the `auth` file, its backup and `daemon.pkey` as owner-only, independent of the umask. `auth` and `auth.bak` are written to a new 0600 temp file and renamed into place, so they are never readable by others, and a symlink is never followed. An `auth` file that an older version left readable is made owner-only on load.
- Daemon: an account change that cannot be saved now raises an error, and the account list in memory stays the same as the file. Before, the change was reported as done and could be lost or undone at restart.
- Daemon: an account removed from the `auth` file can no longer log in after the file is reloaded.
- Daemon and Web UI: limit failed logins per client address. After 5 failed logins the address is blocked for 30 seconds, and each further failure doubles the block, up to 15 minutes. A login during a block is refused without a password check, so the daemon does not spend scrypt time on it. A good login resets the count, and so do 60 minutes with no failed login. IPv6 addresses count per /64. The Web UI also limits the old-password check in a password change. The Web UI shows a block as a failed login. Behind a reverse proxy, all Web UI clients share the proxy's address.
- HTTP downloads (torrent URLs, tracker pages and icons, blocklists) stop at 256 MiB of decoded data, so a hostile server cannot exhaust memory.
- Daemon: generate the localclient password with `secrets` and compare plaintext passwords in constant time.
- Plugins are no longer put at the front of `sys.path`, so files in a writable plugin dir cannot shadow other modules.
- Tracker icons: only decode ICO, PNG, GIF, JPEG and BMP with Pillow. GTK UI: escape tracker status before Pango markup.
- Notifications: refuse to send the SMTP password when TLS is enabled but the server does not offer STARTTLS, and verify the server certificate.
- Skipping a file now only deletes it if it was wanted before and is incomplete. Complete files are no longer deleted.
- Require libtorrent >= 2.0.15 and < 2.1, Pillow >= 13.0.0 (on Python >= 3.11), Twisted >= 18.7 and rencode >= 1.0.7 (CVE-2021-40839).
- Generate the daemon TLS key and certificate with `cryptography`. pyOpenSSL 26.3 removed `X509Req`, so a new install could not start `squalld`.

### Packaging

- The deb no longer enables the user `squalld`/`squall-web` units for all users, and no longer enables or starts the system `squall-web` service on install. Enable them explicitly.
- `SQUALLD_OPTS` and `DELUGE_WEB_OPTS` in `/etc/default/squall-*` are now passed to the services.
- System services set `PYTHONNOUSERSITE=1`. logrotate rotates the daemon log as the daemon user.
- CI: read-only workflow token by default, credentials not persisted, actions pinned to commit SHAs, weekly deb rebuild, pip upgraded in the venv.
- CI: the deb workflow runs the test suite and only publishes a release when it passes. The test job limit is 30 minutes.
- The debs no longer depend on the system `python3-libtorrent`. The venv bundles the libtorrent wheel.
- `client.start_daemon` runs `squalld`, not `deluged`.

### Removed

- Dropped support for Python 3.8 or older. (Requires Python >= 3.10)

### Core

#### Added

- SSL torrents support for secure peer-to-peer connections. See [libtorrent docs](https://libtorrent.org/manual-ref.html#ssl-torrents) for further implementation details.
- Add option to announce to trackers in all tiers (uTorrent behavior). (#1395)

#### Changed

- Passwords are now stored encrypted with scrypt. A fallback mechanism will still validate existing plaintext passwords in auth files. (#2442)

### GTK UI

#### Fixed

- Fix passwords being ignored in certain dialogs such as Tray Password and Connection Manager.
- Fix Status tab appending `pieces`/`num_pieces` to its status key list on every update, growing the list and the status RPC request without bound while the pieces bar is enabled.
- Fix a new pieces bar widget being packed into the Status tab each time the `show_piecesbar` preference is toggled on, leaving the previous one alive and hidden.
- Fix the Files tab caching the file list of every torrent ever viewed. The cache is now bounded and cleared on disconnect.
- Fix `SessionProxy` retaining per-torrent status key timestamps after disconnect.
- Fix the sidebar filter tree keeping a row for every filter value ever seen. Transient values such as tracker hosts are now removed rather than hidden.

## 2.2.0 (2025-04-28)

### Breaking changes

- Removed Python 3.6 support (Python >= 3.7)

### Core

- Fix GHSL-2024-189 - insecure HTTP for new version check.
- Fix alert handler segfault.
- Add support for creating v2 torrents.

### GTK UI

- Fix changing torrent ownership.
- Fix upper limit of upload/download in Add Torrent dialog.
- Fix #3339 - Resizing window crashes with Piecesbar or Stats plugin.
- Fix #3350 - Unable to use quick search.
- Fix #3598 - Missing AppIndicator option in Preferences.
- Set Appindicator as default for tray icon on Linux.
- Add feature to switch between dark/light themes.

### Web UI

- Fix GHSL-2024-191 - potential flag endpoint path traversal.
- Fix GHSL-2024-188 - js script dir traversal vulnerability.
- Fix GHSL-2024-190 - insecure tracker icon endpoint.
- Fix unable to stop daemon in connection manager.
- Fix responsiveness to avoid "Connection lost".
- Add support for network interface name as well as IP address.
- Add ability to change UI theme.

### Console UI

- Fix 'rm' and 'move' commands hanging when done.
- Fix #3538 - Unable to add host in connection manager.
- Disable interactive-mode on Windows.

### UI library

- Fix tracker icon display by converting to png format.
- Fix splitting trackers by newline
- Add clickable URLs for torrent comment and tracker status.

### Label

- Fix torrent deletion not removed from config.
- Fix label display name in submenu.

### AutoAdd

- Fix #3515 - Torrent file decoding errors disabled watch folder.

## 2.1.1 (2022-07-10)

### Core

- Fix missing trackers added via magnet
- Fix handling magnets with tracker tiers

## 2.1.0 (2022-06-28)

### Breaking changes

- Python 2 support removed (Python >= 3.6)
- libtorrent minimum requirement increased (>= 1.2).

### Core

- Add support for SVG tracker icons.
- Fix tracker icon error handling.
- Fix cleaning-up tracker icon temp files.
- Fix Plugin manager to handle new metadata 2.1.
- Hide passwords in config logs.
- Fix cleaning-up temp files in add_torrent_url.
- Fix KeyError in sessionproxy after torrent delete.
- Remove libtorrent deprecated functions.
- Fix file_completed_alert handling.
- Add plugin keys to get_torrents_status.
- Add support for pygeoip dependency.
- Fix crash logging to Windows protected folder.
- Add is_interface and is_interface_name to validate network interfaces.
- Fix is_url and is_infohash error with None value.
- Fix load_libintl error.
- Add support for IPv6 in host lists.
- Add systemd user services.
- Fix refresh and expire the torrent status cache.
- Fix crash when logging errors initializing gettext.

### Web UI

- Fix ETA column sorting in correct order (#3413).
- Fix defining foreground and background colors.
- Accept charset in content-type for json messages.
- Fix 'Complete Seen' and 'Completed' sorting.
- Fix encoding HTML entities for torrent attributes to prevent XSS.

### Gtk UI

- Fix download location textbox width.
- Fix obscured port number in Connection Manager.
- Increase connection manager default height.
- Fix bug with setting move completed in Options tab.
- Fix adding daemon accounts.
- Add workaround for crash on Windows with ico or gif icons.
- Hide account password length in log.
- Added a torrent menu option for magnet copy.
- Fix unable to prefetch magnet in thinclient mode.
- Use GtkSpinner when testing open port.
- Update About Dialog year.
- Fix Edit Torrents dialogs close issues.
- Fix ETA being copied to neighboring empty cells.
- Disable GTK CSD by default on Windows.

### Console UI

- Fix curses.init_pair raise ValueError on Py3.10.
- Swap j and k key's behavior to fit vim mode.
- Fix torrent details status error.
- Fix incorrect test for when a host is online.
- Add the torrent label to info command.

### AutoAdd

- Fix handling torrent decode errors.
- Fix error dialog not being shown on error.

### Blocklist

- Add frequency unit to interval label.

### Notifications

- Fix UnicodeEncodeError upon non-ascii torrent name.

## 2.0.5 (2021-12-15)

### WebUI

- Fix js minifying error resulting in WebUI blank screen.
- Silence erronous missing translations warning.

## 2.0.4 (2021-12-12)

### Packaging

- Fix python optional setup.py requirements

### Gtk UI

- Add detection of torrent URL on GTK UI focus
- Fix piecesbar crashing when enabled
- Remove num_blocks_cache_hits in stats
- Fix unhandled error with empty clipboard
- Add torrentdetails tabs position menu (#3441)
- Hide pygame community banner in console
- Fix cmp function for None types (#3309)
- Fix loading config with double-quotes in string
- Fix Status tab download speed and uploaded

### Web UI

- Handle torrent add failures
- Add menu option to copy magnet URI
- Fix md5sums in torrent files breaking file listing (#3388)
- Add country flag alt/title for accessibility

### Console UI

- Fix allowing use of windows-curses on Windows
- Fix hostlist status lookup errors
- Fix AttributeError setting config values
- Fix setting 'Skip' priority

### Core

- Add workaround libtorrent 2.0 file_progress error
- Fix allow enabling any plugin Python version
- Export torrent get_magnet_uri method
- Fix loading magnet with resume_data and no metadata (#3478)
- Fix httpdownloader reencoding torrent file downloads (#3440)
- Fix lt listen_interfaces not comma-separated (#3337)
- Fix unable to remove magnet with delete_copies enabled (#3325)
- Fix Python 3.8 compatibility
- Fix loading config with double-quotes in string
- Fix pickle loading non-ascii state error (#3298)
- Fix creation of pidfile via command option
- Fix for peer.client UnicodeDecodeError
- Fix show_file unhandled dbus error

### Documentation

- Add How-to guides about services.

### Stats plugin

- Fix constant session status key warnings
- Fix cairo error

### Notifications plugin

- Fix email KeyError with status name
- Fix unhandled TypeErrors on Python 3

### Autoadd plugin

- Fix magnet missing applied labels

### Execute plugin

- Fix failing to run on Windows (#3439)

## 2.0.3 (2019-06-12)

### Gtk UI

- Fix errors running on Wayland (#3265).
- Fix Peers Tab tooltip and context menu errors (#3266).

### Web UI

- Fix TypeError in Peers Tab setting country flag.
- Fix reverse proxy header TypeError (#3260).
- Fix request.base 'idna' codec error (#3261).
- Fix unable to change password (#3262).

### Extractor plugin

- Fix potential error starting plugin.

### Documentation

- Fix macOS install typo.
- Fix Windows install instructions.

## 2.0.2 (2019-06-08)

### Packaging

- Add systemd deluged and deluge-web service files to package tarball (#2034)

### Core

- Fix Python 2 compatibility issue with SimpleNamespace.

## 2.0.1 (2019-06-07)

### Packaging

- Fix `setup.py` build error without git installed.

## 2.0.0 (2019-06-06)

### Codebase

- Ported to Python 3

### Core

- Improved Logging
- Removed the AutoAdd feature on the core. It's now handled with the AutoAdd
  plugin, which is also shipped with Deluge, and it does a better job and
  now, it even supports multiple users perfectly.
- Authentication/Permission exceptions are now sent to clients and recreated
  there to allow acting upon them.
- Updated SSL/TLS Protocol parameters for better security.
- Make the distinction between adding to the session new unmanaged torrents
  and torrents loaded from state. This will break backwards compatibility.
- Pass a copy of an event instead of passing the event arguments to the
  event handlers. This will break backwards compatibility.
- Allow changing ownership of torrents.
- File modifications on the auth file are now detected and when they happen,
  the file is reloaded. Upon finding an old auth file with an old format, an
  upgrade to the new format is made, file saved, and reloaded.
- Authentication no longer requires a username/password. If one or both of
  these is missing, an authentication error will be sent to the client
  which should then ask the username/password to the user.
- Implemented sequential downloads.
- Provide information about a torrent's pieces states
- Add Option To Specify Outgoing Connection Interface.
- Fix potential for host_id collision when creating hostlist entries.

### Gtk UI

- Ported to GTK3 (3rd-party plugins will need updated).
- Allow changing ownership of torrents.
- Host entries in the Connection Manager UI are now editable.
- Implemented sequential downloads UI handling.
- Add optional pieces bar instead of a regular progress bar in torrent status tab.
- Make torrent opening compatible with all Unicode paths.
- Fix magnet association button on Windows.
- Add keyboard shortcuts for changing queue position:
  - Up: `Ctrl+Alt+Up`
  - Down: `Ctrl+Alt+Down`
  - Top: `Ctrl+Alt+Shift+Up`
  - Bottom: `Ctrl+Alt+Shift+Down`

### Web UI

- Server (deluge-web) now daemonizes by default, use '-d' or '--do-not-daemonize' to disable.
- Fixed the '--base' option to work for regular use, not just with reverse proxies.

### Blocklist Plugin

- Implemented whitelist support to both core and GTK UI.
- Implemented IP filter cleaning before each update. Restarting the deluge
  daemon is no longer needed.
- If "check_after_days" is 0(zero), the timer is not started anymore. It
  would keep updating one call after the other. If the value changed, the
  timer is now stopped and restarted using the new value.
