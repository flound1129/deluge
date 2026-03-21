#
# Copyright (C) 2007 Andrew Resch <andrewresch@gmail.com>
#
# This file is part of Deluge and is licensed under GNU General Public License 3.0, or later, with
# the additional special exception to link portions of this program with the OpenSSL library.
# See LICENSE for more details.
#


"""PluginManagerBase"""

import configparser
import email
import logging
import os
import os.path
import sys
import zipfile
from importlib import import_module

from twisted.internet import defer
from twisted.python.failure import Failure

import deluge.common
import deluge.component as component
import deluge.configmanager

log = logging.getLogger(__name__)

METADATA_KEYS = [
    'Name',
    'License',
    'Author',
    'Home-page',
    'Summary',
    'Platform',
    'Version',
    'Author-email',
    'Description',
]

DEPRECATION_WARNING = """
The plugin %s is not using the "deluge_" namespace.
In order to avoid package name clashes between regular python packages and
deluge plugins, the way deluge plugins should be created has changed.
If you're seeing this message and you're not the developer of the plugin which
triggered this warning, please report to it's author.
If you're the developer, please take a look at the plugins hosted on deluge's
git repository to have an idea of what needs to be changed.
"""


class _PluginDistribution:
    """Lightweight distribution object for plugin discovery.

    Holds the metadata and entry points for a single plugin discovered
    from an egg-info directory, egg zip/directory, or egg-link file.
    """

    __slots__ = ('project_name', 'version', 'location', '_metadata', '_entry_points')

    def __init__(self, project_name, version, location, metadata, entry_points):
        self.project_name = project_name
        self.version = version
        self.location = location
        self._metadata = metadata
        self._entry_points = entry_points

    def get_metadata(self, name):
        if name == 'PKG-INFO':
            return self._metadata
        raise FileNotFoundError(name)

    def get_entry_map(self, group):
        return self._entry_points.get(group, {})

    def load_entry_point(self, group, name):
        ep = self._entry_points.get(group, {}).get(name)
        if ep is None:
            raise KeyError(f'No entry point {name!r} in group {group!r}')
        module_path, attr = ep.rsplit(':', 1)
        mod = import_module(module_path)
        return getattr(mod, attr)


def _parse_entry_points_txt(text):
    """Parse an entry_points.txt file into {group: {name: value}} dict."""
    result = {}
    cp = configparser.ConfigParser()
    cp.read_string(text)
    for section in cp.sections():
        group = {}
        for name, value in cp.items(section):
            group[name] = value.strip()
        result[section] = group
    return result


def _read_egg_info(egg_info_dir):
    """Read a .egg-info directory and return a _PluginDistribution or None."""
    pkg_info_path = os.path.join(egg_info_dir, 'PKG-INFO')
    if not os.path.isfile(pkg_info_path):
        return None

    with open(pkg_info_path, encoding='utf-8') as f:
        metadata_text = f.read()

    msg = email.message_from_string(metadata_text)
    project_name = msg.get('Name', '')
    version = msg.get('Version', '')

    entry_points = {}
    ep_path = os.path.join(egg_info_dir, 'entry_points.txt')
    if os.path.isfile(ep_path):
        with open(ep_path, encoding='utf-8') as f:
            entry_points = _parse_entry_points_txt(f.read())

    location = os.path.dirname(egg_info_dir)
    return _PluginDistribution(project_name, version, location, metadata_text, entry_points)


def _read_egg_zip(egg_path):
    """Read a .egg zip file and return a _PluginDistribution or None."""
    if not zipfile.is_zipfile(egg_path):
        return None

    try:
        with zipfile.ZipFile(egg_path, 'r') as zf:
            try:
                metadata_text = zf.read('EGG-INFO/PKG-INFO').decode('utf-8')
            except KeyError:
                return None

            msg = email.message_from_string(metadata_text)
            project_name = msg.get('Name', '')
            version = msg.get('Version', '')

            entry_points = {}
            try:
                ep_text = zf.read('EGG-INFO/entry_points.txt').decode('utf-8')
                entry_points = _parse_entry_points_txt(ep_text)
            except KeyError:
                pass

            return _PluginDistribution(
                project_name, version, egg_path, metadata_text, entry_points
            )
    except (zipfile.BadZipFile, OSError):
        return None


def _read_egg_dir(egg_dir):
    """Read an unpacked .egg directory (with EGG-INFO/) and return a _PluginDistribution or None."""
    egg_info = os.path.join(egg_dir, 'EGG-INFO')
    if not os.path.isdir(egg_info):
        return None

    pkg_info_path = os.path.join(egg_info, 'PKG-INFO')
    if not os.path.isfile(pkg_info_path):
        return None

    with open(pkg_info_path, encoding='utf-8') as f:
        metadata_text = f.read()

    msg = email.message_from_string(metadata_text)
    project_name = msg.get('Name', '')
    version = msg.get('Version', '')

    entry_points = {}
    ep_path = os.path.join(egg_info, 'entry_points.txt')
    if os.path.isfile(ep_path):
        with open(ep_path, encoding='utf-8') as f:
            entry_points = _parse_entry_points_txt(f.read())

    return _PluginDistribution(project_name, version, egg_dir, metadata_text, entry_points)


def _scan_plugin_dirs(dirs):
    """Scan directories for plugin distributions.

    Discovers plugins from:
    - .egg-info directories (setuptools develop/egg_info installs)
    - .egg zip files (bdist_egg)
    - unpacked .egg directories (Ubuntu-style installs)
    - .egg-link files (develop installs pointing to source directories)

    Returns a dict mapping normalised plugin names to lists of _PluginDistribution.
    """
    found = {}

    for scan_dir in dirs:
        if not os.path.isdir(scan_dir):
            continue

        for entry in os.listdir(scan_dir):
            full_path = os.path.join(scan_dir, entry)
            dist = None

            if entry.endswith('.egg-info') and os.path.isdir(full_path):
                dist = _read_egg_info(full_path)

            elif entry.endswith('.egg'):
                if os.path.isfile(full_path):
                    dist = _read_egg_zip(full_path)
                elif os.path.isdir(full_path):
                    dist = _read_egg_dir(full_path)

            elif entry.endswith('.egg-link') and os.path.isfile(full_path):
                with open(full_path, encoding='utf-8') as f:
                    lines = f.read().splitlines()
                if lines:
                    source_dir = lines[0].strip()
                    if os.path.isdir(source_dir):
                        if source_dir not in sys.path:
                            sys.path.insert(0, source_dir)
                        # Look for .egg-info dirs inside the source directory
                        for sub in os.listdir(source_dir):
                            sub_path = os.path.join(source_dir, sub)
                            if sub.endswith('.egg-info') and os.path.isdir(sub_path):
                                dist = _read_egg_info(sub_path)
                                if dist:
                                    break

            if dist and dist.project_name:
                norm_name = dist.project_name.lower().replace('-', ' ').replace('_', ' ')
                if norm_name not in found:
                    found[norm_name] = []
                found[norm_name].append(dist)

    return found


class _PluginEnvironment:
    """Dict-like lookup of plugin distributions by name.

    Keys are case-insensitive and dash/underscore/space normalised.
    """

    def __init__(self, distributions):
        self._dists = distributions

    def _normalise(self, name):
        return name.lower().replace('-', ' ').replace('_', ' ')

    def __getitem__(self, name):
        return self._dists.get(self._normalise(name), [])

    def __iter__(self):
        return iter(self._dists)

    def __contains__(self, name):
        return self._normalise(name) in self._dists


class PluginManagerBase:
    """PluginManagerBase is a base class for PluginManagers to inherit"""

    def __init__(
        self,
        config_file: str,
        entry_name: str,
        plugin_dirs: list[str | os.PathLike] | None = None,
    ) -> None:
        """Initialise the plugin manager.

        Args:
            config_file: Name of the config file (e.g. 'core.conf').
            entry_name: The setuptools entry-point group to load plugins from
                (e.g. 'deluge.plugin.core').
            plugin_dirs: Directories to scan for plugins. Defaults to None,
                which uses the standard base and user plugin directories.
                Primarily intended for testing.
        """
        log.debug('Plugin manager init..')

        self.config = deluge.configmanager.ConfigManager(config_file)

        # Create the plugins folder if it doesn't exist
        if not os.path.exists(
            os.path.join(deluge.configmanager.get_config_dir(), 'plugins')
        ):
            os.mkdir(os.path.join(deluge.configmanager.get_config_dir(), 'plugins'))

        # This is the entry we want to load..
        self.entry_name = entry_name

        # Loaded plugins
        self.plugins = {}

        # Directories scanned for plugins
        self.plugin_dirs = plugin_dirs if plugin_dirs else self.default_plugin_dirs()

        # Scan the plugin folders for plugins
        self.scan_for_plugins()

    def enable_plugins(self):
        # Load plugins that are enabled in the config.
        for name in self.config['enabled_plugins']:
            self.enable_plugin(name)

    def disable_plugins(self):
        """Disable all plugins that are enabled"""
        # Dict will be modified so iterate over generated list
        for key in list(self.plugins):
            self.disable_plugin(key)

    def __getitem__(self, key):
        return self.plugins[key]

    def get_available_plugins(self):
        """Returns a list of the available plugins name"""
        return self.available_plugins

    def get_enabled_plugins(self):
        """Returns a list of enabled plugins"""
        return list(self.plugins)

    @staticmethod
    def default_plugin_dirs() -> list[str]:
        """Returns the default directories to scan for plugins."""
        base_dir = deluge.common.resource_filename('deluge', 'plugins')
        user_dir = os.path.join(deluge.configmanager.get_config_dir(), 'plugins')
        base_subdir = [
            os.path.join(base_dir, f)
            for f in os.listdir(base_dir)
            if os.path.isdir(os.path.join(base_dir, f))
        ]
        plugin_dirs = [base_dir, user_dir] + base_subdir
        return plugin_dirs

    def scan_for_plugins(self) -> None:
        """Scan plugin_dirs for available plugins."""
        str_dirs = [str(d) for d in self.plugin_dirs]
        for dirname in str_dirs:
            if os.path.isdir(dirname) and dirname not in sys.path:
                sys.path.insert(0, dirname)
        self.pkg_env = _PluginEnvironment(_scan_plugin_dirs(str_dirs))

        self.available_plugins = []
        for name in self.pkg_env:
            dists = self.pkg_env[name]
            if dists:
                dist = dists[0]
                log.debug(
                    'Found plugin: %s %s at %s',
                    dist.project_name,
                    dist.version,
                    dist.location,
                )
                self.available_plugins.append(dist.project_name)

    def enable_plugin(self, plugin_name):
        """Enable a plugin.

        Args:
            plugin_name (str): The plugin name.

        Returns:
            Deferred: A deferred with callback value True or False indicating
                whether the plugin is enabled or not.

        """
        if plugin_name not in self.available_plugins:
            log.warning('Cannot enable non-existent plugin %s', plugin_name)
            return defer.succeed(False)

        if plugin_name in self.plugins:
            log.warning('Cannot enable already enabled plugin %s', plugin_name)
            return defer.succeed(True)

        plugin_name = plugin_name.replace(' ', '-')
        dists = self.pkg_env[plugin_name]
        if not dists:
            log.warning('Cannot find distribution for plugin %s', plugin_name)
            return defer.succeed(False)
        egg = dists[0]
        # Ensure the plugin location is importable
        if egg.location not in sys.path:
            sys.path.insert(0, egg.location)
        return_d = defer.succeed(True)

        for name in egg.get_entry_map(self.entry_name):
            try:
                cls = egg.load_entry_point(self.entry_name, name)
                instance = cls(plugin_name.replace('-', '_'))
            except component.ComponentAlreadyRegistered as ex:
                log.error(ex)
                return defer.succeed(False)
            except Exception as ex:
                log.error(
                    'Unable to instantiate plugin %r from %r!', name, egg.location
                )
                log.exception(ex)
                continue
            try:
                return_d = defer.maybeDeferred(instance.enable)
            except Exception as ex:
                log.error('Unable to enable plugin: %s', name)
                log.exception(ex)
                return_d = defer.fail(False)

            if not instance.__module__.startswith('deluge_'):
                import warnings

                warnings.warn_explicit(
                    DEPRECATION_WARNING % name,
                    DeprecationWarning,
                    instance.__module__,
                    0,
                )
            if self._component_state == 'Started':

                def on_enabled(result, instance):
                    return component.start([instance.plugin._component_name])

                return_d.addCallback(on_enabled, instance)

            def on_started(result, instance):
                plugin_name_space = plugin_name.replace('-', ' ')
                self.plugins[plugin_name_space] = instance
                if plugin_name_space not in self.config['enabled_plugins']:
                    log.debug(
                        'Adding %s to enabled_plugins list in config', plugin_name_space
                    )
                    self.config['enabled_plugins'].append(plugin_name_space)
                log.info('Plugin %s enabled...', plugin_name_space)
                return True

            def on_started_error(result, instance):
                log.error(
                    'Failed to start plugin: %s\n%s',
                    plugin_name,
                    result.getTraceback(elideFrameworkCode=1, detail='brief'),
                )
                self.plugins[plugin_name.replace('-', ' ')] = instance
                self.disable_plugin(plugin_name)
                return False

            return_d.addCallbacks(
                on_started,
                on_started_error,
                callbackArgs=[instance],
                errbackArgs=[instance],
            )
            return return_d

        return defer.succeed(False)

    def disable_plugin(self, name):
        """Disable a plugin.

        Args:
            plugin_name (str): The plugin name.

        Returns:
            Deferred: A deferred with callback value True or False indicating
                whether the plugin is disabled or not.

        """
        if name not in self.plugins:
            log.warning('Plugin "%s" is not enabled...', name)
            return defer.succeed(True)

        try:
            d = defer.maybeDeferred(self.plugins[name].disable)
        except Exception as ex:
            log.error('Error when disabling plugin: %s', self.plugin._component_name)
            log.debug(ex)
            d = defer.succeed(False)

        def on_disabled(result):
            ret = True
            if isinstance(result, Failure):
                log.debug(
                    'Error when disabling plugin %s: %s', name, result.getTraceback()
                )
                ret = False
            try:
                component.deregister(self.plugins[name].plugin)
                del self.plugins[name]
                self.config['enabled_plugins'].remove(name)
            except Exception as ex:
                log.warning('Problems occurred disabling plugin: %s', name)
                log.debug(ex)
                ret = False
            else:
                log.info('Plugin %s disabled...', name)
            return ret

        d.addBoth(on_disabled)
        return d

    def get_plugin_info(self, name):
        """Returns a dictionary of plugin info from the metadata"""

        if not self.pkg_env[name]:
            log.warning('Failed to retrieve info for plugin: %s', name)
            info = {}.fromkeys(METADATA_KEYS, '')
            info['Name'] = info['Version'] = 'not available'
            return info

        pkg_info = self.pkg_env[name][0].get_metadata('PKG-INFO')
        return self.parse_pkg_info(pkg_info)

    @staticmethod
    def parse_pkg_info(pkg_info):
        metadata_msg = email.message_from_string(pkg_info)
        metadata_ver = metadata_msg.get('Metadata-Version')

        info = {key: metadata_msg.get(key, '') for key in METADATA_KEYS}

        # Optional Description field in body (Metadata spec >=2.1)
        if not info['Description'] and metadata_ver.startswith('2'):
            info['Description'] = metadata_msg.get_payload().strip()

        return info
