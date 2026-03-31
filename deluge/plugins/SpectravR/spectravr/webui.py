"""SpectraVR web plugin — registers the settings JS with Deluge's web UI."""

from deluge.plugins.pluginbase import WebPluginBase

from .common import get_resource


class WebUI(WebPluginBase):
    scripts = [get_resource('spectravr.js')]
    debug_scripts = scripts
