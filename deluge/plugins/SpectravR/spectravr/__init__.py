"""SpectraVR Deluge plugin."""

PLUGIN_NAME = "SpectravR"
PLUGIN_DESCRIPTION = "REST API for torrent management, streaming, and file ops"
PLUGIN_VERSION = "0.1.0"
PLUGIN_AUTHOR = "SpectraVR"


def CorePlugin(plugin_api, *args, **kwargs):
    from .core import Core
    return Core(plugin_api, *args, **kwargs)
