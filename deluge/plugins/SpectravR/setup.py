from setuptools import setup, find_packages

setup(
    name="SpectravR",
    version="0.1.0",
    description="SpectraVR Deluge plugin — REST API for torrent management and streaming",
    author="SpectraVR",
    packages=find_packages(exclude=["tests"]),
    package_data={
        "spectravr": ["data/*.js"],
    },
    entry_points={
        "deluge.plugin.core": [
            "SpectravR = spectravr:CorePlugin",
        ],
        "deluge.plugin.web": [
            "SpectravR = spectravr.webui:WebUI",
        ],
    },
)
