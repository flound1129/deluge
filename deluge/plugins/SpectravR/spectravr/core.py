"""SpectraVR plugin core — REST endpoints, SQLite state, streaming."""

import json
import os
import sqlite3
import logging

log = logging.getLogger(__name__)

# VR projection suffix map  (projection key → filename suffix, no extension)
VR_TAGS = {
    "vr180_lr":        "_180_lr",
    "vr180_tb":        "_180_ou",
    "sphere_360_mono": "_360",
    "sphere_360_3d":   "_360_3d",
    "fisheye":         "_fisheye_180",
}

ALL_VR_SUFFIXES = list(VR_TAGS.values())


def strip_vr_tag(stem: str) -> str:
    """Remove any existing VR suffix from a filename stem (no extension)."""
    for suffix in ALL_VR_SUFFIXES:
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def apply_vr_tag_to_name(filename: str, projection: str | None) -> str:
    """Return new filename with VR tag applied (or removed if projection is None)."""
    if "." in filename:
        stem, ext = filename.rsplit(".", 1)
        ext = "." + ext
    else:
        stem, ext = filename, ""
    clean = strip_vr_tag(stem)
    if projection is None:
        return clean + ext
    suffix = VR_TAGS.get(projection, "")
    return clean + suffix + ext


def db_connect(db_path: str) -> sqlite3.Connection:
    """Open (or create) the plugin SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_metadata (
            path TEXT PRIMARY KEY,
            favorited INTEGER DEFAULT 0,
            hidden    INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def db_toggle(conn: sqlite3.Connection, path: str, column: str) -> None:
    """Toggle a boolean column in file_metadata for the given path key."""
    assert column in ("favorited", "hidden")
    conn.execute(
        f"INSERT INTO file_metadata (path, {column}) VALUES (?, 1) "
        f"ON CONFLICT(path) DO UPDATE SET {column} = 1 - {column}",
        (path,),
    )
    conn.commit()


def db_get(conn: sqlite3.Connection, path: str) -> dict:
    """Return {favorited, hidden} for path; defaults 0 if not present."""
    row = conn.execute(
        "SELECT favorited, hidden FROM file_metadata WHERE path = ?", (path,)
    ).fetchone()
    return {"favorited": bool(row[0]), "hidden": bool(row[1])} if row else {"favorited": False, "hidden": False}


class Core:
    """Deluge core plugin class — registered by setup.py entry point."""

    def __init__(self, plugin_api, *args, **kwargs):
        self.plugin_api = plugin_api
        self.resource = None
        self.db = None

    def enable(self):
        """Called when plugin is enabled in Deluge preferences."""
        import deluge.configmanager as cm
        config_dir = cm.get_config_dir()
        db_path = os.path.join(config_dir, "spectravr.db")
        conf_path = os.path.join(config_dir, "spectravr.conf")
        self.token = self._load_token(conf_path)
        self.db = db_connect(db_path)

        # Register REST resource on Deluge's Twisted web server.
        try:
            import deluge.component as component
            from .resource import SpectravRResource
            self.resource = SpectravRResource(self)
            component.get("DelugeWeb").top_level.putChild(b"spectravr", self.resource)
            log.info("SpectravR plugin enabled, resource registered at /spectravr/")
        except Exception as e:
            log.error("Failed to register SpectravR resource: %s", e)

    def disable(self):
        """Called when plugin is disabled."""
        try:
            import deluge.component as component
            top = component.get("DelugeWeb").top_level
            if b"spectravr" in top.children:
                del top.children[b"spectravr"]
        except Exception as e:
            log.warning("Error deregistering SpectravR resource: %s", e)
        if self.db:
            self.db.close()
            self.db = None

    def update(self):
        pass

    @staticmethod
    def _load_token(conf_path: str) -> str:
        """Read token from spectravr.conf; return empty string if missing."""
        if not os.path.exists(conf_path):
            return ""
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(conf_path)
        return cfg.get("spectravr", "token", fallback="")
