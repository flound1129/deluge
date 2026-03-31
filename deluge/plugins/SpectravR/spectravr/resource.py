"""Twisted Resource subclass for all /spectravr/* REST endpoints."""

import json
import logging
import os

from twisted.web import resource, http

from spectravr.core import db_get, db_toggle

log = logging.getLogger(__name__)


def check_auth(header_value: str | None, expected_token: str) -> bool:
    """Return True if the Authorization header contains the correct bearer token."""
    if not header_value:
        return False
    parts = header_value.split(" ", 1)
    return len(parts) == 2 and parts[0] == "Bearer" and parts[1] == expected_token


def json_response(request, data: dict, code: int = 200) -> bytes:
    request.setHeader(b"Content-Type", b"application/json")
    request.setResponseCode(code)
    return json.dumps(data).encode("utf-8")


def error_response(request, message: str, code: int) -> bytes:
    return json_response(request, {"error": message}, code)


def require_auth(request, token: str) -> bool:
    """Check auth; if failed, write 401 to request. Returns True if auth ok."""
    auth = request.getHeader("Authorization")
    if not check_auth(auth, token):
        request.write(error_response(request, "Unauthorized", 401))
        request.finish()
        return False
    return True


def check_deluge_session(request) -> bool:
    """Return True if the request carries a valid Deluge web session cookie."""
    try:
        from deluge.ui.web.auth import get_session_id
        import deluge.component as component
        cookie = request.getCookie(b"_session_id")
        if not cookie:
            return False
        session_id = get_session_id(cookie.decode())
        auth = component.get("Auth")
        return session_id in auth.config["sessions"]
    except Exception:
        return False


def body_json(request) -> dict:
    """Parse request body as JSON, return {} on error."""
    try:
        return json.loads(request.content.read())
    except Exception:
        return {}


class SpectravRResource(resource.Resource):
    """Root resource at /spectravr/. Routes requests by path segments."""
    isLeaf = True

    def __init__(self, core):
        super().__init__()
        self.core = core

    def render(self, request):
        path = request.postpath  # list of bytes segments
        method = request.method.decode("utf-8").upper()

        # Admin endpoint: reveal token to a logged-in Deluge web user.
        # Protected by Deluge session cookie, not the bearer token.
        if path == [b"admin", b"token"] and method == "GET":
            if not check_deluge_session(request):
                return error_response(request, "Unauthorized", 401)
            return json_response(request, {"token": getattr(self.core, "token", "")})

        token = getattr(self.core, "token", "")
        auth = request.getHeader("Authorization")
        if not check_auth(auth, token):
            return error_response(request, "Unauthorized", 401)

        try:
            return self._route(request, method, path)
        except Exception as e:
            log.exception("SpectravR handler error")
            return error_response(request, str(e), 500)

    def _route(self, request, method: str, path: list[bytes]) -> bytes:
        segs = [s.decode("utf-8") for s in path if s]

        # GET /spectravr/ping
        if segs == ["ping"] and method == "GET":
            return json_response(request, {"status": "ok"})

        # GET /spectravr/torrents
        if segs == ["torrents"] and method == "GET":
            return self._get_torrents(request)

        # POST /spectravr/torrents/add
        if segs == ["torrents", "add"] and method == "POST":
            return self._add_torrent(request)

        # POST /spectravr/torrents/{hash}/pause|resume|remove|recheck|move
        if len(segs) == 3 and segs[0] == "torrents" and method == "POST":
            return self._torrent_action(request, segs[1], segs[2])

        # GET /spectravr/torrents/{hash}/files
        if len(segs) == 3 and segs[0] == "torrents" and segs[2] == "files" and method == "GET":
            return self._get_files(request, segs[1])

        # GET /spectravr/torrents/{hash}/magnet
        if len(segs) == 3 and segs[0] == "torrents" and segs[2] == "magnet" and method == "GET":
            return self._get_magnet(request, segs[1])

        # POST /spectravr/files/rename|tag|priorities|favorite|hidden|trash
        if len(segs) == 2 and segs[0] == "files" and method == "POST":
            return self._file_action(request, segs[1])

        # GET /spectravr/stream/{hash}/{file_index}
        if len(segs) == 3 and segs[0] == "stream" and method == "GET":
            return self._stream(request, segs[1], segs[2])

        return error_response(request, "Not found", 404)

    # ------------------------------------------------------------------ torrents

    def _get_torrents(self, request) -> bytes:
        import deluge.component as component
        core = component.get("Core")
        fields = ["name", "progress", "state", "total_size"]
        status = core.get_torrents_status({}, fields)
        torrents = [
            {
                "hash": h,
                "name": v.get("name", ""),
                "progress": v.get("progress", 0.0),
                "state": v.get("state", ""),
                "total_size": v.get("total_size", 0),
            }
            for h, v in status.items()
        ]
        return json_response(request, {"torrents": torrents})

    def _add_torrent(self, request) -> bytes:
        body = body_json(request)
        uri = body.get("uri", "")
        if not uri:
            return error_response(request, "uri required", 400)
        import deluge.component as component
        core = component.get("Core")
        options = {"add_paused": True}
        if uri.startswith("magnet:"):
            torrent_hash = core.add_torrent_magnet(uri, options)
        else:
            torrent_hash = core.add_torrent_url(uri, options)
        if not torrent_hash:
            return error_response(request, "Failed to add torrent", 500)
        return json_response(request, {"hash": torrent_hash})

    def _torrent_action(self, request, torrent_hash: str, action: str) -> bytes:
        import deluge.component as component
        core = component.get("Core")
        body = body_json(request)
        if action == "pause":
            core.pause_torrent([torrent_hash])
        elif action == "resume":
            core.resume_torrent([torrent_hash])
        elif action == "remove":
            core.remove_torrent(torrent_hash, body.get("delete_data", False))
        elif action == "recheck":
            core.force_recheck([torrent_hash])
        elif action == "move":
            dest = body.get("path", "")
            if not dest:
                return error_response(request, "path required", 400)
            core.move_storage([torrent_hash], dest)
        else:
            return error_response(request, f"Unknown action: {action}", 404)
        return json_response(request, {"ok": True})

    def _get_magnet(self, request, torrent_hash: str) -> bytes:
        import deluge.component as component
        status = component.get("Core").get_torrent_status(torrent_hash, ["magnet_uri"])
        magnet = status.get("magnet_uri", "")
        return json_response(request, {"magnet": magnet})

    # ------------------------------------------------------------------ files

    def _get_files(self, request, torrent_hash: str) -> bytes:
        import deluge.component as component
        status = component.get("Core").get_torrent_status(
            torrent_hash, ["files", "file_progress", "save_path"]
        )
        raw_files = status.get("files", [])
        progress_list = status.get("file_progress", [])
        files = []
        for i, f in enumerate(raw_files):
            rel_path = f.get("path", f.get("filename", ""))
            meta_key = f"{torrent_hash}/{rel_path}"
            meta = db_get(self.core.db, meta_key)
            files.append({
                "index": i,
                "path": rel_path,
                "size": f.get("size", 0),
                "progress": progress_list[i] if i < len(progress_list) else 0.0,
                "favorited": meta["favorited"],
                "hidden": meta["hidden"],
            })
        return json_response(request, {"files": files})

    def _file_action(self, request, action: str) -> bytes:
        body = body_json(request)
        torrent_hash = body.get("hash", "")
        file_index = body.get("file_index", -1)

        if action == "rename":
            new_name = body.get("new_name", "")
            if not new_name:
                return error_response(request, "new_name required", 400)
            import deluge.component as component
            component.get("Core").rename_files(torrent_hash, [(file_index, new_name)])
            return json_response(request, {"ok": True})

        if action == "tag":
            from spectravr.core import apply_vr_tag_to_name
            import deluge.component as component
            projection = body.get("projection")
            status = component.get("Core").get_torrent_status(torrent_hash, ["files"])
            raw_files = status.get("files", [])
            if file_index >= len(raw_files):
                return error_response(request, "file_index out of range", 400)
            old_path = raw_files[file_index].get("path", raw_files[file_index].get("filename", ""))
            basename = os.path.basename(old_path)
            new_basename = apply_vr_tag_to_name(basename, projection)
            new_path = os.path.join(os.path.dirname(old_path), new_basename)
            component.get("Core").rename_files(torrent_hash, [(file_index, new_path)])
            return json_response(request, {"ok": True})

        if action == "priorities":
            priorities = body.get("priorities", [])
            import deluge.component as component
            component.get("Core").set_torrent_file_priorities(torrent_hash, priorities)
            return json_response(request, {"ok": True})

        if action in ("favorite", "hidden"):
            status = self._file_meta_key(torrent_hash, file_index)
            if status is None:
                return error_response(request, "Cannot resolve file path", 400)
            col = "favorited" if action == "favorite" else "hidden"
            db_toggle(self.core.db, status, col)
            return json_response(request, {"ok": True})

        if action == "trash":
            import deluge.component as component
            ts = component.get("Core").get_torrent_status(torrent_hash, ["save_path", "files"])
            save_path = ts.get("save_path", "")
            raw_files = ts.get("files", [])
            if file_index >= len(raw_files):
                return error_response(request, "file_index out of range", 400)
            rel = raw_files[file_index].get("path", raw_files[file_index].get("filename", ""))
            full_path = os.path.join(save_path, rel)
            trash_dir = os.path.join(save_path, ".trash")
            os.makedirs(trash_dir, exist_ok=True)
            dest = os.path.join(trash_dir, os.path.basename(rel))
            os.rename(full_path, dest)
            return json_response(request, {"ok": True})

        return error_response(request, f"Unknown file action: {action}", 404)

    def _file_meta_key(self, torrent_hash: str, file_index: int) -> str | None:
        """Build the DB key {hash}/{rel_path} for a given file index."""
        import deluge.component as component
        status = component.get("Core").get_torrent_status(torrent_hash, ["files"])
        raw_files = status.get("files", [])
        if file_index >= len(raw_files):
            return None
        rel = raw_files[file_index].get("path", raw_files[file_index].get("filename", ""))
        return f"{torrent_hash}/{rel}"

    # ------------------------------------------------------------------ streaming

    def _stream(self, request, torrent_hash: str, file_index_str: str) -> bytes | None:
        try:
            file_index = int(file_index_str)
        except ValueError:
            return error_response(request, "Invalid file index", 400)

        import deluge.component as component
        status = component.get("Core").get_torrent_status(
            torrent_hash, ["save_path", "files"]
        )
        save_path = status.get("save_path", "")
        raw_files = status.get("files", [])
        if file_index >= len(raw_files):
            return error_response(request, "file_index out of range", 400)
        rel = raw_files[file_index].get("path", raw_files[file_index].get("filename", ""))
        file_path = os.path.join(save_path, rel)

        if not os.path.isfile(file_path):
            return error_response(request, "File not on disk", 404)

        file_size = os.path.getsize(file_path)
        range_header = request.getHeader("Range")

        start, end = 0, file_size - 1
        if range_header and range_header.startswith("bytes="):
            parts = range_header[6:].split("-")
            try:
                start = int(parts[0]) if parts[0] else 0
                end = int(parts[1]) if parts[1] else file_size - 1
            except (IndexError, ValueError):
                pass

        start = max(0, min(start, file_size - 1))
        end = max(start, min(end, file_size - 1))
        length = end - start + 1

        request.setHeader(b"Content-Type", b"video/mp4")
        request.setHeader(b"Content-Length", str(length).encode())
        request.setHeader(
            b"Content-Range", f"bytes {start}-{end}/{file_size}".encode()
        )
        request.setHeader(b"Accept-Ranges", b"bytes")
        request.setResponseCode(206)

        with open(file_path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                request.write(chunk)
                remaining -= len(chunk)
        request.finish()
        return b""  # already written
