"""Unit tests for spectravr.core pure functions."""
import sqlite3
import pytest
from spectravr.core import (
    strip_vr_tag,
    apply_vr_tag_to_name,
    db_connect,
    db_toggle,
    db_get,
)


class TestStripVrTag:
    def test_strips_180_lr(self):
        assert strip_vr_tag("movie_180_lr") == "movie"

    def test_strips_180_ou(self):
        assert strip_vr_tag("clip_180_ou") == "clip"

    def test_strips_360(self):
        assert strip_vr_tag("video_360") == "video"

    def test_strips_360_3d(self):
        assert strip_vr_tag("show_360_3d") == "show"

    def test_strips_fisheye_180(self):
        assert strip_vr_tag("content_fisheye_180") == "content"

    def test_no_tag_unchanged(self):
        assert strip_vr_tag("plain_video") == "plain_video"

    def test_partial_match_not_stripped(self):
        # "_lr" alone should not be stripped (must be "_180_lr")
        assert strip_vr_tag("video_lr") == "video_lr"


class TestApplyVrTagToName:
    def test_applies_180_lr(self):
        assert apply_vr_tag_to_name("video.mp4", "vr180_lr") == "video_180_lr.mp4"

    def test_applies_fisheye(self):
        assert apply_vr_tag_to_name("clip.mkv", "fisheye") == "clip_fisheye_180.mkv"

    def test_replaces_existing_tag(self):
        assert apply_vr_tag_to_name("video_180_lr.mp4", "sphere_360_mono") == "video_360.mp4"

    def test_removes_tag_when_none(self):
        assert apply_vr_tag_to_name("video_360.mp4", None) == "video.mp4"

    def test_no_extension(self):
        assert apply_vr_tag_to_name("rawfile", "vr180_lr") == "rawfile_180_lr"

    def test_unknown_projection_appends_empty(self):
        # Unknown projection key → suffix "" → no change beyond stripping old tag
        result = apply_vr_tag_to_name("video.mp4", "unknown")
        assert result == "video.mp4"


class TestDbToggle:
    def setup_method(self):
        self.conn = db_connect(":memory:")

    def test_toggle_favorited_on(self):
        db_toggle(self.conn, "abc/file.mp4", "favorited")
        assert db_get(self.conn, "abc/file.mp4")["favorited"] is True

    def test_toggle_favorited_off(self):
        db_toggle(self.conn, "abc/file.mp4", "favorited")
        db_toggle(self.conn, "abc/file.mp4", "favorited")
        assert db_get(self.conn, "abc/file.mp4")["favorited"] is False

    def test_toggle_hidden(self):
        db_toggle(self.conn, "abc/file.mp4", "hidden")
        assert db_get(self.conn, "abc/file.mp4")["hidden"] is True

    def test_default_when_not_present(self):
        result = db_get(self.conn, "not/present.mp4")
        assert result == {"favorited": False, "hidden": False}

    def test_different_keys_independent(self):
        db_toggle(self.conn, "abc/file1.mp4", "favorited")
        result = db_get(self.conn, "abc/file2.mp4")
        assert result["favorited"] is False


class TestAuthCheck:
    """Test the check_auth pure helper (extracted from resource)."""

    def test_valid_token(self):
        from spectravr.resource import check_auth
        assert check_auth("Bearer mytoken", "mytoken") is True

    def test_wrong_token(self):
        from spectravr.resource import check_auth
        assert check_auth("Bearer wrong", "mytoken") is False

    def test_missing_header(self):
        from spectravr.resource import check_auth
        assert check_auth(None, "mytoken") is False

    def test_no_bearer_prefix(self):
        from spectravr.resource import check_auth
        assert check_auth("mytoken", "mytoken") is False
