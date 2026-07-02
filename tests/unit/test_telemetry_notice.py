# tests/unit/test_telemetry_notice.py
#
# Tests for telemetry/notice.py
#
# Verifies:
# - Notice prints on first run
# - Notice does NOT print on subsequent runs
# - Marker file is created after first display
# - Notice does not crash if marker dir is unwritable
# - Notice reflects current telemetry status correctly

from pathlib import Path
from unittest.mock import patch

import pytest

from telemetry.notice import show_first_run_notice_if_needed


# =====================================================
# HELPERS
# =====================================================


def _marker(tmp_path: Path) -> Path:
    """Return the expected marker file path."""
    return tmp_path / "notice_shown"


# =====================================================
# FIRST RUN — notice should print
# =====================================================


class TestFirstRun:
    def test_prints_on_first_run(self, tmp_path, capsys):
        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert "Verdict collects" in captured.out

    def test_marker_created_after_first_run(self, tmp_path, capsys):
        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()

        assert _marker(tmp_path).exists()

    def test_shows_enabled_status_when_telemetry_on(self, tmp_path, capsys):
        with (
            patch("telemetry.notice.get_db_dir", return_value=tmp_path),
            patch("telemetry.notice.is_telemetry_enabled", return_value=True),
        ):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert "enabled" in captured.out.lower()

    def test_shows_disabled_status_when_telemetry_off(self, tmp_path, capsys):
        with (
            patch("telemetry.notice.get_db_dir", return_value=tmp_path),
            patch("telemetry.notice.is_telemetry_enabled", return_value=False),
        ):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert "disabled" in captured.out.lower()

    def test_opt_out_instructions_included(self, tmp_path, capsys):
        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert "OW_HISTORY_ENABLED=false" in captured.out

    def test_docs_link_included(self, tmp_path, capsys):
        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert "obsidianwall.dev" in captured.out


# =====================================================
# SUBSEQUENT RUNS — notice should NOT print
# =====================================================


class TestSubsequentRuns:
    def test_no_output_on_second_run(self, tmp_path, capsys):
        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()  # first run
            capsys.readouterr()                # clear output
            show_first_run_notice_if_needed()  # second run

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_output_when_marker_pre_exists(self, tmp_path, capsys):
        _marker(tmp_path).touch()  # simulate prior run

        with patch("telemetry.notice.get_db_dir", return_value=tmp_path):
            show_first_run_notice_if_needed()

        captured = capsys.readouterr()
        assert captured.out == ""


# =====================================================
# RESILIENCE — notice must never crash CLI
# =====================================================


class TestResilience:
    def test_does_not_raise_if_marker_write_fails(self, tmp_path, capsys):
        """
        If the marker file cannot be written or read due to
        filesystem permissions, the notice should still print
        and must not raise any exception.
        """
        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()
        read_only_dir.chmod(0o444)

        try:
            with patch("telemetry.notice.get_db_dir", return_value=read_only_dir):
                # Must not raise even if exists() and touch() fail
                show_first_run_notice_if_needed()
        except Exception as exc:
            pytest.fail(
                f"show_first_run_notice_if_needed() raised unexpectedly: {exc}"
            )
        finally:
            # Restore permissions so pytest can clean up tmp_path
            read_only_dir.chmod(0o755)

    def test_notice_still_printed_when_marker_unreadable(self, tmp_path, capsys):
        """
        When marker.exists() raises PermissionError, the notice
        should still be shown (treating it as a first run).
        """
        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()
        read_only_dir.chmod(0o444)

        try:
            with patch("telemetry.notice.get_db_dir", return_value=read_only_dir):
                show_first_run_notice_if_needed()

            captured = capsys.readouterr()
            assert "Verdict collects" in captured.out
        finally:
            read_only_dir.chmod(0o755)