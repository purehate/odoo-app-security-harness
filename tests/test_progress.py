"""Tests for progress indicators and UX helpers."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from odoo_security_harness.progress import (
    ProgressBar,
    ProgressSpinner,
    confirm_prompt,
    print_error,
    print_success,
    print_summary,
    print_warning,
    progress,
    timed_operation,
)


class TestProgressSpinner:
    """Test ProgressSpinner context manager."""

    def test_spinner_start_stop(self, capsys):
        with ProgressSpinner("Testing"):
            pass
        captured = capsys.readouterr()
        assert "Testing..." in captured.out
        assert "✓" in captured.out

    def test_spinner_failure(self, capsys):
        with pytest.raises(RuntimeError):
            with ProgressSpinner("Testing"):
                raise RuntimeError("boom")
        captured = capsys.readouterr()
        assert "Testing..." in captured.out
        assert "✗" in captured.out

    def test_spinner_elapsed_time(self, capsys):
        with ProgressSpinner("Testing"):
            pass
        captured = capsys.readouterr()
        # Should contain elapsed time in seconds, e.g. (0.0s)
        assert "s)" in captured.out


class TestProgressBar:
    """Test ProgressBar display."""

    def test_progress_bar_completes(self, capsys):
        bar = ProgressBar(total=5, desc="Test")
        for _ in range(5):
            bar.update(1)
        captured = capsys.readouterr()
        assert "Test:" in captured.out
        assert "5/5" in captured.out
        assert "100.0%" in captured.out

    def test_progress_bar_zero_total(self, capsys):
        bar = ProgressBar(total=0, desc="Test")
        bar.update(1)
        captured = capsys.readouterr()
        # Should not crash and produce no output
        assert captured.out == ""

    def test_finish_sets_total(self, capsys):
        bar = ProgressBar(total=3, desc="Test")
        bar.finish()
        captured = capsys.readouterr()
        assert "3/3" in captured.out
        assert "100.0%" in captured.out


class TestTimedOperation:
    """Test timed_operation context manager."""

    def test_success_timing(self, capsys):
        with timed_operation("Build"):
            pass
        captured = capsys.readouterr()
        assert "▶ Build..." in captured.out
        assert "✓ Build completed in" in captured.out

    def test_failure_timing(self, capsys):
        with pytest.raises(ValueError):
            with timed_operation("Build"):
                raise ValueError("fail")
        captured = capsys.readouterr()
        assert "▶ Build..." in captured.out
        assert "✗ Build failed after" in captured.out


class TestPrintHelpers:
    """Test print helper functions."""

    def test_print_error(self, capsys):
        print_error("something went wrong")
        captured = capsys.readouterr()
        assert "ERROR: something went wrong" in captured.err

    def test_print_warning(self, capsys):
        print_warning("be careful")
        captured = capsys.readouterr()
        assert "WARNING: be careful" in captured.out

    def test_print_success(self, capsys):
        print_success("done")
        captured = capsys.readouterr()
        assert "✓ done" in captured.out

    def test_progress_message(self, capsys):
        progress("scan started")
        captured = capsys.readouterr()
        assert "[odoo-review-run] scan started" in captured.out

    def test_print_summary(self, capsys):
        print_summary("Results", {"high": 3, "medium": 5}, total=8)
        captured = capsys.readouterr()
        assert "Results" in captured.out
        assert "high" in captured.out
        assert "Total" in captured.out
        assert "8" in captured.out


class TestConfirmPrompt:
    """Test confirm_prompt interaction."""

    def test_yes_response(self):
        with patch("builtins.input", return_value="y"):
            assert confirm_prompt("Continue?") is True

    def test_no_response(self):
        with patch("builtins.input", return_value="n"):
            assert confirm_prompt("Continue?") is False

    def test_empty_default_false(self):
        with patch("builtins.input", return_value=""):
            assert confirm_prompt("Continue?", default=False) is False

    def test_empty_default_true(self):
        with patch("builtins.input", return_value=""):
            assert confirm_prompt("Continue?", default=True) is True

    def test_eof_returns_false(self):
        with patch("builtins.input", side_effect=EOFError):
            assert confirm_prompt("Continue?") is False
