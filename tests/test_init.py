"""Tests for odoo_security_harness package utilities."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from odoo_security_harness import (
    clean_output,
    compute_fingerprint,
    load_json,
    normalize_line,
    progress,
    rel,
    setup_logging,
    severity_rank,
    should_skip,
    timestamp,
    write_json,
)


class TestSetupLogging:
    """Test logging configuration."""

    def test_sets_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        kwargs: dict[str, object] = {}

        def fake_basic_config(**config: object) -> None:
            kwargs.update(config)

        monkeypatch.setattr(logging, "basicConfig", fake_basic_config)

        setup_logging(logging.DEBUG)
        assert kwargs["level"] == logging.DEBUG


class TestCleanOutput:
    """Test ANSI stripping."""

    def test_strips_ansi_codes(self) -> None:
        text = "\x1b[31mred\x1b[0m normal"
        assert clean_output(text) == "red normal"

    def test_converts_crlf(self) -> None:
        assert clean_output("line1\rline2") == "line1\nline2"


class TestProgress:
    """Test progress output."""

    def test_prints_message(self, capsys: pytest.CaptureFixture[str]) -> None:
        progress("scanning")
        captured = capsys.readouterr()
        assert "scanning" in captured.out


class TestRel:
    """Test relative path helper."""

    def test_relative_path(self, tmp_path: Path) -> None:
        root = tmp_path / "project"
        path = root / "models" / "sale.py"
        assert rel(path, root) == "models/sale.py"

    def test_falls_back_to_absolute(self, tmp_path: Path) -> None:
        root = tmp_path / "a"
        path = tmp_path / "b" / "file.py"
        assert rel(path, root) == str(path)


class TestShouldSkip:
    """Test path filtering."""

    def test_skips_git(self) -> None:
        assert should_skip(Path("repo/.git/config")) is True

    def test_skips_audit_dirs(self) -> None:
        assert should_skip(Path("repo/.audit-deep/foo")) is True

    def test_allows_audit_files(self) -> None:
        assert should_skip(Path("repo/.audit-accepted-risks.yml")) is False

    def test_allows_source(self) -> None:
        assert should_skip(Path("repo/models/sale.py")) is False


class TestNormalizeLine:
    """Test whitespace normalization."""

    def test_collapses_spaces(self) -> None:
        assert normalize_line("  hello   world  ") == "hello world"


class TestComputeFingerprint:
    """Test fingerprint generation."""

    def test_stable_output(self) -> None:
        finding = {
            "rule_id": "test",
            "file": "/tmp/test.py",
            "line": 5,
            "description": "something",
        }
        fp1 = compute_fingerprint(finding)
        fp2 = compute_fingerprint(finding)
        assert fp1 == fp2
        assert fp1.startswith("sha256:")

    def test_different_inputs_differ(self) -> None:
        fp1 = compute_fingerprint({"rule_id": "a", "file": "f", "line": 1})
        fp2 = compute_fingerprint({"rule_id": "b", "file": "f", "line": 1})
        assert fp1 != fp2


class TestSeverityRank:
    """Test severity ranking."""

    def test_known_severities(self) -> None:
        assert severity_rank("critical") == 4
        assert severity_rank("high") == 3
        assert severity_rank("medium") == 2
        assert severity_rank("low") == 1
        assert severity_rank("info") == 0

    def test_unknown_defaults_to_medium(self) -> None:
        assert severity_rank("unknown") == 2
        assert severity_rank(None) == 2


class TestLoadJson:
    """Test JSON loading."""

    def test_loads_valid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "data.json"
        path.write_text('{"key": "value"}', encoding="utf-8")
        assert load_json(path) == {"key": "value"}

    def test_raises_on_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            load_json(path)

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_json(tmp_path / "missing.json")


class TestWriteJson:
    """Test JSON writing."""

    def test_writes_json(self, tmp_path: Path) -> None:
        path = tmp_path / "out" / "data.json"
        write_json(path, {"key": "value"})
        assert json.loads(path.read_text(encoding="utf-8")) == {"key": "value"}


class TestTimestamp:
    """Test timestamp generation."""

    def test_returns_iso_format(self) -> None:
        ts = timestamp()
        assert ts.endswith("+00:00")
        assert "T" in ts
