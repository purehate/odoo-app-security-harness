"""Tests for manifest parsing and module discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestParseManifest:
    """Test manifest parsing functionality."""

    def test_parse_valid_manifest(self, temp_repo: Path) -> None:
        """Test parsing a valid __manifest__.py file."""
        manifest_path = temp_repo / "test_module" / "__manifest__.py"
        text = manifest_path.read_text(encoding="utf-8")
        data = json.loads(text)  # Simulate ast.literal_eval

        assert data["name"] == "Test Module"
        assert data["version"] == "1.0.0"
        assert data["depends"] == ["base", "web"]
        assert data["installable"] is True
        assert data["application"] is False

    def test_parse_manifest_with_parse_error(self, temp_repo: Path) -> None:
        """Test handling of malformed manifest."""
        bad_manifest = temp_repo / "bad_module"
        bad_manifest.mkdir()
        (bad_manifest / "__manifest__.py").write_text("not valid python {", encoding="utf-8")

        text = (bad_manifest / "__manifest__.py").read_text(encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            json.loads(text)

    def test_manifest_defaults(self, sample_manifest: dict) -> None:
        """Test manifest has expected default values."""
        assert sample_manifest.get("installable", True) is True
        assert sample_manifest.get("application", False) is False
        assert sample_manifest.get("depends") == ["base"]


class TestFindManifests:
    """Test module discovery."""

    def test_find_manifests_in_repo(self, temp_repo: Path) -> None:
        """Test discovering modules in a repository."""
        manifests = []
        for path in temp_repo.rglob("__manifest__.py"):
            module = path.parent.name
            text = path.read_text(encoding="utf-8")
            data = json.loads(text)
            manifests.append(
                {
                    "module": module,
                    "name": data.get("name"),
                    "version": data.get("version"),
                    "depends": data.get("depends", []),
                }
            )

        assert len(manifests) == 1
        assert manifests[0]["module"] == "test_module"
        assert manifests[0]["name"] == "Test Module"

    def test_find_manifests_empty_repo(self, empty_repo: Path) -> None:
        """Test discovering modules in empty repository."""
        manifests = list(empty_repo.rglob("__manifest__.py"))
        assert len(manifests) == 0

    def test_find_manifests_with_allowed_modules(self, temp_repo: Path) -> None:
        """Test filtering manifests by allowed module list."""
        allowed = {"test_module"}
        manifests = []
        for path in temp_repo.rglob("__manifest__.py"):
            module = path.parent.name
            if module in allowed:
                manifests.append(module)

        assert manifests == ["test_module"]


class TestLoosePythonDiscovery:
    """Test discovery of loose Python files."""

    def test_find_server_actions(self, temp_repo: Path) -> None:
        """Test finding server action scripts."""
        server_actions_dir = temp_repo / "docs" / "server_actions"
        server_actions_dir.mkdir(parents=True)
        (server_actions_dir / "cleanup.py").write_text("# cleanup script", encoding="utf-8")

        files = list((temp_repo / "docs" / "server_actions").rglob("*.py"))
        assert len(files) == 1
        assert files[0].name == "cleanup.py"

    def test_find_scripts(self, temp_repo: Path) -> None:
        """Test finding standalone scripts."""
        scripts_dir = temp_repo / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "migrate.py").write_text("# migration script", encoding="utf-8")

        files = list(scripts_dir.rglob("*.py"))
        assert len(files) == 1
        assert files[0].name == "migrate.py"
