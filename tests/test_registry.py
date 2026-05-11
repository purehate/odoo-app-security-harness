"""Tests for scanner registry utilities."""

from __future__ import annotations

import types
from pathlib import Path

import pytest

from odoo_security_harness import registry


@pytest.fixture(autouse=True)
def clear_registry() -> None:
    registry._SCANNER_REGISTRY.clear()


def test_register_scanner_direct_and_run(tmp_path: Path) -> None:
    def scan_repo(repo_path: Path) -> list[dict[str, str]]:
        return [{"file": repo_path.name}]

    returned = registry.register_scanner("demo", scan_repo, source_types={"python"}, description="Demo scanner")

    assert returned is scan_repo
    assert registry.list_scanner_names() == ["demo"]
    assert registry.get_scanner("demo").description == "Demo scanner"
    assert registry.get_scanner("demo").source_types == {"python"}
    assert registry.run_scanner("demo", tmp_path) == [{"file": tmp_path.name}]


def test_register_scanner_decorator(tmp_path: Path) -> None:
    @registry.register_scanner("decorated", source_types={"xml"})
    def scan_decorated(repo_path: Path) -> list[str]:
        return [repo_path.name]

    assert registry.run_scanner("decorated", tmp_path) == [tmp_path.name]
    assert registry.get_scanner("decorated").source_types == {"xml"}


def test_run_all_scanners_filters_names(tmp_path: Path) -> None:
    registry.register_scanner("a", lambda repo_path: ["a"])
    registry.register_scanner("b", lambda repo_path: ["b"])

    assert registry.run_all_scanners(tmp_path, names=["b"]) == {"b": ["b"]}


def test_run_scanner_unknown_name_raises(tmp_path: Path) -> None:
    with pytest.raises(KeyError):
        registry.run_scanner("missing", tmp_path)


def test_auto_discover_registers_scan_functions(monkeypatch) -> None:
    module = types.ModuleType("odoo_security_harness.fake_scanner")

    def scan_fake(repo_path: Path) -> list[str]:
        """Fake scanner."""
        return [repo_path.name]

    scan_fake._source_types = {"python"}
    module.scan_fake = scan_fake
    module.helper = lambda repo_path: []

    monkeypatch.setattr(registry.pkgutil, "iter_modules", lambda paths: [(None, "fake_scanner", False)])
    monkeypatch.setattr(registry.importlib, "import_module", lambda name: module)

    registry.auto_discover()

    assert registry.list_scanner_names() == ["fake"]
    assert registry.get_scanner("fake").description == "Fake scanner."
    assert registry.get_scanner("fake").source_types == {"python"}


def test_auto_discover_skips_import_failures(monkeypatch) -> None:
    monkeypatch.setattr(registry.pkgutil, "iter_modules", lambda paths: [(None, "broken_scanner", False)])

    def fail_import(name: str) -> types.ModuleType:
        raise RuntimeError("broken")

    monkeypatch.setattr(registry.importlib, "import_module", fail_import)

    registry.auto_discover()

    assert registry.list_scanner_names() == []
