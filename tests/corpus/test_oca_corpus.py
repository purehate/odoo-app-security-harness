"""OCA corpus integration tests.

These tests run the security harness scanners against real OCA modules.
They are skipped by default; run with:

    pytest -m corpus tests/corpus/

Or fetch corpus first:

    python -m tests.corpus.fetch_oca
    pytest -m corpus tests/corpus/
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

CORPUS_DIR = Path(__file__).with_suffix("").parent / ".cache"


def _discover_module_paths() -> list[Path]:
    paths: list[Path] = []
    if not CORPUS_DIR.exists():
        return paths
    for repo_dir in CORPUS_DIR.iterdir():
        if not repo_dir.is_dir():
            continue
        for candidate in repo_dir.iterdir():
            manifest = candidate / "__manifest__.py"
            if candidate.is_dir() and manifest.exists():
                paths.append(candidate)
    return paths


MODULE_PATHS = _discover_module_paths()


pytestmark = pytest.mark.corpus


@pytest.mark.skipif(not MODULE_PATHS, reason="OCA corpus not fetched; run python -m tests.corpus.fetch_oca")
def test_corpus_modules_discovered() -> None:
    """Smoke test that we found at least one OCA module."""
    assert len(MODULE_PATHS) >= 1, f"No modules found under {CORPUS_DIR}"


@pytest.mark.parametrize("module_path", MODULE_PATHS)
@pytest.mark.skipif(not MODULE_PATHS, reason="OCA corpus not fetched")
def test_corpus_module_scans_without_crashing(module_path: Path, tmp_path: Path) -> None:
    """Each OCA module must scan without raising unhandled exceptions."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "odoo_security_harness.scripts.odoo_deep_scan",
            str(module_path),
            "--out",
            str(tmp_path),
            "--fail-on",
            "none",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, None):
        pytest.fail(f"Scan crashed for {module_path.name}: exit {result.returncode}\n" f"stderr: {result.stderr[:500]}")
