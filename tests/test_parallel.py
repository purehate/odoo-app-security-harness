"""Tests for parallel scanner execution."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from odoo_security_harness.parallel import ParallelScanner


class TestParallelScanner:
    """Test ParallelScanner execution and error handling."""

    def test_run_single_scanner_success(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        cmd = ["python", "-c", "print('hello')"]
        result = scanner.run_scanner("test", cmd, tmp_path, log_path)
        assert result["name"] == "test"
        assert result["success"] is True
        assert result["returncode"] == 0
        assert "hello" in result["output"]

    def test_run_single_scanner_failure(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        cmd = ["python", "-c", "import sys; sys.exit(1)"]
        result = scanner.run_scanner("test", cmd, tmp_path, log_path)
        assert result["success"] is False
        assert result["returncode"] == 1

    def test_run_single_scanner_timeout(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        cmd = ["python", "-c", "import time; time.sleep(10)"]
        result = scanner.run_scanner("test", cmd, tmp_path, log_path, timeout=1)
        assert result["success"] is False
        assert result["returncode"] == 124
        assert "timeout" in result.get("error", "").lower()

    def test_run_all_parallel(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=2)
        log_path = tmp_path / "scan.log"
        scanners = [
            ("a", ["python", "-c", "print('a')"], tmp_path, log_path, 10),
            ("b", ["python", "-c", "print('b')"], tmp_path, log_path, 10),
        ]
        results = scanner.run_all(scanners)
        assert len(results) == 2
        assert results["a"]["success"] is True
        assert results["b"]["success"] is True

    def test_get_summary(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        scanner.run_all(
            [
                ("ok", ["python", "-c", "print('ok')"], tmp_path, log_path, 10),
                ("fail", ["python", "-c", "import sys; sys.exit(1)"], tmp_path, log_path, 10),
            ]
        )
        summary = scanner.get_summary()
        assert summary["total"] == 2
        assert summary["passed"] == 1
        assert summary["failed"] == 1
        assert summary["timeouts"] == 0

    def test_logs_written(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        scanner.run_scanner("test", ["python", "-c", "print('hello')"], tmp_path, log_path)
        assert log_path.exists()
        content = log_path.read_text()
        assert "python" in content
        assert "[exit 0]" in content

    def test_nested_log_directory_is_created(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "logs" / "nested" / "scan.log"
        result = scanner.run_scanner("test", ["python", "-c", "print('hello')"], tmp_path, log_path)
        assert result["success"] is True
        assert log_path.exists()

    def test_memory_limit_uses_child_preexec(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"

        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="ok")) as run:
            result = scanner.run_scanner("test", ["python", "-c", "print('ok')"], tmp_path, log_path, max_memory_mb=128)

        assert result["success"] is True
        preexec_fn = run.call_args.kwargs["preexec_fn"]
        assert callable(preexec_fn)

    def test_run_scanner_exception_handled(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        with patch("subprocess.run", side_effect=OSError("broken")):
            result = scanner.run_scanner("test", ["false"], tmp_path, log_path)
        assert result["success"] is False
        assert "broken" in result.get("error", "")

    def test_future_exception_in_run_all(self, tmp_path: Path) -> None:
        scanner = ParallelScanner(max_workers=1)
        log_path = tmp_path / "scan.log"
        scanners = [
            ("crash", ["python", "-c", "print('x')"], tmp_path, log_path, 10),
        ]
        with patch.object(scanner, "run_scanner", side_effect=RuntimeError("boom")):
            results = scanner.run_all(scanners)
        assert results["crash"]["success"] is False
        assert "boom" in results["crash"].get("error", "")
