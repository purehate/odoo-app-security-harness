"""Odoo Application Security Harness - Parallel scanner execution."""

from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from odoo_security_harness import progress


class ParallelScanner:
    """Execute multiple scanners in parallel."""
    
    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max_workers
        self.results: dict[str, dict] = {}
    
    def run_scanner(
        self,
        name: str,
        cmd: list[str],
        cwd: Path,
        log_path: Path,
        timeout: int = 1800,
    ) -> dict:
        """Run a single scanner and return results."""
        progress(f"start {name}: {' '.join(cmd[:4])}{' ...' if len(cmd) > 4 else ''}")
        
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"$ {' '.join(cmd)}\n")
        
        try:
            completed = subprocess.run(
                cmd,
                cwd=str(cwd),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
            
            output = completed.stdout or ""
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write output to log
            with log_path.open("a", encoding="utf-8") as log:
                log.write(output[-12000:])
                log.write(f"\n[exit {completed.returncode}]\n\n")
            
            result = {
                "name": name,
                "returncode": completed.returncode,
                "output": output,
                "success": completed.returncode == 0,
            }
            
            progress(f"done {name}: exit {completed.returncode}")
            return result
            
        except subprocess.TimeoutExpired:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n[TIMEOUT after {timeout}s]\n\n")
            
            result = {
                "name": name,
                "returncode": 124,
                "output": "",
                "success": False,
                "error": f"timeout after {timeout}s",
            }
            
            progress(f"timeout {name}: after {timeout}s")
            return result
            
        except Exception as exc:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(f"\n[ERROR {exc}]\n\n")
            
            result = {
                "name": name,
                "returncode": 1,
                "output": "",
                "success": False,
                "error": str(exc),
            }
            
            progress(f"error {name}: {exc}")
            return result
    
    def run_all(
        self,
        scanners: list[tuple[str, list[str], Path, Path, int]],
    ) -> dict[str, dict]:
        """Run multiple scanners in parallel.
        
        Args:
            scanners: List of (name, cmd, cwd, log_path, timeout) tuples
            
        Returns:
            Dictionary mapping scanner name to result
        """
        self.results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.run_scanner, name, cmd, cwd, log_path, timeout): name
                for name, cmd, cwd, log_path, timeout in scanners
            }
            
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    self.results[name] = result
                except Exception as exc:
                    self.results[name] = {
                        "name": name,
                        "returncode": 1,
                        "success": False,
                        "error": str(exc),
                    }
        
        return self.results
    
    def get_summary(self) -> dict[str, int]:
        """Get summary of scanner results."""
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results.values() if r.get("success")),
            "failed": sum(1 for r in self.results.values() if not r.get("success")),
            "timeouts": sum(1 for r in self.results.values() if r.get("returncode") == 124),
        }
