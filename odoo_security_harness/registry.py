"""Scanner plugin registry for auto-discovery and orchestration."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ScannerFunc = Callable[[Path], list[Any]]


@dataclass
class ScannerMeta:
    """Metadata for a registered scanner."""

    name: str
    scan_func: ScannerFunc
    source_types: set[str] = field(default_factory=set)
    description: str = ""


_SCANNER_REGISTRY: dict[str, ScannerMeta] = {}


def register_scanner(
    name: str,
    scan_func: ScannerFunc | None = None,
    source_types: set[str] | None = None,
    description: str = "",
) -> ScannerFunc | Callable[[ScannerFunc], ScannerFunc]:
    """Register a scanner function with the global registry.

    Can be used as a decorator::

        @register_scanner("access_overrides", source_types={"python"})
        def scan_access_overrides(repo_path: Path) -> list[object]:
            ...
    """
    source_types = set(source_types or set())

    def decorator(func: ScannerFunc) -> ScannerFunc:
        _SCANNER_REGISTRY[name] = ScannerMeta(
            name=name,
            scan_func=func,
            source_types=source_types,
            description=description,
        )
        return func

    if scan_func is None:
        return decorator
    return decorator(scan_func)


def get_scanner(name: str) -> ScannerMeta | None:
    """Retrieve a scanner by registered name."""
    return _SCANNER_REGISTRY.get(name)


def list_scanners() -> list[ScannerMeta]:
    """Return all registered scanners."""
    return [_SCANNER_REGISTRY[name] for name in list_scanner_names()]


def list_scanner_names() -> list[str]:
    """Return registered scanner names."""
    return sorted(_SCANNER_REGISTRY.keys())


def run_scanner(name: str, repo_path: Path) -> list[Any]:
    """Execute a registered scanner by name."""
    meta = _SCANNER_REGISTRY.get(name)
    if meta is None:
        raise KeyError(f"Scanner '{name}' is not registered")
    return meta.scan_func(repo_path)


def run_all_scanners(repo_path: Path, *, names: list[str] | None = None) -> dict[str, list[Any]]:
    """Run all (or a subset of) registered scanners and return findings grouped by name."""
    results: dict[str, list[Any]] = {}
    for meta in list_scanners():
        if names is not None and meta.name not in names:
            continue
        results[meta.name] = meta.scan_func(repo_path)
    return results


def auto_discover(package_name: str = "odoo_security_harness") -> None:
    """Auto-discover scanners by looking for ``scan_`` prefixed functions in *package_name*.

    This is intentionally conservative: it imports every submodule and looks
    for top-level functions whose name starts with ``scan_`` and whose
    signature accepts a single ``pathlib.Path`` argument.
    """
    import odoo_security_harness as _root

    pkg_path = Path(_root.__file__).parent
    for _finder, mod_name, _ispkg in pkgutil.iter_modules([str(pkg_path)]):
        if mod_name.startswith("_") or mod_name in {"scripts", "base_scanner", "registry"}:
            continue
        full_name = f"{package_name}.{mod_name}"
        mod = None
        with suppress(Exception):
            mod = importlib.import_module(full_name)
        if mod is None:
            continue

        for attr_name, obj in inspect.getmembers(mod, inspect.isfunction):
            if not attr_name.startswith("scan_"):
                continue
            sig = inspect.signature(obj)
            if _is_repo_scanner_signature(sig):
                scanner_name = attr_name.replace("scan_", "", 1)
                if scanner_name not in _SCANNER_REGISTRY:
                    source_types = getattr(obj, "_source_types", set())
                    register_scanner(
                        name=scanner_name,
                        scan_func=obj,
                        source_types=source_types,
                        description=(obj.__doc__ or "").splitlines()[0].strip(),
                    )


def _is_repo_scanner_signature(sig: inspect.Signature) -> bool:
    params = list(sig.parameters.values())
    if len(params) != 1:
        return False
    annotation = params[0].annotation
    return annotation in (Path, inspect.Parameter.empty, "Path", "pathlib.Path")
