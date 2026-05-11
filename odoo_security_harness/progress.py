"""Progress indicators and UX improvements for the harness."""

from __future__ import annotations

import sys
import time
from collections.abc import Generator
from contextlib import contextmanager


class ProgressSpinner:
    """A simple spinner for indicating progress."""

    def __init__(self, message: str = "Working") -> None:
        self.message = message
        self.running = False
        self._start_time: float = 0.0

    def start(self) -> None:
        """Start the spinner."""
        self.running = True
        self._start_time = time.time()
        print(f"{self.message}...", end="", flush=True)

    def stop(self, success: bool = True) -> None:
        """Stop the spinner."""
        self.running = False
        elapsed = time.time() - self._start_time
        status = "✓" if success else "✗"
        print(f"\r{self.message}... {status} ({elapsed:.1f}s)")

    def __enter__(self) -> ProgressSpinner:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop(success=exc_type is None)


class ProgressBar:
    """A simple progress bar."""

    def __init__(self, total: int, desc: str = "Progress", width: int = 40) -> None:
        self.total = total
        self.desc = desc
        self.width = width
        self.current = 0

    def update(self, n: int = 1) -> None:
        """Update progress by n steps."""
        self.current += n
        self._display()

    def _display(self) -> None:
        """Display the progress bar."""
        if self.total == 0:
            return

        percent = self.current / self.total
        filled = int(self.width * percent)
        bar = "█" * filled + "░" * (self.width - filled)

        print(
            f"\r{self.desc}: [{bar}] {self.current}/{self.total} ({percent*100:.1f}%)",
            end="",
            flush=True,
        )

        if self.current >= self.total:
            print()  # New line when complete

    def finish(self) -> None:
        """Mark progress as complete."""
        self.current = self.total
        self._display()


@contextmanager
def timed_operation(name: str) -> Generator[None, None, None]:
    """Context manager for timing operations."""
    start = time.time()
    print(f"▶ {name}...", flush=True)
    try:
        yield
    except Exception:
        elapsed = time.time() - start
        print(f"✗ {name} failed after {elapsed:.1f}s", flush=True)
        raise
    else:
        elapsed = time.time() - start
        print(f"✓ {name} completed in {elapsed:.1f}s", flush=True)


def print_summary(
    title: str,
    items: dict[str, int],
    total: int | None = None,
) -> None:
    """Print a formatted summary."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

    for key, value in items.items():
        if total is not None and total > 0:
            percent = (value / total) * 100
            print(f"  {key:.<40} {value:>5} ({percent:>5.1f}%)")
        else:
            print(f"  {key:.<40} {value:>5}")

    if total is not None:
        print(f"  {'Total':.<40} {total:>5}")

    print(f"{'='*60}\n")


def confirm_prompt(message: str, default: bool = False) -> bool:
    """Show a confirmation prompt."""
    if default:
        prompt = f"{message} [Y/n]: "
    else:
        prompt = f"{message} [y/N]: "

    try:
        response = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    if not response:
        return default

    return response in ("y", "yes")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"✗ ERROR: {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"⚠ WARNING: {message}")


def progress(message: str) -> None:
    """Print a progress/status message."""
    print(f"[odoo-review-run] {message}", flush=True)


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"✓ {message}")
