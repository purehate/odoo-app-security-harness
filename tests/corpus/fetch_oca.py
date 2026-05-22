"""Fetch OCA modules for corpus testing.

Usage:
    python -m tests.corpus.fetch_oca

Clones representative OCA repositories to tests/corpus/.cache/ for scanner
corpus validation. Uses shallow clones to minimize disk usage.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

DEFAULT_REPOS = [
    ("OCA", "web", "18.0"),
    ("OCA", "server-tools", "18.0"),
    ("OCA", "account-invoicing", "18.0"),
]

CACHE_DIR = Path(__file__).with_suffix("").parent / ".cache"


def repo_path(org: str, repo: str) -> Path:
    return CACHE_DIR / f"{org}-{repo}"


def clone_repo(org: str, repo: str, branch: str, force: bool = False) -> Path:
    target = repo_path(org, repo)
    if target.exists() and not force:
        print(f"Using cached {org}/{repo} at {target}")
        return target

    if target.exists():
        print(f"Removing stale {target}")
        subprocess.run(["rm", "-rf", str(target)], check=True)

    url = f"https://github.com/{org}/{repo}.git"
    print(f"Cloning {url} (branch {branch}) ...")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            url,
            str(target),
        ],
        check=True,
        capture_output=True,
    )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch OCA corpus modules")
    parser.add_argument("--force", action="store_true", help="Re-clone even if cached")
    parser.add_argument("--repo", action="append", help="Extra repo in org/repo/branch format")
    args = parser.parse_args(argv)

    repos = list(DEFAULT_REPOS)
    if args.repo:
        for r in args.repo:
            parts = r.split("/")
            if len(parts) != 3:
                parser.error(f"--repo must be org/repo/branch, got: {r}")
            repos.append(tuple(parts))  # type: ignore[arg-type]

    for org, repo, branch in repos:
        try:
            clone_repo(org, repo, branch, force=args.force)
        except subprocess.CalledProcessError as exc:
            print(f"Failed to clone {org}/{repo}: {exc}", file=sys.stderr)
            return 1

    print("Corpus fetch complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
