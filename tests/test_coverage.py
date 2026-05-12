"""Tests for hunter coverage analysis."""

from __future__ import annotations

import re

REVIEWED_RE = re.compile(r"^reviewed:\s*$", re.IGNORECASE | re.MULTILINE)


def parse_reviewed_block(text: str) -> dict[str, str]:
    """Extract Reviewed: block from hunter output."""
    match = REVIEWED_RE.search(text)
    if not match:
        return {}
    start = match.end()
    block: dict[str, str] = {}
    for raw in text[start:].splitlines():
        line = raw.strip()
        if not line:
            if block:
                break
            continue
        if line.startswith("#") or line.startswith("```"):
            break
        if ":" not in line:
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        module, details = line.split(":", 1)
        module = module.strip().strip("`")
        details = details.strip()
        if module and details:
            block[module] = details
    return block


class TestParseReviewedBlock:
    """Test Reviewed: block parsing."""

    def test_parse_simple_block(self) -> None:
        """Test parsing a simple Reviewed block."""
        text = """
# Hunter Report

Reviewed:
- test_module: controllers/main.py, models/test_model.py
- other_module: models/other.py

## Findings

Found something.
"""
        block = parse_reviewed_block(text)
        assert len(block) == 2
        assert "test_module" in block
        assert "other_module" in block
        assert "controllers/main.py" in block["test_module"]

    def test_parse_without_dash(self) -> None:
        """Test parsing Reviewed block without dash prefix."""
        text = """
Reviewed:
test_module: controllers/main.py
other_module: models/other.py
"""
        block = parse_reviewed_block(text)
        assert len(block) == 2
        assert "test_module" in block

    def test_empty_block(self) -> None:
        """Test parsing empty Reviewed block."""
        text = """
Reviewed:

## Findings
"""
        block = parse_reviewed_block(text)
        assert block == {}

    def test_no_reviewed_block(self) -> None:
        """Test parsing text without Reviewed block."""
        text = """
# Hunter Report

## Findings

Found something.
"""
        block = parse_reviewed_block(text)
        assert block == {}

    def test_case_insensitive(self) -> None:
        """Test Reviewed: is case-insensitive."""
        text = "reviewed:\n- test_module: done\n"
        block = parse_reviewed_block(text)
        assert len(block) == 1

    def test_stops_at_heading(self) -> None:
        """Test parsing stops at next heading."""
        text = """
Reviewed:
- test_module: done

## Findings
- other_module: should not appear
"""
        block = parse_reviewed_block(text)
        assert len(block) == 1
        assert "test_module" in block
        assert "other_module" not in block

    def test_inline_backticks(self) -> None:
        """Test module names with backticks."""
        text = """
Reviewed:
- `test_module`: controllers/main.py
"""
        block = parse_reviewed_block(text)
        assert "test_module" in block
        assert "`" not in block["test_module"]

    def test_multiline_block(self) -> None:
        """Test parsing multiline Reviewed block."""
        text = """
Reviewed:
mod1: file1.py
mod2: file2.py
mod3: file3.py

## Summary
"""
        block = parse_reviewed_block(text)
        assert len(block) == 3


class TestCoverageMatrix:
    """Test coverage matrix computation."""

    def test_full_coverage(self) -> None:
        """Test when all modules are reviewed."""
        expected_modules = ["mod1", "mod2", "mod3"]
        hunter_blocks = {
            "hunter1": {"mod1": "done", "mod2": "done", "mod3": "done"},
        }

        gaps = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing

        assert len(gaps) == 0

    def test_partial_coverage(self) -> None:
        """Test when some modules are missing."""
        expected_modules = ["mod1", "mod2", "mod3"]
        hunter_blocks = {
            "hunter1": {"mod1": "done", "mod3": "done"},
        }

        gaps = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing

        assert len(gaps) == 1
        assert "hunter1" in gaps
        assert gaps["hunter1"] == ["mod2"]

    def test_multiple_hunters(self) -> None:
        """Test coverage across multiple hunters."""
        expected_modules = ["mod1", "mod2", "mod3"]
        hunter_blocks = {
            "hunter1": {"mod1": "done", "mod2": "done", "mod3": "done"},
            "hunter2": {"mod1": "done", "mod2": "done"},
            "hunter3": {},
        }

        gaps = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing

        assert len(gaps) == 2
        assert "hunter2" in gaps
        assert gaps["hunter2"] == ["mod3"]
        assert "hunter3" in gaps
        assert gaps["hunter3"] == ["mod1", "mod2", "mod3"]

    def test_empty_expected(self) -> None:
        """Test with no expected modules."""
        expected_modules: list[str] = []
        hunter_blocks = {
            "hunter1": {"mod1": "done"},
        }

        gaps = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing

        assert len(gaps) == 0

    def test_threshold(self) -> None:
        """Test threshold for allowed missing modules."""
        expected_modules = ["mod1", "mod2", "mod3", "mod4", "mod5"]
        hunter_blocks = {
            "hunter1": {"mod1": "done", "mod2": "done", "mod3": "done"},
        }
        threshold = 2

        gaps = {}
        over_threshold = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing
                if len(missing) > threshold:
                    over_threshold[hunter_id] = missing

        assert len(gaps) == 1
        assert len(gaps["hunter1"]) == 2  # mod4, mod5
        assert len(over_threshold) == 0  # 2 missing <= threshold of 2

    def test_over_threshold(self) -> None:
        """Test when missing exceeds threshold."""
        expected_modules = ["mod1", "mod2", "mod3", "mod4", "mod5"]
        hunter_blocks = {
            "hunter1": {"mod1": "done"},
        }
        threshold = 1

        gaps = {}
        over_threshold = {}
        for hunter_id, block in hunter_blocks.items():
            missing = [m for m in expected_modules if m not in block]
            if missing:
                gaps[hunter_id] = missing
                if len(missing) > threshold:
                    over_threshold[hunter_id] = missing

        assert len(over_threshold) == 1
        assert len(over_threshold["hunter1"]) == 4


class TestCoverageReport:
    """Test coverage report generation."""

    def test_coverage_matrix(self) -> None:
        """Test coverage matrix calculation."""
        expected = ["mod1", "mod2", "mod3"]
        matrix = {
            "hunter1": {"mod1": "done", "mod2": "done", "mod3": "done"},
            "hunter2": {"mod1": "done"},
        }

        lines = ["| Hunter | Modules reviewed | Modules missing |"]
        for hunter_id in sorted(matrix.keys()):
            reviewed = len(matrix[hunter_id])
            missing = len(expected) - reviewed
            lines.append(f"| `{hunter_id}` | {reviewed}/{len(expected)} | {missing} |")

        assert len(lines) == 3
        assert "hunter1" in lines[1]
        assert "3/3" in lines[1]
        assert "0" in lines[1]
        assert "hunter2" in lines[2]
        assert "1/3" in lines[2]

    def test_gaps_report(self) -> None:
        """Test gaps report generation."""
        gaps = {
            "hunter1": ["mod2", "mod3"],
        }

        gap_md = ["# Coverage Gaps", ""]
        if not gaps:
            gap_md.append("No gaps detected.")
        else:
            for hunter_id in sorted(gaps.keys()):
                gap_md.append(f"## `{hunter_id}`")
                gap_md.append("")
                for module in gaps[hunter_id]:
                    gap_md.append(f"- `{module}`")
                gap_md.append("")

        content = "\n".join(gap_md)
        assert "hunter1" in content
        assert "mod2" in content
        assert "mod3" in content
