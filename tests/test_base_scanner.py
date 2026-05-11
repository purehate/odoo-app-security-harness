"""Tests for shared base scanner classes and AST helpers."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.base_scanner import (
    AstScanner,
    BaseScanner,
    XmlScanner,
    _call_chain_has_attr,
    _call_root_name,
    _is_odoo_model,
    _literal_string,
    _module_constants,
    _record_fields,
    _resolve_constant,
    _should_skip,
    _target_names,
)


class TestShouldSkip:
    """Test the global _should_skip helper."""

    def test_skips_pycache(self) -> None:
        assert _should_skip(Path("foo/__pycache__/bar.py")) is True

    def test_skips_venv(self) -> None:
        assert _should_skip(Path("project/.venv/lib/site.py")) is True

    def test_allows_source(self) -> None:
        assert _should_skip(Path("project/models/sale.py")) is False


class TestModuleConstants:
    """Test AST constant extraction."""

    def test_extracts_string_constants(self) -> None:
        source = """
MODEL = 'sale.order'
COUNT = 5
"""
        import ast

        tree = ast.parse(source)
        constants = _module_constants(tree)
        assert "MODEL" in constants
        assert constants["MODEL"].value == "sale.order"
        assert constants["COUNT"].value == 5

    def test_skips_function_calls(self) -> None:
        source = "MODEL = get_model()\n"
        import ast

        tree = ast.parse(source)
        constants = _module_constants(tree)
        assert "MODEL" not in constants


class TestResolveConstant:
    """Test constant resolution through bindings."""

    def test_resolves_name_to_constant(self) -> None:
        import ast

        source = "BASE = 'sale.order'\nMODEL = BASE\n"
        tree = ast.parse(source)
        constants = _module_constants(tree)
        node = ast.Name(id="MODEL", ctx=ast.Load())
        resolved = _resolve_constant(node, constants)
        assert isinstance(resolved, ast.Constant)
        assert resolved.value == "sale.order"

    def test_returns_original_when_unbound(self) -> None:
        import ast

        node = ast.Name(id="UNKNOWN", ctx=ast.Load())
        resolved = _resolve_constant(node, {})
        assert isinstance(resolved, ast.Name)


class TestLiteralString:
    """Test _literal_string extraction."""

    def test_extracts_string_literal(self) -> None:
        import ast

        node = ast.Constant(value="hello")
        assert _literal_string(node) == "hello"

    def test_returns_empty_for_non_string(self) -> None:
        import ast

        node = ast.Constant(value=42)
        assert _literal_string(node) == ""


class TestIsOdooModel:
    """Test Odoo model class detection."""

    def test_detects_model_inheritance(self) -> None:
        import ast

        source = "class Sale(models.Model): pass\n"
        tree = ast.parse(source)
        cls = tree.body[0]
        assert isinstance(cls, ast.ClassDef)
        assert _is_odoo_model(cls) is True

    def test_detects_transient_model(self) -> None:
        import ast

        source = "class Wizard(models.TransientModel): pass\n"
        tree = ast.parse(source)
        cls = tree.body[0]
        assert isinstance(cls, ast.ClassDef)
        assert _is_odoo_model(cls) is True

    def test_rejects_plain_class(self) -> None:
        import ast

        source = "class Helper: pass\n"
        tree = ast.parse(source)
        cls = tree.body[0]
        assert isinstance(cls, ast.ClassDef)
        assert _is_odoo_model(cls) is False


class TestCallChainHasAttr:
    """Test call chain attribute detection."""

    def test_detects_sudo_in_chain(self) -> None:
        import ast

        source = "self.env['res.users'].sudo().search([])\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_attr(expr, "sudo") is True

    def test_no_false_positive(self) -> None:
        import ast

        source = "self.env['res.users'].search([])\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_attr(expr, "sudo") is False


class TestCallRootName:
    """Test call root name extraction."""

    def test_extracts_self(self) -> None:
        import ast

        source = "self.env['res.users'].sudo().search([])\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_root_name(expr) == "self"


class TestTargetNames:
    """Test assignment target name extraction."""

    def test_single_name(self) -> None:
        import ast

        node = ast.Name(id="x", ctx=ast.Store())
        assert _target_names(node) == {"x"}

    def test_tuple_unpacking(self) -> None:
        import ast

        node = ast.Tuple(
            elts=[ast.Name(id="a", ctx=ast.Store()), ast.Name(id="b", ctx=ast.Store())],
            ctx=ast.Store(),
        )
        assert _target_names(node) == {"a", "b"}


class TestRecordFields:
    """Test XML record field extraction."""

    def test_extracts_field_text(self) -> None:
        from defusedxml import ElementTree

        xml = '<record><field name="name">Test</field><field name="model">sale.order</field></record>'
        record = ElementTree.fromstring(xml)
        fields = _record_fields(record)
        assert fields == {"name": "Test", "model": "sale.order"}


class TestBaseScanner:
    """Test BaseScanner abstract class."""

    def test_sets_path_alias(self, tmp_path: Path) -> None:
        class DummyScanner(BaseScanner):
            def scan_file(self):
                return []

        scanner = DummyScanner(tmp_path / "test.py")
        assert scanner.source_path == tmp_path / "test.py"
        assert scanner.path == tmp_path / "test.py"


class TestAstScanner:
    """Test AstScanner with real Python source."""

    def test_scans_odoo_model_file(self, tmp_path: Path) -> None:
        source = """
from odoo import models, fields

class SaleOrder(models.Model):
    _name = 'sale.order'

    def action_confirm(self):
        self.write({'state': 'done'})
"""
        path = tmp_path / "sale.py"
        path.write_text(source, encoding="utf-8")

        class DummyAstScanner(AstScanner):
            def scan_xml(self) -> None:
                pass

        scanner = DummyAstScanner(path)
        findings = scanner.scan_file()
        # DummyAstScanner doesn't add findings; just verify it parses without error
        assert findings == []

    def test_tracks_model_stack(self, tmp_path: Path) -> None:
        source = """
from odoo import models

class Sale(models.Model):
    _name = 'sale.order'
"""
        path = tmp_path / "sale.py"
        path.write_text(source, encoding="utf-8")

        scanner = AstScanner(path)
        scanner.scan_file()
        assert scanner.model_stack == []


class TestXmlScanner:
    """Test XmlScanner with real XML source."""

    def test_parses_odoo_xml(self, tmp_path: Path) -> None:
        xml = '<odoo><record id="r1" model="res.partner"><field name="name">Test</field></record></odoo>'
        path = tmp_path / "data.xml"
        path.write_text(xml, encoding="utf-8")

        class DummyXmlScanner(XmlScanner):
            def scan_xml(self) -> None:
                records = list(self.root.iter("record"))
                assert len(records) == 1
                assert records[0].get("id") == "r1"

        scanner = DummyXmlScanner(path)
        scanner.scan_file()

    def test_handles_parse_error_gracefully(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.xml"
        path.write_text("<not-valid", encoding="utf-8")

        class DummyXmlScanner(XmlScanner):
            def scan_xml(self) -> None:
                pass

        scanner = DummyXmlScanner(path)
        findings = scanner.scan_file()
        assert findings == []
