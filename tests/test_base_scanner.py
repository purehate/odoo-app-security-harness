"""Tests for shared base scanner classes and AST helpers."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.base_scanner import (
    AstScanner,
    BaseFinding,
    BaseScanner,
    XmlScanner,
    _call_chain_has_attr,
    _call_chain_has_superuser_with_user,
    _call_root_name,
    _dict_with_field,
    _expanded_dict_keywords,
    _expanded_keywords,
    _is_odoo_model,
    _is_static_literal,
    _is_superuser_arg,
    _literal_string,
    _module_constants,
    _record_fields,
    _resolve_constant,
    _resolve_static_dict,
    _should_skip,
    _static_constants_from_body,
    _target_names,
    _unpack_target_value_pairs,
)


class TestShouldSkip:
    """Test the global _should_skip helper."""

    def test_skips_pycache(self) -> None:
        assert _should_skip(Path("foo/__pycache__/bar.py")) is True

    def test_skips_venv(self) -> None:
        assert _should_skip(Path("project/.venv/lib/site.py")) is True

    def test_allows_source(self) -> None:
        assert _should_skip(Path("project/models/sale.py")) is False


class TestBaseFinding:
    """Test BaseFinding dataclass and serialization."""

    def test_to_dict_minimal(self) -> None:
        finding = BaseFinding(
            rule_id="test",
            title="Test",
            severity="low",
            file="/tmp/test.py",
            line=1,
            message="msg",
        )
        d = finding.to_dict()
        assert d == {
            "rule_id": "test",
            "title": "Test",
            "severity": "low",
            "file": "/tmp/test.py",
            "line": 1,
            "message": "msg",
            "confidence": "medium",
        }

    def test_to_dict_with_optional_fields(self) -> None:
        finding = BaseFinding(
            rule_id="test",
            title="Test",
            severity="low",
            file="/tmp/test.py",
            line=1,
            message="msg",
            model="res.users",
            method="action_confirm",
            route="/api/test",
            sink="eval",
            record_id="r1",
            extra={"foo": "bar"},
        )
        d = finding.to_dict()
        assert d["model"] == "res.users"
        assert d["method"] == "action_confirm"
        assert d["route"] == "/api/test"
        assert d["sink"] == "eval"
        assert d["record_id"] == "r1"
        assert d["foo"] == "bar"


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

    def test_extracts_annotated_constants(self) -> None:
        source = "MODEL: str = 'sale.order'\n"
        import ast

        tree = ast.parse(source)
        constants = _static_constants_from_body(tree.body)
        assert "MODEL" in constants
        assert constants["MODEL"].value == "sale.order"

    def test_dict_constant(self) -> None:
        source = "CONFIG = {'key': 'value'}\n"
        import ast

        tree = ast.parse(source)
        constants = _static_constants_from_body(tree.body)
        assert "CONFIG" in constants
        assert isinstance(constants["CONFIG"], ast.Dict)


class TestIsStaticLiteral:
    """Test static literal detection."""

    def test_constant_string(self) -> None:
        import ast

        assert _is_static_literal(ast.Constant(value="hello")) is True

    def test_constant_int(self) -> None:
        import ast

        assert _is_static_literal(ast.Constant(value=42)) is True

    def test_name_node(self) -> None:
        import ast

        assert _is_static_literal(ast.Name(id="x")) is True

    def test_call_not_literal(self) -> None:
        import ast

        assert _is_static_literal(ast.Call(func=ast.Name(id="foo"), args=[], keywords=[])) is False

    def test_dict_with_none_key(self) -> None:
        import ast

        node = ast.Dict(keys=[None, ast.Constant(value="k")], values=[ast.Constant(value=1), ast.Constant(value=2)])
        assert _is_static_literal(node) is True

    def test_binop_bitor(self) -> None:
        import ast

        node = ast.BinOp(left=ast.Constant(value=1), op=ast.BitOr(), right=ast.Constant(value=2))
        assert _is_static_literal(node) is True


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

    def test_circular_reference_guard(self) -> None:
        import ast

        source = "A = B\nB = A\n"
        tree = ast.parse(source)
        constants = _module_constants(tree)
        node = ast.Name(id="A", ctx=ast.Load())
        resolved = _resolve_constant(node, constants)
        assert isinstance(resolved, ast.Name)


class TestResolveStaticDict:
    """Test static dict resolution."""

    def test_resolves_dict_literal(self) -> None:
        import ast

        node = ast.Dict(keys=[ast.Constant(value="k")], values=[ast.Constant(value="v")])
        result = _resolve_static_dict(node)
        assert isinstance(result, ast.Dict)

    def test_resolves_name_bound_to_dict(self) -> None:
        import ast

        source = "CFG = {'a': 1}\n"
        tree = ast.parse(source)
        constants = _module_constants(tree)
        node = ast.Name(id="CFG", ctx=ast.Load())
        result = _resolve_static_dict(node, constants)
        assert isinstance(result, ast.Dict)

    def test_merges_bitor_dicts(self) -> None:
        import ast

        left = ast.Dict(keys=[ast.Constant(value="a")], values=[ast.Constant(value=1)])
        right = ast.Dict(keys=[ast.Constant(value="b")], values=[ast.Constant(value=2)])
        node = ast.BinOp(left=left, op=ast.BitOr(), right=right)
        result = _resolve_static_dict(node)
        assert isinstance(result, ast.Dict)
        assert len(result.keys) == 2

    def test_dict_with_field_update(self) -> None:
        import ast

        d = ast.Dict(keys=[ast.Constant(value="a")], values=[ast.Constant(value=1)])
        result = _dict_with_field(d, "a", ast.Constant(value=2))
        assert len(result.keys) == 1
        assert result.values[0].value == 2

    def test_dict_with_field_append(self) -> None:
        import ast

        d = ast.Dict(keys=[ast.Constant(value="a")], values=[ast.Constant(value=1)])
        result = _dict_with_field(d, "b", ast.Constant(value=2))
        assert len(result.keys) == 2


class TestExpandedKeywords:
    """Test **kwargs expansion."""

    def test_no_kwargs(self) -> None:
        import ast

        call = ast.Call(
            func=ast.Name(id="foo"),
            args=[],
            keywords=[ast.keyword(arg="a", value=ast.Constant(value=1))],
        )
        result = _expanded_keywords(call)
        assert len(result) == 1
        assert result[0].arg == "a"

    def test_expands_dict_kwargs(self) -> None:
        import ast

        call = ast.Call(
            func=ast.Name(id="foo"),
            args=[],
            keywords=[
                ast.keyword(arg=None, value=ast.Dict(keys=[ast.Constant(value="x")], values=[ast.Constant(value=1)]))
            ],
        )
        result = _expanded_keywords(call)
        assert len(result) == 1
        assert result[0].arg == "x"

    def test_expanded_dict_keywords_none_key(self) -> None:
        import ast

        d = ast.Dict(keys=[None], values=[ast.Constant(value=1)])
        result = _expanded_dict_keywords(d)
        assert result == []


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

    def test_resolves_name_to_string(self) -> None:
        import ast

        source = "BASE = 'hello'\n"
        tree = ast.parse(source)
        constants = _module_constants(tree)
        node = ast.Name(id="BASE", ctx=ast.Load())
        assert _literal_string(node, constants) == "hello"


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

    def test_custom_model_base_names(self) -> None:
        import ast

        source = "class Sale(models.Model): pass\n"
        tree = ast.parse(source)
        cls = tree.body[0]
        assert isinstance(cls, ast.ClassDef)
        assert _is_odoo_model(cls, {"Model"}) is True
        assert _is_odoo_model(cls, {"Other"}) is False


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

    def test_returns_empty_for_unexpected(self) -> None:
        import ast

        assert _call_root_name(ast.Constant(value=1)) == ""


class TestCallChainHasSuperuserWithUser:
    """Test superuser detection in call chains."""

    def test_detects_with_user_superuser_id(self) -> None:
        import ast

        source = "self.env['res.users'].with_user(SUPERUSER_ID)\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_superuser_with_user(expr) is True

    def test_detects_with_user_uid_one(self) -> None:
        import ast

        source = "self.env['res.users'].with_user(1)\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_superuser_with_user(expr) is True

    def test_detects_with_user_ref_admin(self) -> None:
        import ast

        source = "self.env['res.users'].with_user(env.ref('base.user_admin'))\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_superuser_with_user(expr) is True

    def test_detects_keyword_user(self) -> None:
        import ast

        source = "self.env['res.users'].with_user(user=SUPERUSER_ID)\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_superuser_with_user(expr) is True

    def test_no_false_positive(self) -> None:
        import ast

        source = "self.env['res.users'].with_user(user_id)\n"
        tree = ast.parse(source)
        expr = tree.body[0].value
        assert _call_chain_has_superuser_with_user(expr) is False


class TestIsSuperuserArg:
    """Test _is_superuser_arg directly."""

    def test_constant_one(self) -> None:
        import ast

        assert _is_superuser_arg(ast.Constant(value=1)) is True

    def test_constant_base_user_admin(self) -> None:
        import ast

        assert _is_superuser_arg(ast.Constant(value="base.user_admin")) is True

    def test_name_superuser_id(self) -> None:
        import ast

        assert _is_superuser_arg(ast.Name(id="SUPERUSER_ID")) is True

    def test_attribute_superuser_id(self) -> None:
        import ast

        assert _is_superuser_arg(ast.Attribute(value=ast.Name(id="odoo"), attr="SUPERUSER_ID")) is True

    def test_ref_call(self) -> None:
        import ast

        node = ast.Call(
            func=ast.Attribute(value=ast.Name(id="env"), attr="ref"),
            args=[ast.Constant(value="base.user_root")],
            keywords=[],
        )
        assert _is_superuser_arg(node) is True

    def test_unknown_name(self) -> None:
        import ast

        assert _is_superuser_arg(ast.Name(id="user_id")) is False


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

    def test_list_unpacking(self) -> None:
        import ast

        node = ast.List(
            elts=[ast.Name(id="a", ctx=ast.Store()), ast.Name(id="b", ctx=ast.Store())],
            ctx=ast.Store(),
        )
        assert _target_names(node) == {"a", "b"}

    def test_starred(self) -> None:
        import ast

        node = ast.Starred(value=ast.Name(id="rest", ctx=ast.Store()), ctx=ast.Store())
        assert _target_names(node) == {"rest"}


class TestUnpackTargetValuePairs:
    """Test multi-target assignment pairing."""

    def test_simple_tuple(self) -> None:
        import ast

        target = ast.Tuple(elts=[ast.Name(id="a"), ast.Name(id="b")], ctx=ast.Store())
        value = ast.Tuple(elts=[ast.Constant(value=1), ast.Constant(value=2)], ctx=ast.Load())
        result = _unpack_target_value_pairs(target, value)
        assert len(result) == 2

    def test_starred_target(self) -> None:
        import ast

        target = ast.Tuple(
            elts=[ast.Name(id="a"), ast.Starred(value=ast.Name(id="rest"), ctx=ast.Store()), ast.Name(id="b")],
            ctx=ast.Store(),
        )
        value = ast.Tuple(
            elts=[
                ast.Constant(value=1),
                ast.Constant(value=2),
                ast.Constant(value=3),
                ast.Constant(value=4),
            ],
            ctx=ast.Load(),
        )
        result = _unpack_target_value_pairs(target, value)
        assert len(result) == 3


class TestRecordFields:
    """Test XML record field extraction."""

    def test_extracts_field_text(self) -> None:
        from defusedxml import ElementTree

        xml = '<record><field name="name">Test</field><field name="model">sale.order</field></record>'
        record = ElementTree.fromstring(xml)
        fields = _record_fields(record)
        assert fields == {"name": "Test", "model": "sale.order"}

    def test_extracts_ref_attribute(self) -> None:
        from defusedxml import ElementTree

        xml = '<record><field name="inherit_id" ref="base.view_partner_form"/></record>'
        record = ElementTree.fromstring(xml)
        fields = _record_fields(record)
        assert fields == {"inherit_id": "base.view_partner_form"}

    def test_extracts_eval_attribute(self) -> None:
        from defusedxml import ElementTree

        xml = '<record><field name="active" eval="True"/></record>'
        record = ElementTree.fromstring(xml)
        fields = _record_fields(record)
        assert fields == {"active": "True"}

    def test_extracts_nested_text(self) -> None:
        from defusedxml import ElementTree

        xml = '<record><field name="arch" type="xml"><form><field name="name"/></form></field></record>'
        record = ElementTree.fromstring(xml)
        fields = _record_fields(record)
        assert "arch" in fields


class TestBaseScanner:
    """Test BaseScanner abstract class."""

    def test_sets_path_alias(self, tmp_path: Path) -> None:
        class DummyScanner(BaseScanner):
            def scan_file(self):
                return []

        scanner = DummyScanner(tmp_path / "test.py")
        assert scanner.source_path == tmp_path / "test.py"
        assert scanner.path == tmp_path / "test.py"

    def test_add_finding_returns_finding(self, tmp_path: Path) -> None:
        class DummyScanner(BaseScanner):
            def scan_file(self):
                return []

        scanner = DummyScanner(tmp_path / "test.py")
        finding = scanner.add_finding("r1", "Title", "high", 5, "message", model="res.users")
        assert finding.rule_id == "r1"
        assert finding.model == "res.users"
        assert len(scanner.findings) == 1


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

    def test_effective_constants_merges_scopes(self, tmp_path: Path) -> None:
        source = "MODULE = 'sale.order'\n"
        path = tmp_path / "sale.py"
        path.write_text(source, encoding="utf-8")

        scanner = AstScanner(path)
        scanner.scan_file()
        assert "MODULE" in scanner._effective_constants()

    def test_current_model_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.py"
        path.write_text("", encoding="utf-8")

        scanner = AstScanner(path)
        scanner.scan_file()
        assert scanner._current_model() == ""

    def test_import_tracking(self, tmp_path: Path) -> None:
        source = """
from odoo import SUPERUSER_ID, http
from odoo.models import Model
from odoo.http import request

class Helper:
    pass
"""
        path = tmp_path / "imports.py"
        path.write_text(source, encoding="utf-8")

        scanner = AstScanner(path)
        scanner.scan_file()
        assert "SUPERUSER_ID" in scanner.superuser_names
        assert "http" in scanner.http_module_names
        assert "Model" in scanner.model_base_names
        assert "request" in scanner.request_names


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

    def test_clears_findings_on_rescan(self, tmp_path: Path) -> None:
        xml = '<odoo><record id="r1" model="res.partner"/></odoo>'
        path = tmp_path / "data.xml"
        path.write_text(xml, encoding="utf-8")

        class DummyXmlScanner(XmlScanner):
            def scan_xml(self) -> None:
                self.add_finding("test", "T", "low", 1, "msg")

        scanner = DummyXmlScanner(path)
        findings1 = scanner.scan_file()
        assert len(findings1) == 1
        findings2 = scanner.scan_file()
        assert len(findings2) == 1
