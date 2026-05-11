"""Tests for Odoo ir.sequence scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.sequence_scanner import scan_sequences


def test_flags_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Public routes should not hand out predictable token-like sequences."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    @http.route('/invite/code', auth='public')
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_imported_route_decorator_public_sensitive_sequence_use(tmp_path: Path) -> None:
    """Imported route decorators should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Invite(http.Controller):
    @route('/invite/code', auth='public')
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_aliased_imported_route_decorator_public_sensitive_sequence_use(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Invite(http.Controller):
    @web_route('/invite/code', auth='public')
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_aliased_http_module_route_public_sensitive_sequence_use(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Invite(odoo_http.Controller):
    @odoo_http.route('/invite/code', auth='public')
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_imported_odoo_http_module_public_sensitive_sequence_use(tmp_path: Path) -> None:
    """Direct odoo.http imports should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
import odoo.http as odoo_http

class Invite(odoo_http.Controller):
    @odoo_http.route('/invite/code', auth='public')
    def code(self):
        return odoo_http.request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_imported_odoo_module_public_sensitive_sequence_use(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
import odoo as od

class Invite(od.http.Controller):
    @od.http.route('/invite/code', auth='public')
    def code(self):
        return od.http.request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_non_odoo_route_decorator_sequence_use_is_not_public_route(tmp_path: Path) -> None:
    """Local route decorators should not make sequence use public."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Invite(http.Controller):
    @router.route('/invite/code', auth='public')
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" not in rule_ids
    assert "odoo-sequence-sensitive-code-use" in rule_ids


def test_constant_backed_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Constant-backed route metadata should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

INVITE_ROUTES = ['/invite/code']
INVITE_AUTH = 'public'

class Invite(http.Controller):
    @http.route(INVITE_ROUTES, auth=INVITE_AUTH)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_recursive_constant_backed_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Recursive constants should not hide public sequence issuance or sensitive codes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

INVITE_ROUTE = '/invite/code'
ROUTE_ALIAS = INVITE_ROUTE
INVITE_ROUTES = [ROUTE_ALIAS]
ROUTES_ALIAS = INVITE_ROUTES
PUBLIC_AUTH = 'public'
AUTH_ALIAS = PUBLIC_AUTH
SEQUENCE_MODEL = 'ir.sequence'
MODEL_ALIAS = SEQUENCE_MODEL
TOKEN_CODE = 'access.token.sequence'
CODE_ALIAS = TOKEN_CODE

class Invite(http.Controller):
    @http.route(ROUTES_ALIAS, auth=AUTH_ALIAS)
    def code(self):
        return request.env[MODEL_ALIAS].next_by_code(CODE_ALIAS)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-sequence-sensitive-code-use" and f.code == "access.token.sequence"
        for f in findings
    )


def test_local_constant_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Function-local model and code constants should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    @http.route('/invite/code', auth='public')
    def code(self):
        sequence_model = 'ir.sequence'
        token_code = 'access.token.sequence'
        return request.env[sequence_model].next_by_code(token_code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-sequence-sensitive-code-use" and f.code == "access.token.sequence"
        for f in findings
    )


def test_local_constant_public_route_sequence_alias_use(tmp_path: Path) -> None:
    """Function-local constants should resolve before ir.sequence aliases are tracked."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    @http.route('/invite/code', auth='public')
    def code(self):
        sequence_model = 'ir.sequence'
        token_code = 'invite.token.sequence'
        sequences = request.env[sequence_model]
        return sequences.next_by_code(token_code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-public-route-next" for f in findings)
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_static_unpack_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Static **route options should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

INVITE_ROUTE = '/invite/code'
INVITE_OPTIONS = {'routes': [INVITE_ROUTE], 'auth': 'public'}

class Invite(http.Controller):
    @http.route(**INVITE_OPTIONS)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_nested_static_unpack_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Nested static **route options should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
INVITE_OPTIONS = {**BASE_OPTIONS, 'routes': ['/invite/code']}

class Invite(http.Controller):
    @http.route(**INVITE_OPTIONS)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_class_constant_backed_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Class-scoped route constants should not hide public sequence issuance."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    INVITE_ROUTE = '/invite/code'
    INVITE_AUTH = 'public'

    @http.route(INVITE_ROUTE, auth=INVITE_AUTH)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_class_constant_static_unpack_public_route_sensitive_sequence_use(tmp_path: Path) -> None:
    """Class-scoped static **route options should preserve public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    INVITE_ROUTE = '/invite/code'
    INVITE_OPTIONS = {'routes': [INVITE_ROUTE], 'auth': 'public'}

    @http.route(**INVITE_OPTIONS)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "high"
        and f.route == "/invite/code"
        for f in findings
    )
    assert any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_class_constant_model_and_code_aliases_sensitive_sequence_use(tmp_path: Path) -> None:
    """Class-scoped model and code constants should resolve inside sequence calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    SEQUENCE_MODEL = 'ir.sequence'
    MODEL_ALIAS = SEQUENCE_MODEL
    TOKEN_CODE = 'access.token.sequence'
    CODE_ALIAS = TOKEN_CODE

    @http.route('/invite/code', auth='user')
    def code(self):
        sequence = request.env[MODEL_ALIAS]
        return sequence.next_by_code(CODE_ALIAS)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-sensitive-code-use" and f.code == "access.token.sequence"
        for f in findings
    )


def test_keyword_constant_backed_none_route_sequence_use_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep sequence issuance critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

INVITE_ROUTE = '/invite/code'
INVITE_AUTH = 'none'

class Invite(http.Controller):
    @http.route(route=INVITE_ROUTE, auth=INVITE_AUTH)
    def code(self):
        return request.env['ir.sequence'].next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(
        f.rule_id == "odoo-sequence-public-route-next"
        and f.severity == "critical"
        and f.route == "/invite/code"
        for f in findings
    )


def test_flags_request_controlled_sequence_code(tmp_path: Path) -> None:
    """Request-selected sequence codes can consume unintended counters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        return sequence.next_by_code(kwargs.get('code'))
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_request_alias_controlled_sequence_code(tmp_path: Path) -> None:
    """Aliased request imports should still taint selected sequence codes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self):
        payload = req.get_http_params()
        sequence = req.env['ir.sequence']
        return sequence.next_by_code(payload.get('code'))
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_request_alias_direct_sequence_code(tmp_path: Path) -> None:
    """Direct aliased request params should taint next_by_code calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self):
        return req.env['ir.sequence'].next_by_code(req.params.get('code'))
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_imported_odoo_http_module_direct_sequence_code(tmp_path: Path) -> None:
    """Direct odoo.http request params should taint next_by_code calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
import odoo.http as odoo_http

class Sequence(odoo_http.Controller):
    @odoo_http.route('/sequence/next', auth='user')
    def next(self):
        return odoo_http.request.env['ir.sequence'].next_by_code(odoo_http.request.params.get('code'))
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_imported_odoo_module_direct_sequence_code(tmp_path: Path) -> None:
    """Direct odoo module request params should taint next_by_code calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
import odoo as od

class Sequence(od.http.Controller):
    @od.http.route('/sequence/next', auth='user')
    def next(self):
        return od.http.request.env['ir.sequence'].next_by_code(od.http.request.params.get('code'))
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_flags_sequence_code_argument(tmp_path: Path) -> None:
    """Sequence-code method arguments should be treated as caller-controlled."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sequence.py").write_text(
        """
from odoo import models

class Sequence(models.Model):
    _name = 'x.sequence'

    def next_for_code(self, code):
        sequence = self.env['ir.sequence']
        return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_flags_tuple_unpacked_sequence_alias(tmp_path: Path) -> None:
    """Tuple-unpacked ir.sequence aliases should still be recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence, code = request.env['ir.sequence'], kwargs.get('code')
        return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_flags_starred_rest_sequence_alias_and_code(tmp_path: Path) -> None:
    """Starred-rest unpacking should preserve sequence aliases and tainted codes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        marker, *items, tail = 'x', request.env['ir.sequence'], kwargs.get('code'), 'end'
        sequence = items[0]
        code = items[1]
        return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_reassigned_sequence_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned ir.sequence aliases should not keep sequence-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sequence.py").write_text(
        """
from odoo import models

class Sequence(models.Model):
    _name = 'x.sequence'

    def next_partner(self):
        sequence = self.env['ir.sequence']
        sequence = self.env['res.partner']
        return sequence.next_by_code('access.token.sequence')
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert not any(f.rule_id == "odoo-sequence-sensitive-code-use" for f in findings)


def test_reassigned_sequence_code_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request-derived code alias for a safe literal should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        code = kwargs.get('code')
        code = 'sale.order'
        return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert not any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_loop_derived_sequence_code_is_reported(tmp_path: Path) -> None:
    """Loop variables over request data should remain tainted for next_by_code."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        for code in kwargs.get('codes'):
            return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_safe_loop_reassignment_clears_sequence_code_taint(tmp_path: Path) -> None:
    """Loop target taint should clear when rebound from safe sequence codes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        for code in kwargs.get('codes'):
            pass
        for code in ['sale.order']:
            return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert not any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_comprehension_derived_sequence_code_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehensions should stay tainted for next_by_code."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        codes = [code.strip() for code in kwargs.get('codes')]
        sequence = request.env['ir.sequence']
        return sequence.next_by_code(codes[0])
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_comprehension_filter_derived_sequence_code_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint next_by_code."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        requested = kwargs.get('code')
        codes = ['sale.order' for marker in ['x'] if requested]
        sequence = request.env['ir.sequence']
        return sequence.next_by_code(codes[0])
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_named_expression_sequence_code_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request sequence codes should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        if code := kwargs.get('code'):
            return sequence.next_by_code(code)
        return False
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_boolop_sequence_code_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep sequence codes tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/next', auth='user')
    def next(self, **kwargs):
        sequence = request.env['ir.sequence']
        code = kwargs.get('code') or 'sale.order'
        return sequence.next_by_code(code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)

    assert any(f.rule_id == "odoo-sequence-tainted-code" for f in findings)


def test_flags_route_path_sequence_code(tmp_path: Path) -> None:
    """Path-selected sequence codes can consume unintended counters."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "sequence.py").write_text(
        """
from odoo import http
from odoo.http import request

class Sequence(http.Controller):
    @http.route('/sequence/<string:sequence_code>/next', auth='public')
    def next_path(self, sequence_code):
        return request.env['ir.sequence'].next_by_code(sequence_code)
""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-public-route-next" in rule_ids
    assert "odoo-sequence-tainted-code" in rule_ids


def test_flags_sensitive_and_global_business_xml_sequences(tmp_path: Path) -> None:
    """Sequence records should not model secrets or global multi-company identifiers accidentally."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "sequences.xml").write_text(
        """<odoo>
  <record id="seq_invite_token" model="ir.sequence">
    <field name="name">Invite Token</field>
    <field name="code">invite.token</field>
    <field name="prefix">TOKEN-%(year)s-</field>
  </record>
  <record id="seq_sale_order" model="ir.sequence">
    <field name="name">Sale Order</field>
    <field name="code">sale.order</field>
    <field name="prefix">SO</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-sensitive-declaration" in rule_ids
    assert "odoo-sequence-sensitive-global-scope" in rule_ids
    assert "odoo-sequence-business-global-scope" in rule_ids


def test_flags_sensitive_and_global_business_csv_sequences(tmp_path: Path) -> None:
    """CSV ir.sequence declarations should use the same declaration checks as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.sequence.csv").write_text(
        "id,name,code,prefix\n"
        "seq_invite_token,Invite Token,invite.token,TOKEN-\n"
        "seq_sale_order,Sale Order,sale.order,SO\n",
        encoding="utf-8",
    )

    findings = scan_sequences(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-sequence-sensitive-declaration" in rule_ids
    assert "odoo-sequence-sensitive-global-scope" in rule_ids
    assert "odoo-sequence-business-global-scope" in rule_ids


def test_company_scoped_normal_csv_sequence_is_ignored(tmp_path: Path) -> None:
    """Company-scoped non-sensitive CSV sequences should not be noisy."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_sequence.csv").write_text(
        "id,name,code,company_id/id\n"
        "seq_ticket,Helpdesk Ticket,helpdesk.ticket,base.main_company\n",
        encoding="utf-8",
    )

    assert scan_sequences(tmp_path) == []


def test_company_scoped_normal_csv_sequence_colon_company_is_ignored(tmp_path: Path) -> None:
    """Company-scoped CSV sequences exported with colon headers should not be noisy."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_sequence.csv").write_text(
        "id,name,code,company_id:id\n"
        "seq_ticket,Helpdesk Ticket,helpdesk.ticket,base.main_company\n",
        encoding="utf-8",
    )

    assert scan_sequences(tmp_path) == []


def test_xml_entities_are_not_expanded_into_sequence_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize sensitive sequence declarations."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "sequences.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_code "password.reset.token">
]>
<odoo>
  <record id="seq_entity" model="ir.sequence">
    <field name="name">Normal Counter</field>
    <field name="code">&sensitive_code;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_sequences(tmp_path) == []


def test_company_scoped_normal_sequence_is_ignored(tmp_path: Path) -> None:
    """Company-scoped non-sensitive sequences should not be noisy."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "sequences.xml").write_text(
        """<odoo>
  <record id="seq_ticket" model="ir.sequence">
    <field name="name">Helpdesk Ticket</field>
    <field name="code">helpdesk.ticket</field>
    <field name="company_id" ref="base.main_company"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_sequences(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_sequence.py").write_text(
        """
def test_next(request):
    request.env['ir.sequence'].next_by_code('access.token')
""",
        encoding="utf-8",
    )

    assert scan_sequences(tmp_path) == []
