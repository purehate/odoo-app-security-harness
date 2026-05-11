"""Tests for Python act_window scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.action_window_scanner import scan_action_windows


def test_flags_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Public action windows should not take domain/context from request data."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_imported_route_decorator_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Imported route decorators should not hide action-window taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import route

class Window(http.Controller):
    @route('/window/orders', auth='public')
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_aliased_imported_route_decorator_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide action-window taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import route as public_route

class Window(http.Controller):
    @public_route('/window/orders', auth='public')
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_aliased_http_module_route_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should preserve public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http as odoo_http

class Window(odoo_http.Controller):
    @odoo_http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-act-window-tainted-context" and f.route == "/window/orders" for f in findings)


def test_imported_odoo_http_module_route_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Direct odoo.http imports should preserve public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
import odoo.http as odoo_http

class Window(odoo_http.Controller):
    @odoo_http.route('/window/orders', auth='public')
    def orders(self):
        payload = odoo_http.request.get_http_params()
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': payload.get('domain'),
            'context': payload.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-act-window-tainted-context" and f.route == "/window/orders" for f in findings)


def test_imported_odoo_module_route_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Direct odoo imports should preserve public route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
import odoo as od

class Window(od.http.Controller):
    @od.http.route('/window/orders', auth='public')
    def orders(self):
        payload = od.http.request.get_http_params()
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': payload.get('domain'),
            'context': payload.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-act-window-tainted-context" and f.route == "/window/orders" for f in findings)


def test_non_odoo_route_decorator_does_not_make_action_window_public(tmp_path: Path) -> None:
    """Local route decorators should not create public action-window route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Window(http.Controller):
    @router.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert not any(
        f.rule_id == "odoo-act-window-tainted-domain" and f.severity == "critical" for f in findings
    )
    assert any(f.rule_id == "odoo-act-window-tainted-domain" and f.severity == "high" for f in findings)


def test_static_unpack_public_route_options_tainted_domain_and_context(tmp_path: Path) -> None:
    """Static route option unpacking should preserve public action-window context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

ROUTE_OPTIONS = {'auth': 'public'}

class Window(http.Controller):
    @http.route('/window/orders', **ROUTE_OPTIONS)
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_constant_backed_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Route constants should not hide public action-window taint severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

WINDOW_ROUTES = ['/window/orders', '/window/orders/alt']
AUTH = 'public'

class Window(http.Controller):
    @http.route(WINDOW_ROUTES, auth=AUTH)
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
            'context': kwargs.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        f.rule_id == "odoo-act-window-tainted-domain"
        and f.severity == "critical"
        and f.route == "/window/orders,/window/orders/alt"
        for f in findings
    )
    assert any(f.rule_id == "odoo-act-window-tainted-context" for f in findings)


def test_class_constant_public_sensitive_action_window_is_reported(tmp_path: Path) -> None:
    """Class-scoped route and action constants should not hide public sensitive windows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    ACTION_TYPE_VALUE = 'ir.actions.act_window'
    ACTION_TYPE = ACTION_TYPE_VALUE
    TARGET_MODEL_VALUE = 'res.partner'
    TARGET_MODEL = TARGET_MODEL_VALUE
    EMPTY_DOMAIN_VALUE = []
    BROAD_DOMAIN = EMPTY_DOMAIN_VALUE
    PUBLIC_AUTH = 'public'
    ACTION_AUTH = PUBLIC_AUTH
    ROUTE_MAIN = '/window/partners'
    ROUTE_ALIAS = ROUTE_MAIN
    WINDOW_ROUTES = [ROUTE_MAIN, ROUTE_ALIAS]

    @http.route(WINDOW_ROUTES, auth=ACTION_AUTH)
    def partners(self):
        return {
            'type': ACTION_TYPE,
            'res_model': TARGET_MODEL,
            'domain': BROAD_DOMAIN,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert any(
        f.rule_id == "odoo-act-window-public-sensitive-model"
        and f.severity == "critical"
        and f.route == "/window/partners,/window/partners"
        for f in findings
    )


def test_local_constant_public_sensitive_action_window_is_reported(tmp_path: Path) -> None:
    """Function-local action constants should not hide public sensitive windows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/users', auth='public')
    def users(self):
        action_type = 'ir.actions.act_window'
        target_model = 'res.users'
        broad_domain = []
        return {
            'type': action_type,
            'res_model': target_model,
            'domain': broad_domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert any(
        f.rule_id == "odoo-act-window-public-sensitive-model"
        and f.severity == "critical"
        and f.route == "/window/users"
        for f in findings
    )


def test_class_constant_static_route_options_tainted_domain_is_critical(tmp_path: Path) -> None:
    """Class-scoped **route options should preserve public action-window severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    WINDOW_ROUTE = '/window/orders'
    PUBLIC_AUTH = 'public'
    ROUTE_OPTIONS = {'route': WINDOW_ROUTE, 'auth': PUBLIC_AUTH}

    @http.route(**ROUTE_OPTIONS)
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        f.rule_id == "odoo-act-window-tainted-domain"
        and f.severity == "critical"
        and f.route == "/window/orders"
        for f in findings
    )


def test_nested_static_route_options_tainted_domain_is_critical(tmp_path: Path) -> None:
    """Nested **route options should preserve public action-window severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = {**BASE_OPTIONS, 'route': '/window/orders'}

class Window(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        f.rule_id == "odoo-act-window-tainted-domain"
        and f.severity == "critical"
        and f.route == "/window/orders"
        for f in findings
    )


def test_dict_union_static_route_options_tainted_domain_is_critical(tmp_path: Path) -> None:
    """Dict-union **route options should preserve public action-window severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = BASE_OPTIONS | {'route': '/window/orders'}

class Window(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def orders(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': kwargs.get('domain'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        f.rule_id == "odoo-act-window-tainted-domain"
        and f.severity == "critical"
        and f.route == "/window/orders"
        for f in findings
    )


def test_flags_public_tainted_domain_and_context_from_unpacking(tmp_path: Path) -> None:
    """Unpacked request data should remain tainted in action window fields."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        domain, context = kwargs.get('domain'), kwargs.get('context')
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
            'context': context,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_flags_public_tainted_domain_and_context_from_starred_rest_items(tmp_path: Path) -> None:
    """Request data later in a starred-rest collection should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        label, *items = 'orders', [], kwargs.get('domain'), kwargs.get('context')
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': items[1],
            'context': items[2],
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_flags_public_tainted_domain_from_comprehension_alias(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import request

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self):
        payload = request.get_json_data()
        domain = [term for term in payload.get('domain', [])]
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_request_alias_public_tainted_domain_and_context(tmp_path: Path) -> None:
    """Aliased request payloads should still taint action-window fields."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self):
        payload = req.get_json_data()
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': payload.get('domain'),
            'context': payload.get('context'),
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_flags_public_tainted_domain_from_comprehension_filter(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated action domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import request

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self):
        domain = [('id', '=', 1) for _ in range(1) if request.params.get('show')]
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_flags_public_tainted_domain_from_named_expression(tmp_path: Path) -> None:
    """Walrus-bound action domains should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import request

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self):
        if domain := request.params.get('domain'):
            return {
                'type': 'ir.actions.act_window',
                'res_model': 'sale.order',
                'domain': domain,
            }
        return {'type': 'ir.actions.act_window', 'res_model': 'sale.order', 'domain': []}
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_walrus_action_window_mutated_tainted_domain_is_reported(tmp_path: Path) -> None:
    """Walrus-bound action dicts should be tracked through subscript mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        if action := {'type': 'ir.actions.act_window', 'res_model': 'sale.order', 'domain': []}:
            action['domain'] = kwargs.get('domain')
            return action
        return False
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        finding.rule_id == "odoo-act-window-tainted-domain"
        and finding.sink == "python-dict-mutation"
        for finding in findings
    )


def test_walrus_action_window_update_tainted_context_is_reported(tmp_path: Path) -> None:
    """Walrus-bound action dicts should be tracked through update() calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        if action := {'type': 'ir.actions.act_window', 'res_model': 'sale.order', 'domain': []}:
            action.update({'context': kwargs.get('context')})
            return action
        return False
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        finding.rule_id == "odoo-act-window-tainted-context"
        and finding.sink == "python-dict-update"
        for finding in findings
    )


def test_walrus_reassigned_action_window_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus action aliases should clear when rebound before mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        if action := {'type': 'ir.actions.act_window', 'res_model': 'sale.order', 'domain': []}:
            action = {}
            action['domain'] = kwargs.get('domain')
            return action
        return False
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert not any(
        finding.rule_id == "odoo-act-window-tainted-domain"
        and finding.sink == "python-dict-mutation"
        for finding in findings
    )


def test_flags_public_tainted_res_model(tmp_path: Path) -> None:
    """Public action windows should not let request input choose the target model."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/open', auth='public')
    def open_window(self, **kwargs):
        return {
            'type': 'ir.actions.act_window',
            'res_model': kwargs.get('model'),
            'domain': [],
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-res-model" for f in findings)


def test_flags_domain_argument_action_window(tmp_path: Path) -> None:
    """Domain-like function arguments should still seed tainted action domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='user')
    def orders(self, domain):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_reassigned_action_window_domain_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request domain alias for safe static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/orders', auth='public')
    def orders(self, **kwargs):
        domain = kwargs.get('domain')
        domain = [('user_id', '=', 1)]
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert not any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_flags_public_sensitive_action_window(tmp_path: Path) -> None:
    """Public routes should not directly return client actions for sensitive models."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/users', auth='public')
    def users(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.users',
            'domain': [('id', '=', 1)],
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    public_findings = [f for f in findings if f.rule_id == "odoo-act-window-public-sensitive-model"]

    assert len(public_findings) == 1
    assert public_findings[0].severity == "high"
    assert public_findings[0].route == "/window/users"


def test_keyword_constant_backed_public_sensitive_action_window(tmp_path: Path) -> None:
    """route= constants should not hide public sensitive action windows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

WINDOW_ROUTE = '/window/users'
AUTH = 'public'

class Window(http.Controller):
    @http.route(route=WINDOW_ROUTE, auth=AUTH)
    def users(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.users',
            'domain': [('id', '=', 1)],
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    public_findings = [f for f in findings if f.rule_id == "odoo-act-window-public-sensitive-model"]

    assert len(public_findings) == 1
    assert public_findings[0].route == "/window/users"


def test_flags_public_broad_sensitive_action_window_as_critical(tmp_path: Path) -> None:
    """Broad public sensitive client actions should stand out as critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/partners', auth='none')
    def partners(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.partner',
            'domain': [],
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    public_findings = [f for f in findings if f.rule_id == "odoo-act-window-public-sensitive-model"]

    assert len(public_findings) == 1
    assert public_findings[0].severity == "critical"


def test_constant_backed_public_broad_sensitive_action_window_is_reported(tmp_path: Path) -> None:
    """Constant-backed action fields should still expose broad sensitive public windows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

ACTION_TYPE = 'ir.actions.act_window'
TARGET_MODEL = 'res.partner'
BROAD_DOMAIN = []

class Window(http.Controller):
    @http.route('/window/partners', auth='none')
    def partners(self):
        return {
            'type': ACTION_TYPE,
            'res_model': TARGET_MODEL,
            'domain': BROAD_DOMAIN,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert any(
        f.rule_id == "odoo-act-window-public-sensitive-model" and f.severity == "critical"
        for f in findings
    )


def test_recursive_constant_backed_public_broad_sensitive_action_window_is_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide sensitive public action windows."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

ACTION_TYPE_VALUE = 'ir.actions.act_window'
ACTION_TYPE = ACTION_TYPE_VALUE
BASE_MODEL = 'res.partner'
TARGET_MODEL = BASE_MODEL
EMPTY_DOMAIN = []
BROAD_DOMAIN = EMPTY_DOMAIN
PUBLIC_AUTH = 'public'
ACTION_AUTH = PUBLIC_AUTH
ROUTE_MAIN = '/window/partners'
ROUTE_ALIAS = ROUTE_MAIN
WINDOW_ROUTES = [ROUTE_MAIN, ROUTE_ALIAS]

class Window(http.Controller):
    @http.route(WINDOW_ROUTES, auth=ACTION_AUTH)
    def partners(self):
        return {
            'type': ACTION_TYPE,
            'res_model': TARGET_MODEL,
            'domain': BROAD_DOMAIN,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert any(
        f.rule_id == "odoo-act-window-public-sensitive-model"
        and f.severity == "critical"
        and f.route == "/window/partners,/window/partners"
        for f in findings
    )


def test_flags_privileged_default_and_active_test_context(tmp_path: Path) -> None:
    """Action windows can seed create defaults and archived visibility."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import models

class Users(models.Model):
    _inherit = 'res.users'

    def action_invite_admin(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.users',
            'domain': [],
            'context': {
                'default_groups_id': [(4, self.env.ref('base.group_system').id)],
                'active_test': False,
            },
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids


def test_constant_backed_privileged_action_window_context_is_reported(tmp_path: Path) -> None:
    """Constant-backed context dictionaries should still surface privilege flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
ACTION_CONTEXT = {
    'default_groups_id': [(4, 1)],
    'active_test': False,
    'allowed_company_ids': [1],
}

class Users:
    def action_invite_admin(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'res.users',
            'domain': [],
            'context': ACTION_CONTEXT,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-company-scope-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids
    assert {"default_groups_id", "allowed_company_ids", "active_test"} <= flags


def test_flags_xml_privileged_default_context(tmp_path: Path) -> None:
    """XML act_window records can seed privileged create defaults too."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_create_admin" model="ir.actions.act_window">
    <field name="res_model">res.users</field>
    <field name="domain">[]</field>
    <field name="context">{'default_groups_id': [(4, ref('base.group_system'))], 'active_test': False}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids


def test_flags_csv_privileged_default_context(tmp_path: Path) -> None:
    """CSV act_window records can seed privileged create defaults too."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_act_window.csv").write_text(
        "id,res_model,domain,context\n"
        "action_create_admin,res.users,[],"
        "\"{'default_groups_id': [(4, ref('base.group_system'))], 'active_test': False}\"\n",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-sensitive-broad-domain" in rule_ids
    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids


def test_sensitive_xml_res_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """XML model refs should resolve before sensitive act_window checks."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_system_parameters" model="ir.actions.act_window">
    <field name="res_model" ref="base.model_ir_config_parameter"/>
    <field name="domain">[]</field>
  </record>
  <record id="action_payment_providers" model="ir.actions.act_window">
    <field name="res_model" ref="payment.model_payment_provider"/>
    <field name="domain">[]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    sensitive_models = {
        finding.model for finding in findings if finding.rule_id == "odoo-act-window-sensitive-broad-domain"
    }

    assert {"ir.config_parameter", "payment.provider"} <= sensitive_models


def test_sensitive_csv_res_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """CSV model refs should resolve before sensitive act_window checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,res_model/id,domain\n"
        "action_system_parameters,base.model_ir_config_parameter,[]\n"
        "action_payment_providers,payment.model_payment_provider,[]\n",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    sensitive_models = {
        finding.model for finding in findings if finding.rule_id == "odoo-act-window-sensitive-broad-domain"
    }

    assert {"ir.config_parameter", "payment.provider"} <= sensitive_models


def test_sensitive_csv_colon_res_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """CSV model refs exported with colon headers should resolve before sensitive checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,res_model:id,domain\n"
        "action_system_parameters,base.model_ir_config_parameter,[]\n"
        "action_payment_providers,payment.model_payment_provider,[]\n",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    sensitive_models = {
        finding.model for finding in findings if finding.rule_id == "odoo-act-window-sensitive-broad-domain"
    }

    assert {"ir.config_parameter", "payment.provider"} <= sensitive_models


def test_csv_colon_groups_id_suppresses_grouped_sensitive_broad_action_window(tmp_path: Path) -> None:
    """CSV group refs exported with colon headers should be treated as restrictions."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,res_model,domain,groups_id:id\n"
        "action_users,res.users,[],base.group_system\n",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert not any(
        finding.rule_id == "odoo-act-window-sensitive-broad-domain" and finding.model == "res.users"
        for finding in findings
    )


def test_empty_groups_eval_does_not_hide_sensitive_xml_broad_action_window(tmp_path: Path) -> None:
    """Empty XML groups evals should still be treated as unrestricted action windows."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_all_users" model="ir.actions.act_window">
    <field name="res_model">res.users</field>
    <field name="domain">[]</field>
    <field name="groups_id" eval="[]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        finding.rule_id == "odoo-act-window-sensitive-broad-domain" and finding.model == "res.users"
        for finding in findings
    )


def test_flags_company_scope_context(tmp_path: Path) -> None:
    """Action window context should not silently alter company scope."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "orders.py").write_text(
        """
from odoo import models

class Order(models.Model):
    _inherit = 'sale.order'

    def action_cross_company(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': [('partner_id', '=', self.partner_id.id)],
            'context': {
                'allowed_company_ids': self.env.companies.ids,
                'force_company': self.company_id.id,
            },
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    flags = {finding.flag for finding in findings if finding.rule_id == "odoo-act-window-company-scope-context"}

    assert {"allowed_company_ids", "force_company"} <= flags


def test_flags_xml_company_scope_context(tmp_path: Path) -> None:
    """XML action contexts can also change company scoping."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_company_orders" model="ir.actions.act_window">
    <field name="res_model">sale.order</field>
    <field name="domain">[('state', '!=', 'cancel')]</field>
    <field name="context">{'allowed_company_ids': user.company_ids.ids, 'force_company': user.company_id.id}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    flags = {finding.flag for finding in findings if finding.rule_id == "odoo-act-window-company-scope-context"}

    assert {"allowed_company_ids", "force_company"} <= flags


def test_flags_csv_company_scope_context(tmp_path: Path) -> None:
    """CSV action contexts can also change company scoping."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_act_window.csv").write_text(
        "id,res_model,domain,context\n"
        "action_company_orders,sale.order,\"[('state', '!=', 'cancel')]\","
        "\"{'allowed_company_ids': user.company_ids.ids, 'force_company': user.company_id.id}\"\n",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    flags = {finding.flag for finding in findings if finding.rule_id == "odoo-act-window-company-scope-context"}

    assert {"allowed_company_ids", "force_company"} <= flags


def test_xml_entities_are_not_expanded_into_action_window_findings(tmp_path: Path) -> None:
    """act_window XML parsing should reject entities instead of expanding them into findings."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY privileged_context "{'default_groups_id': [(4, ref('base.group_system'))], 'active_test': False}">
]>
<odoo>
  <record id="action_entity_context" model="ir.actions.act_window">
    <field name="res_model">res.users</field>
    <field name="domain">[]</field>
    <field name="context">&privileged_context;</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert not findings


def test_flags_mutated_tainted_action_window_fields(tmp_path: Path) -> None:
    """Assigning action window fields after dict creation should still be scanned."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/mutated', auth='public')
    def mutated(self, **kwargs):
        action = {'type': 'ir.actions.act_window'}
        action['res_model'] = kwargs.get('model')
        action['domain'] = kwargs.get('domain')
        action['context'] = kwargs.get('context')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-res-model" in rule_ids
    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_class_constant_mutated_action_window_context_key_is_reported(tmp_path: Path) -> None:
    """Class-scoped action and subscript-key constants should not hide context flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
class Users:
    ACTION_TYPE = 'ir.actions.act_window'
    CONTEXT_KEY_VALUE = 'context'
    CONTEXT_KEY = CONTEXT_KEY_VALUE
    ACTION_CONTEXT = {
        'default_groups_id': [(4, 1)],
        'active_test': False,
        'allowed_company_ids': [1],
    }

    def action_invite_admin(self):
        action = {'type': ACTION_TYPE, 'res_model': 'res.users'}
        action[CONTEXT_KEY] = ACTION_CONTEXT
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-company-scope-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids
    assert {"default_groups_id", "allowed_company_ids", "active_test"} <= flags


def test_local_constant_mutated_action_window_context_key_is_reported(tmp_path: Path) -> None:
    """Function-local action and subscript-key constants should not hide context flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
class Users:
    def action_invite_admin(self):
        action_type = 'ir.actions.act_window'
        context_key = 'context'
        action_context = {
            'default_groups_id': [(4, 1)],
            'active_test': False,
            'allowed_company_ids': [1],
        }
        action = {'type': action_type, 'res_model': 'res.users'}
        action[context_key] = action_context
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-company-scope-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids
    assert {"default_groups_id", "allowed_company_ids", "active_test"} <= flags


def test_request_alias_mutated_tainted_action_window_fields(tmp_path: Path) -> None:
    """Aliased request sources should taint later action-window field mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Window(http.Controller):
    @http.route('/window/mutated', auth='public')
    def mutated(self):
        payload = req.params
        action = {'type': 'ir.actions.act_window'}
        action['res_model'] = payload.get('model')
        action['domain'] = payload.get('domain')
        action['context'] = payload.get('context')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-res-model" in rule_ids
    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_starred_rest_action_window_alias_mutation_is_reported(tmp_path: Path) -> None:
    """act_window dicts later in starred-rest collections should keep mutation tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/mutated', auth='public')
    def mutated(self, **kwargs):
        label, *items = 'orders', {}, {'type': 'ir.actions.act_window'}
        action = items[1]
        action['res_model'] = kwargs.get('model')
        action['domain'] = kwargs.get('domain')
        action['context'] = kwargs.get('context')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-res-model" in rule_ids
    assert "odoo-act-window-tainted-domain" in rule_ids
    assert "odoo-act-window-tainted-context" in rule_ids


def test_flags_mutated_public_sensitive_action_window_model(tmp_path: Path) -> None:
    """Public-sensitive model detection should also cover mutated action dicts."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/mutated-users', auth='public')
    def mutated_users(self):
        action = {'type': 'ir.actions.act_window'}
        action['res_model'] = 'res.users'
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(
        f.rule_id == "odoo-act-window-public-sensitive-model" and f.sink == "python-dict-mutation" for f in findings
    )


def test_reassigned_action_window_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned action-window aliases should not keep mutation tracking state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/reassigned', auth='public')
    def reassigned(self, **kwargs):
        action = {'type': 'ir.actions.act_window'}
        action = {}
        action['res_model'] = kwargs.get('model')
        action['domain'] = kwargs.get('domain')
        action['context'] = kwargs.get('context')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-window-tainted-res-model" not in rule_ids
    assert "odoo-act-window-tainted-domain" not in rule_ids
    assert "odoo-act-window-tainted-context" not in rule_ids


def test_flags_update_mutated_privileged_action_window_context(tmp_path: Path) -> None:
    """dict.update on an action window should be scanned for context flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import models

class Users(models.Model):
    _inherit = 'res.users'

    def action_invite_admin(self):
        action = {'type': 'ir.actions.act_window', 'res_model': 'res.users'}
        action.update({
            'context': {
                'default_groups_id': [(4, self.env.ref('base.group_system').id)],
                'allowed_company_ids': self.env.companies.ids,
                'active_test': False,
            }
        })
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-act-window-privileged-default-context" in rule_ids
    assert "odoo-act-window-company-scope-context" in rule_ids
    assert "odoo-act-window-active-test-disabled" in rule_ids
    assert {"default_groups_id", "allowed_company_ids", "active_test"} <= flags


def test_loop_accumulated_domain_is_reported(tmp_path: Path) -> None:
    """Request-derived loop variables appended into domains should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "window.py").write_text(
        """
from odoo import http

class Window(http.Controller):
    @http.route('/window/filter', auth='public')
    def filter(self, **kwargs):
        domain = []
        for partner_id in kwargs.get('partner_ids', []):
            domain.append(('partner_id', '=', int(partner_id)))
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'sale.order',
            'domain': domain,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_windows(tmp_path)

    assert any(f.rule_id == "odoo-act-window-tainted-domain" for f in findings)


def test_safe_local_action_window_is_ignored(tmp_path: Path) -> None:
    """Narrow non-sensitive actions should be ignored."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "task.py").write_text(
        """
from odoo import models

class Task(models.Model):
    _name = 'x.task'

    def action_tasks(self):
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'project.task',
            'domain': [('user_id', '=', self.env.user.id)],
            'context': {'default_name': 'Task'},
            'groups_id': 'project.group_project_user',
        }
""",
        encoding="utf-8",
    )

    assert scan_action_windows(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_window.py").write_text(
        """
def test_action(kwargs):
    return {'type': 'ir.actions.act_window', 'res_model': 'sale.order', 'domain': kwargs.get('domain')}
""",
        encoding="utf-8",
    )

    assert scan_action_windows(tmp_path) == []
