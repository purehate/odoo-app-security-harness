"""Tests for Odoo act_url scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.action_url_scanner import scan_action_urls


def test_flags_public_tainted_act_url(tmp_path: Path) -> None:
    """Returned act_url dictionaries should not navigate to request-controlled URLs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_imported_route_decorator_public_tainted_act_url(tmp_path: Path) -> None:
    """Imported route decorators should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import route

class Redirect(http.Controller):
    @route('/go/action', auth='public')
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_aliased_imported_route_decorator_public_tainted_act_url(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import route as public_route

class Redirect(http.Controller):
    @public_route('/go/action', auth='public')
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_aliased_http_module_route_public_tainted_act_url(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http as odoo_http

class Redirect(odoo_http.Controller):
    @odoo_http.route('/go/action', auth='public')
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_imported_odoo_http_module_route_public_tainted_act_url(tmp_path: Path) -> None:
    """Direct odoo.http imports should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
import odoo.http as odoo_http

class Redirect(odoo_http.Controller):
    @odoo_http.route('/go/action', auth='public')
    def go(self):
        payload = odoo_http.request.get_http_params()
        return {'type': 'ir.actions.act_url', 'url': payload.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_imported_odoo_module_route_public_tainted_act_url(tmp_path: Path) -> None:
    """Direct odoo imports should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
import odoo as od

class Redirect(od.http.Controller):
    @od.http.route('/go/action', auth='public')
    def go(self):
        payload = od.http.request.get_http_params()
        return {'type': 'ir.actions.act_url', 'url': payload.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_common_redirect_parameter_aliases(tmp_path: Path) -> None:
    """Common redirect URL parameter names should be treated as request-controlled."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, target_url=None, next_url=None, success_url=None):
        return [
            {'type': 'ir.actions.act_url', 'url': target_url, 'target': 'self'},
            {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'},
            {'type': 'ir.actions.act_url', 'url': success_url, 'target': 'self'},
        ]
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert sum(1 for finding in findings if finding.rule_id == "odoo-act-url-tainted-url") == 3


def test_non_odoo_route_decorator_tainted_act_url_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make act_url redirects public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Redirect(http.Controller):
    @router.route('/go/action', auth='public')
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" not in rule_ids


def test_static_unpack_public_route_options_tainted_act_url(tmp_path: Path) -> None:
    """Static route option unpacking should preserve public act_url context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

ROUTE_OPTIONS = {'auth': 'public'}

class Redirect(http.Controller):
    @http.route('/go/action', **ROUTE_OPTIONS)
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_constant_backed_public_tainted_act_url(tmp_path: Path) -> None:
    """Route constants should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

ACTION_ROUTES = ['/go/action', '/go/action/alt']
AUTH = 'public'

class Redirect(http.Controller):
    @http.route(ACTION_ROUTES, auth=AUTH)
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(
        f.rule_id == "odoo-act-url-tainted-url" and f.severity == "critical" and f.route == "/go/action,/go/action/alt"
        for f in findings
    )
    assert any(f.rule_id == "odoo-act-url-public-route" for f in findings)


def test_class_constant_backed_public_tainted_act_url(tmp_path: Path) -> None:
    """Class-scoped route constants should not hide public act_url redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    ACTION_ROUTES = ['/go/action/class', '/go/action/class/alt']
    AUTH = 'public'

    @http.route(ACTION_ROUTES, auth=AUTH)
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(
        f.rule_id == "odoo-act-url-tainted-url"
        and f.severity == "critical"
        and f.route == "/go/action/class,/go/action/class/alt"
        for f in findings
    )
    assert any(f.rule_id == "odoo-act-url-public-route" for f in findings)


def test_class_constant_static_unpack_public_route_options_tainted_act_url(tmp_path: Path) -> None:
    """Class-scoped static route option unpacking should preserve public act_url context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    ROUTE_OPTIONS = {
        'routes': ['/go/action/class-options'],
        'auth': 'public',
    }

    @http.route(**ROUTE_OPTIONS)
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids
    assert any(f.route == "/go/action/class-options" for f in findings)


def test_nested_static_unpack_public_route_options_tainted_act_url(tmp_path: Path) -> None:
    """Nested static route option unpacking should preserve public act_url context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = {
    **BASE_OPTIONS,
    'routes': ['/go/action/nested-options'],
}

class Redirect(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def go(self, **kwargs):
        return {'type': 'ir.actions.act_url', 'url': kwargs.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids
    assert any(f.route == "/go/action/nested-options" for f in findings)


def test_flags_public_tainted_act_url_from_unpacking(tmp_path: Path) -> None:
    """Tuple unpacking should not hide request-controlled act_url targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        label, next_url = 'continue', kwargs.get('next')
        return {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_public_tainted_act_url_from_starred_unpacking(tmp_path: Path) -> None:
    """Starred tuple unpacking should not hide request-controlled act_url targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        label, *next_urls = ('continue', kwargs.get('next'))
        return {'type': 'ir.actions.act_url', 'url': next_urls[0], 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_public_tainted_act_url_from_starred_rest_item(tmp_path: Path) -> None:
    """Request URLs later in a starred-rest collection should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        label, *items = 'continue', '/web', kwargs.get('next')
        return {'type': 'ir.actions.act_url', 'url': items[1], 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_public_tainted_act_url_from_comprehension_alias(tmp_path: Path) -> None:
    """Comprehension aliases over request data should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self):
        payload = request.get_http_params()
        urls = [candidate for candidate in payload.get('next_urls', [])]
        return {'type': 'ir.actions.act_url', 'url': urls[0], 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_request_alias_public_tainted_act_url_is_reported(tmp_path: Path) -> None:
    """Aliased request objects should not hide act_url open redirects."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self):
        payload = req.get_http_params()
        return {'type': 'ir.actions.act_url', 'url': payload.get('next'), 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_public_route_path_id_act_url(tmp_path: Path) -> None:
    """Route path IDs should be treated as request-controlled URL action input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/public/content/<int:attachment_id>', auth='public')
    def go(self, attachment_id):
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{attachment_id}?download=1',
            'target': 'self',
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_flags_url_argument_act_url(tmp_path: Path) -> None:
    """URL-like function arguments should still seed tainted URL actions."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='user')
    def go(self, url):
        return {'type': 'ir.actions.act_url', 'url': url, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_reassigned_url_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request URL alias for safe static data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        next = kwargs.get('next')
        next = '/web'
        return {'type': 'ir.actions.act_url', 'url': next, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" not in rule_ids
    assert "odoo-act-url-public-route" not in rule_ids


def test_loop_derived_url_alias_is_reported(tmp_path: Path) -> None:
    """Loop aliases over request URL lists should stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        for next_url in kwargs.get('next_urls'):
            return {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_safe_loop_reassignment_clears_url_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale URL taint before act_url use."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        next_url = kwargs.get('next')
        for next_url in ['/web']:
            return {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert not any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_comprehension_filter_derived_url_alias_is_reported(tmp_path: Path) -> None:
    """Tainted comprehension filters should preserve URL alias taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        urls = [candidate for candidate in ['/web'] if kwargs.get('next')]
        return {'type': 'ir.actions.act_url', 'url': urls[0], 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_named_expression_derived_url_alias_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request URLs should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        if next_url := kwargs.get('next'):
            return {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'}
        return {'type': 'ir.actions.act_url', 'url': '/web', 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_boolop_derived_url_alias_is_reported(tmp_path: Path) -> None:
    """Boolean fallback URL expressions should not clear request taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/action', auth='public')
    def go(self, **kwargs):
        next_url = kwargs.get('next') or '/web'
        return {'type': 'ir.actions.act_url', 'url': next_url, 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)


def test_flags_external_xml_act_url_without_groups(tmp_path: Path) -> None:
    """External XML URL actions should be grouped and reviewed."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_external_docs" model="ir.actions.act_url">
    <field name="name">External Docs</field>
    <field name="url">https://evil.example.com/path?access_token=abc</field>
    <field name="target">new</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-external-no-groups" in rule_ids
    assert "odoo-act-url-external-new-window" in rule_ids
    assert "odoo-act-url-sensitive-url" in rule_ids


def test_flags_broad_sensitive_xml_act_url_markers(tmp_path: Path) -> None:
    """URL actions should catch reset/signup/key-shaped data in URLs."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_reset_link" model="ir.actions.act_url">
    <field name="name">Reset Link</field>
    <field name="url">/web/reset_password?reset_password_url=/web/reset&amp;private_key=abc</field>
    <field name="target">self</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-sensitive-url" and f.record_id == "action_reset_link" for f in findings)


def test_flags_external_csv_act_url_without_groups(tmp_path: Path) -> None:
    """CSV URL action declarations should get the same exposure checks as XML."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_act_url.csv").write_text(
        "id,name,url,target\naction_external_docs,External Docs,https://evil.example.com/path?access_token=abc,new\n",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-external-no-groups" in rule_ids
    assert "odoo-act-url-external-new-window" in rule_ids
    assert "odoo-act-url-sensitive-url" in rule_ids


def test_flags_unsafe_scheme_csv_act_url(tmp_path: Path) -> None:
    """CSV URL actions should not use executable schemes."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_url.csv").write_text(
        "id,name,url,target,groups_id/id\n"
        "action_javascript,Run Script,javascript:alert(document.domain),self,base.group_user\n",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" for f in findings)


def test_grouped_external_csv_act_url_with_colon_groups_is_not_ungrouped(tmp_path: Path) -> None:
    """Colon-style groups headers should count as URL action group restrictions."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_url.csv").write_text(
        "id,name,url,target,groups_id:id\n"
        "action_external_docs,External Docs,https://docs.example.com/path,new,base.group_user\n",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-external-no-groups" not in rule_ids
    assert "odoo-act-url-external-new-window" in rule_ids


def test_empty_groups_eval_does_not_hide_external_xml_act_url(tmp_path: Path) -> None:
    """Empty groups eval values still leave external URL actions unrestricted."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_external_docs" model="ir.actions.act_url">
    <field name="name">External Docs</field>
    <field name="url">https://evil.example.com/path</field>
    <field name="groups_id" eval="[]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-external-no-groups" for f in findings)


def test_flags_scheme_relative_external_xml_act_url(tmp_path: Path) -> None:
    """Scheme-relative external URLs should not evade external navigation checks."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_scheme_relative" model="ir.actions.act_url">
    <field name="name">External Docs</field>
    <field name="url">//evil.example.com/path</field>
    <field name="target">new</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-external-no-groups" in rule_ids
    assert "odoo-act-url-external-new-window" in rule_ids


def test_flags_public_scheme_relative_python_act_url(tmp_path: Path) -> None:
    """Public Python act_url actions should treat //host URLs as external."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/external', auth='public')
    def go(self):
        return {'type': 'ir.actions.act_url', 'url': '//evil.example.com/path', 'target': 'new'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-public-route" in rule_ids
    assert "odoo-act-url-external-new-window" in rule_ids


def test_keyword_constant_backed_public_external_python_act_url(tmp_path: Path) -> None:
    """route= constants should preserve public act_url route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

ACTION_ROUTE = '/go/external'
AUTH = 'public'

class Redirect(http.Controller):
    @http.route(route=ACTION_ROUTE, auth=AUTH)
    def go(self):
        return {'type': 'ir.actions.act_url', 'url': 'https://evil.example.com/path', 'target': 'new'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-public-route" and f.route == "/go/external" for f in findings)
    assert any(f.rule_id == "odoo-act-url-external-new-window" for f in findings)


def test_constant_alias_python_action_dict_fields_are_reported(tmp_path: Path) -> None:
    """Constant-backed action dict keys and values should still be scanned."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

ACTION_TYPE_KEY = 'type'
ACTION_TYPE = 'ir.actions.act_url'
URL_KEY = 'url'
EXTERNAL_URL = 'https://evil.example.com/path?access_token=abc'
TARGET_KEY = 'target'
TARGET_NEW = 'new'
PUBLIC_AUTH = 'public'
ACTION_AUTH = PUBLIC_AUTH
ROUTE_MAIN = '/go/external'
ROUTE_ALT = '/go/external-alt'
ACTION_ROUTES = [ROUTE_MAIN, ROUTE_ALT]

class Redirect(http.Controller):
    @http.route(ACTION_ROUTES, auth=ACTION_AUTH)
    def go(self):
        return {
            ACTION_TYPE_KEY: ACTION_TYPE,
            URL_KEY: EXTERNAL_URL,
            TARGET_KEY: TARGET_NEW,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(
        f.rule_id == "odoo-act-url-public-route" and f.route == "/go/external,/go/external-alt" for f in findings
    )
    assert any(f.rule_id == "odoo-act-url-external-new-window" for f in findings)
    assert any(f.rule_id == "odoo-act-url-sensitive-url" for f in findings)


def test_local_constant_alias_python_action_dict_fields_are_reported(tmp_path: Path) -> None:
    """Function-local action dict constants should still be scanned."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/external', auth='public')
    def go(self):
        action_type_key = 'type'
        action_type = 'ir.actions.act_url'
        url_key = 'url'
        external_url = 'https://evil.example.com/path?access_token=abc'
        target_key = 'target'
        target_new = 'new'
        return {
            action_type_key: action_type,
            url_key: external_url,
            target_key: target_new,
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-public-route" for f in findings)
    assert any(f.rule_id == "odoo-act-url-external-new-window" for f in findings)
    assert any(f.rule_id == "odoo-act-url-sensitive-url" for f in findings)


def test_local_constant_alias_mutated_action_url_is_reported(tmp_path: Path) -> None:
    """Local constants should be honored when mutating act_url dictionaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/external', auth='public')
    def go(self):
        type_key = 'type'
        action_type = 'ir.actions.act_url'
        url_key = 'url'
        action = {type_key: action_type, url_key: '/web'}
        action[url_key] = 'javascript:alert(document.domain)'
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" for f in findings)


def test_flags_unsafe_scheme_act_url(tmp_path: Path) -> None:
    """URL actions should not use browser-executable or local-file schemes."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_javascript" model="ir.actions.act_url">
    <field name="name">Run Script</field>
    <field name="url">javascript:alert(document.domain)</field>
    <field name="target">self</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" for f in findings)


def test_flags_vbscript_scheme_act_url(tmp_path: Path) -> None:
    """Legacy executable URL schemes should not bypass act_url review."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_vbscript" model="ir.actions.act_url">
    <field name="name">Run Script</field>
    <field name="url">vbscript:msgbox("x")</field>
    <field name="target">self</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(
        f.rule_id == "odoo-act-url-unsafe-scheme" and f.url.startswith("vbscript:") and f.severity == "high"
        for f in findings
    )


def test_xml_entities_are_not_expanded_into_act_url_findings(tmp_path: Path) -> None:
    """act_url XML parsing should reject entities instead of expanding them into findings."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_url "https://evil.example.com/path?access_token=abc">
]>
<odoo>
  <record id="action_entity_url" model="ir.actions.act_url">
    <field name="url">&sensitive_url;</field>
    <field name="target">new</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert not findings


def test_flags_python_dynamic_sensitive_act_url(tmp_path: Path) -> None:
    """Python-built URL actions can leak tokens even when the URL is not request-derived."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "document.py").write_text(
        """
from odoo import models

class Document(models.Model):
    _name = 'x.document'

    def action_share(self):
        token = self.access_token
        return {
            'type': 'ir.actions.act_url',
            'url': f'/web/content/{self.attachment_id.id}?access_token={token}',
            'target': 'self',
        }
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-sensitive-url" for f in findings)


def test_flags_mutated_tainted_act_url(tmp_path: Path) -> None:
    """Building an act_url dict before assigning url should not hide taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/mutated', auth='public')
    def go(self, **kwargs):
        action = {'type': 'ir.actions.act_url', 'target': 'self'}
        action['url'] = kwargs.get('next')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_request_alias_mutated_tainted_act_url_is_reported(tmp_path: Path) -> None:
    """Aliased request params should taint later act_url url mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Redirect(http.Controller):
    @http.route('/go/mutated', auth='public')
    def go(self):
        action = {'type': 'ir.actions.act_url', 'target': 'self'}
        action['url'] = req.params.get('next')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_starred_rest_action_url_alias_mutation_is_reported(tmp_path: Path) -> None:
    """act_url dicts later in starred-rest collections should keep mutation tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/mutated', auth='public')
    def go(self, **kwargs):
        label, *items = 'continue', {}, {'type': 'ir.actions.act_url', 'target': 'self'}
        action = items[1]
        action['url'] = kwargs.get('next')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-act-url-tainted-url" in rule_ids
    assert "odoo-act-url-public-route" in rule_ids


def test_reassigned_act_url_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned act_url aliases should not keep mutation tracking state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

class Redirect(http.Controller):
    @http.route('/go/reassigned', auth='public')
    def go(self, **kwargs):
        action = {'type': 'ir.actions.act_url', 'target': 'self'}
        action = {}
        action['url'] = kwargs.get('next')
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert not any(f.rule_id == "odoo-act-url-tainted-url" for f in findings)
    assert not any(f.rule_id == "odoo-act-url-public-route" for f in findings)


def test_flags_update_mutated_sensitive_act_url(tmp_path: Path) -> None:
    """dict.update on an act_url should be scanned for sensitive URLs."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "document.py").write_text(
        """
from odoo import models

class Document(models.Model):
    _name = 'x.document'

    def action_share(self):
        action = {'type': 'ir.actions.act_url', 'target': 'new'}
        action.update({'url': f'/web/content/{self.attachment_id.id}?access_token={self.access_token}'})
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-sensitive-url" for f in findings)


def test_flags_annotated_mutated_unsafe_act_url(tmp_path: Path) -> None:
    """Annotated act_url variables should be tracked through later url assignment."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "document.py").write_text(
        """
from odoo import models

class Document(models.Model):
    _name = 'x.document'

    def action_open(self):
        action: dict = {'type': 'ir.actions.act_url', 'target': 'self'}
        action['url'] = 'javascript:alert(document.domain)'
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" for f in findings)


def test_constant_alias_mutated_action_url_is_reported(tmp_path: Path) -> None:
    """Constant-backed act_url dict markers should keep later url mutation tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "redirect.py").write_text(
        """
from odoo import http

TYPE_KEY = 'type'
ACTION_KIND = 'ir.actions.act_url'
TARGET_KEY = 'target'
TARGET_SELF = 'self'
URL_KEY = 'url'
UNSAFE_URL = 'javascript:alert(document.domain)'

class Redirect(http.Controller):
    @http.route('/go/mutated', auth='user')
    def go(self):
        action = {TYPE_KEY: ACTION_KIND, TARGET_KEY: TARGET_SELF}
        action[URL_KEY] = UNSAFE_URL
        return action
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" and f.sink == "python-dict-mutation" for f in findings)


def test_flags_python_vbscript_scheme_act_url(tmp_path: Path) -> None:
    """Python returned act_url dictionaries should catch vbscript URLs too."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "document.py").write_text(
        """
from odoo import models

class Document(models.Model):
    _name = 'x.document'

    def action_open(self):
        return {'type': 'ir.actions.act_url', 'url': 'vbscript:msgbox("x")', 'target': 'self'}
""",
        encoding="utf-8",
    )

    findings = scan_action_urls(tmp_path)

    assert any(f.rule_id == "odoo-act-url-unsafe-scheme" and f.sink == "python-dict" for f in findings)


def test_safe_local_act_url_is_ignored(tmp_path: Path) -> None:
    """Static local URL actions are normally benign."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_local" model="ir.actions.act_url">
    <field name="url">/web#menu_id=1</field>
    <field name="target">self</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_action_urls(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_action.py").write_text(
        """
def test_action(kwargs):
    return {'type': 'ir.actions.act_url', 'url': kwargs.get('next')}
""",
        encoding="utf-8",
    )

    assert scan_action_urls(tmp_path) == []
