"""Tests for risky Odoo ORM domain construction scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.orm_domain_scanner import scan_orm_domains


def test_flags_public_route_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Public controllers should not pass request domains into sudo searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_public_route_tainted_sudo_search_count_domain(tmp_path: Path) -> None:
    """Request-controlled search_count domains are elevated existence oracles."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def count(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search_count(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_constant_backed_public_route_tainted_sudo_search_domain_is_critical(tmp_path: Path) -> None:
    """Constant-backed public route auth should not downgrade sudo domain searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

SEARCH_ROUTE = '/public/search'
SEARCH_AUTH = 'public'

class Search(http.Controller):
    @http.route(SEARCH_ROUTE, auth=SEARCH_AUTH)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_recursive_constant_backed_public_route_tainted_sudo_search_domain_is_critical(tmp_path: Path) -> None:
    """Recursive route auth constants should not downgrade sudo domain searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

SEARCH_ROUTE = '/public/search'
ROUTE_ALIAS = SEARCH_ROUTE
PUBLIC_AUTH = 'public'
AUTH_ALIAS = PUBLIC_AUTH

class Search(http.Controller):
    @http.route(ROUTE_ALIAS, auth=AUTH_ALIAS)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_keyword_constant_backed_none_route_tainted_search_domain_is_high(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep tainted search severity high."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

SEARCH_ROUTE = '/public/search'
SEARCH_AUTH = 'none'

class Search(http.Controller):
    @http.route(route=SEARCH_ROUTE, auth=SEARCH_AUTH)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" and f.severity == "high" for f in findings)


def test_flags_keyword_public_route_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Keyword ORM domains should receive the same sudo search review."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain=domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_imported_route_decorator_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Imported route decorators should not hide public sudo searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Search(http.Controller):
    @route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_aliased_imported_route_decorator_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public sudo searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request, route as public_route

class Search(http.Controller):
    @public_route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_aliased_http_module_route_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Search(odoo_http.Controller):
    @odoo_http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_imported_odoo_http_module_route_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Direct odoo.http route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo.http as odoo_http

class Search(odoo_http.Controller):
    @odoo_http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return odoo_http.request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_imported_odoo_module_route_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Direct odoo module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo as od

class Search(od.http.Controller):
    @od.http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return od.http.request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_non_odoo_route_decorator_tainted_sudo_search_domain_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make tainted sudo searches public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Search(http.Controller):
    @router.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert not any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "high" for f in findings)


def test_static_unpack_public_route_options_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Static route option unpacking should preserve public sudo-search severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_OPTIONS = {'auth': 'public'}

class Search(http.Controller):
    @http.route('/public/search', **ROUTE_OPTIONS)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].sudo().search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_class_constant_static_unpack_public_route_options_tainted_search_is_high(tmp_path: Path) -> None:
    """Class-scoped **route options should preserve public ORM-domain severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    SEARCH_ROUTE = '/public/search'
    PUBLIC_AUTH = 'public'
    ROUTE_OPTIONS = {'route': SEARCH_ROUTE, 'auth': PUBLIC_AUTH}

    @http.route(**ROUTE_OPTIONS)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" and f.severity == "high" for f in findings)


def test_nested_static_unpack_public_route_options_tainted_search_is_high(tmp_path: Path) -> None:
    """Nested **route options should preserve public ORM-domain severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = {**BASE_OPTIONS, 'route': '/public/search'}

class Search(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" and f.severity == "high" for f in findings)


def test_dict_union_public_route_options_tainted_search_is_high(tmp_path: Path) -> None:
    """Dict-union **route options should preserve public ORM-domain severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public'}
ROUTE_OPTIONS = BASE_OPTIONS | {'route': '/public/search'}

class Search(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" and f.severity == "high" for f in findings)


def test_request_alias_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Aliased request imports should still taint sudo search domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self):
        payload = req.get_http_params()
        return req.env['res.partner'].sudo().search(payload.get('domain'))
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_imported_odoo_http_request_public_tainted_sudo_search_domain(tmp_path: Path) -> None:
    """Direct odoo.http request access should still taint sudo search domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
import odoo.http as odoo_http

class Search(odoo_http.Controller):
    @odoo_http.route('/public/search', auth='public')
    def search(self):
        payload = odoo_http.request.get_http_params()
        return odoo_http.request.env['res.partner'].sudo().search(payload.get('domain'))
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_public_route_tainted_superuser_search_domain(tmp_path: Path) -> None:
    """Public controllers should not pass request domains into superuser searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import SUPERUSER_ID, http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(SUPERUSER_ID).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_public_route_tainted_import_aliased_superuser_search_domain(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases should keep public tainted domains privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(ROOT_UID).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_constant_backed_public_route_tainted_superuser_search_domain(tmp_path: Path) -> None:
    """Superuser constants should keep tainted domains classified as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ROOT_UID = 1

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(ROOT_UID).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_recursive_constant_backed_public_route_tainted_superuser_search_domain(tmp_path: Path) -> None:
    """Recursive superuser constants should keep tainted domains classified as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(ADMIN_UID).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_class_constant_public_route_tainted_superuser_search_domain_is_critical(tmp_path: Path) -> None:
    """Class-scoped route and superuser constants should preserve elevated severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    SEARCH_ROUTE = '/public/search'
    PUBLIC_AUTH = 'public'
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    @http.route(SEARCH_ROUTE, auth=PUBLIC_AUTH)
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(ADMIN_UID).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_local_constant_public_route_tainted_superuser_search_domain_is_critical(tmp_path: Path) -> None:
    """Function-local superuser constants should preserve elevated severity."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        root_uid = 1
        domain = kwargs.get('domain')
        return request.env['res.partner'].with_user(root_uid).search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" and f.severity == "critical" for f in findings)


def test_flags_aliased_superuser_tainted_search_domain(tmp_path: Path) -> None:
    """Superuser model aliases should still classify tainted domains as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        Partners = request.env['res.partner'].with_user(1)
        return Partners.search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_constant_backed_aliased_superuser_tainted_search_domain(tmp_path: Path) -> None:
    """Aliased with_user constants should preserve elevated search posture."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ROOT_UID = 1

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        Partners = request.env['res.partner'].with_user(ROOT_UID)
        return Partners.search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_class_constant_aliased_superuser_tainted_search_domain_is_reported(tmp_path: Path) -> None:
    """Class-scoped with_user constants should preserve elevated alias tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        Partners = request.env['res.partner'].with_user(ADMIN_UID)
        return Partners.search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_local_constant_aliased_superuser_tainted_search_domain_is_reported(tmp_path: Path) -> None:
    """Function-local with_user constants should preserve elevated alias tracking."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        root_uid = 1
        domain = kwargs.get('domain')
        Partners = request.env['res.partner'].with_user(root_uid)
        return Partners.search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_env_ref_admin_tainted_search_domain(tmp_path: Path) -> None:
    """Admin XML-ID model aliases should classify tainted domains as privileged."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        Partners = request.env['res.partner'].with_user(request.env.ref('base.user_admin'))
        return Partners.search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-sudo-search" for f in findings)


def test_flags_context_domain_search(tmp_path: Path) -> None:
    """Context-provided domains are caller-controlled enough to require review."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_search(self):
        domain = self.env.context.get('active_domain')
        return self.env['sale.order'].search_read(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_flags_domain_argument_search(tmp_path: Path) -> None:
    """Domain-shaped method arguments should be treated as caller-controlled."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_search(self, domain):
        return self.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_flags_dynamic_eval_domain(tmp_path: Path) -> None:
    """Request-derived strings should not be evaluated into ORM domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "eval_domain.py").write_text(
        """
from odoo import http
from odoo.http import request
from odoo.tools.safe_eval import safe_eval

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = safe_eval(request.params.get('domain'))
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-dynamic-eval" for f in findings)


def test_flags_keyword_dynamic_eval_domain(tmp_path: Path) -> None:
    """Keyword eval expressions should still flag request-derived domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "eval_domain.py").write_text(
        """
from odoo import http
from odoo.http import request
from odoo.tools.safe_eval import safe_eval

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = safe_eval(expr=request.params.get('domain'))
        return request.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-dynamic-eval" for f in findings)


def test_request_alias_dynamic_eval_domain(tmp_path: Path) -> None:
    """Aliased request params should still taint evaluated ORM domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "eval_domain.py").write_text(
        """
from odoo import http
from odoo.http import request as req
from odoo.tools.safe_eval import safe_eval

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self):
        domain = safe_eval(req.params.get('domain'))
        return req.env['res.partner'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-dynamic-eval" for f in findings)


def test_flags_filtered_lambda_with_request_logic(tmp_path: Path) -> None:
    """Python-side filtering with request/env logic can hide missing record-rule checks."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "filter.py").write_text(
        """
from odoo import http
from odoo.http import request

class Filter(http.Controller):
    @http.route('/my/filter', auth='user')
    def filter(self):
        records = request.env['sale.order'].search([])
        return records.filtered(lambda record: record.user_id.id == request.env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-filtered-dynamic" for f in findings)


def test_request_alias_filtered_lambda_with_request_logic(tmp_path: Path) -> None:
    """Aliased request references in filtered lambdas should still be reported."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "filter.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Filter(http.Controller):
    @http.route('/my/filter', auth='user')
    def filter(self):
        records = req.env['sale.order'].search([])
        return records.filtered(lambda record: record.user_id.id == req.env.uid)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-filtered-dynamic" for f in findings)


def test_reassigned_domain_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a domain alias for a safe static domain should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        domain = [('state', '=', 'sale')]
        return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert not any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_loop_derived_domain_is_reported(tmp_path: Path) -> None:
    """Domains derived from tainted iterables should stay tainted through loops."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domains = kwargs.get('domains')
        for domain in domains:
            return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_safe_loop_reassignment_clears_domain_taint(tmp_path: Path) -> None:
    """Safe loop targets should clear stale domain taint before ORM use."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain')
        for domain in [[('state', '=', 'sale')]]:
            return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert not any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_comprehension_derived_domain_is_reported(tmp_path: Path) -> None:
    """Comprehensions carrying request data into a domain should be reported."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        values = kwargs.get('states')
        domain = [('state', '=', value) for value in values]
        return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_comprehension_filter_derived_domain_is_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated ORM domains."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = [('state', '=', 'sale') for _ in range(1) if kwargs.get('states')]
        return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_named_expression_derived_domain_is_reported(tmp_path: Path) -> None:
    """Walrus-bound request domains should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        if domain := kwargs.get('domain'):
            return request.env['sale.order'].search(domain)
        return request.env['sale.order']
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_boolop_derived_domain_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should keep ORM domains tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Search(http.Controller):
    @http.route('/public/search', auth='public')
    def search(self, **kwargs):
        domain = kwargs.get('domain') or [('state', '=', 'sale')]
        return request.env['sale.order'].search(domain)
""",
        encoding="utf-8",
    )

    findings = scan_orm_domains(tmp_path)

    assert any(f.rule_id == "odoo-orm-domain-tainted-search" for f in findings)


def test_safe_static_domain_is_ignored(tmp_path: Path) -> None:
    """Static literal domains should avoid ORM-domain noise."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import models

class Safe(models.Model):
    _name = 'x.safe'

    def action_search(self):
        return self.env['sale.order'].search([('state', '=', 'sale')], limit=10)
""",
        encoding="utf-8",
    )

    assert scan_orm_domains(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """ORM-domain fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_domain.py").write_text(
        """
from odoo.http import request

def test_search(kwargs):
    return request.env['res.partner'].sudo().search(kwargs.get('domain'))
""",
        encoding="utf-8",
    )

    assert scan_orm_domains(tmp_path) == []
