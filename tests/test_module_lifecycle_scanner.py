"""Tests for Odoo module lifecycle scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.module_lifecycle_scanner import scan_module_lifecycle


def test_public_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Public routes must not install request-selected modules."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_constant_backed_public_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Constant-backed public route metadata should not hide module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

INSTALL_ROUTE = '/public/install'
INSTALL_AUTH = 'public'

class Controller(http.Controller):
    @http.route(INSTALL_ROUTE, auth=INSTALL_AUTH, csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert any(
        finding.rule_id == "odoo-module-tainted-selection"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )


def test_keyword_constant_backed_none_routes_keep_lifecycle_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep lifecycle findings critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

LIFECYCLE_ROUTES = ['/public/install', '/public/modules/install']
LIFECYCLE_AUTH = 'none'

class Controller(http.Controller):
    @http.route(routes=LIFECYCLE_ROUTES, auth=LIFECYCLE_AUTH, csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.severity == "critical"
        and finding.route == "/public/install,/public/modules/install"
        for finding in findings
    )
    assert any(
        finding.rule_id == "odoo-module-tainted-selection" and finding.severity == "critical" for finding in findings
    )


def test_recursive_constant_route_and_module_model_lifecycle_is_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide public module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_ONE = '/public/install'
ROUTE_TWO = '/public/modules/install'
LIFECYCLE_ROUTES = [ROUTE_ONE, ROUTE_TWO]
AUTH_PUBLIC = 'public'
LIFECYCLE_AUTH = AUTH_PUBLIC
MODULE_MODEL = 'ir.module.module'
TARGET_MODEL = MODULE_MODEL

class Controller(http.Controller):
    @http.route(routes=LIFECYCLE_ROUTES, auth=LIFECYCLE_AUTH, csrf=False)
    def install(self, **kwargs):
        module = request.env[TARGET_MODEL].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.route == "/public/install,/public/modules/install"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-module-sudo-lifecycle" for finding in findings)
    assert any(finding.rule_id == "odoo-module-immediate-lifecycle" for finding in findings)
    assert any(finding.rule_id == "odoo-module-tainted-selection" for finding in findings)


def test_imported_route_decorator_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should not hide module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Controller(http.Controller):
    @route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_aliased_imported_route_decorator_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Controller(http.Controller):
    @web_route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_aliased_http_module_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Aliased odoo.http module route decorators should remain recognized."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_imported_odoo_http_module_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Direct odoo.http imports should not hide routes or request-selected modules."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
import odoo.http as odoo_http

class Controller(odoo_http.Controller):
    @odoo_http.route('/public/install', auth='public', csrf=False)
    def install(self):
        params = odoo_http.request.get_http_params()
        module = odoo_http.request.env['ir.module.module'].sudo().search([('name', '=', params.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_imported_odoo_module_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Direct odoo module imports should not hide routes or request-selected modules."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
import odoo as od

class Controller(od.http.Controller):
    @od.http.route('/public/install', auth='public', csrf=False)
    def install(self):
        params = od.http.request.get_http_params()
        module = od.http.request.env['ir.module.module'].sudo().search([('name', '=', params.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_non_odoo_route_decorator_module_lifecycle_is_not_public(tmp_path: Path) -> None:
    """Local route decorators should not make module lifecycle calls public routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Controller(http.Controller):
    @router.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" not in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_static_unpack_public_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Static **route options should not hide public module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

INSTALL_OPTIONS = {'route': '/public/install', 'auth': 'public', 'csrf': False}

class Controller(http.Controller):
    @http.route(**INSTALL_OPTIONS)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )
    assert any(
        finding.rule_id == "odoo-module-tainted-selection"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )


def test_nested_static_unpack_public_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Nested static **route options should not hide public module lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

BASE_OPTIONS = {'auth': 'public', 'csrf': False}
INSTALL_OPTIONS = {**BASE_OPTIONS, 'route': '/public/install'}

class Controller(http.Controller):
    @http.route(**INSTALL_OPTIONS)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )
    assert any(
        finding.rule_id == "odoo-module-tainted-selection"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )


def test_class_constant_public_route_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Class-scoped route and module constants should not hide lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ROUTE_ONE = '/public/install'
    ROUTE_TWO = '/public/modules/install'
    LIFECYCLE_ROUTES = [ROUTE_ONE, ROUTE_TWO]
    AUTH_PUBLIC = 'public'
    LIFECYCLE_AUTH = AUTH_PUBLIC
    MODULE_MODEL = 'ir.module.module'
    TARGET_MODEL = MODULE_MODEL

    @http.route(routes=LIFECYCLE_ROUTES, auth=LIFECYCLE_AUTH, csrf=False)
    def install(self, **kwargs):
        module = request.env[TARGET_MODEL].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.route == "/public/install,/public/modules/install"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-module-sudo-lifecycle" for finding in findings)
    assert any(finding.rule_id == "odoo-module-immediate-lifecycle" for finding in findings)
    assert any(finding.rule_id == "odoo-module-tainted-selection" for finding in findings)


def test_class_constant_static_unpack_public_route_lifecycle_is_reported(tmp_path: Path) -> None:
    """Class-scoped static **route options should preserve lifecycle route metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    INSTALL_ROUTE = '/public/install'
    INSTALL_AUTH = 'public'
    INSTALL_OPTIONS = {'route': INSTALL_ROUTE, 'auth': INSTALL_AUTH, 'csrf': False}

    @http.route(**INSTALL_OPTIONS)
    def install(self, **kwargs):
        module = request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(
        finding.rule_id == "odoo-module-public-route-lifecycle"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )
    assert any(
        finding.rule_id == "odoo-module-tainted-selection"
        and finding.severity == "critical"
        and finding.route == "/public/install"
        for finding in findings
    )


def test_request_alias_immediate_install_from_request_is_reported(tmp_path: Path) -> None:
    """Aliased request imports should still taint module lifecycle selection."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/public/install', auth='public', csrf=False)
    def install(self):
        payload = req.get_http_params()
        module = req.env['ir.module.module'].sudo().search([('name', '=', payload.get('module'))])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_request_alias_direct_module_selection_is_reported(tmp_path: Path) -> None:
    """Direct aliased request params should taint selected modules."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/modules/upgrade', auth='user')
    def upgrade(self):
        selected = req.env['ir.module.module'].sudo().search([('name', '=', req.params.get('module'))])
        return selected.button_immediate_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(f.rule_id == "odoo-module-tainted-selection" for f in findings)


def test_sudo_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Admin helpers that sudo-upgrade modules should be review-visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def upgrade_sale(self):
        return self.env['ir.module.module'].sudo().search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_superuser_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Admin helpers that superuser-upgrade modules should be review-visible."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
from odoo import SUPERUSER_ID

class ModuleHelper:
    def upgrade_sale(self):
        return self.env['ir.module.module'].with_user(SUPERUSER_ID).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_aliased_import_superuser_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Imported SUPERUSER_ID aliases in module lifecycle calls are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID

class ModuleHelper:
    def upgrade_sale(self):
        return self.env['ir.module.module'].with_user(ROOT_UID).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids


def test_keyword_superuser_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Keyword with_user(user=SUPERUSER_ID) module lifecycle calls are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
from odoo import SUPERUSER_ID

class ModuleHelper:
    def upgrade_sale(self):
        return self.env['ir.module.module'].with_user(user=SUPERUSER_ID).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_recursive_constant_superuser_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Recursive superuser aliases should count as elevated module lifecycle."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
from odoo import SUPERUSER_ID

ROOT_USER = SUPERUSER_ID
ADMIN_USER = ROOT_USER
MODULE_MODEL = 'ir.module.module'
TARGET_MODEL = MODULE_MODEL

class ModuleHelper:
    def upgrade_sale(self):
        return self.env[TARGET_MODEL].with_user(user=ADMIN_USER).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_class_constant_superuser_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Class-scoped superuser and module-model aliases should count as elevated lifecycle."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
from odoo import SUPERUSER_ID

class ModuleHelper:
    ROOT_USER = SUPERUSER_ID
    ADMIN_USER = ROOT_USER
    MODULE_MODEL = 'ir.module.module'
    TARGET_MODEL = MODULE_MODEL

    def upgrade_sale(self):
        return self.env[TARGET_MODEL].with_user(user=ADMIN_USER).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_env_ref_admin_upgrade_on_module_model_is_reported(tmp_path: Path) -> None:
    """Admin XML-ID with_user calls should count as elevated module lifecycle."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def upgrade_sale(self):
        return self.env['ir.module.module'].with_user(self.env.ref('base.user_admin')).search([('name', '=', 'sale')]).button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_unpacked_tainted_module_selection_is_reported(tmp_path: Path) -> None:
    """Tuple-unpacked request values that select modules must stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module_name, action = kwargs.get('module'), 'install'
        module = request.env['ir.module.module'].sudo().search([('name', '=', module_name)])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_starred_rest_tainted_module_selection_is_reported(tmp_path: Path) -> None:
    """Starred tuple-rest request values that select modules must stay tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        marker, *items, tail = 'x', kwargs.get('module'), 'install', 'end'
        module_name = items[0]
        module = request.env['ir.module.module'].sudo().search([('name', '=', module_name)])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_module_argument_selection_is_reported(tmp_path: Path) -> None:
    """Module-like function arguments should still seed lifecycle selection taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/modules/upgrade', auth='user')
    def upgrade(self, module):
        selected = request.env['ir.module.module'].sudo().search([('name', '=', module)])
        return selected.button_immediate_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)

    assert any(f.rule_id == "odoo-module-tainted-selection" for f in findings)


def test_reassigned_module_name_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request module name alias for a static module should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/public/install', auth='public', csrf=False)
    def install(self, **kwargs):
        module_name = kwargs.get('module')
        module_name = 'sale'
        module = request.env['ir.module.module'].sudo().search([('name', '=', module_name)])
        return module.button_immediate_install()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-public-route-lifecycle" in rule_ids
    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" not in rule_ids


def test_comprehension_tainted_module_selection_is_reported(tmp_path: Path) -> None:
    """Comprehensions fed by request data should taint module searches."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/modules/upgrade', auth='user')
    def upgrade(self, **kwargs):
        names = [name for name in kwargs.get('modules', []) if name]
        modules = request.env['ir.module.module'].sudo().search([('name', 'in', names)])
        return modules.button_immediate_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_comprehension_filter_tainted_module_selection_is_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated module names."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/modules/upgrade', auth='user')
    def upgrade(self, **kwargs):
        names = ['sale' for _ in range(1) if kwargs.get('module')]
        modules = request.env['ir.module.module'].sudo().search([('name', 'in', names)])
        return modules.button_immediate_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids
    assert "odoo-module-public-route-lifecycle" not in rule_ids


def test_named_expression_tainted_module_selection_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned module names should remain tainted for lifecycle calls."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "modules.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/modules/upgrade', auth='user')
    def upgrade(self, **kwargs):
        if module_name := kwargs.get('module'):
            modules = request.env['ir.module.module'].sudo().search([('name', '=', module_name)])
            return modules.button_immediate_upgrade()
        return False
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-immediate-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" in rule_ids


def test_tuple_unpacked_sudo_module_alias_is_reported(tmp_path: Path) -> None:
    """Sudo module recordsets should be tracked through tuple unpacking."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def upgrade_sale(self):
        module, partner = self.env['ir.module.module'].sudo().search([('name', '=', 'sale')]), self.env.user.partner_id
        return module.button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" not in rule_ids


def test_aliased_superuser_module_recordset_is_reported(tmp_path: Path) -> None:
    """Superuser module recordsets should be tracked through aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def upgrade_sale(self):
        module = self.env['ir.module.module'].with_user(1).search([('name', '=', 'sale')])
        return module.button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" not in rule_ids


def test_starred_rest_sudo_module_alias_is_reported(tmp_path: Path) -> None:
    """Sudo module recordsets should be tracked through starred tuple-rest unpacking."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def upgrade_sale(self):
        marker, *items, tail = 'x', self.env['ir.module.module'].sudo().search([('name', '=', 'sale')]), self.env.user.partner_id, 'end'
        module = items[0]
        return module.button_upgrade()
""",
        encoding="utf-8",
    )

    findings = scan_module_lifecycle(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-module-sudo-lifecycle" in rule_ids
    assert "odoo-module-tainted-selection" not in rule_ids


def test_safe_non_sudo_internal_module_query_is_ignored(tmp_path: Path) -> None:
    """Reading module metadata should not trigger lifecycle findings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "modules.py").write_text(
        """
class ModuleHelper:
    def list_sale(self):
        return self.env['ir.module.module'].search([('name', '=', 'sale')])
""",
        encoding="utf-8",
    )

    assert scan_module_lifecycle(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_modules.py").write_text(
        """
def test_install():
    request.env['ir.module.module'].sudo().search([('name', '=', kwargs.get('module'))]).button_immediate_install()
""",
        encoding="utf-8",
    )

    assert scan_module_lifecycle(tmp_path) == []
