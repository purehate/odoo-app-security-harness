"""Tests for Odoo ir.default scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.default_value_scanner import scan_default_values


def test_flags_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Public routes should not persist request-controlled defaults."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/group', auth='public')
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_imported_route_decorator_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Imported route decorators should not hide public ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Defaults(http.Controller):
    @route('/defaults/group', auth='public')
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_aliased_imported_route_decorator_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Aliased imported route decorators should not hide public ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request, route as odoo_route

class Defaults(http.Controller):
    @odoo_route('/defaults/group', auth='public')
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_aliased_http_module_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Aliased Odoo http module imports should not hide public ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http as odoo_http
from odoo.http import request

class Defaults(odoo_http.Controller):
    @odoo_http.route('/defaults/group', auth='public')
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_non_odoo_route_decorator_public_default_set_is_ignored(tmp_path: Path) -> None:
    """Local route-like decorators should not create Odoo route context."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo.http import request

class Router:
    def route(self, *args, **kwargs):
        def decorate(func):
            return func
        return decorate

router = Router()

class Defaults:
    @router.route('/defaults/group', auth='public')
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(f.rule_id == "odoo-default-public-route-set" for f in findings)
    assert any(f.rule_id == "odoo-default-sudo-set" for f in findings)


def test_constant_backed_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Constant-backed public auth should still expose ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

DEFAULT_ROUTES = ['/defaults/group', '/defaults/group/alt']
DEFAULT_AUTH = 'public'

class Defaults(http.Controller):
    @http.route(DEFAULT_ROUTES, auth=DEFAULT_AUTH)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_static_unpack_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Static route option dictionaries should not hide public ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

DEFAULT_OPTIONS = {'auth': 'public'}

class Defaults(http.Controller):
    @http.route('/defaults/group', **DEFAULT_OPTIONS)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids


def test_class_constant_backed_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Class-scoped public auth constants should still expose ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    DEFAULT_ROUTES = ['/defaults/group', '/defaults/group/alt']
    DEFAULT_AUTH = 'public'

    @http.route(DEFAULT_ROUTES, auth=DEFAULT_AUTH)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_class_constant_static_unpack_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Class-scoped static route option dictionaries should expose public ir.default writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    AUTH_BASE = 'public'
    DEFAULT_AUTH = AUTH_BASE
    DEFAULT_OPTIONS = {'auth': DEFAULT_AUTH}
    OPTIONS_ALIAS = DEFAULT_OPTIONS

    @http.route('/defaults/group', **OPTIONS_ALIAS)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids


def test_keyword_constant_backed_none_default_value_is_critical(tmp_path: Path) -> None:
    """Constant-backed auth='none' should keep request-derived default writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

DEFAULT_ROUTE = '/defaults/group'
DEFAULT_AUTH = 'none'

class Defaults(http.Controller):
    @http.route(route=DEFAULT_ROUTE, auth=DEFAULT_AUTH)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-public-route-set" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-default-request-derived-set" and f.severity == "critical" for f in findings)


def test_recursive_static_unpack_none_default_value_is_critical(tmp_path: Path) -> None:
    """Recursive route option aliases should keep auth='none' default writes critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

AUTH_BASE = 'none'
DEFAULT_AUTH = AUTH_BASE
DEFAULT_OPTIONS = {'auth': DEFAULT_AUTH}
OPTIONS_ALIAS = DEFAULT_OPTIONS

class Defaults(http.Controller):
    @http.route('/defaults/group', **OPTIONS_ALIAS)
    def set_group(self, **kwargs):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', kwargs.get('groups_id'))
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-public-route-set" and f.severity == "critical" for f in findings)
    assert any(f.rule_id == "odoo-default-request-derived-set" and f.severity == "critical" for f in findings)


def test_request_alias_public_sudo_default_set_from_request(tmp_path: Path) -> None:
    """Request aliases should still taint ir.default field/value writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Defaults(http.Controller):
    @http.route('/defaults/group', auth='public')
    def set_group(self):
        params = req.params
        return req.env['ir.default'].sudo().set(
            'res.users',
            params.get('field_name'),
            params.get('value'),
        )
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids


def test_flags_alias_default_set_for_sensitive_field(tmp_path: Path) -> None:
    """ir.default aliases should still be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        defaults = self.env['ir.default'].sudo()
        return defaults.set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_superuser_with_user_default_set_is_elevated(tmp_path: Path) -> None:
    """Admin-root with_user should be treated like sudo for persisted defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        return self.env['ir.default'].with_user(user=SUPERUSER_ID).set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(finding.rule_id == "odoo-default-sudo-set" for finding in findings)


def test_regular_with_user_default_set_is_not_elevated(tmp_path: Path) -> None:
    """Regular user context switches should not be reported as sudo/default elevation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self, user):
        return self.env['ir.default'].with_user(user).set('sale.order', 'note', 'ok')
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(finding.rule_id == "odoo-default-sudo-set" for finding in findings)


def test_flags_copied_elevated_default_alias(tmp_path: Path) -> None:
    """Copied ir.default aliases should preserve elevated-context state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        defaults = self.env['ir.default'].sudo()
        alias = defaults
        return alias.set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_tuple_unpacked_default_alias(tmp_path: Path) -> None:
    """Tuple-unpacked ir.default aliases should still be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        defaults, users = self.env['ir.default'].sudo(), self.env['res.users']
        defaults.set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_starred_rest_default_alias(tmp_path: Path) -> None:
    """Starred-rest ir.default aliases should still be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        marker, *items = 'x', self.env['ir.default'].sudo(), self.env['res.users']
        defaults = items[0]
        defaults.set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_default_values(tmp_path)}

    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_walrus_elevated_default_alias(tmp_path: Path) -> None:
    """Walrus-bound ir.default aliases should preserve elevated-context state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company_default(self):
        if defaults := self.env['ir.default'].sudo():
            return defaults.set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_default_values(tmp_path)}

    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_reassigned_default_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned ir.default aliases should not keep default-model state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_partner_name(self):
        defaults = self.env['ir.default'].sudo()
        defaults = self.env['res.partner']
        return defaults.set('res.partner', 'name', 'ok')
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(f.rule_id == "odoo-default-sudo-set" for f in findings)


def test_walrus_reassigned_default_alias_is_not_stale(tmp_path: Path) -> None:
    """Walrus reassignment should clear stale ir.default alias state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_partner_name(self):
        defaults = self.env['ir.default'].sudo()
        if defaults := self.env['res.partner']:
            return defaults.set('res.partner', 'name', 'ok')
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(f.rule_id == "odoo-default-sudo-set" for f in findings)


def test_constant_backed_model_and_field_default_set_are_labeled(tmp_path: Path) -> None:
    """Constant-backed model and field names should preserve sensitive finding labels."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

DEFAULT_MODEL_BASE = 'res.users'
DEFAULT_MODEL = DEFAULT_MODEL_BASE
DEFAULT_FIELD_BASE = 'groups_id'
DEFAULT_FIELD = DEFAULT_FIELD_BASE

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_group_default(self):
        return self.env['ir.default'].sudo().set(DEFAULT_MODEL, DEFAULT_FIELD, [self.env.ref('base.group_user').id])
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(
        f.rule_id == "odoo-default-sensitive-field-set"
        and f.model == "res.users"
        and f.field == "groups_id"
        for f in findings
    )


def test_class_constant_model_field_and_default_model_are_labeled(tmp_path: Path) -> None:
    """Class-scoped model, field, and ir.default aliases should preserve labels."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'
    IR_DEFAULT_BASE = 'ir.default'
    IR_DEFAULT = IR_DEFAULT_BASE
    DEFAULT_MODEL_BASE = 'res.users'
    DEFAULT_MODEL = DEFAULT_MODEL_BASE
    DEFAULT_FIELD_BASE = 'groups_id'
    DEFAULT_FIELD = DEFAULT_FIELD_BASE

    def set_group_default(self):
        defaults = self.env[IR_DEFAULT].sudo()
        return defaults.set(DEFAULT_MODEL, DEFAULT_FIELD, [self.env.ref('base.group_user').id])
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(
        f.rule_id == "odoo-default-sensitive-field-set"
        and f.model == "res.users"
        and f.field == "groups_id"
        for f in findings
    )
    assert any(f.rule_id == "odoo-default-sensitive-model-set" and f.model == "res.users" for f in findings)


def test_class_constant_superuser_with_user_default_set_is_elevated(tmp_path: Path) -> None:
    """Class-scoped superuser aliases should still mark elevated default writes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Defaults(models.Model):
    _name = 'x.defaults'
    ROOT_UID = SUPERUSER_ID
    ADMIN_UID = ROOT_UID

    def set_company_default(self):
        return self.env['ir.default'].with_user(user=ADMIN_UID).set('sale.order', 'company_id', self.env.company.id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(finding.rule_id == "odoo-default-sudo-set" for finding in findings)


def test_flags_request_value_through_local_alias(tmp_path: Path) -> None:
    """Request-derived values should remain tainted when assigned before ir.default.set."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='public')
    def set_company(self, **post):
        company = post.get('company_id')
        defaults = request.env['ir.default']
        return defaults.set('sale.order', 'company_id', company)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_starred_rest_request_value_alias(tmp_path: Path) -> None:
    """Starred-rest request-derived values should remain tainted for ir.default.set."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='public')
    def set_company(self, **post):
        marker, *items = 'x', post.get('company_id'), request.env.company.id
        company = items[0]
        defaults = request.env['ir.default']
        return defaults.set('sale.order', 'company_id', company)
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_default_values(tmp_path)}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_value_argument_default_set(tmp_path: Path) -> None:
    """Default value method arguments should be treated as caller-controlled."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
from odoo import models

class Defaults(models.Model):
    _name = 'x.defaults'

    def set_company(self, value):
        defaults = self.env['ir.default']
        return defaults.set('sale.order', 'company_id', value)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_reassigned_default_value_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request-derived value alias for a safe default should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        value = post.get('company_id')
        value = request.env.company.id
        defaults = request.env['ir.default']
        return defaults.set('sale.order', 'company_id', value)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_loop_derived_default_value_is_reported(tmp_path: Path) -> None:
    """Loop variables over request data should remain tainted for ir.default.set."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        defaults = request.env['ir.default']
        for value in post.get('company_ids'):
            defaults.set('sale.order', 'company_id', value)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_safe_loop_reassignment_clears_default_value_taint(tmp_path: Path) -> None:
    """Loop target taint should clear when rebound from safe data."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        defaults = request.env['ir.default']
        for value in post.get('company_ids'):
            pass
        for value in [request.env.company.id]:
            defaults.set('sale.order', 'company_id', value)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert not any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_comprehension_derived_default_value_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehensions should stay tainted for ir.default.set."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        values = [int(value) for value in post.get('company_ids')]
        defaults = request.env['ir.default']
        return defaults.set('sale.order', 'company_id', values[0])
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_comprehension_filter_derived_default_value_is_reported(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated default values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        values = [request.env.company.id for _ in range(1) if post.get('company_ids')]
        defaults = request.env['ir.default']
        return defaults.set('sale.order', 'company_id', values[0])
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_named_expression_derived_default_value_is_reported(tmp_path: Path) -> None:
    """Walrus-bound default values should remain tainted after the condition."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        defaults = request.env['ir.default']
        if company_id := post.get('company_id'):
            return defaults.set('sale.order', 'company_id', company_id)
        return None
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_boolop_derived_default_value_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should taint ir.default.set values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/company', auth='user')
    def set_company(self, **post):
        defaults = request.env['ir.default']
        company_id = post.get('company_id') or request.env.company.id
        return defaults.set('sale.order', 'company_id', company_id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)

    assert any(f.rule_id == "odoo-default-request-derived-set" for f in findings)


def test_flags_route_path_id_default_value(tmp_path: Path) -> None:
    """Path-selected IDs are request-controlled default values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "defaults.py").write_text(
        """
from odoo import http
from odoo.http import request

class Defaults(http.Controller):
    @http.route('/defaults/groups/<int:group_id>', auth='public')
    def set_group(self, group_id):
        return request.env['ir.default'].sudo().set('res.users', 'groups_id', group_id)
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-public-route-set" in rule_ids
    assert "odoo-default-sudo-set" in rule_ids
    assert "odoo-default-request-derived-set" in rule_ids
    assert "odoo-default-sensitive-field-set" in rule_ids


def test_flags_sensitive_model_runtime_default(tmp_path: Path) -> None:
    """Generic fields on security/payment models should still be sensitive defaults."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "defaults.py").write_text(
        """
class Defaults:
    def set_defaults(self):
        self.env['ir.default'].set('ir.config_parameter', 'value', 'https://example.test')
        self.env['ir.default'].set('payment.provider', 'state', 'enabled')
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    sensitive_model_defaults = [
        finding for finding in findings if finding.rule_id == "odoo-default-sensitive-model-set"
    ]

    assert len(sensitive_model_defaults) == 2


def test_flags_global_sensitive_xml_default(tmp_path: Path) -> None:
    """Global ir.default XML records can seed sensitive values broadly."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "defaults.xml").write_text(
        """<odoo>
  <record id="default_user_group" model="ir.default">
    <field name="model">res.users</field>
    <field name="field_id" ref="base.field_res_users__groups_id"/>
    <field name="json_value">[1]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-global-scope" in rule_ids
    assert "odoo-default-sensitive-value" in rule_ids


def test_flags_sensitive_model_xml_default(tmp_path: Path) -> None:
    """XML defaults on sensitive models should not depend only on field names."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "defaults.xml").write_text(
        """<odoo>
  <record id="default_config_value" model="ir.default">
    <field name="model">ir.config_parameter</field>
    <field name="field_name">value</field>
    <field name="json_value">"https://example.test"</field>
  </record>
  <record id="default_payment_provider_state" model="ir.default">
    <field name="model">payment.provider</field>
    <field name="field_name">state</field>
    <field name="json_value">"enabled"</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    sensitive_model_defaults = [
        finding for finding in findings if finding.rule_id == "odoo-default-sensitive-model-value"
    ]

    assert len(sensitive_model_defaults) == 2


def test_flags_global_sensitive_csv_default(tmp_path: Path) -> None:
    """Global ir.default CSV records can seed sensitive values broadly."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.default.csv").write_text(
        """id,model,field_id/id,json_value
default_user_group,res.users,base.field_res_users__groups_id,[1]
""",
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-default-global-scope" in rule_ids
    assert "odoo-default-sensitive-value" in rule_ids


def test_flags_sensitive_model_csv_default(tmp_path: Path) -> None:
    """CSV defaults on sensitive models should not depend only on field names."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_default.csv").write_text(
        '''id,model,field_name,json_value
default_config_value,ir.config_parameter,value,"""https://example.test"""
default_payment_provider_state,payment.provider,state,"""enabled"""
''',
        encoding="utf-8",
    )

    findings = scan_default_values(tmp_path)
    sensitive_model_defaults = [
        finding for finding in findings if finding.rule_id == "odoo-default-sensitive-model-value"
    ]

    assert len(sensitive_model_defaults) == 2


def test_company_scoped_non_sensitive_csv_default_is_ignored(tmp_path: Path) -> None:
    """Scoped benign CSV defaults should not create noise."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.default.csv").write_text(
        '''id,model,field_name,company_id/id,json_value
default_note,project.task,description,base.main_company,"""todo"""
''',
        encoding="utf-8",
    )

    assert scan_default_values(tmp_path) == []


def test_xml_entities_are_not_expanded_into_default_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize sensitive default fields."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "defaults.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY sensitive_field "groups_id">
]>
<odoo>
  <record id="default_entity" model="ir.default">
    <field name="model">res.users</field>
    <field name="field_name">&sensitive_field;</field>
    <field name="json_value">[1]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_default_values(tmp_path) == []


def test_company_scoped_non_sensitive_default_is_ignored(tmp_path: Path) -> None:
    """Scoped benign defaults should not create noise."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "defaults.xml").write_text(
        """<odoo>
  <record id="default_note" model="ir.default">
    <field name="model">project.task</field>
    <field name="field_name">description</field>
    <field name="company_id" ref="base.main_company"/>
    <field name="json_value">"todo"</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_default_values(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_defaults.py").write_text(
        """
def test_default(request):
    request.env['ir.default'].sudo().set('res.users', 'groups_id', [])
""",
        encoding="utf-8",
    )

    assert scan_default_values(tmp_path) == []
