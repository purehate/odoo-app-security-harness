"""Tests for Odoo identity mutation scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.identity_mutation_scanner import scan_identity_mutations


def test_flags_public_route_sudo_user_group_write(tmp_path: Path) -> None:
    """Public routes must not change user group membership under sudo."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/signup/promote', auth='public', type='http')
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-public-route-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_constant_backed_public_route_sudo_user_group_write(tmp_path: Path) -> None:
    """Constant-backed public route metadata should not hide identity mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

PROMOTE_ROUTE = '/signup/promote'
PROMOTE_AUTH = 'public'

class Users(http.Controller):
    @http.route(PROMOTE_ROUTE, auth=PROMOTE_AUTH, type='http')
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-public-route-mutation" in rule_ids
    assert any(
        finding.rule_id == "odoo-identity-elevated-mutation"
        and finding.severity == "critical"
        and finding.route == "/signup/promote"
        for finding in findings
    )
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_keyword_constant_backed_none_routes_identity_write_is_critical(tmp_path: Path) -> None:
    """Keyword route constants with auth='none' should keep identity mutations critical."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

PROMOTE_ROUTES = ['/signup/promote', '/public/promote']
PROMOTE_AUTH = 'none'

class Users(http.Controller):
    @http.route(routes=PROMOTE_ROUTES, auth=PROMOTE_AUTH, type='http')
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'company_ids': kwargs.get('company_ids')})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(
        finding.rule_id == "odoo-identity-public-route-mutation"
        and finding.severity == "critical"
        and finding.route == "/signup/promote,/public/promote"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-identity-elevated-mutation" and finding.severity == "critical" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-request-derived-mutation" for finding in findings)


def test_recursive_constant_route_model_and_privilege_key_are_reported(tmp_path: Path) -> None:
    """Recursive constants should not hide public identity writes or privilege keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

ROUTE_ONE = '/signup/promote'
ROUTE_TWO = '/public/promote'
PROMOTE_ROUTES = [ROUTE_ONE, ROUTE_TWO]
AUTH_PUBLIC = 'public'
PROMOTE_AUTH = AUTH_PUBLIC
USER_MODEL = 'res.users'
TARGET_MODEL = USER_MODEL
GROUP_FIELD = 'groups_id'
PRIV_FIELD = GROUP_FIELD

class Users(http.Controller):
    @http.route(PROMOTE_ROUTES, auth=PROMOTE_AUTH, type='http')
    def promote(self, user_id, **kwargs):
        user = request.env[TARGET_MODEL].sudo().browse(int(user_id))
        return user.write({PRIV_FIELD: kwargs.get('groups_id')})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(
        finding.rule_id == "odoo-identity-public-route-mutation"
        and finding.route == "/signup/promote,/public/promote"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-identity-elevated-mutation" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-request-derived-mutation" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_superuser_with_user_identity_write_is_elevated(tmp_path: Path) -> None:
    """Admin-root with_user should be treated like sudo for identity mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class UserTool(models.Model):
    _name = 'x.user.tool'

    def rename_user(self, user_id):
        user = self.env['res.users'].with_user(user=SUPERUSER_ID).browse(user_id)
        return user.write({'name': 'Reviewed'})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(finding.rule_id == "odoo-identity-elevated-mutation" for finding in findings)


def test_recursive_constant_superuser_with_user_identity_write_is_elevated(tmp_path: Path) -> None:
    """Recursive SUPERUSER_ID aliases should be treated like sudo for identity mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import SUPERUSER_ID, models

ROOT_USER = SUPERUSER_ID
ADMIN_USER = ROOT_USER

class UserTool(models.Model):
    _name = 'x.user.tool'

    def rename_user(self, user_id):
        user = self.env['res.users'].with_user(user=ADMIN_USER).browse(user_id)
        return user.write({'name': 'Reviewed'})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(finding.rule_id == "odoo-identity-elevated-mutation" for finding in findings)


def test_regular_with_user_identity_write_is_not_elevated(tmp_path: Path) -> None:
    """Regular user context switches should not be reported as identity elevation."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import models

class UserTool(models.Model):
    _name = 'x.user.tool'

    def rename_user(self, user, target):
        target = self.env['res.users'].with_user(user).browse(target.id)
        return target.write({'name': 'Reviewed'})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert not any(finding.rule_id == "odoo-identity-elevated-mutation" for finding in findings)


def test_imported_route_decorator_public_identity_mutation_is_reported(tmp_path: Path) -> None:
    """Imported route decorators must still be treated as public controller routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request, route

class Users(http.Controller):
    @route('/signup/promote', auth='public', type='http')
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-public-route-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_aliased_imported_route_decorator_public_identity_mutation_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators must still expose public identity mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request, route as web_route

class Users(http.Controller):
    @web_route('/signup/promote', auth='public', type='http')
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-public-route-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_static_unpack_public_route_identity_mutation_is_reported(tmp_path: Path) -> None:
    """Static **route options should not hide public identity mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

PROMOTE_AUTH = 'public'
ROUTE_OPTIONS = {'route': '/signup/promote', 'auth': PROMOTE_AUTH, 'type': 'http'}

class Users(http.Controller):
    @http.route(**ROUTE_OPTIONS)
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(
        finding.rule_id == "odoo-identity-public-route-mutation"
        and finding.severity == "critical"
        and finding.route == "/signup/promote"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-identity-elevated-mutation" and finding.severity == "critical" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_class_constant_route_model_and_privilege_key_are_reported(tmp_path: Path) -> None:
    """Class-scoped constants should not hide public identity writes or privilege keys."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    ROUTE_ONE = '/signup/promote'
    ROUTE_TWO = '/public/promote'
    PROMOTE_ROUTES = [ROUTE_ONE, ROUTE_TWO]
    AUTH_PUBLIC = 'public'
    PROMOTE_AUTH = AUTH_PUBLIC
    USER_MODEL = 'res.users'
    TARGET_MODEL = USER_MODEL
    GROUP_FIELD = 'groups_id'
    PRIV_FIELD = GROUP_FIELD

    @http.route(PROMOTE_ROUTES, auth=PROMOTE_AUTH, type='http')
    def promote(self, user_id, **kwargs):
        user = request.env[TARGET_MODEL].sudo().browse(int(user_id))
        return user.write({PRIV_FIELD: kwargs.get('groups_id')})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(
        finding.rule_id == "odoo-identity-public-route-mutation"
        and finding.route == "/signup/promote,/public/promote"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-identity-elevated-mutation" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-request-derived-mutation" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_class_constant_static_unpack_public_route_identity_mutation_is_reported(tmp_path: Path) -> None:
    """Class-scoped **route options should not hide public identity mutations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    PROMOTE_AUTH = 'public'
    ROUTE_OPTIONS = {'route': '/signup/promote', 'auth': PROMOTE_AUTH, 'type': 'http'}

    @http.route(**ROUTE_OPTIONS)
    def promote(self, user_id, **kwargs):
        user = request.env['res.users'].sudo().browse(int(user_id))
        return user.write({'groups_id': [(4, request.env.ref('base.group_system').id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(
        finding.rule_id == "odoo-identity-public-route-mutation"
        and finding.severity == "critical"
        and finding.route == "/signup/promote"
        for finding in findings
    )
    assert any(finding.rule_id == "odoo-identity-elevated-mutation" and finding.severity == "critical" for finding in findings)
    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_flags_request_payload_reaching_identity_create(tmp_path: Path) -> None:
    """Request payloads should not flow directly into res.users create."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request

class Invite(http.Controller):
    @http.route('/invite', auth='user', type='json')
    def invite(self):
        payload = request.jsonrequest
        return request.env['res.users'].sudo().create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids


def test_request_alias_payload_reaching_identity_create(tmp_path: Path) -> None:
    """Aliased Odoo request objects should still seed identity mutation taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "invite.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Invite(http.Controller):
    @http.route('/invite', auth='user', type='json')
    def invite(self):
        payload = req.jsonrequest
        return req.env['res.users'].sudo().create(payload)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids


def test_flags_identity_values_argument_reaching_identity_write(tmp_path: Path) -> None:
    """Route payload arguments should still be treated as request-derived."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/update', auth='user', type='json')
    def update_user(self, values):
        return request.env['res.users'].write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids


def test_request_alias_params_reaching_identity_write(tmp_path: Path) -> None:
    """Aliased request params should taint user/group write values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self):
        payload = req.params
        values = {'groups_id': payload.get('group_ids')}
        return req.env['res.users'].browse(1).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_reassigned_identity_values_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a tainted request values name for safe data should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/update', auth='user', type='json')
    def update_user(self, **kwargs):
        values = kwargs
        values = {'name': 'Portal User'}
        return request.env['res.users'].write(values)
""",
        encoding="utf-8",
    )

    assert scan_identity_mutations(tmp_path) == []


def test_flags_comprehension_from_request_reaching_identity_write(tmp_path: Path) -> None:
    """Request-derived comprehensions should remain tainted before identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self, **kwargs):
        group_ids = [int(group_id) for group_id in kwargs.get('group_ids')]
        values = {'groups_id': [(6, 0, group_ids)]}
        return request.env['res.users'].browse(1).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_flags_starred_unpacked_identity_write(tmp_path: Path) -> None:
    """Starred identity aliases and values should remain visible before identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self, **kwargs):
        _, *items = (
            'fixed',
            request.env['res.users'].sudo().browse(1),
            {'groups_id': [(6, 0, kwargs.get('group_ids'))]},
        )
        user = items[0]
        values = items[1]
        return user.write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_flags_comprehension_filter_reaching_identity_write(tmp_path: Path) -> None:
    """Request-only comprehension filters should taint generated identity values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self, **kwargs):
        group_ids = [1 for _ in range(1) if kwargs.get('group_ids')]
        values = {'groups_id': [(6, 0, group_ids)]}
        return request.env['res.users'].browse(1).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_named_expression_reaching_identity_write_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request values should remain tainted before identity writes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self, **kwargs):
        if values := kwargs.get('values'):
            return request.env['res.users'].browse(1).write(values)
        return False
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(f.rule_id == "odoo-identity-request-derived-mutation" for f in findings)


def test_boolop_reaching_identity_write_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide identity write values."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/groups', auth='user', type='json')
    def update_groups(self, **kwargs):
        values = kwargs.get('values') or {'name': 'fallback'}
        return request.env['res.users'].browse(1).write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(f.rule_id == "odoo-identity-request-derived-mutation" for f in findings)


def test_flags_async_loop_value_reaching_identity_write(tmp_path: Path) -> None:
    """Async loop targets derived from request data should be treated as tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/users/update', auth='user', type='json')
    async def update_user(self, **kwargs):
        async for value in kwargs.get('values'):
            return request.env['res.users'].browse(1).write({'name': value})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(f.rule_id == "odoo-identity-request-derived-mutation" for f in findings)


def test_flags_route_path_id_identity_write_as_request_derived(tmp_path: Path) -> None:
    """Route IDs selecting identity records or companies are request-derived."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "users.py").write_text(
        """
from odoo import http
from odoo.http import request

class Users(http.Controller):
    @http.route('/public/users/<int:user_id>/company/<int:company_id>', auth='public', type='http')
    def assign_company(self, user_id, company_id):
        user = request.env['res.users'].sudo().browse(user_id)
        return user.write({'company_ids': [(4, company_id)]})
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-public-route-mutation" in rule_ids
    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-request-derived-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_flags_group_implied_ids_write_through_alias(tmp_path: Path) -> None:
    """Group implication changes are privilege boundary changes."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "group_sync.py").write_text(
        """
from odoo import models

class GroupSync(models.Model):
    _name = 'x.group.sync'

    def sync(self):
        group = self.env['res.groups'].with_user(self.env.ref('base.user_admin'))
        values = {'implied_ids': [(4, self.env.ref('base.group_system').id)]}
        group.write(values)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-identity-elevated-mutation" in rule_ids
    assert "odoo-identity-privilege-field-write" in rule_ids


def test_constant_privilege_values_direct_write_is_reported(tmp_path: Path) -> None:
    """Module constant value dictionaries should still expose privilege fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "group_sync.py").write_text(
        """
from odoo import models

VALUES = {'implied_ids': []}

class GroupSync(models.Model):
    _name = 'x.group.sync'

    def sync(self):
        return self.env['res.groups'].write(VALUES)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_class_constant_privilege_values_direct_write_is_reported(tmp_path: Path) -> None:
    """Class-scoped value dictionaries should still expose privilege fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "group_sync.py").write_text(
        """
from odoo import models

class GroupSync(models.Model):
    _name = 'x.group.sync'
    VALUES = {'implied_ids': []}

    def sync(self):
        return self.env['res.groups'].write(VALUES)
""",
        encoding="utf-8",
    )

    findings = scan_identity_mutations(tmp_path)

    assert any(finding.rule_id == "odoo-identity-privilege-field-write" for finding in findings)


def test_reassigned_identity_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing an identity-model variable should clear prior model/elevation state."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import models

class Users(models.Model):
    _name = 'x.users'

    def sync(self):
        user = self.env['res.users'].sudo()
        user = object()
        user.write({'groups_id': []})
""",
        encoding="utf-8",
    )

    assert scan_identity_mutations(tmp_path) == []


def test_reassigned_privilege_values_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing values for safe fields should clear remembered privilege keys."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "group_sync.py").write_text(
        """
from odoo import models

class GroupSync(models.Model):
    _name = 'x.group.sync'

    def sync(self):
        group = self.env['res.groups']
        field_map = {'implied_ids': [(4, self.env.ref('base.group_system').id)]}
        field_map = {'name': 'Portal'}
        group.write(field_map)
""",
        encoding="utf-8",
    )

    assert scan_identity_mutations(tmp_path) == []


def test_non_identity_model_write_is_ignored(tmp_path: Path) -> None:
    """Normal model writes should be left to other scanners."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class PartnerTool(models.Model):
    _name = 'x.partner.tool'

    def sync(self):
        return self.env['res.partner'].sudo().write({'active': False})
""",
        encoding="utf-8",
    )

    assert scan_identity_mutations(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_users.py").write_text(
        """
def test_promote(request):
    request.env['res.users'].sudo().write({'groups_id': []})
""",
        encoding="utf-8",
    )

    assert scan_identity_mutations(tmp_path) == []
