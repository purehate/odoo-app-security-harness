"""Tests for Odoo ORM context override scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.orm_context_scanner import scan_orm_context


def test_flags_active_test_disabled_and_sudo_read(tmp_path: Path) -> None:
    """Python-side active_test=False should be visible to reviewers."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        return self.env['sale.order'].sudo().with_context(active_test=False).search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_active_test_disabled_sudo_search_count(tmp_path: Path) -> None:
    """Privileged archived-record counts should be treated as read exposure."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_order_count(self):
        return self.env['sale.order'].sudo().with_context(active_test=False).search_count([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_aliased_active_test_disabled_and_sudo_read(tmp_path: Path) -> None:
    """Context and sudo posture should survive local recordset aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        Orders = self.env['sale.order'].sudo().with_context(active_test=False)
        return Orders.search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_with_user_superuser_active_test_read(tmp_path: Path) -> None:
    """Superuser with_user reads should be treated like sudo active_test reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        return self.env['sale.order'].with_user(SUPERUSER_ID).with_context(active_test=False).search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_constant_backed_with_user_active_test_read(tmp_path: Path) -> None:
    """Constants should not hide superuser active_test reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

ROOT_UID = 1
INCLUDE_ARCHIVED = False

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        return self.env['sale.order'].with_user(ROOT_UID).with_context(active_test=INCLUDE_ARCHIVED).search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_recursive_constant_with_user_active_test_read(tmp_path: Path) -> None:
    """Recursive constants should not hide superuser active_test reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

ROOT_UID = 1
ADMIN_UID = ROOT_UID
INCLUDE_ARCHIVED = False
ACTIVE_TEST = INCLUDE_ARCHIVED

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        return self.env['sale.order'].with_user(ADMIN_UID).with_context(active_test=ACTIVE_TEST).search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_class_constant_with_user_active_test_read(tmp_path: Path) -> None:
    """Class-level constants should not hide superuser active_test reads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    ROOT_UID = 1
    ADMIN_UID = ROOT_UID
    INCLUDE_ARCHIVED = False
    ACTIVE_TEST = INCLUDE_ARCHIVED

    def archived_orders(self):
        return self.env['sale.order'].with_user(ADMIN_UID).with_context(active_test=ACTIVE_TEST).search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_aliased_with_user_one_active_test_read(tmp_path: Path) -> None:
    """Aliased with_user(1) recordsets should preserve privileged read posture."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        Orders = self.env['sale.order'].with_user(1).with_context(active_test=False)
        return Orders.search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_env_ref_admin_active_test_read(tmp_path: Path) -> None:
    """with_user(base.user_admin) active_test reads should be treated like sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def archived_orders(self):
        Orders = self.env['sale.order'].with_user(self.env.ref('base.user_admin')).with_context(active_test=False)
        return Orders.search([])
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-active-test-disabled" in rule_ids
    assert "odoo-orm-context-sudo-active-test-read" in rule_ids


def test_flags_tracking_disabled_mutation_from_dict_context(tmp_path: Path) -> None:
    """Audit/chatter suppression around writes should be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        return self.with_context({'tracking_disable': True, 'mail_create_nosubscribe': True}).write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_aliased_tracking_disabled_mutation(tmp_path: Path) -> None:
    """Tracking suppression should not disappear when the recordset is aliased."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        partners = self.with_context(tracking_disable=True)
        return partners.write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_context_dict_alias_tracking_disabled_mutation(tmp_path: Path) -> None:
    """Local context dictionaries should preserve risky flags through with_context."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        ctx = {'tracking_disable': True}
        return self.with_context(ctx).write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_constant_backed_context_dict_tracking_disabled_mutation(tmp_path: Path) -> None:
    """Constants in context dictionaries should preserve risky flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

TRACKING_FLAG = 'tracking_disable'
ENABLED = True

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        ctx = {TRACKING_FLAG: ENABLED}
        return self.with_context(ctx).write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_recursive_constant_context_dict_tracking_disabled_mutation(tmp_path: Path) -> None:
    """Recursive module-level context dictionaries should preserve risky flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

TRACKING_FLAG = 'tracking_disable'
FLAG_ALIAS = TRACKING_FLAG
ENABLED = True
ENABLED_ALIAS = ENABLED
QUIET_CONTEXT = {FLAG_ALIAS: ENABLED_ALIAS}
CONTEXT_ALIAS = QUIET_CONTEXT

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        return self.with_context(CONTEXT_ALIAS).write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_context_dict_alias_used_as_kwargs(tmp_path: Path) -> None:
    """with_context(**ctx) should be equivalent to an inline keyword context."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        ctx = {'no_reset_password': True}
        return self.with_context(**ctx).write({'name': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-notification-disabled-mutation" for f in findings)


def test_flags_context_dict_named_expression_tracking_disabled_mutation(tmp_path: Path) -> None:
    """Walrus-assigned context dictionaries should preserve risky flags."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "partner.py").write_text(
        """
from odoo import models

class Partner(models.Model):
    _name = 'x.partner'

    def quiet_update(self):
        if ctx := {'tracking_disable': True}:
            return self.with_context(ctx).write({'name': 'x'})
        return False
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-tracking-disabled-mutation" for f in findings)


def test_flags_notification_disabled_mutation(tmp_path: Path) -> None:
    """User/account notification suppression should be surfaced."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "users.py").write_text(
        """
from odoo import models

class Users(models.Model):
    _inherit = 'res.users'

    def create_user(self, values):
        return self.with_context(no_reset_password=True).create(values)
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-notification-disabled-mutation" for f in findings)


def test_flags_privileged_context_on_mutation(tmp_path: Path) -> None:
    """Install/uninstall context flags around mutations can bypass normal safeguards."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def purge(self):
        self.env['ir.model.data'].with_context(module_uninstall=True).unlink()
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-privileged-mode" in rule_ids
    assert "odoo-orm-context-privileged-mode-mutation" in rule_ids


def test_flags_privileged_default_context_on_create(tmp_path: Path) -> None:
    """Context defaults can silently seed ownership, visibility, or group fields."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "invite.py").write_text(
        """
from odoo import models

class Invite(models.Model):
    _name = 'x.invite'

    def invite_admin(self):
        return self.env['res.users'].with_context(
            default_groups_id=[(4, self.env.ref('base.group_system').id)],
            default_company_id=self.env.company.id,
        ).create({'name': 'Admin'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-orm-context-privileged-default" in rule_ids
    assert "odoo-orm-context-privileged-default-mutation" in rule_ids
    assert {"default_groups_id", "default_company_id"} <= flags


def test_flags_request_update_context_risky_flags(tmp_path: Path) -> None:
    """request.update_context should be treated as request-wide context mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/quiet-admin', auth='user')
    def quiet_admin(self):
        request.update_context(
            active_test=False,
            tracking_disable=True,
            default_groups_id=[(4, request.env.ref('base.group_system').id)],
            module_uninstall=True,
        )
        return request.env['res.users'].create({'name': 'Admin'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    flags = {finding.flag for finding in findings}

    assert "odoo-orm-context-request-active-test-disabled" in rule_ids
    assert "odoo-orm-context-request-tracking-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids
    assert "odoo-orm-context-request-privileged-default" in rule_ids
    assert {"active_test", "tracking_disable", "module_uninstall", "default_groups_id"} <= flags


def test_flags_request_update_context_constant_values(tmp_path: Path) -> None:
    """request.update_context should resolve simple boolean constants."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

DISABLED = False
ENABLED = True

class Controller(http.Controller):
    @http.route('/quiet-admin', auth='user')
    def quiet_admin(self):
        request.update_context(active_test=DISABLED, module_uninstall=ENABLED)
        return request.env['res.users'].create({'name': 'Admin'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-request-active-test-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids


def test_flags_request_update_context_recursive_constant_dict(tmp_path: Path) -> None:
    """request.update_context should resolve recursive module-level context dictionaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

ACTIVE_KEY = 'active_test'
ACTIVE_ALIAS = ACTIVE_KEY
DISABLED = False
DISABLED_ALIAS = DISABLED
MODULE_KEY = 'module_uninstall'
MODULE_ALIAS = MODULE_KEY
ENABLED = True
ENABLED_ALIAS = ENABLED
REQUEST_CONTEXT = {ACTIVE_ALIAS: DISABLED_ALIAS, MODULE_ALIAS: ENABLED_ALIAS}
CONTEXT_ALIAS = REQUEST_CONTEXT

class Controller(http.Controller):
    @http.route('/quiet-admin', auth='user')
    def quiet_admin(self):
        request.update_context(CONTEXT_ALIAS)
        return request.env['res.users'].create({'name': 'Admin'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-request-active-test-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids


def test_flags_request_update_context_class_constant_dict(tmp_path: Path) -> None:
    """request.update_context should resolve recursive class-level context dictionaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    ACTIVE_KEY = 'active_test'
    ACTIVE_ALIAS = ACTIVE_KEY
    DISABLED = False
    DISABLED_ALIAS = DISABLED
    MODULE_KEY = 'module_uninstall'
    MODULE_ALIAS = MODULE_KEY
    ENABLED = True
    ENABLED_ALIAS = ENABLED
    REQUEST_CONTEXT = {ACTIVE_ALIAS: DISABLED_ALIAS, MODULE_ALIAS: ENABLED_ALIAS}
    CONTEXT_ALIAS = REQUEST_CONTEXT

    @http.route('/quiet-admin', auth='user')
    def quiet_admin(self):
        request.update_context(CONTEXT_ALIAS)
        return request.env['res.users'].create({'name': 'Admin'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-request-active-test-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids


def test_flags_request_update_context_dict_flags(tmp_path: Path) -> None:
    """Dictionary-style request.update_context calls should expose notification suppression."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/reset', auth='user')
    def reset(self):
        request.update_context({'no_reset_password': True})
        return request.env['res.users'].create({'name': 'Quiet'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)

    assert any(f.rule_id == "odoo-orm-context-request-notification-disabled" for f in findings)


def test_flags_request_alias_update_context(tmp_path: Path) -> None:
    """Aliased Odoo request imports should still expose request-wide context mutation."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "main.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/quiet', auth='user')
    def quiet(self):
        req.update_context(tracking_disable=True, module_uninstall=True)
        return req.env['res.partner'].create({'name': 'Quiet'})
""",
        encoding="utf-8",
    )

    findings = scan_orm_context(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-orm-context-request-tracking-disabled" in rule_ids
    assert "odoo-orm-context-request-privileged-mode" in rule_ids


def test_safe_context_is_ignored(tmp_path: Path) -> None:
    """Benign context values should not be noisy."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "safe.py").write_text(
        """
from odoo import models

class Safe(models.Model):
    _name = 'x.safe'

    def renamed(self):
        return self.with_context(lang='fr_FR').write({'name': 'x'})
""",
        encoding="utf-8",
    )

    assert scan_orm_context(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_context.py").write_text(
        """
class Sale(models.Model):
    def archived_orders(self):
        return self.with_context(active_test=False).search([])
""",
        encoding="utf-8",
    )

    assert scan_orm_context(tmp_path) == []
