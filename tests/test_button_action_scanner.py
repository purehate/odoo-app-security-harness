"""Tests for Odoo button/action method scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.button_action_scanner import scan_button_actions


def test_flags_sudo_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Button methods that sudo-write should be review leads."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        self.env['sale.order'].sudo().write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_direct_model_base_button_action(tmp_path: Path) -> None:
    """Direct Model bases should not hide button-action mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo.models import Model

class Sale(Model):
    _name = 'x.sale'

    def action_approve(self):
        self.env['sale.order'].sudo().write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_aliased_sudo_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Sudo recordset aliases inside button methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        orders = self.env['sale.order'].sudo()
        orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_with_user_superuser_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """SUPERUSER_ID elevation in button methods should be treated like sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        self.env['sale.order'].with_user(SUPERUSER_ID).write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_keyword_with_user_superuser_mutation_and_missing_access_check(
    tmp_path: Path,
) -> None:
    """Keyword with_user(user=SUPERUSER_ID) button mutations are elevated."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        self.env['sale.order'].with_user(user=SUPERUSER_ID).write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_aliased_with_user_one_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Aliases elevated with user id 1 should be treated like sudo aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        orders = self.env['sale.order'].with_user(1)
        orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_constant_backed_with_user_mutation_and_model_name(tmp_path: Path) -> None:
    """Constant-backed model names and superuser IDs should not hide sudo mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

SALE_MODEL = 'x.sale'
ROOT_UID = 1
STATE_FIELD = 'state'
APPROVED = 'approved'

class Sale(models.Model):
    _name = SALE_MODEL

    def action_approve(self):
        orders = self.env['sale.order'].with_user(ROOT_UID)
        orders.write({STATE_FIELD: APPROVED})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-sensitive-state-write" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids
    assert any(f.model == "x.sale" for f in findings)


def test_flags_recursive_constant_button_state_and_superuser_mutation(tmp_path: Path) -> None:
    """Recursive constant-backed states and superuser IDs should still be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

SALE_MODEL = 'x.sale'
MODEL_ALIAS = SALE_MODEL
ROOT_UID = 1
ADMIN_UID = ROOT_UID
STATE_FIELD = 'state'
STATE_ALIAS = STATE_FIELD
APPROVED = 'approved'
APPROVED_ALIAS = APPROVED

class Sale(models.Model):
    _name = MODEL_ALIAS

    def action_approve(self):
        orders = self.env['sale.order'].with_user(ADMIN_UID)
        orders.write({STATE_ALIAS: APPROVED_ALIAS})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-sensitive-state-write" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids
    assert any(f.model == "x.sale" for f in findings)


def test_flags_env_ref_admin_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Aliases elevated with base.user_admin should be treated like sudo aliases."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        orders = self.env['sale.order'].with_user(self.env.ref('base.user_admin'))
        orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_tuple_unpacked_sudo_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Tuple-unpacked sudo aliases inside button methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        orders, label = self.env['sale.order'].sudo(), self.name
        orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_named_expression_sudo_mutation_and_missing_access_check(tmp_path: Path) -> None:
    """Walrus-assigned sudo aliases inside button methods should be recognized."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        if orders := self.env['sale.order'].sudo():
            orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_starred_tuple_sudo_alias_mutation(tmp_path: Path) -> None:
    """Starred tuple targets should preserve sudo alias tracking."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        *orders, label = self.env['sale.order'].sudo(), self.name
        return orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_flags_starred_rest_sudo_alias_mutation(tmp_path: Path) -> None:
    """Starred-rest targets should preserve sudo aliases inside collected values."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        label, *items = self.name, self.env['sale.order'].sudo(), self.partner_id
        orders = items[0]
        orders.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sudo-mutation" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" in rule_ids


def test_mixed_tuple_sudo_alias_does_not_overtaint_button_action(tmp_path: Path) -> None:
    """Mixed tuple assignments should not mark non-sudo button neighbors."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        orders, partner = self.env['sale.order'].sudo(), self.partner_id
        partner.write({'comment': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    assert not any(f.rule_id == "odoo-button-action-sudo-mutation" for f in findings)


def test_flags_sensitive_state_write(tmp_path: Path) -> None:
    """Workflow state changes deserve review even without sudo."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "invoice.py").write_text(
        """
from odoo import models

class Invoice(models.Model):
    _name = 'x.invoice'

    def button_post(self):
        self.write({'state': 'posted'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    assert any(f.rule_id == "odoo-button-action-sensitive-state-write" for f in findings)


def test_flags_sensitive_model_mutation(tmp_path: Path) -> None:
    """Object buttons mutating security/payment/config models should be reviewed."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

class Settings(models.Model):
    _name = 'x.settings'

    def action_rotate_access(self):
        self.env['res.users'].write({'active': False})
        self.env['ir.config_parameter'].set_param('auth_signup.invitation_scope', 'b2c')
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    sensitive_findings = [
        finding for finding in findings if finding.rule_id == "odoo-button-action-sensitive-model-mutation"
    ]
    assert len(sensitive_findings) == 2
    assert {finding.severity for finding in sensitive_findings} == {"high"}


def test_flags_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """Constant-backed env model names should still flag security model mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

USERS_MODEL = 'res.users'
CONFIG_MODEL = 'ir.config_parameter'

class Settings(models.Model):
    _name = 'x.settings'

    def action_rotate_access(self):
        self.env[USERS_MODEL].write({'active': False})
        self.env[CONFIG_MODEL].set_param('auth_signup.invitation_scope', 'b2c')
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    assert len(
        [finding for finding in findings if finding.rule_id == "odoo-button-action-sensitive-model-mutation"]
    ) == 2


def test_flags_recursive_constant_sensitive_model_mutation(tmp_path: Path) -> None:
    """Recursive constant-backed env model names should still flag sensitive mutations."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "settings.py").write_text(
        """
from odoo import models

USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL

class Settings(models.Model):
    _name = 'x.settings'

    def action_rotate_access(self):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    assert any(f.rule_id == "odoo-button-action-sensitive-model-mutation" for f in findings)


def test_flags_unlink_without_access_check(tmp_path: Path) -> None:
    """Button methods deleting records should show explicit access checks."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "cleanup.py").write_text(
        """
from odoo import models

class Cleanup(models.Model):
    _name = 'x.cleanup'

    def action_delete(self):
        self.unlink()
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)

    assert any(f.rule_id == "odoo-button-action-unlink-no-access-check" for f in findings)


def test_access_checked_action_is_lower_noise(tmp_path: Path) -> None:
    """Visible access/group checks should suppress missing-access findings."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "sale.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    _name = 'x.sale'

    def action_approve(self):
        self.check_access_rights('write')
        self.write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    findings = scan_button_actions(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-button-action-sensitive-state-write" in rule_ids
    assert "odoo-button-action-mutation-no-access-check" not in rule_ids


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Button/action fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_button.py").write_text(
        """
from odoo import models

class Sale(models.Model):
    def action_approve(self):
        self.sudo().write({'state': 'approved'})
""",
        encoding="utf-8",
    )

    assert scan_button_actions(tmp_path) == []
