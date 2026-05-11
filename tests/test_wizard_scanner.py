"""Tests for Odoo TransientModel wizard scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.wizard_scanner import scan_wizards


def test_flags_wizard_binary_field_and_upload_parser(tmp_path: Path) -> None:
    """Binary import fields and parser calls in wizards should be review-visible."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "import.py").write_text(
        """
import base64
from odoo import fields, models

class ImportWizard(models.TransientModel):
    _name = 'import.wizard'
    upload = fields.Binary()

    def action_import(self):
        return base64.b64decode(self.upload)
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-binary-import-field" in rule_ids
    assert "odoo-wizard-upload-parser" in rule_ids


def test_flags_direct_transient_model_base_wizard_binary_field(tmp_path: Path) -> None:
    """Direct TransientModel bases should not hide wizard findings."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "import.py").write_text(
        """
from odoo import fields
from odoo.models import TransientModel

class ImportWizard(TransientModel):
    _name = 'import.wizard'
    upload = fields.Binary()
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-binary-import-field" for f in findings)


def test_flags_long_transient_retention(tmp_path: Path) -> None:
    """Long-lived wizard records should be review-visible."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_hours = 48
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" for f in findings)


def test_flags_constant_backed_disabled_transient_age_retention(tmp_path: Path) -> None:
    """Constant-backed unlimited age retention should not hide wizard review leads."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

RETENTION_HOURS = 0

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_hours = RETENTION_HOURS
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" for f in findings)


def test_flags_recursive_constant_backed_disabled_transient_age_retention(tmp_path: Path) -> None:
    """Chained unlimited age retention constants should not hide wizard review leads."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

DISABLED_RETENTION = 0
RETENTION_HOURS = DISABLED_RETENTION

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_hours = RETENTION_HOURS
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" for f in findings)


def test_flags_class_constant_backed_disabled_transient_age_retention(tmp_path: Path) -> None:
    """Class-scoped unlimited age retention constants should not hide wizard review leads."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

class RetentionWizard(models.TransientModel):
    MODEL_NAME = 'retention.wizard'
    DISABLED_RETENTION = 0
    RETENTION_HOURS = DISABLED_RETENTION
    _name = MODEL_NAME
    _transient_max_hours = RETENTION_HOURS
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" and f.model == "retention.wizard" for f in findings)


def test_flags_constant_backed_disabled_transient_count_retention(tmp_path: Path) -> None:
    """Constant-backed unlimited count retention should not hide wizard review leads."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

RETENTION_COUNT = 0

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_count = RETENTION_COUNT
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" for f in findings)


def test_flags_large_transient_count_retention(tmp_path: Path) -> None:
    """Very high wizard row retention should be review-visible."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_count = 50000
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-long-transient-retention" for f in findings)


def test_short_transient_retention_is_ignored(tmp_path: Path) -> None:
    """Ordinary short wizard retention should not produce noise."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_hours = 2
""",
        encoding="utf-8",
    )

    assert scan_wizards(tmp_path) == []


def test_short_transient_count_retention_is_ignored(tmp_path: Path) -> None:
    """Ordinary bounded wizard row retention should not produce noise."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "retention.py").write_text(
        """
from odoo import models

class RetentionWizard(models.TransientModel):
    _name = 'retention.wizard'
    _transient_max_count = 1000
""",
        encoding="utf-8",
    )

    assert scan_wizards(tmp_path) == []


def test_flags_active_ids_sudo_bulk_mutation(tmp_path: Path) -> None:
    """Wizards mutating active_ids through sudo are high-signal findings."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.wizard'

    def action_apply(self):
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        records.sudo().write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_sudo_alias_active_ids_mutation(tmp_path: Path) -> None:
    """Sudo record aliases should still count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_alias.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.alias.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated = records.sudo()
        return elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_named_expression_sudo_alias_active_ids_mutation(tmp_path: Path) -> None:
    """Walrus-bound sudo aliases should still count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_alias.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.alias.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        if elevated := records.sudo():
            return elevated.write({'state': 'done'})
        return False
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_active_id_sudo_mutation(tmp_path: Path) -> None:
    """Single active_id wizard flows should be treated as selected-record mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_single.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.single.wizard'

    def action_apply(self):
        active_id = self.env.context.get('active_id')
        record = self.env['sale.order'].browse(active_id)
        return record.sudo().write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_search_count_active_ids_does_not_mark_recordset(tmp_path: Path) -> None:
    """Counting active_ids should not be treated as a mutable selected recordset."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "count_orders.py").write_text(
        """
from odoo import models

class CountOrdersWizard(models.TransientModel):
    _name = 'count.orders.wizard'

    def action_count(self):
        active_ids = self.env.context.get('active_ids')
        count = self.env['sale.order'].search_count([('id', 'in', active_ids)])
        return {'count': count}
""",
        encoding="utf-8",
    )

    assert scan_wizards(tmp_path) == []


def test_flags_active_ids_superuser_mutation(tmp_path: Path) -> None:
    """Wizards mutating active_ids through with_user(SUPERUSER_ID) are privileged."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_superuser.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class ApproveWizard(models.TransientModel):
    _name = 'approve.superuser.wizard'

    def action_apply(self):
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        return records.with_user(SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_active_ids_import_aliased_superuser_mutation(tmp_path: Path) -> None:
    """Wizards mutating active_ids through imported SUPERUSER_ID aliases are privileged."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_superuser.py").write_text(
        """
from odoo import SUPERUSER_ID as ROOT_UID, models

class ApproveWizard(models.TransientModel):
    _name = 'approve.superuser.wizard'

    def action_apply(self):
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        return records.with_user(ROOT_UID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_keyword_active_ids_superuser_mutation(tmp_path: Path) -> None:
    """Wizards mutating active_ids through keyword with_user are privileged."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_superuser.py").write_text(
        """
from odoo import SUPERUSER_ID, models

class ApproveWizard(models.TransientModel):
    _name = 'approve.superuser.wizard'

    def action_apply(self):
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        return records.with_user(user=SUPERUSER_ID).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_tuple_unpacked_sudo_alias_mutation(tmp_path: Path) -> None:
    """Tuple-unpacked sudo record aliases should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_tuple_sudo.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.tuple.sudo.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated, note = records.sudo(), self.note
        return elevated.write({'note': note})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_env_ref_root_active_ids_mutation(tmp_path: Path) -> None:
    """Root XML-ID with_user calls should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_root.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.root.wizard'

    def action_apply(self):
        records = self.env['sale.order'].browse(self.env.context.get('active_ids'))
        return records.with_user(self.env.ref('base.user_root')).write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_aliased_superuser_mutation(tmp_path: Path) -> None:
    """with_user(1) record aliases should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_alias_superuser.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.alias.superuser.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated = records.with_user(1)
        return elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_recursive_constant_superuser_mutation(tmp_path: Path) -> None:
    """Chained superuser ID constants should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_alias_superuser.py").write_text(
        """
from odoo import models

ROOT_UID = 1
ADMIN_UID = ROOT_UID

class ApproveWizard(models.TransientModel):
    _name = 'approve.alias.superuser.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated = records.with_user(ADMIN_UID)
        return elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_class_constant_superuser_mutation(tmp_path: Path) -> None:
    """Class-scoped superuser ID constants should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_alias_superuser.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    MODEL_NAME = 'approve.alias.superuser.wizard'
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID
    _name = MODEL_NAME

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated = records.with_user(ADMIN_UID)
        return elevated.write({'state': 'done'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids
    assert any(f.model == "approve.alias.superuser.wizard" for f in findings)


def test_flags_starred_rest_sudo_alias_mutation(tmp_path: Path) -> None:
    """Starred-rest sudo record aliases should count as privileged wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_starred_sudo.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.starred.sudo.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        marker, *items, tail = 'x', records.sudo(), self.note, 'end'
        elevated = items[0]
        return elevated.write({'note': self.note})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sudo-mutation" in rule_ids
    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_mixed_tuple_sudo_alias_does_not_overtaint_wizard(tmp_path: Path) -> None:
    """Mixed tuple assignments should not mark non-sudo wizard neighbors."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_mixed_sudo.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.mixed.sudo.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        records = self.env['sale.order'].browse(active_ids)
        elevated, partner = records.sudo(), self.partner_id
        return partner.write({'comment': 'x'})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert not any(f.rule_id == "odoo-wizard-sudo-mutation" for f in findings)


def test_flags_tuple_unpacked_active_ids_mutation(tmp_path: Path) -> None:
    """Recordsets unpacked from active_ids should still be recognized."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "approve_tuple.py").write_text(
        """
from odoo import models

class ApproveWizard(models.TransientModel):
    _name = 'approve.tuple.wizard'

    def action_apply(self):
        active_ids = self.env.context.get('active_ids')
        orders, note = self.env['sale.order'].browse(active_ids), self.note
        return orders.write({'note': note})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-active-ids-bulk-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_sensitive_model_mutation(tmp_path: Path) -> None:
    """Wizards mutating identity/config models should be review-visible."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "config.py").write_text(
        """
from odoo import models

class ConfigWizard(models.TransientModel):
    _name = 'config.wizard'

    def action_apply(self):
        self.env['res.users'].write({'active': False})
        self.env['ir.config_parameter'].set_param('auth_signup.invitation_scope', 'b2c')
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    sensitive_findings = [finding for finding in findings if finding.rule_id == "odoo-wizard-sensitive-model-mutation"]
    assert len(sensitive_findings) == 2
    assert {finding.severity for finding in sensitive_findings} == {"high"}
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """Chained env model-name constants should still reveal sensitive wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "config.py").write_text(
        """
from odoo import models

USERS_MODEL = 'res.users'
TARGET_MODEL = USERS_MODEL

class ConfigWizard(models.TransientModel):
    _name = 'config.wizard'

    def action_apply(self):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sensitive-model-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids


def test_flags_class_constant_backed_sensitive_model_mutation(tmp_path: Path) -> None:
    """Class-scoped env model-name constants should still reveal sensitive wizard mutations."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "config.py").write_text(
        """
from odoo import models

class ConfigWizard(models.TransientModel):
    MODEL_NAME = 'config.wizard'
    USERS_MODEL = 'res.users'
    TARGET_MODEL = USERS_MODEL
    _name = MODEL_NAME

    def action_apply(self):
        self.env[TARGET_MODEL].write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-sensitive-model-mutation" in rule_ids
    assert "odoo-wizard-mutation-no-access-check" in rule_ids
    assert any(f.model == "config.wizard" for f in findings)


def test_flags_upload_parser_aliases(tmp_path: Path) -> None:
    """Parser imports and module aliases should not hide uploaded file parsing."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "import_alias.py").write_text(
        """
from base64 import b64decode
import openpyxl as oxl
from odoo import fields, models

class ImportWizard(models.TransientModel):
    _name = 'import.alias.wizard'
    upload = fields.Binary()

    def action_import(self):
        data = b64decode(self.upload)
        return oxl.load_workbook(data)
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    parser_findings = [finding for finding in findings if finding.rule_id == "odoo-wizard-upload-parser"]

    assert len(parser_findings) == 2
    assert any(f.rule_id == "odoo-wizard-upload-parser-no-size-check" for f in findings)


def test_upload_parser_with_size_check_is_not_reported_as_unguarded(tmp_path: Path) -> None:
    """Visible upload size checks should suppress the parser size-guard finding."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "import_size.py").write_text(
        """
import base64
from odoo import fields, models

class ImportWizard(models.TransientModel):
    _name = 'import.size.wizard'
    upload = fields.Binary()

    def action_import(self):
        if len(self.upload or b'') > 2_000_000:
            raise ValueError('too large')
        return base64.b64decode(self.upload)
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-wizard-upload-parser" in rule_ids
    assert "odoo-wizard-upload-parser-no-size-check" not in rule_ids


def test_flags_dynamic_active_model(tmp_path: Path) -> None:
    """active_model-based env access should be constrained to safe models."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "dynamic.py").write_text(
        """
from odoo import models

class DynamicWizard(models.TransientModel):
    _name = 'dynamic.wizard'

    def action_apply(self):
        model = self.env.context.get('active_model')
        return self.env[model].browse(self.env.context.get('active_ids')).write({'active': False})
""",
        encoding="utf-8",
    )

    findings = scan_wizards(tmp_path)

    assert any(f.rule_id == "odoo-wizard-dynamic-active-model" for f in findings)


def test_safe_wizard_is_ignored(tmp_path: Path) -> None:
    """Read-only TransientModel helpers should not produce findings."""
    wizards = tmp_path / "module" / "wizards"
    wizards.mkdir(parents=True)
    (wizards / "safe.py").write_text(
        """
from odoo import models

class SafeWizard(models.TransientModel):
    _name = 'safe.wizard'

    def action_open(self):
        return {'type': 'ir.actions.act_window_close'}
""",
        encoding="utf-8",
    )

    assert scan_wizards(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Wizard fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_wizard.py").write_text(
        """
class ImportWizard(models.TransientModel):
    upload = fields.Binary()
""",
        encoding="utf-8",
    )

    assert scan_wizards(tmp_path) == []
