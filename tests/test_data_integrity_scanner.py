"""Tests for XML data/external-ID integrity scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.data_integrity_scanner import scan_data_integrity


def test_xml_entities_are_not_expanded_into_data_integrity_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize core XML ID integrity findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "entity.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY core_xmlid "base.group_system">
]>
<odoo>
  <record id="&core_xmlid;" model="res.groups"/>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_data_integrity(tmp_path) == []


def test_flags_core_xmlid_override(tmp_path: Path) -> None:
    """Records that target core module XML IDs should be review leads."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "override.xml").write_text(
        """<odoo>
  <record id="base.group_system" model="res.groups">
    <field name="name">System Override</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)

    assert any(f.rule_id == "odoo-data-core-xmlid-override" for f in findings)


def test_flags_sensitive_noupdate_records(tmp_path: Path) -> None:
    """Security-relevant records under noupdate can miss future fixes."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "security.xml").write_text(
        """<odoo>
  <data noupdate="1">
    <record id="rule_sale" model="ir.rule">
      <field name="name">Sale Rule</field>
    </record>
  </data>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)

    assert any(f.rule_id == "odoo-data-sensitive-noupdate-record" for f in findings)


def test_flags_forcecreate_false_and_manual_ir_model_data(tmp_path: Path) -> None:
    """Manual XML ID writes and forcecreate=False should be visible."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "xmlids.xml").write_text(
        """<odoo>
  <record id="missing_acl" model="ir.model.access" forcecreate="False">
    <field name="name">Missing ACL</field>
  </record>
  <record id="manual_xmlid" model="ir.model.data">
    <field name="module">base</field>
    <field name="name">group_system</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-forcecreate-disabled" in rule_ids
    assert "odoo-data-manual-ir-model-data" in rule_ids


def test_flags_sensitive_delete_and_core_xmlid_delete(tmp_path: Path) -> None:
    """XML deletes of security data or core XML IDs should be review leads."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "delete.xml").write_text(
        """<odoo>
  <delete id="base.default_user" model="res.users"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-sensitive-delete" in rule_ids
    assert "odoo-data-core-xmlid-delete" in rule_ids


def test_flags_sensitive_search_delete_under_noupdate(tmp_path: Path) -> None:
    """Search deletes on sensitive models are brittle across versions and installs."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "delete.xml").write_text(
        """<odoo>
  <data noupdate="1">
    <delete model="ir.rule" search="[('model_id.model', '=', 'res.partner')]"/>
  </data>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-sensitive-delete" in rule_ids
    assert "odoo-data-sensitive-search-delete" in rule_ids
    assert "odoo-data-sensitive-noupdate-delete" in rule_ids


def test_flags_payment_transaction_search_delete(tmp_path: Path) -> None:
    """Payment transaction XML deletes should be treated as sensitive data changes."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "delete_payment.xml").write_text(
        """<odoo>
  <delete model="payment.transaction" search="[('state', '=', 'draft')]"/>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-sensitive-delete" in rule_ids
    assert "odoo-data-sensitive-search-delete" in rule_ids


def test_flags_sensitive_function_mutation_under_noupdate(tmp_path: Path) -> None:
    """XML functions can mutate sensitive records during install/update."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "functions.xml").write_text(
        """<odoo>
  <data noupdate="1">
    <function model="res.groups" name="write" eval="([ref('base.group_portal')], {'implied_ids': [(4, ref('base.group_user'))]})"/>
  </data>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-sensitive-function-mutation" in rule_ids
    assert "odoo-data-sensitive-noupdate-function" in rule_ids


def test_flags_attachment_function_mutation_under_noupdate(tmp_path: Path) -> None:
    """Attachment XML functions can silently expose or rebind files during updates."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "attachments.xml").write_text(
        """<odoo>
  <data noupdate="1">
    <function model="ir.attachment" name="write" eval="([ref('module.private_attachment')], {'public': True})"/>
  </data>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_data_integrity(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-data-sensitive-function-mutation" in rule_ids
    assert "odoo-data-sensitive-noupdate-function" in rule_ids


def test_safe_module_data_is_ignored(tmp_path: Path) -> None:
    """Normal module-owned data should not produce integrity findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "records.xml").write_text(
        """<odoo>
  <record id="module_task_stage" model="project.task.type">
    <field name="name">New</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_data_integrity(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """XML fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "override.xml").write_text(
        """<odoo><record id="base.group_system" model="res.groups"/></odoo>""",
        encoding="utf-8",
    )

    assert scan_data_integrity(tmp_path) == []
