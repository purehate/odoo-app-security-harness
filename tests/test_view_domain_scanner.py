"""Tests for XML view/action domain and context scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.view_domain_scanner import scan_view_domains


def test_flags_active_test_disabled_and_company_context(tmp_path: Path) -> None:
    """View contexts can change record visibility and company scope."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "sale.xml").write_text(
        """<odoo>
  <record id="view_sale_tree" model="ir.ui.view">
    <field name="arch" type="xml">
      <tree>
        <field name="partner_id" context="{'active_test': False, 'allowed_company_ids': active_ids}"/>
      </tree>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-context-active-test-disabled" in rule_ids
    assert "odoo-view-context-user-company-scope" in rule_ids


def test_flags_dynamic_eval_and_default_groups_context(tmp_path: Path) -> None:
    """XML domain/context expressions should not evaluate code or default group assignment."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "users.xml").write_text(
        """<odoo>
  <record id="view_users_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="groups_id" domain="safe_eval(context.get('domain'))" context="{'default_groups_id': [(4, ref('base.group_system'))]}"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-domain-dynamic-eval" in rule_ids
    assert "odoo-view-context-default-groups" in rule_ids


def test_xml_entities_are_not_expanded_into_view_domain_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize privileged view context findings."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "users.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY privileged_context "{'default_groups_id': [(4, ref('base.group_system'))]}">
]>
<odoo>
  <record id="view_users_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="groups_id" context="&privileged_context;"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_view_domains(tmp_path) == []


def test_flags_privileged_default_context_keys(tmp_path: Path) -> None:
    """XML contexts can prefill sensitive defaults before create/write rules run."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "users.xml").write_text(
        """<odoo>
  <record id="view_users_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="partner_id" context="{'default_company_id': user.company_id.id, 'default_share': True}"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)

    assert any(f.rule_id == "odoo-view-context-privileged-default" for f in findings)


def test_flags_risky_framework_context_flags(tmp_path: Path) -> None:
    """XML contexts should highlight framework flags that suppress safeguards."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "moves.xml").write_text(
        """<odoo>
  <record id="view_move_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="line_ids" context="{'tracking_disable': True, 'module_uninstall': True, 'check_move_validity': False}"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)

    assert any(f.rule_id == "odoo-view-context-risky-framework-flag" for f in findings)


def test_flags_user_company_scope_context(tmp_path: Path) -> None:
    """User company helpers still need review when they drive explicit company context."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "company.xml").write_text(
        """<odoo>
  <record id="view_company_form" model="ir.ui.view">
    <field name="arch" type="xml">
      <form>
        <field name="partner_id" context="{'allowed_company_ids': user.company_ids.ids, 'force_company': user.company_id.id}"/>
      </form>
    </field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)

    assert any(f.rule_id == "odoo-view-context-user-company-scope" for f in findings)


def test_flags_sensitive_action_broad_domain_without_groups(tmp_path: Path) -> None:
    """Broad sensitive actions without groups should be visible review leads."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_partners" model="ir.actions.act_window">
    <field name="res_model">res.partner</field>
    <field name="domain">[]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)

    assert any(f.rule_id == "odoo-view-domain-sensitive-action-broad-domain" for f in findings)


def test_flags_sensitive_csv_action_broad_domain_without_groups(tmp_path: Path) -> None:
    """CSV act_window domains should feed the view-domain action checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_actions_act_window.csv").write_text(
        "id,res_model,domain,context\n"
        "action_partners,res.partner,[],\"{'active_test': False}\"\n",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-domain-sensitive-action-broad-domain" in rule_ids
    assert "odoo-view-context-active-test-disabled" in rule_ids


def test_grouped_sensitive_csv_action_broad_domain_is_ignored(tmp_path: Path) -> None:
    """Grouped CSV act_window records should not be broad-exposure findings."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir.actions.act_window.csv").write_text(
        "id,res_model,domain,groups_id/id\n"
        "action_partners,res.partner,[],base.group_user\n",
        encoding="utf-8",
    )

    assert scan_view_domains(tmp_path) == []


def test_empty_groups_eval_does_not_hide_sensitive_broad_action(tmp_path: Path) -> None:
    """Empty groups eval values still leave sensitive actions unrestricted."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_partners" model="ir.actions.act_window">
    <field name="res_model">res.partner</field>
    <field name="domain">[]</field>
    <field name="groups_id" eval="[]"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)

    assert any(f.rule_id == "odoo-view-domain-sensitive-action-broad-domain" for f in findings)


def test_sensitive_action_model_external_ids_are_normalized(tmp_path: Path) -> None:
    """Action res_model refs should normalize before sensitive-domain checks."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_params" model="ir.actions.act_window">
    <field name="res_model" ref="base.model_ir_config_parameter"/>
    <field name="domain">[]</field>
  </record>
  <record id="action_payment_provider" model="ir.actions.act_window">
    <field name="res_model" ref="payment.model_payment_provider"/>
    <field name="domain">[]</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    sensitive_actions = [
        finding for finding in findings if finding.rule_id == "odoo-view-domain-sensitive-action-broad-domain"
    ]

    assert len(sensitive_actions) == 2


def test_flags_global_sensitive_saved_filter(tmp_path: Path) -> None:
    """Global saved filters on sensitive models can affect broad search defaults."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "filters.xml").write_text(
        """<odoo>
  <record id="filter_all_partners" model="ir.filters">
    <field name="name">All partners</field>
    <field name="model_id">res.partner</field>
    <field name="domain">[]</field>
    <field name="context">{'active_test': False}</field>
    <field name="is_default">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-domain-global-sensitive-filter-broad-domain" in rule_ids
    assert "odoo-view-filter-global-default-sensitive" in rule_ids
    assert "odoo-view-domain-default-sensitive-filter" in rule_ids
    assert "odoo-view-context-active-test-disabled" in rule_ids


def test_flags_global_sensitive_saved_filter_in_csv(tmp_path: Path) -> None:
    """CSV ir.filters rows should feed global sensitive filter checks."""
    data = tmp_path / "module" / "data"
    data.mkdir(parents=True)
    (data / "ir_filters.csv").write_text(
        "id,name,model_id,domain,context,is_default,user_id\n"
        "filter_all_partners,All partners,res.partner,[],\"{'active_test': False}\",True,\n",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-domain-global-sensitive-filter-broad-domain" in rule_ids
    assert "odoo-view-filter-global-default-sensitive" in rule_ids
    assert "odoo-view-domain-default-sensitive-filter" in rule_ids
    assert "odoo-view-context-active-test-disabled" in rule_ids


def test_false_user_eval_is_treated_as_global_sensitive_filter(tmp_path: Path) -> None:
    """user_id eval=False means a saved filter is global, not user-scoped."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "filters.xml").write_text(
        """<odoo>
  <record id="filter_all_partners" model="ir.filters">
    <field name="name">All partners</field>
    <field name="model_id">res.partner</field>
    <field name="domain">[]</field>
    <field name="is_default">True</field>
    <field name="user_id" eval="False"/>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-domain-global-sensitive-filter-broad-domain" in rule_ids
    assert "odoo-view-filter-global-default-sensitive" in rule_ids


def test_flags_global_default_sensitive_filter_even_when_domain_is_narrow(tmp_path: Path) -> None:
    """Global default filters on sensitive models deserve review even with narrow domains."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "filters.xml").write_text(
        """<odoo>
  <record id="filter_posted_invoices" model="ir.filters">
    <field name="name">Posted invoices</field>
    <field name="model_id">account.move</field>
    <field name="domain">[('state', '!=', 'cancel')]</field>
    <field name="is_default">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_view_domains(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-view-filter-global-default-sensitive" in rule_ids
    assert "odoo-view-domain-default-sensitive-filter" not in rule_ids
    assert "odoo-view-domain-global-sensitive-filter-broad-domain" not in rule_ids


def test_ignores_guarded_safe_action_context(tmp_path: Path) -> None:
    """Scoped actions with groups and ordinary contexts should avoid findings."""
    views = tmp_path / "module" / "views"
    views.mkdir(parents=True)
    (views / "actions.xml").write_text(
        """<odoo>
  <record id="action_partners" model="ir.actions.act_window">
    <field name="res_model">res.partner</field>
    <field name="groups_id" eval="[(4, ref('base.group_user'))]"/>
    <field name="domain">[('customer_rank', '&gt;', 0)]</field>
    <field name="context">{'search_default_customer': 1}</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_view_domains(tmp_path) == []


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """XML fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "views.xml").write_text(
        """<odoo><field name="x" context="{'active_test': False}"/></odoo>""",
        encoding="utf-8",
    )

    assert scan_view_domains(tmp_path) == []
