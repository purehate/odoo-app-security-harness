"""Tests for deployment posture scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.deployment_scanner import scan_deployment_config


def test_xml_entities_are_not_expanded_into_deployment_findings(tmp_path: Path) -> None:
    """XML entities must not synthesize insecure deployment findings."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "entity.xml").write_text(
        """<!DOCTYPE odoo [
<!ENTITY open_signup "auth_signup.allow_uninvited">
]>
<odoo>
  <record id="entity_signup" model="ir.config_parameter">
    <field name="key">&open_signup;</field>
    <field name="value">True</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_deployment_config(tmp_path) == []


def test_scan_deployment_config_flags_risky_odoo_conf(tmp_path: Path) -> None:
    """Config files should flag insecure production posture choices."""
    config = tmp_path / "odoo.conf"
    config.write_text(
        """
[options]
list_db = True
database_create = True
database_drop = True
dbfilter =
proxy_mode = False
log_level = debug
log_handler = :INFO,odoo.sql_db:DEBUG,werkzeug:WARNING
db_sslmode = prefer
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-database-create-enabled" in rule_ids
    assert "odoo-deploy-database-drop-enabled" in rule_ids
    assert "odoo-deploy-empty-dbfilter" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-debug-logging" in rule_ids
    assert "odoo-deploy-debug-log-handler" in rule_ids
    assert "odoo-deploy-db-sslmode-opportunistic" in rule_ids


def test_scan_deployment_config_flags_wildcard_database_filter(tmp_path: Path) -> None:
    """Wildcard dbfilter values should be called out for multi-database deployments."""
    config = tmp_path / "odoo.conf"
    config.write_text(
        """
[options]
dbfilter = ^.*$
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-wildcard-dbfilter" in rule_ids


def test_scan_deployment_config_flags_master_password_and_dev_modes(tmp_path: Path) -> None:
    """Deployment config should surface weak master passwords and dev/test flags."""
    config = tmp_path / "odoo.conf"
    config.write_text(
        """
[options]
admin_passwd = admin
dev_mode = reload,qweb,xml
test_enable = True
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-weak-admin-passwd" in rule_ids
    assert "odoo-deploy-dev-mode-enabled" in rule_ids
    assert "odoo-deploy-test-enable" in rule_ids


def test_scan_deployment_config_flags_disabled_workers_and_time_limits(tmp_path: Path) -> None:
    """Production deployments should not disable workers or execution time limits."""
    config = tmp_path / "odoo.conf"
    config.write_text(
        """
[options]
workers = 0
limit_time_cpu = 0
limit_time_real = -1
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-workers-disabled" in rule_ids
    assert "odoo-deploy-time-limit-disabled" in rule_ids


def test_scan_deployment_config_flags_committed_master_password(tmp_path: Path) -> None:
    """Even strong-looking master passwords should not live in committed config."""
    config = tmp_path / ".env.production"
    config.write_text(
        "ADMIN_PASSWD = prod-master-password-123456\n",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)

    assert any(finding.rule_id == "odoo-deploy-admin-passwd-committed" for finding in findings)


def test_scan_deployment_config_flags_odoo_prefixed_env_keys(tmp_path: Path) -> None:
    """Odoo deployment env files commonly prefix config keys with ODOO_."""
    config = tmp_path / ".env.production"
    config.write_text(
        """
ODOO_ADMIN_PASSWD=prod-master-password-123456
ODOO_LIST_DB=true
ODOO_PROXY_MODE=false
ODOO_DB_SSLMODE=prefer
ODOO_WEB_BASE_URL=http://localhost:8069
ODOO_AUTH_SIGNUP_ALLOW_UNINVITED=true
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-admin-passwd-committed" in rule_ids
    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-db-sslmode-opportunistic" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids
    assert "odoo-deploy-open-signup" in rule_ids


def test_scan_deployment_config_flags_dockerfile_odoo_env_keys(tmp_path: Path) -> None:
    """Dockerfile ARG/ENV layers can bake risky Odoo production settings."""
    config = tmp_path / "Dockerfile"
    config.write_text(
        """FROM odoo:18
ARG ODOO_LIST_DB=true
ENV ODOO_PROXY_MODE=false
ENV ODOO_WEB_BASE_URL http://localhost:8069
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids


def test_scan_deployment_config_flags_compose_odoo_env_keys(tmp_path: Path) -> None:
    """Docker Compose service environments should feed deployment posture checks."""
    config = tmp_path / "docker-compose.yml"
    config.write_text(
        """services:
  odoo:
    image: odoo:18
    environment:
      ODOO_LIST_DB: "true"
      ODOO_PROXY_MODE: "false"
  worker:
    image: odoo:18
    environment:
      - ODOO_WEB_BASE_URL=http://localhost:8069
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids


def test_scan_deployment_config_flags_kubernetes_odoo_env_keys(tmp_path: Path) -> None:
    """Kubernetes container env values should feed deployment posture checks."""
    config = tmp_path / "deployment.yaml"
    config.write_text(
        """apiVersion: apps/v1
kind: Deployment
metadata:
  name: odoo
spec:
  template:
    spec:
      containers:
        - name: odoo
          image: odoo:18
          env:
            - name: ODOO_LIST_DB
              value: "true"
            - name: ODOO_PROXY_MODE
              value: "false"
            - name: ODOO_WEB_BASE_URL
              value: http://localhost:8069
            - name: ODOO_DB_SSLMODE
              valueFrom:
                configMapKeyRef:
                  name: odoo
                  key: db_sslmode
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids
    assert "odoo-deploy-db-sslmode-opportunistic" not in rule_ids


def test_scan_deployment_config_flags_helm_values_odoo_env_keys(tmp_path: Path) -> None:
    """Helm values files should feed obvious Odoo env settings into posture checks."""
    config = tmp_path / "values-production.yaml"
    config.write_text(
        """odoo:
  env:
    ODOO_LIST_DB: true
    ODOO_PROXY_MODE: false
extraEnvVars:
  - name: ODOO_WEB_BASE_URL
    value: http://localhost:8069
  - name: ODOO_DB_SSLMODE
    valueFrom:
      secretKeyRef:
        name: odoo
        key: db_sslmode
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-list-db-enabled" in rule_ids
    assert "odoo-deploy-proxy-mode-disabled" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids
    assert "odoo-deploy-db-sslmode-opportunistic" not in rule_ids


def test_scan_deployment_config_flags_signup_and_base_url_xml(tmp_path: Path) -> None:
    """XML config parameters should flag open signup and mutable base URL settings."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "config.xml").write_text(
        """<odoo>
  <record id="base_url_freeze" model="ir.config_parameter">
    <field name="key">web.base.url.freeze</field>
    <field name="value">False</field>
  </record>
  <record id="base_url" model="ir.config_parameter">
    <field name="key">web.base.url</field>
    <field name="value">http://localhost:8069</field>
  </record>
  <record id="open_signup" model="ir.config_parameter">
    <field name="key">auth_signup.allow_uninvited</field>
    <field name="value">True</field>
  </record>
  <record id="db_create" model="ir.config_parameter">
    <field name="key">database.create</field>
    <field name="value">True</field>
  </record>
  <record id="db_drop" model="ir.config_parameter">
    <field name="key">database.drop</field>
    <field name="value">True</field>
  </record>
  <record id="oauth_signup" model="ir.config_parameter">
    <field name="key">auth_oauth.allow_signup</field>
    <field name="value">1</field>
  </record>
  <record id="b2c_signup" model="ir.config_parameter">
    <field name="key">auth_signup.invitation_scope</field>
    <field name="value">b2c</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-base-url-not-frozen" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids
    assert "odoo-deploy-open-signup" in rule_ids
    assert "odoo-deploy-database-create-enabled" in rule_ids
    assert "odoo-deploy-database-drop-enabled" in rule_ids
    assert "odoo-deploy-oauth-auto-signup" in rule_ids
    assert "odoo-deploy-b2c-signup" in rule_ids


def test_scan_deployment_config_flags_signup_and_base_url_csv(tmp_path: Path) -> None:
    """CSV config parameters should flag open signup and mutable base URL settings."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "ir.config_parameter.csv").write_text(
        """id,key,value
base_url_freeze,web.base.url.freeze,False
base_url,web.base.url,http://localhost:8069
open_signup,auth_signup.allow_uninvited,True
db_create,database.create,True
db_drop,database.drop,True
oauth_signup,auth_oauth.allow_signup,1
b2c_signup,auth_signup.invitation_scope,b2c
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-base-url-not-frozen" in rule_ids
    assert "odoo-deploy-insecure-base-url" in rule_ids
    assert "odoo-deploy-open-signup" in rule_ids
    assert "odoo-deploy-database-create-enabled" in rule_ids
    assert "odoo-deploy-database-drop-enabled" in rule_ids
    assert "odoo-deploy-oauth-auto-signup" in rule_ids
    assert "odoo-deploy-b2c-signup" in rule_ids


def test_scan_deployment_config_flags_risky_oauth_provider_xml(tmp_path: Path) -> None:
    """OAuth provider records should expose insecure auth posture."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "oauth.xml").write_text(
        """<odoo>
  <record id="oauth_partner" model="auth.oauth.provider">
    <field name="name">Partner OAuth</field>
    <field name="enabled">True</field>
    <field name="auth_endpoint">http://idp.example.com/auth</field>
    <field name="token_endpoint">https://idp.example.com/token</field>
    <field name="client_secret">prod-secret-1234567890</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-oauth-missing-validation-endpoint" in rule_ids
    assert "odoo-deploy-oauth-insecure-endpoint" in rule_ids
    assert "odoo-deploy-oauth-client-secret-committed" in rule_ids


def test_scan_deployment_config_flags_risky_oauth_provider_csv(tmp_path: Path) -> None:
    """OAuth provider CSV records should expose insecure auth posture."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "auth_oauth_provider.csv").write_text(
        """id,name,enabled,auth_endpoint,token_endpoint,client_secret
oauth_partner,Partner OAuth,True,http://idp.example.com/auth,https://idp.example.com/token,prod-secret-1234567890
""",
        encoding="utf-8",
    )

    findings = scan_deployment_config(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-deploy-oauth-missing-validation-endpoint" in rule_ids
    assert "odoo-deploy-oauth-insecure-endpoint" in rule_ids
    assert "odoo-deploy-oauth-client-secret-committed" in rule_ids


def test_scan_deployment_config_ignores_safe_oauth_provider_xml(tmp_path: Path) -> None:
    """HTTPS OAuth providers with validation and placeholder secrets should avoid findings."""
    data_dir = tmp_path / "module" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "oauth.xml").write_text(
        """<odoo>
  <record id="oauth_partner" model="auth.oauth.provider">
    <field name="name">Partner OAuth</field>
    <field name="enabled">True</field>
    <field name="auth_endpoint">https://idp.example.com/auth</field>
    <field name="validation_endpoint">https://idp.example.com/userinfo</field>
    <field name="token_endpoint">https://idp.example.com/token</field>
    <field name="client_secret">changeme</field>
  </record>
</odoo>""",
        encoding="utf-8",
    )

    assert scan_deployment_config(tmp_path) == []


def test_scan_deployment_config_ignores_safe_values(tmp_path: Path) -> None:
    """Safe or locked-down values should not produce deployment findings."""
    (tmp_path / "odoo.conf").write_text(
        """
list_db = False
dbfilter = ^%h$
proxy_mode = True
log_level = info
log_handler = :INFO,odoo.sql_db:INFO
workers = 4
limit_time_cpu = 60
limit_time_real = 120
db_sslmode = verify-full
web.base.url = https://odoo.example.com
""",
        encoding="utf-8",
    )

    assert scan_deployment_config(tmp_path) == []
