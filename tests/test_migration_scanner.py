"""Tests for migration and lifecycle hook scanning."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.migration_scanner import MigrationScanner, scan_migrations


def test_interpolated_migration_sql_is_reported(tmp_path: Path) -> None:
    """Migration SQL should not be built through string interpolation."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(cr, version):
    table = "res_partner"
    cr.execute("UPDATE %s SET active = false" % table)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-interpolated-sql" for f in findings)


def test_unpacked_interpolated_migration_sql_is_reported(tmp_path: Path) -> None:
    """Tuple-unpacked SQL aliases should stay tracked into cr.execute."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(cr, version):
    query, params = "UPDATE %s SET active = false" % table, []
    cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-interpolated-sql" for f in findings)


def test_starred_rest_interpolated_migration_sql_is_reported(tmp_path: Path) -> None:
    """Starred tuple-rest SQL aliases should stay tracked into cr.execute."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(cr, version):
    marker, *items, tail = "x", "UPDATE %s SET active = false" % table, [], "end"
    query = items[0]
    cr.execute(query)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-interpolated-sql" for f in findings)


def test_destructive_migration_sql_is_reported(tmp_path: Path) -> None:
    """DROP/TRUNCATE/DELETE without WHERE are critical migration review leads."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(cr, version):
    cr.execute("DELETE FROM account_move")
    cr.execute("DROP TABLE legacy_secret")
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-destructive-sql" and f.severity == "critical" for f in findings)


def test_recursive_constant_destructive_migration_sql_is_reported(tmp_path: Path) -> None:
    """Recursive SQL constants should still be inspected when executed."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
BASE_QUERY = "DELETE FROM account_move"
QUERY_ALIAS = BASE_QUERY

def migrate(cr, version):
    cr.execute(QUERY_ALIAS)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-destructive-sql" and f.severity == "critical" for f in findings)


def test_class_constant_destructive_migration_sql_is_reported(tmp_path: Path) -> None:
    """Class-level SQL constants should still be inspected when executed."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
class PartnerMigration:
    BASE_QUERY = "DELETE FROM account_move"
    QUERY_ALIAS = BASE_QUERY

    def migrate(self, cr, version):
        cr.execute(QUERY_ALIAS)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-destructive-sql" and f.severity == "critical" for f in findings)


def test_sudo_mutation_and_manual_transaction_are_reported(tmp_path: Path) -> None:
    """Migration hooks often run privileged; sudo writes and commits need review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    env['res.partner'].sudo().search([]).write({'active': False})
    env.cr.commit()
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-migration-sudo-mutation" in rule_ids
    assert "odoo-migration-manual-transaction" in rule_ids


def test_sudo_alias_mutation_is_reported(tmp_path: Path) -> None:
    """Sudo recordset aliases in migrations should still trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    partners, company = env['res.partner'].sudo().search([]), env.company
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_with_user_superuser_mutation_is_reported(tmp_path: Path) -> None:
    """Superuser with_user mutations in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
from odoo import SUPERUSER_ID

def migrate(env):
    env['res.partner'].with_user(SUPERUSER_ID).search([]).write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_constant_backed_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """Migration scanners should resolve simple constants used for superuser aliases."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
ROOT_UID = 1

def migrate(env):
    partners = env['res.partner'].with_user(ROOT_UID).search([])
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_recursive_constant_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """Recursive superuser constants in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
ROOT_UID = 1
ADMIN_UID = ROOT_UID

def migrate(env):
    partners = env['res.partner'].with_user(ADMIN_UID).search([])
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_class_constant_with_user_mutation_is_reported(tmp_path: Path) -> None:
    """Class-level superuser constants in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
class PartnerMigration:
    ROOT_UID = 1
    ADMIN_UID = ROOT_UID

    def migrate(self, env):
        partners = env['res.partner'].with_user(ADMIN_UID).search([])
        partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_aliased_with_user_one_mutation_is_reported(tmp_path: Path) -> None:
    """Aliased with_user(1) recordsets in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    partners, company = env['res.partner'].with_user(1).search([]), env.company
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_env_ref_admin_mutation_is_reported(tmp_path: Path) -> None:
    """Admin XML-ID with_user migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    partners = env['res.partner'].with_user(env.ref('base.user_admin')).search([])
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_starred_rest_sudo_alias_mutation_is_reported(tmp_path: Path) -> None:
    """Starred tuple-rest sudo aliases in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    marker, *items, tail = "x", env['res.partner'].sudo().search([]), env.company, "end"
    partners = items[0]
    partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_named_expression_sudo_alias_mutation_is_reported(tmp_path: Path) -> None:
    """Walrus-bound sudo recordset aliases in migrations should trigger mutation review."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    if partners := env['res.partner'].sudo().search([]):
        partners.write({'active': False})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_mixed_tuple_sudo_alias_does_not_overtaint_migration(tmp_path: Path) -> None:
    """Mixed tuple assignments should not mark non-sudo migration neighbors."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
def migrate(env):
    partners, company = env['res.partner'].sudo(), env.company
    company.write({'name': 'Renamed'})
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert not any(f.rule_id == "odoo-migration-sudo-mutation" for f in findings)


def test_http_and_process_calls_are_reported(tmp_path: Path) -> None:
    """Migration scripts should not hide network/process side effects."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
from requests import post as http_post
import subprocess as sp

def migrate(cr, version):
    http_post("https://example.test/upgrade")
    sp.run(["odoo-bin", "--stop-after-init"], timeout=30)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-migration-http-no-timeout" in rule_ids
    assert "odoo-migration-process-execution" in rule_ids


def test_urllib_urlopen_without_timeout_is_reported(tmp_path: Path) -> None:
    """urllib.request.urlopen should be treated as migration outbound HTTP."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
from urllib.request import urlopen
import urllib.request as urlreq

def migrate(cr, version):
    urlopen("https://example.test/upgrade")
    urlreq.urlopen("https://example.test/status", timeout=10)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert len([finding for finding in findings if finding.rule_id == "odoo-migration-http-no-timeout"]) == 1


def test_urllib_request_import_alias_without_timeout_is_reported(tmp_path: Path) -> None:
    """from urllib import request aliases should count as migration outbound HTTP."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
from urllib import request as urlreq

def migrate(cr, version):
    urlreq.urlopen("https://example.test/upgrade")
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(finding.rule_id == "odoo-migration-http-no-timeout" for finding in findings)


def test_aiohttp_request_without_timeout_is_reported(tmp_path: Path) -> None:
    """aiohttp module calls in migrations should require a timeout."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import aiohttp as ah
from aiohttp import request as http_request

def migrate(cr, version):
    ah.request("POST", "https://example.test/upgrade")
    http_request("GET", "https://example.test/status", timeout=10)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert len([finding for finding in findings if finding.rule_id == "odoo-migration-http-no-timeout"]) == 1


def test_head_without_timeout_is_reported_in_migration(tmp_path: Path) -> None:
    """HEAD requests in migrations should still require explicit timeouts."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import httpx

def migrate(cr, version):
    httpx.head("https://example.test/health")
    httpx.head("https://example.test/ready", timeout=10)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert len([finding for finding in findings if finding.rule_id == "odoo-migration-http-no-timeout"]) == 1


def test_http_timeout_none_is_reported_in_migration(tmp_path: Path) -> None:
    """Migration HTTP should treat timeout=None as no effective timeout."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import requests

def migrate(cr, version):
    requests.post("https://example.test/upgrade", timeout=None)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(finding.rule_id == "odoo-migration-http-no-timeout" for finding in findings)


def test_http_constant_timeout_none_is_reported_in_migration(tmp_path: Path) -> None:
    """Migration HTTP should resolve constants used for timeout values."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import requests

MIGRATION_TIMEOUT = None

def migrate(cr, version):
    requests.post("https://example.test/upgrade", timeout=MIGRATION_TIMEOUT)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(finding.rule_id == "odoo-migration-http-no-timeout" for finding in findings)


def test_http_static_kwargs_timeout_is_not_reported_in_migration(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should satisfy migration HTTP timeout checks."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import requests

HTTP_OPTIONS = {'timeout': 10}

def migrate(cr, version):
    requests.post("https://example.test/upgrade", **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert not any(finding.rule_id == "odoo-migration-http-no-timeout" for finding in findings)


def test_tls_verification_disabled_is_reported_in_migration(tmp_path: Path) -> None:
    """Migration outbound HTTP should not disable TLS verification."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import requests

VERIFY_TLS = False

def migrate(cr, version):
    requests.post("https://example.test/upgrade", timeout=10, verify=VERIFY_TLS)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(finding.rule_id == "odoo-migration-tls-verify-disabled" for finding in findings)


def test_tls_verification_disabled_static_kwargs_is_reported_in_migration(tmp_path: Path) -> None:
    """Static **kwargs dictionaries should not hide migration TLS verification disabling."""
    py = tmp_path / "post-migrate.py"
    py.write_text(
        """
import requests

HTTP_OPTIONS = {'timeout': 10, 'verify': False}

def migrate(cr, version):
    requests.post("https://example.test/upgrade", **HTTP_OPTIONS)
""",
        encoding="utf-8",
    )

    findings = MigrationScanner(py, "migration").scan_file()

    assert any(finding.rule_id == "odoo-migration-tls-verify-disabled" for finding in findings)


def test_manifest_declared_lifecycle_hook_is_scanned(tmp_path: Path) -> None:
    """Manifest hook names should locate and scan hook functions."""
    module = tmp_path / "module"
    module.mkdir()
    (module / "__manifest__.py").write_text(
        "{'name': 'Hooked', 'post_init_hook': 'post_init'}",
        encoding="utf-8",
    )
    (module / "hooks.py").write_text(
        """
def post_init(cr, registry):
    cr.execute("TRUNCATE TABLE legacy_import")
""",
        encoding="utf-8",
    )

    findings = scan_migrations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-migration-lifecycle-hook" in rule_ids
    assert "odoo-migration-destructive-sql" in rule_ids


def test_manifest_missing_lifecycle_hook_function_is_reported(tmp_path: Path) -> None:
    """Manifest hook names that cannot be resolved should not disappear."""
    module = tmp_path / "module"
    module.mkdir()
    (module / "__manifest__.py").write_text(
        "{'name': 'Broken Hook', 'post_init_hook': 'post_init'}",
        encoding="utf-8",
    )
    (module / "hooks.py").write_text(
        """
def unrelated(cr, registry):
    return None
""",
        encoding="utf-8",
    )

    findings = scan_migrations(tmp_path)

    assert any(
        finding.rule_id == "odoo-migration-missing-lifecycle-hook" and finding.context == "manifest:post_init"
        for finding in findings
    )


def test_repository_scan_finds_migration_files(tmp_path: Path) -> None:
    """Repository scanner should include addon migrations directories."""
    migration = tmp_path / "module" / "migrations" / "16.0.1.0"
    migration.mkdir(parents=True)
    (migration / "post-migrate.py").write_text(
        """
def migrate(cr, version):
    cr.execute("ALTER TABLE res_partner DROP COLUMN legacy_token")
""",
        encoding="utf-8",
    )

    findings = scan_migrations(tmp_path)

    assert any(f.rule_id == "odoo-migration-destructive-sql" for f in findings)
