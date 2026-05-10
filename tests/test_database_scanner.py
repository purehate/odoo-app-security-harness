"""Tests for Odoo database operation route scanner."""

from __future__ import annotations

from pathlib import Path

from odoo_security_harness.database_scanner import scan_database_operations


def test_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Unauthenticated database manager behavior should be high-signal."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/drop', auth='none', csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-listing-route" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_request_alias_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo request objects should not hide database session selection."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/db/drop', auth='none', csrf=False)
    def drop(self):
        payload = req.get_http_params()
        req.session.db = payload.get('db')
        return service.db.exp_drop(payload.get('password'), payload.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_imported_route_decorator_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Imported route decorators should still expose public database manager behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request, route

class Controller(http.Controller):
    @route('/db/drop', auth='none', csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-listing-route" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_aliased_imported_route_decorator_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Aliased imported route decorators should still expose public database manager behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request, route as odoo_route

class Controller(http.Controller):
    @odoo_route('/db/drop', auth='none', csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-listing-route" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_aliased_http_module_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Aliased Odoo http modules should still expose public database manager behavior."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http as odoo_http, service
from odoo.http import request

class Controller(odoo_http.Controller):
    @odoo_http.route('/db/drop', auth='none', csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-listing-route" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_constant_backed_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Constant-backed route metadata should not hide public database manager exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request

DB_ROUTES = ['/db/drop', '/db/drop/alt']
DB_AUTH = 'none'

class Controller(http.Controller):
    @http.route(DB_ROUTES, auth=DB_AUTH, csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-management-call"
        and f.severity == "critical"
        and f.route == "/db/drop,/db/drop/alt"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-database-listing-route"
        and f.severity == "high"
        and f.route == "/db/drop,/db/drop/alt"
        for f in findings
    )
    assert any(f.rule_id == "odoo-database-session-db-assignment" and f.severity == "critical" for f in findings)


def test_recursive_constant_backed_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Recursive route constants should preserve public database manager evidence."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request

ROUTE_BASE = '/db/drop'
DB_ROUTE = ROUTE_BASE
DB_ROUTES = [DB_ROUTE]
AUTH_BASE = 'none'
DB_AUTH = AUTH_BASE

class Controller(http.Controller):
    @http.route(DB_ROUTES, auth=DB_AUTH, csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-management-call"
        and f.severity == "critical"
        and f.route == "/db/drop"
        for f in findings
    )
    assert any(f.rule_id == "odoo-database-session-db-assignment" and f.severity == "critical" for f in findings)


def test_static_unpack_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Static route option dictionaries should preserve DB manager route metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

DB_OPTIONS = {
    'route': '/db/drop',
    'auth': 'none',
    'csrf': False,
}

class Controller(http.Controller):
    @http.route(**DB_OPTIONS)
    def drop(self, **kwargs):
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-management-call"
        and f.severity == "critical"
        and f.route == "/db/drop"
        for f in findings
    )
    assert any(f.rule_id == "odoo-database-tainted-management-input" for f in findings)


def test_class_constant_backed_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Class-scoped route metadata should not hide public database manager exposure."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request

class Controller(http.Controller):
    DB_ROUTES = ['/db/drop', '/db/drop/alt']
    DB_AUTH = 'none'

    @http.route(DB_ROUTES, auth=DB_AUTH, csrf=False)
    def drop(self, **kwargs):
        request.session.db = kwargs.get('db')
        service.db.list_dbs()
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-management-call"
        and f.severity == "critical"
        and f.route == "/db/drop,/db/drop/alt"
        for f in findings
    )
    assert any(
        f.rule_id == "odoo-database-listing-route"
        and f.severity == "high"
        and f.route == "/db/drop,/db/drop/alt"
        for f in findings
    )
    assert any(f.rule_id == "odoo-database-session-db-assignment" and f.severity == "critical" for f in findings)


def test_class_constant_static_unpack_public_database_manager_route_is_reported(tmp_path: Path) -> None:
    """Class-scoped static route option dictionaries should preserve DB manager metadata."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    ROUTE_BASE = '/db/drop'
    DB_ROUTE = ROUTE_BASE
    AUTH_BASE = 'none'
    DB_AUTH = AUTH_BASE
    DB_OPTIONS = {
        'route': DB_ROUTE,
        'auth': DB_AUTH,
        'csrf': False,
    }
    OPTIONS_ALIAS = DB_OPTIONS

    @http.route(**OPTIONS_ALIAS)
    def drop(self, **kwargs):
        return service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-management-call"
        and f.severity == "critical"
        and f.route == "/db/drop"
        for f in findings
    )
    assert any(f.rule_id == "odoo-database-tainted-management-input" for f in findings)


def test_keyword_constant_backed_public_database_selection_route_is_reported(tmp_path: Path) -> None:
    """Keyword route constants should preserve route evidence for DB selection."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import db_filter

SELECT_ROUTE = '/db/select'
SELECT_AUTH = 'public'

class Controller(http.Controller):
    @http.route(route=SELECT_ROUTE, auth=SELECT_AUTH)
    def select(self, **kwargs):
        return db_filter(kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(
        f.rule_id == "odoo-database-tainted-selection"
        and f.severity == "critical"
        and f.route == "/db/select"
        for f in findings
    )


def test_tainted_db_filter_is_reported(tmp_path: Path) -> None:
    """Request-derived db_filter calls can cross tenant boundaries."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import db_filter

class Controller(http.Controller):
    @http.route('/db/select', auth='public')
    def select(self, **kwargs):
        return db_filter(kwargs.get('db'))
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(f.rule_id == "odoo-database-tainted-selection" for f in findings)


def test_route_path_database_name_management_input_is_reported(tmp_path: Path) -> None:
    """Path-selected database names should taint database manager operations."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/drop/<string:database_name>', auth='none', csrf=False)
    def drop_named(self, database_name):
        request.session.db = database_name
        return service.db.exp_drop('master-password', database_name)
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids
    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_ignores_non_odoo_route_path_database_name_taint(tmp_path: Path) -> None:
    """Arbitrary .route decorators should not taint database-name parameters as Odoo routes."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo.service.db import db_filter

class Bus:
    def route(self, path, **kwargs):
        return lambda func: func

bus = Bus()

class Controller:
    @bus.route('/db/select/<string:database_name>', auth='public')
    def select(self, database_name):
        return db_filter(database_name)
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert not any(f.rule_id == "odoo-database-tainted-selection" for f in findings)


def test_unpacked_database_management_input_is_reported(tmp_path: Path) -> None:
    """Unpacked request-derived database names should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        _, db_name = ('fixed', kwargs.get('db'))
        return service.db.exp_backup(kwargs.get('password'), db_name, 'zip')
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_starred_database_management_input_is_reported(tmp_path: Path) -> None:
    """Starred request-derived database names should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        *db_name, marker = kwargs.get('db'), 'x'
        return service.db.exp_backup(kwargs.get('password'), db_name, 'zip')
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_starred_rest_database_management_input_is_reported(tmp_path: Path) -> None:
    """Starred-rest unpacking should not hide request-derived database names."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        marker, *items = 'x', kwargs.get('db'), 'zip'
        db_name = items[0]
        return service.db.exp_backup(kwargs.get('password'), db_name, 'zip')
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_database_name_argument_management_input_is_reported(tmp_path: Path) -> None:
    """Database-like arguments should still seed database-manager taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='user')
    def backup(self, db_name):
        return service.db.exp_backup('master-password', db_name, 'zip')
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_reassigned_database_name_alias_is_not_stale(tmp_path: Path) -> None:
    """Reusing a request database name alias for a static database should clear taint."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        db_name = kwargs.get('db')
        db_name = 'production'
        return service.db.exp_backup('master-password', db_name, 'zip')
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" not in rule_ids


def test_comprehension_database_selection_is_reported(tmp_path: Path) -> None:
    """Comprehension-derived database names should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import db_filter

class Controller(http.Controller):
    @http.route('/db/select', auth='public')
    def select(self, **kwargs):
        names = [value for value in kwargs.get('databases')]
        return db_filter(names[0])
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(f.rule_id == "odoo-database-tainted-selection" for f in findings)


def test_comprehension_filter_database_selection_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint database selection."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import db_filter

class Controller(http.Controller):
    @http.route('/db/select', auth='public')
    def select(self, **kwargs):
        requested = kwargs.get('db')
        names = ['production' for marker in ['x'] if requested]
        return db_filter(names[0])
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)

    assert any(f.rule_id == "odoo-database-tainted-selection" for f in findings)


def test_comprehension_filter_database_management_input_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint database manager inputs."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        requested = kwargs.get('db')
        names = ['production' for marker in ['x'] if requested]
        return service.db.exp_backup('master-password', names[0], 'zip')
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_named_expression_database_management_input_is_reported(tmp_path: Path) -> None:
    """Walrus-assigned request database names should remain tainted."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        if db_name := kwargs.get('db'):
            return service.db.exp_backup('master-password', db_name, 'zip')
        return 'missing'
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_boolop_database_management_input_is_reported(tmp_path: Path) -> None:
    """Boolean fallback expressions should not hide database manager input."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http, service

class Controller(http.Controller):
    @http.route('/db/backup', auth='none', csrf=False)
    def backup(self, **kwargs):
        db_name = kwargs.get('db') or 'production'
        return service.db.exp_backup('master-password', db_name, 'zip')
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" in rule_ids


def test_aliased_session_database_assignment_is_reported(tmp_path: Path) -> None:
    """request.session aliases should not hide direct database assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self, **kwargs):
        session = request.session
        session.db = kwargs.get('db')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids


def test_request_alias_session_database_assignment_is_reported(tmp_path: Path) -> None:
    """Aliased request.session objects should still be treated as DB session targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request as req

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self):
        session = req.session
        session.db = req.params.get('db')
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids


def test_starred_session_database_assignment_is_reported(tmp_path: Path) -> None:
    """Starred request.session aliases should still be treated as DB session targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self, **kwargs):
        *session, marker = request.session, 'x'
        session.db = kwargs.get('db')
        return 'ok'
""",
        encoding="utf-8",
    )

    findings = scan_database_operations(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids


def test_starred_rest_session_database_assignment_is_reported(tmp_path: Path) -> None:
    """Starred-rest request.session aliases should still be treated as DB session targets."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self, **kwargs):
        marker, *items = 'x', request.session, object()
        session = items[0]
        session.db = kwargs.get('db')
        return 'ok'
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids


def test_comprehension_filter_session_database_assignment_is_reported(tmp_path: Path) -> None:
    """Request-derived comprehension filters should taint session database assignment."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self, **kwargs):
        requested = kwargs.get('db')
        names = ['production' for marker in ['x'] if requested]
        request.session.db = names[0]
        return 'ok'
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-session-db-assignment" in rule_ids
    assert "odoo-database-tainted-selection" in rule_ids


def test_reassigned_session_alias_is_not_stale(tmp_path: Path) -> None:
    """Reassigned request.session aliases should not keep database-session state."""
    controllers = tmp_path / "module" / "controllers"
    controllers.mkdir(parents=True)
    (controllers / "db.py").write_text(
        """
from odoo import http
from odoo.http import request

class Controller(http.Controller):
    @http.route('/db/session', auth='public', csrf=False)
    def session_db(self, **kwargs):
        session = request.session
        session = object()
        session.db = kwargs.get('db')
        return 'ok'
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-session-db-assignment" not in rule_ids
    assert "odoo-database-tainted-selection" not in rule_ids


def test_safe_internal_database_constant_is_not_tainted(tmp_path: Path) -> None:
    """Constant database maintenance helpers should not be marked request-tainted."""
    models = tmp_path / "module" / "models"
    models.mkdir(parents=True)
    (models / "db.py").write_text(
        """
from odoo import service

class Maintenance:
    def backup_known_db(self):
        return service.db.exp_backup('secret', 'production', 'zip')
""",
        encoding="utf-8",
    )

    rule_ids = {finding.rule_id for finding in scan_database_operations(tmp_path)}

    assert "odoo-database-management-call" in rule_ids
    assert "odoo-database-tainted-management-input" not in rule_ids


def test_repo_scan_skips_tests(tmp_path: Path) -> None:
    """Fixtures under tests should not affect repository scans."""
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_db.py").write_text(
        """
def test_drop(kwargs):
    service.db.exp_drop(kwargs.get('password'), kwargs.get('db'))
""",
        encoding="utf-8",
    )

    assert scan_database_operations(tmp_path) == []
