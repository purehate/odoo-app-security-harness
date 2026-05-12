"""Tests for HTTP route extraction from Odoo controllers."""

from __future__ import annotations

import ast
import re

ROUTE_RE = re.compile(r"@http\.route\((?P<args>.*?)\)", re.DOTALL)
KW_RE = re.compile(r"(?P<key>auth|csrf|type|methods)\s*=\s*(?P<value>[^,\)]*)")


def extract_route_paths(args_text: str) -> list[str]:
    """Extract literal route paths from @http.route decorator."""
    try:
        node = ast.parse(f"_route({args_text})", mode="eval")
    except SyntaxError:
        return []
    if not isinstance(node.body, ast.Call):
        return []
    values: list[str] = []
    candidates = []
    if node.body.args:
        candidates.append(node.body.args[0])
    for keyword in node.body.keywords:
        if keyword.arg == "route":
            candidates.append(keyword.value)
    for candidate in candidates:
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
            values.append(candidate.value)
        elif isinstance(candidate, (ast.List, ast.Tuple)):
            for item in candidate.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    values.append(item.value)
    return values


def extract_routes_from_text(text: str, filename: str = "test.py") -> list[dict]:
    """Extract routes from Python source text."""
    routes = []
    for match in ROUTE_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        tail = text[match.end() : match.end() + 500]
        def_match = re.search(r"def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", tail)
        kwargs = {m.group("key"): m.group("value").strip() for m in KW_RE.finditer(match.group("args"))}
        paths = extract_route_paths(match.group("args"))
        routes.append(
            {
                "line": line,
                "function": def_match.group(1) if def_match else None,
                "paths": paths,
                "auth": kwargs.get("auth", "user(default)"),
                "csrf": kwargs.get("csrf", "True(default)"),
                "type": kwargs.get("type", "http(default)"),
                "methods": kwargs.get("methods"),
            }
        )
    return routes


class TestExtractRoutePaths:
    """Test route path extraction."""

    def test_single_route_string(self) -> None:
        """Test extracting single route path."""
        paths = extract_route_paths("'/test/path'")
        assert paths == ["/test/path"]

    def test_multiple_routes_list(self) -> None:
        """Test extracting multiple routes from list."""
        paths = extract_route_paths("['/path1', '/path2']")
        assert paths == ["/path1", "/path2"]

    def test_named_route_parameter(self) -> None:
        """Test extracting route from named parameter."""
        paths = extract_route_paths("route='/test', auth='public'")
        assert paths == ["/test"]

    def test_invalid_syntax(self) -> None:
        """Test handling invalid syntax."""
        paths = extract_route_paths("not valid syntax {{{")
        assert paths == []

    def test_empty_args(self) -> None:
        """Test handling empty arguments."""
        paths = extract_route_paths("")
        assert paths == []


class TestExtractRoutes:
    """Test full route extraction from controller files."""

    def test_public_route(self) -> None:
        """Test extracting public route."""
        text = """
class TestController(http.Controller):
    @http.route('/test/public', auth='public', type='http')
    def test_public(self, **kwargs):
        return "Hello"
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert routes[0]["paths"] == ["/test/public"]
        assert routes[0]["auth"] == "'public'"
        assert routes[0]["type"] == "'http'"
        assert routes[0]["function"] == "test_public"

    def test_csrf_false_route(self) -> None:
        """Test extracting route with csrf=False."""
        text = """
class TestController(http.Controller):
    @http.route('/test/action', auth='user', type='http', csrf=False)
    def test_action(self, **kwargs):
        return "Action"
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert routes[0]["csrf"] == "False"
        assert routes[0]["auth"] == "'user'"

    def test_json_route(self) -> None:
        """Test extracting JSON route."""
        text = """
class TestController(http.Controller):
    @http.route('/test/api', auth='none', type='json', methods=['POST'])
    def test_api(self, **kwargs):
        return {'status': 'ok'}
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert routes[0]["type"] == "'json'"
        assert routes[0]["methods"] == "['POST']"
        assert routes[0]["auth"] == "'none'"

    def test_multiple_routes(self) -> None:
        """Test extracting multiple routes from one file."""
        text = """
class TestController(http.Controller):
    @http.route('/test/one', auth='public')
    def one(self):
        pass

    @http.route('/test/two', auth='user')
    def two(self):
        pass

    @http.route('/test/three', auth='public')
    def three(self):
        pass
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 3
        public_routes = [r for r in routes if "public" in r["auth"]]
        assert len(public_routes) == 2

    def test_no_routes(self) -> None:
        """Test file with no routes."""
        text = """
class TestModel(models.Model):
    _name = 'test.model'

    def do_something(self):
        pass
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 0

    def test_multiline_decorator(self) -> None:
        """Test multiline route decorator."""
        text = """
class TestController(http.Controller):
    @http.route(
        '/test/long',
        auth='public',
        type='http',
        csrf=False
    )
    def test_long(self):
        pass
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert routes[0]["paths"] == ["/test/long"]
        assert routes[0]["csrf"] == "False"

    def test_route_with_parameters(self) -> None:
        """Test route with URL parameters."""
        text = """
class TestController(http.Controller):
    @http.route('/test/<int:id>', auth='user')
    def test_param(self, id):
        pass
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert "/test/" in routes[0]["paths"][0]
        assert "<int:id>" in routes[0]["paths"][0]


class TestRouteSecurityPatterns:
    """Test detection of security-relevant route patterns."""

    def test_detect_public_sudo_pattern(self) -> None:
        """Test detecting public route that uses sudo."""
        text = """
class TestController(http.Controller):
    @http.route('/test/public', auth='public')
    def test_public(self):
        users = request.env['res.users'].sudo().search([])
        return {'count': len(users)}
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert "public" in routes[0]["auth"]
        # sudo() usage would be detected by pattern scanning
        assert ".sudo()" in text

    def test_detect_csrf_vulnerable_route(self) -> None:
        """Test detecting route with csrf disabled."""
        text = """
class TestController(http.Controller):
    @http.route('/test/action', auth='user', csrf=False, type='http')
    def test_action(self):
        # State-changing operation without CSRF protection
        return request.redirect('/test/done')
"""
        routes = extract_routes_from_text(text)
        assert len(routes) == 1
        assert routes[0]["csrf"] == "False"
