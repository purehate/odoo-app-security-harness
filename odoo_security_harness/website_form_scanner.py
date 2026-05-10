"""Scanner for risky Odoo website form submission surfaces."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defusedxml import ElementTree


@dataclass
class WebsiteFormFinding:
    """Represents a website form exposure finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    model: str = ""
    field: str = ""


SENSITIVE_MODELS = {
    "account.move",
    "account.payment",
    "crm.lead",
    "helpdesk.ticket",
    "hr.applicant",
    "ir.attachment",
    "ir.config_parameter",
    "ir.cron",
    "ir.model.access",
    "ir.rule",
    "mail.message",
    "payment.provider",
    "payment.transaction",
    "project.task",
    "purchase.order",
    "res.groups",
    "res.partner",
    "res.users",
    "res.users.apikeys",
    "sale.order",
}
SENSITIVE_FIELD_NAMES = {
    "access_token",
    "active",
    "amount_total",
    "company_id",
    "groups_id",
    "is_admin",
    "model_id",
    "partner_id",
    "password",
    "public",
    "state",
    "type",
    "user_id",
}


def scan_website_forms(repo_path: Path) -> list[WebsiteFormFinding]:
    """Scan XML templates/views for public website form submission risks."""
    findings: list[WebsiteFormFinding] = []
    for path in repo_path.rglob("*.xml"):
        if _should_skip(path):
            continue
        findings.extend(WebsiteFormScanner(path).scan_file())
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(WebsiteFormFieldScanner(path).scan_file())
        findings.extend(WebsiteFormRouteScanner(path).scan_file())
    return findings


class WebsiteFormScanner:
    """Scanner for one XML file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.content = ""
        self.findings: list[WebsiteFormFinding] = []

    def scan_file(self) -> list[WebsiteFormFinding]:
        """Scan the XML file."""
        try:
            self.content = self.path.read_text(encoding="utf-8", errors="replace")
            root = ElementTree.fromstring(self.content)
        except ElementTree.ParseError:
            return []
        except Exception:
            return []

        for form in root.iter("form"):
            if self._is_website_form(form):
                self._scan_form(form)
        return self.findings

    def _is_website_form(self, form: ElementTree.Element) -> bool:
        action = _form_action(form)
        return (
            "/website/form/" in action
            or bool(_form_model_attr(form))
            or any(_field_name(child) in {"model_name", "model"} for child in form.iter("input"))
        )

    def _scan_form(self, form: ElementTree.Element) -> None:
        model = self._form_model(form)
        line = self._line_for_form(form)
        fields = self._field_names(form)
        severity = "high" if model in SENSITIVE_MODELS else "medium"

        self._add(
            "odoo-website-form-public-model-create",
            "Website form posts directly to an Odoo model",
            severity,
            line,
            "Website form submits to Odoo model creation; verify website_form allowed fields, required authentication, rate limiting, and post-create side effects",
            model,
            "",
        )

        if form.get("enctype", "").lower() == "multipart/form-data" or self._has_file_input(form):
            self._add(
                "odoo-website-form-file-upload",
                "Website form accepts file uploads",
                "medium",
                line,
                "Public website form accepts file uploads; verify MIME/type checks, size limits, attachment visibility, and malware scanning",
                model,
                "",
            )

        if self._is_post_form(form) and "csrf_token" not in fields:
            self._add(
                "odoo-website-form-missing-csrf-token",
                "Website form has no visible CSRF token",
                "high" if model in SENSITIVE_MODELS else "medium",
                line,
                "Website form posts to model creation without a visible csrf_token input; verify Odoo CSRF protection is present and cannot be bypassed cross-site",
                model,
                "csrf_token",
            )

        success_page = self._success_page(form)
        if _is_dangerous_url_scheme(success_page):
            self._add(
                "odoo-website-form-dangerous-success-redirect",
                "Website form success redirect uses dangerous URL scheme",
                "high",
                line,
                f"Website form success page uses dangerous URL '{success_page}'; restrict success redirects to local routes or reviewed HTTPS destinations",
                model,
                "success_page",
            )
        elif _is_external_url(success_page):
            self._add(
                "odoo-website-form-external-success-redirect",
                "Website form redirects to external success URL",
                "medium",
                line,
                f"Website form success page points to external URL '{success_page}'; verify it cannot become phishing, token leakage, or open-redirect surface",
                model,
                "success_page",
            )

        for field in sorted(fields & SENSITIVE_FIELD_NAMES):
            self._add(
                "odoo-website-form-sensitive-field",
                "Website form exposes sensitive model field",
                "high",
                _line_for(self.content, f'name="{field}"'),
                f"Website form includes field '{field}'; verify public users cannot set ownership, workflow, company, token, privilege, or visibility fields",
                model,
                field,
            )

        if self._has_hidden_model_selector(form):
            self._add(
                "odoo-website-form-hidden-model-selector",
                "Website form carries model selector in hidden input",
                "medium",
                line,
                "Website form includes a hidden model selector; verify clients cannot tamper with submitted model/field metadata",
                model,
                "model_name",
            )

        if self._has_disabled_sanitize_form(form):
            self._add(
                "odoo-website-form-sanitize-disabled",
                "Website form disables input sanitization",
                "high",
                _line_for(self.content, 'name="sanitize_form"'),
                "Website form submits sanitize_form=false; verify public users cannot persist unsafe HTML through website_form handling",
                model,
                "sanitize_form",
            )

    def _form_model(self, form: ElementTree.Element) -> str:
        model = _form_model_attr(form)
        if model:
            return model
        action = _form_action(form)
        match = re.search(r"/website/form/([a-zA-Z0-9_.-]+)", action)
        if match:
            return match.group(1)
        for child in form.iter("input"):
            if _field_name(child) in {"model_name", "model"}:
                return child.get("value", "")
        return ""

    def _field_names(self, form: ElementTree.Element) -> set[str]:
        fields: set[str] = set()
        for element in form.iter():
            if element.tag not in {"input", "select", "textarea"}:
                continue
            name = _field_name(element)
            if name and name not in {"csrf_token", "model", "model_name"}:
                fields.add(name)
        return fields

    def _is_post_form(self, form: ElementTree.Element) -> bool:
        return form.get("method", "post").strip().lower() == "post"

    def _success_page(self, form: ElementTree.Element) -> str:
        for attr in {
            "data-success-page",
            "data-success_page",
            "success-page",
            "success_page",
            "t-att-data-success-page",
            "t-attf-data-success-page",
        }:
            value = form.get(attr, "").strip()
            if value:
                return value.strip("'\"")
        return ""

    def _has_file_input(self, form: ElementTree.Element) -> bool:
        return any(element.get("type", "").lower() == "file" for element in form.iter("input"))

    def _has_hidden_model_selector(self, form: ElementTree.Element) -> bool:
        return any(
            element.get("type", "").lower() == "hidden" and _field_name(element) in {"model_name", "model"}
            for element in form.iter("input")
        )

    def _has_disabled_sanitize_form(self, form: ElementTree.Element) -> bool:
        for element in form.iter("input"):
            if _field_name(element) != "sanitize_form":
                continue
            if element.get("value", "").strip().lower() in {"0", "false", "no", "off"}:
                return True
        return False

    def _line_for_form(self, form: ElementTree.Element) -> int:
        action = _form_action(form)
        if action:
            return _line_for_form_action(self.content, action)
        model = form.get("data-model_name")
        if model:
            return _line_for(self.content, f'data-model_name="{model}"')
        model = _form_model_attr(form)
        if model:
            for attr in ("data-model_name", "data-model-name", "data-model", "t-att-data-model_name"):
                line = _line_for(self.content, f'{attr}="{model}"')
                if line != 1:
                    return line
        return _line_for(self.content, "<form")

    def _add(
        self,
        rule_id: str,
        title: str,
        severity: str,
        line: int,
        message: str,
        model: str,
        field: str,
    ) -> None:
        self.findings.append(
            WebsiteFormFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                model=model,
                field=field,
            )
        )


class WebsiteFormFieldScanner(ast.NodeVisitor):
    """Scanner for model fields explicitly exposed to website forms."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[WebsiteFormFinding] = []
        self.model_stack: list[str] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []

    def scan_file(self) -> list[WebsiteFormFinding]:
        """Scan Python model declarations."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        model = _class_model_name(node)
        self.model_stack.append(model)
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()
        self.model_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        if _is_website_form_allowed_field(node.value, self._effective_constants()):
            model = self.model_stack[-1] if self.model_stack else ""
            for target in node.targets:
                field = _assigned_field_name(target)
                self._add_exposed_field(model, field, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if _is_website_form_allowed_field(node.value, self._effective_constants()):
            model = self.model_stack[-1] if self.model_stack else ""
            self._add_exposed_field(model, _assigned_field_name(node.target), node.lineno)
        self.generic_visit(node)

    def _add_exposed_field(self, model: str, field: str, line: int) -> None:
        if field not in SENSITIVE_FIELD_NAMES and model not in SENSITIVE_MODELS:
            return
        self.findings.append(
            WebsiteFormFinding(
                rule_id="odoo-website-form-field-allowlisted-sensitive",
                title="Sensitive field is allowlisted for website forms",
                severity="high" if field in SENSITIVE_FIELD_NAMES else "medium",
                file=str(self.path),
                line=line,
                message=(
                    f"Model field '{field}' sets website_form_blacklisted=False; verify public website forms cannot set "
                    "ownership, workflow, company, token, privilege, or visibility fields"
                ),
                model=model,
                field=field,
            )
        )

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        return constants


class WebsiteFormRouteScanner(ast.NodeVisitor):
    """Scanner for custom website form routes that weaken CSRF protection."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[WebsiteFormFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}

    def scan_file(self) -> list[WebsiteFormFinding]:
        """Scan Python controller declarations."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        self.constants = _module_constants(tree)
        self.visit(tree)
        return self.findings

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.class_constants_stack.append(_static_constants_from_body(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        route = _website_form_route_with_csrf_disabled(node, self._effective_constants())
        if route:
            self.findings.append(
                WebsiteFormFinding(
                    rule_id="odoo-website-form-route-csrf-disabled",
                    title="Website form route disables CSRF protection",
                    severity="high",
                    file=str(self.path),
                    line=node.lineno,
                    message=(
                        f"Route '{route}' disables csrf protection for a website form endpoint; verify no public "
                        "cross-site request can create or mutate records through website_form handling"
                    ),
                    model="",
                    field="csrf",
                )
            )
        previous_local_constants = self.local_constants
        self.local_constants = {}
        self.generic_visit(node)
        self.local_constants = previous_local_constants

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        for target in node.targets:
            self._mark_local_constant_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if node.value is not None:
            self._mark_local_constant_target(node.target, node.value)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._mark_local_constant_target(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        if _call_disables_sanitize_form(node, self._effective_constants()):
            self.findings.append(
                WebsiteFormFinding(
                    rule_id="odoo-website-form-sanitize-disabled",
                    title="Website form disables input sanitization",
                    severity="high",
                    file=str(self.path),
                    line=node.lineno,
                    message="Call passes sanitize_form=False; verify public users cannot persist unsafe HTML through website_form handling",
                    model="",
                    field="sanitize_form",
                )
            )
        self.generic_visit(node)

    def _mark_local_constant_target(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Name):
            if _is_static_literal(value):
                self.local_constants[target.id] = value
            else:
                self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Starred):
            self._mark_local_constant_target(target.value, value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _discard_local_constant_target(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.local_constants.pop(target.id, None)
            return
        if isinstance(target, ast.Starred):
            self._discard_local_constant_target(target.value)
            return
        if isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._discard_local_constant_target(element)

    def _effective_constants(self) -> dict[str, ast.AST]:
        if not self.class_constants_stack and not self.local_constants:
            return self.constants
        constants = dict(self.constants)
        for class_constants in self.class_constants_stack:
            constants.update(class_constants)
        constants.update(self.local_constants)
        return constants


def _field_name(element: ElementTree.Element) -> str:
    for attr in ("name", "t-att-name", "t-attf-name"):
        value = element.get(attr, "").strip()
        if value:
            return value.strip("'\"")
    return ""


def _form_model_attr(form: ElementTree.Element) -> str:
    for attr in (
        "data-model_name",
        "data-model-name",
        "data-model",
        "t-att-data-model_name",
        "t-att-data-model-name",
        "t-att-data-model",
        "t-attf-data-model_name",
        "t-attf-data-model-name",
        "t-attf-data-model",
    ):
        value = form.get(attr, "").strip()
        if value:
            return value.strip("'\"")
    return ""


def _form_action(form: ElementTree.Element) -> str:
    for attr in ("action", "t-att-action", "t-attf-action"):
        value = form.get(attr, "").strip()
        if value:
            return value.strip("'\"")
    return ""


def _line_for_form_action(content: str, action: str) -> int:
    for attr in ("action", "t-att-action", "t-attf-action"):
        for quote in ('"', "'"):
            line = _line_for(content, f"{attr}={quote}{action}{quote}")
            if line != 1:
                return line
    return _line_for(content, action)


def _line_for(content: str, needle: str) -> int:
    index = content.find(needle)
    if index < 0:
        return 1
    return content[:index].count("\n") + 1


def _is_external_url(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith(("http://", "https://", "//"))


def _is_dangerous_url_scheme(value: str) -> bool:
    lowered = value.strip().strip("'\"").lower()
    return lowered.startswith(
        (
            "javascript:",
            "vbscript:",
            "file:",
            "data:text/html",
            "data:application/javascript",
            "data:application/xhtml+xml",
        )
    )


def _class_model_name(node: ast.ClassDef) -> str:
    model_name = ""
    inherit_name = ""
    for statement in node.body:
        if not isinstance(statement, ast.Assign):
            continue
        for target in statement.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == "_name":
                model_name = _constant_string(statement.value)
            elif target.id == "_inherit":
                inherit_name = _constant_string(statement.value)
    return model_name or inherit_name


def _is_website_form_allowed_field(node: ast.AST | None, constants: dict[str, ast.AST] | None = None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if not _field_call_type(node.func):
        return False
    return any(
        keyword.arg == "website_form_blacklisted" and _is_false_constant(keyword.value, constants)
        for keyword in node.keywords
    )


def _field_call_type(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "fields":
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _website_form_route_with_csrf_disabled(
    node: ast.FunctionDef | ast.AsyncFunctionDef, constants: dict[str, ast.AST] | None = None
) -> str:
    for decorator in node.decorator_list:
        route = _http_route_path(decorator, constants)
        if route and "/website/form" in route and _route_csrf_disabled(decorator, constants):
            return route
    return ""


def _http_route_path(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    if isinstance(node, ast.Call):
        if not _is_http_route(node.func):
            return ""
        if node.args:
            return _route_path_from_arg(node.args[0], constants)
        for keyword in node.keywords:
            if keyword.arg == "route":
                return _route_path_from_arg(keyword.value, constants)
        return ""
    if _is_http_route(node):
        return ""
    return ""


def _route_path_from_arg(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> str:
    node = _resolve_constant(node, constants or {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.List | ast.Tuple):
        return " ".join(_route_path_from_arg(element, constants) for element in node.elts)
    return ""


def _route_csrf_disabled(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    if not isinstance(node, ast.Call):
        return False
    return any(
        keyword.arg == "csrf" and _is_false_constant(keyword.value, constants)
        for keyword in node.keywords
    )


def _call_disables_sanitize_form(node: ast.Call, constants: dict[str, ast.AST] | None = None) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "sanitize_form" and _is_false_constant(keyword.value, constants):
            return True
    return False


def _is_http_route(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "route"
    if isinstance(node, ast.Name):
        return node.id == "route"
    return False


def _assigned_field_name(node: ast.AST) -> str:
    return node.id if isinstance(node, ast.Name) else ""


def _constant_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    return _static_constants_from_body(tree.body)


def _static_constants_from_body(statements: list[ast.stmt]) -> dict[str, ast.AST]:
    constants: dict[str, ast.AST] = {}
    for statement in statements:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and _is_static_literal(statement.value):
                    constants[target.id] = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.value is not None
            and _is_static_literal(statement.value)
        ):
            constants[statement.target.id] = statement.value
    return constants


def _resolve_constant(node: ast.AST, constants: dict[str, ast.AST]) -> ast.AST:
    if isinstance(node, ast.Name):
        return constants.get(node.id, node)
    return node


def _is_static_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str | bool | int | float | type(None))
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return all(_is_static_literal(element) for element in node.elts)
    return False


def _is_false_constant(node: ast.AST, constants: dict[str, ast.AST] | None = None) -> bool:
    value = _resolve_constant(node, constants or {})
    return isinstance(value, ast.Constant) and value.value is False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"__pycache__", ".venv", "venv", ".git", "node_modules", "htmlcov", "tests"})


def findings_to_json(findings: list[WebsiteFormFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "model": f.model,
            "field": f.field,
        }
        for f in findings
    ]
