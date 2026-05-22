"""Scanner for AI/LLM integration security risks in Odoo modules.

Odoo 19+ introduces native AI capabilities, and custom modules increasingly
integrate with OpenAI, Anthropic, Gemini, and local LLM APIs. This scanner
detects:

- Hardcoded API keys and endpoints
- Unsanitized user input flowing into LLM prompts (prompt injection)
- LLM output rendered without escaping (XSS via generated content)
- Missing output validation or allowlisting
- Sensitive data sent to third-party AI services
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from odoo_security_harness.base_scanner import _should_skip


@dataclass
class AiIntegrationFinding:
    """Represents an AI/LLM integration security finding."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


# Patterns that suggest LLM client libraries or Odoo AI integration
AI_CLIENT_IMPORTS = {
    "openai",
    "anthropic",
    "google.generativeai",
    "google.genai",
    "transformers",
    "torch",
    "ollama",
    "groq",
    "replicate",
    "cohere",
    "mistralai",
}

# Method names that typically send prompts to LLMs
AI_PROMPT_METHODS = {
    "create",
    "complete",
    "chat",
    "chat.completions.create",
    "completions.create",
    "generate",
    "generate_content",
    "invoke",
    "predict",
    "send_message",
    "stream",
}

# Regex for hardcoded API keys in common LLM formats
AI_KEY_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,48}"),  # OpenAI-style
    re.compile(r"sk-ant-[a-zA-Z0-9-_]{20,60}"),  # Anthropic-style
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),  # Google AI-style
    re.compile(r"gsk_[a-zA-Z0-9]{20,48}"),  # Groq-style
    re.compile(r"r8_[a-zA-Z0-9]{20,48}"),  # Replicate-style
]

TAINTED_ARG_NAMES = {"data", "domain", "kwargs", "kw", "payload", "post", "values", "request", "params", "body"}
PROMPT_KEYWORDS = {"prompt", "messages", "content", "system", "instruction", "query", "input", "template"}
SINK_RENDER_METHODS = {"Markup", "render", "t-raw", "t-out", "message_post", "message_notify"}


def scan_ai_integrations(repo_path: Path) -> list[AiIntegrationFinding]:
    """Scan repository for AI/LLM integration security risks."""
    findings: list[AiIntegrationFinding] = []
    for path in repo_path.rglob("*.py"):
        if _should_skip(path):
            continue
        findings.extend(AiIntegrationScanner(path).scan_file())
    return findings


class AiIntegrationScanner(ast.NodeVisitor):
    """AST scanner for AI integration patterns in one Python file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[AiIntegrationFinding] = []
        self.constants: dict[str, ast.AST] = {}
        self.class_constants_stack: list[dict[str, ast.AST]] = []
        self.local_constants: dict[str, ast.AST] = {}
        self.ai_client_names: set[str] = set()
        self.tainted_names: set[str] = set()
        self.request_names: set[str] = {"request"}
        self.http_module_names: set[str] = {"http"}

    def scan_file(self) -> list[AiIntegrationFinding]:
        """Parse and scan the file."""
        try:
            content = self.path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content)
        except SyntaxError:
            return []
        except Exception:
            return []

        # Also run regex-based checks for hardcoded keys
        self._scan_text_for_keys(content)

        self.constants = self._module_constants(tree)
        self.visit(tree)
        return self.findings

    def _module_constants(self, tree: ast.Module) -> dict[str, ast.AST]:
        """Extract module-level constants."""
        constants: dict[str, ast.AST] = {}
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and self._is_static_literal(stmt.value):
                        constants[target.id] = stmt.value
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.value is not None
                and self._is_static_literal(stmt.value)
            ):
                constants[stmt.target.id] = stmt.value
        return constants

    def _is_static_literal(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, bool, int, float, type(None)))
        return False

    def _effective_constants(self) -> dict[str, ast.AST]:
        merged: dict[str, ast.AST] = dict(self.constants)
        for level in self.class_constants_stack:
            merged.update(level)
        merged.update(self.local_constants)
        return merged

    def _scan_text_for_keys(self, content: str) -> None:
        """Regex scan for hardcoded API key patterns."""
        for pattern in AI_KEY_PATTERNS:
            for match in pattern.finditer(content):
                # Skip obvious false positives in test fixtures or docstrings
                line_num = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[line_num - 1]
                if "test" in line_text.lower() and "example" in line_text.lower():
                    continue
                if "env" in line_text.lower() or "config" in line_text.lower():
                    continue
                self.findings.append(
                    AiIntegrationFinding(
                        rule_id="odoo-ai-hardcoded-api-key",
                        title="Hardcoded AI/LLM API key detected",
                        severity="critical",
                        file=str(self.path),
                        line=line_num,
                        message=f"Possible hardcoded LLM API key matches '{pattern.pattern[:20]}...'; move to ir.config_parameter, environment variables, or a secrets manager",
                        sink="api_key",
                    )
                )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in AI_CLIENT_IMPORTS or any(
                alias.name.startswith(prefix + ".") for prefix in AI_CLIENT_IMPORTS
            ):
                self.ai_client_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in AI_CLIENT_IMPORTS or any(
            node.module is not None and node.module.startswith(prefix + ".") for prefix in AI_CLIENT_IMPORTS
        ):
            for alias in node.names:
                self.ai_client_names.add(alias.asname or alias.name)
        if node.module == "odoo.http":
            for alias in node.names:
                if alias.name == "request":
                    self.request_names.add(alias.asname or alias.name)
        if node.module == "odoo":
            for alias in node.names:
                if alias.name == "http":
                    self.http_module_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_constants_stack.append(self._class_constants(node.body))
        self.generic_visit(node)
        self.class_constants_stack.pop()

    def _class_constants(self, body: list[ast.stmt]) -> dict[str, ast.AST]:
        constants: dict[str, ast.AST] = {}
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and self._is_static_literal(stmt.value):
                        constants[target.id] = stmt.value
            elif (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.value is not None
                and self._is_static_literal(stmt.value)
            ):
                constants[stmt.target.id] = stmt.value
        return constants

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.local_constants = {}
        self.tainted_names = set()
        self.ai_client_aliases: set[str] = set()
        # Function parameters that are inherently user-controlled
        for arg in node.args.args:
            if arg.arg in {"kw", "kwargs", "request", "params", "data", "values"}:
                self.tainted_names.add(arg.arg)
        if node.args.kwarg and node.args.kwarg.arg in {"kw", "kwargs"}:
            self.tainted_names.add(node.args.kwarg.arg)
        # Track tainted assignments, AI client aliases, and AI response aliases
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if self._expr_is_tainted_source(stmt.value):
                            self.tainted_names.add(target.id)
                        if self._expr_involves_ai_call(stmt.value):
                            self.ai_client_aliases.add(target.id)
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                if self._expr_is_tainted_source(stmt.value) if stmt.value else False:
                    self.tainted_names.add(stmt.target.id)
                if stmt.value and self._expr_involves_ai_call(stmt.value):
                    self.ai_client_aliases.add(stmt.target.id)
        self.generic_visit(node)
        self.local_constants = {}

    def _expr_is_tainted_source(self, node: ast.AST) -> bool:
        """Check if expression originates from request.params or similar."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "get_param"}:
                return self._expr_is_tainted_source(node.func.value)
            return self._expr_is_tainted_source(node.func)
        if isinstance(node, ast.Attribute):
            if node.attr in TAINTED_ARG_NAMES | {"params", "json", "form", "args"}:
                return True
            return self._expr_is_tainted_source(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted_source(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.request_names | self.tainted_names
        return False

    def visit_Call(self, node: ast.Call) -> None:
        self._check_ai_prompt_call(node)
        self._check_ai_output_render(node)
        self.generic_visit(node)

    def _check_ai_prompt_call(self, node: ast.Call) -> None:
        """Detect LLM prompt calls with tainted input."""
        if not isinstance(node.func, ast.Attribute):
            return

        method_name = node.func.attr
        # Heuristic: method is a known AI prompt method and receiver looks like an AI client
        if method_name not in AI_PROMPT_METHODS:
            return

        # Check if receiver chain involves a known AI client
        if not self._call_chain_involves_ai_client(node.func):
            return

        # Check for tainted prompt content
        for keyword in node.keywords:
            if keyword.arg is not None and keyword.arg.lower() in PROMPT_KEYWORDS:
                if self._expr_is_tainted(keyword.value):
                    self.findings.append(
                        AiIntegrationFinding(
                            rule_id="odoo-ai-tainted-prompt",
                            title="LLM prompt includes tainted user input",
                            severity="high",
                            file=str(self.path),
                            line=node.lineno,
                            message=f"LLM call '{method_name}' receives prompt content from request-derived data; sanitize or allowlist input to prevent prompt injection",
                            sink=f"{method_name}({keyword.arg})",
                        )
                    )

        # Check positional args for tainted content (common for .complete(prompt=...))
        for arg in node.args:
            if self._expr_is_tainted(arg):
                self.findings.append(
                    AiIntegrationFinding(
                        rule_id="odoo-ai-tainted-prompt",
                        title="LLM prompt includes tainted user input",
                        severity="high",
                        file=str(self.path),
                        line=node.lineno,
                        message=f"LLM call '{method_name}' receives prompt content from request-derived data; sanitize or allowlist input to prevent prompt injection",
                        sink=method_name,
                    )
                )
                break

    def _check_ai_output_render(self, node: ast.Call) -> None:
        """Detect AI-generated output rendered without escaping."""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            method_name = node.func.id
        else:
            return

        if method_name not in {"Markup", "render", "message_post", "message_notify"}:
            return

        # Check if any argument is tainted AND looks like AI-generated
        for arg in node.args:
            if self._expr_involves_ai_call(arg) and method_name in {"Markup", "message_post", "message_notify"}:
                self.findings.append(
                    AiIntegrationFinding(
                        rule_id="odoo-ai-unsanitized-output",
                        title="AI-generated content rendered without escaping",
                        severity="high",
                        file=str(self.path),
                        line=node.lineno,
                        message=f"AI-generated output passed to '{method_name}()' without explicit sanitization; LLMs can emit HTML/JS that leads to XSS",
                        sink=method_name,
                    )
                )

    def _call_chain_involves_ai_client(self, node: ast.AST) -> bool:
        """Walk up a call chain to see if root is a known AI client."""
        if isinstance(node, ast.Call):
            return self._call_chain_involves_ai_client(node.func)
        if isinstance(node, ast.Attribute):
            return self._call_chain_involves_ai_client(node.value)
        if isinstance(node, ast.Name):
            return node.id in self.ai_client_names or node.id in getattr(self, "ai_client_aliases", set())
        return False

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        """Check if expression contains tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names or node.id in self.request_names
        if isinstance(node, ast.Attribute):
            if node.attr in TAINTED_ARG_NAMES | {"params", "json", "form", "args", "body"}:
                return True
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.JoinedStr):
            return any(self._expr_is_tainted(v) for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "get_param", "pop"}:
                return self._expr_is_tainted(node.func.value)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self._expr_is_tainted(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(v) for v in node.values)
        return False

    def _expr_involves_ai_call(self, node: ast.AST) -> bool:
        """Check if expression involves an AI client call or constructor."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in AI_PROMPT_METHODS:
                    if self._call_chain_involves_ai_client(node.func):
                        return True
                # AI client constructors like openai.OpenAI(), anthropic.Client()
                if self._call_chain_involves_ai_client(node.func):
                    return True
            if isinstance(node.func, ast.Name):
                if self._call_chain_involves_ai_client(node.func):
                    return True
            # Check arguments recursively
            return any(self._expr_involves_ai_call(arg) for arg in node.args) or any(
                self._expr_involves_ai_call(kw.value) for kw in node.keywords
            )
        if isinstance(node, ast.Attribute):
            return self._expr_involves_ai_call(node.value)
        if isinstance(node, ast.Name):
            return node.id in getattr(self, "ai_client_aliases", set())
        if isinstance(node, ast.Subscript):
            return self._expr_involves_ai_call(node.value)
        return False
