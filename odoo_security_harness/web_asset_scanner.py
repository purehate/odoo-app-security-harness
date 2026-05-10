"""Scanner for Odoo JavaScript/OWL frontend assets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class WebAssetFinding:
    """Represents a finding in frontend assets."""

    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    message: str
    sink: str = ""


DOM_XSS_PATTERNS = {
    "innerHTML": re.compile(r"\.innerHTML\s*="),
    "outerHTML": re.compile(r"\.outerHTML\s*="),
    "insertAdjacentHTML": re.compile(r"\.insertAdjacentHTML\s*\("),
    "document.write": re.compile(r"\bdocument\.write(?:ln)?\s*\("),
    "jquery.html": re.compile(r"\.(?:html|append|prepend|before|after|replaceWith)\s*\(\s*[^)\s]"),
    "jquery.parseHTML": re.compile(r"(?:\$|jQuery)\.parseHTML\s*\("),
    "DOMParser.parseFromString": re.compile(
        r"\.parseFromString\s*\([^,\n]+,\s*['\"]text/html['\"]",
        re.IGNORECASE,
    ),
    "Range.createContextualFragment": re.compile(r"\.createContextualFragment\s*\("),
    "iframe.srcdoc": re.compile(r"\.srcdoc\s*=|\.setAttribute\s*\(\s*['\"]srcdoc['\"]\s*,"),
}
DOM_EVENT_HANDLER_NAMES = (
    "abort",
    "auxclick",
    "beforeinput",
    "blur",
    "change",
    "click",
    "dblclick",
    "error",
    "focus",
    "input",
    "keydown",
    "keypress",
    "keyup",
    "load",
    "mousedown",
    "mouseenter",
    "mouseleave",
    "mousemove",
    "mouseout",
    "mouseover",
    "mouseup",
    "pointerdown",
    "pointerenter",
    "pointerleave",
    "pointermove",
    "pointerout",
    "pointerover",
    "pointerup",
    "submit",
    "touchend",
    "touchmove",
    "touchstart",
    "wheel",
)
DOM_EVENT_HANDLER_NAME_RE = "|".join(f"on{name}" for name in DOM_EVENT_HANDLER_NAMES)
DOM_EVENT_HANDLER_ASSIGNMENT_RE = re.compile(
    rf"\.(?P<event>{DOM_EVENT_HANDLER_NAME_RE})\s*=\s*(?P<value>[^;\n]+)",
    re.IGNORECASE,
)
DOM_EVENT_HANDLER_SETATTRIBUTE_RE = re.compile(
    rf"\.setAttribute\s*\(\s*['\"](?P<event>{DOM_EVENT_HANDLER_NAME_RE})['\"]\s*,\s*(?P<value>[^)\n]+)",
    re.IGNORECASE,
)
DOM_EVENT_HANDLER_TAINT_RE = re.compile(
    r"\b(?:event\.data|response\.\w+|data\.\w+|payload(?:\.\w+)?|params(?:\.\w+)?|props(?:\.\w+)?|"
    r"URLSearchParams|location\.(?:search|hash)|document\.referrer|JSON\.parse|requestData|notificationData|"
    r"html|markup|script)\b",
    re.IGNORECASE,
)

STRING_EVAL_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "Function": re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\("),
    "jquery.globalEval": re.compile(r"(?:\$|jQuery)\.globalEval\s*\("),
    "setTimeout-string": re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]"),
}
DYNAMIC_IMPORT_RE = re.compile(r"\bimport\s*\(\s*(?P<target>[^)\n]+)")
DYNAMIC_WORKER_RE = re.compile(r"\bnew\s+(?P<kind>SharedWorker|Worker)\s*\(\s*(?P<target>[^,\)\n]+)")
IMPORT_SCRIPTS_RE = re.compile(r"\bimportScripts\s*\((?P<args>[^;\n]+)\)")
SERVICE_WORKER_REGISTER_RE = re.compile(r"\bnavigator\.serviceWorker\.register\s*\(\s*(?P<target>[^,\)\n]+)")
WASM_DYNAMIC_LOAD_RE = re.compile(
    r"\bWebAssembly\.(?P<sink>instantiateStreaming|compileStreaming|instantiate|compile)\s*\(\s*"
    r"(?P<fetch>fetch\s*\(\s*)?(?P<target>[^,\)\n]+)"
)
CSS_STYLE_INJECTION_RE = re.compile(r"\.(?P<sink>replaceSync|replace|insertRule)\s*\(\s*(?P<css>[^,\)\n]+)")
LIVE_CONNECTION_RE = re.compile(r"\bnew\s+(?P<kind>WebSocket|EventSource)\s*\(\s*(?P<target>[^,\)\n]+)")
DOCUMENT_DOMAIN_ASSIGN_RE = re.compile(r"\bdocument\.domain\s*=")
DOCUMENT_COOKIE_ASSIGN_RE = re.compile(r"\bdocument\.cookie\s*=\s*(?P<value>.+)")
WINDOW_NAME_ASSIGN_RE = re.compile(r"\b(?:window\.)?name\s*=\s*(?P<value>.+)")
INDEXEDDB_WRITE_RE = re.compile(r"\.(?P<sink>put|add)\s*\(\s*(?P<value>[^)\n]+)")
CACHE_API_WRITE_RE = re.compile(r"\.(?P<sink>put|add|addAll)\s*\(\s*(?P<args>[^)\n]+)")
CONSOLE_CALL_RE = re.compile(r"\bconsole\.(?P<sink>log|debug|info|warn|error|trace)\s*\(\s*(?P<args>[^)\n]+)")
SEND_BEACON_RE = re.compile(r"\bnavigator\.sendBeacon\s*\((?P<args>[^;\n]+)\)")
CLIPBOARD_WRITE_RE = re.compile(r"\bnavigator\.clipboard\.(?P<sink>writeText|write)\s*\(\s*(?P<value>[^)\n]+)")
NOTIFICATION_RE = re.compile(
    r"\b(?P<sink>new\s+Notification|showNotification)\s*\((?P<args>[^;\n]+)\)",
    re.IGNORECASE,
)
WEB_CREDENTIAL_RE = re.compile(
    r"\b(?P<sink>navigator\.credentials\.store|new\s+(?:PasswordCredential|FederatedCredential))\s*\("
    r"(?P<value>[^;\n]+)"
)
CRYPTO_IMPORT_KEY_RE = re.compile(r"\b(?:crypto|window\.crypto)\.subtle\.importKey\s*\((?P<args>[^;\n]+)\)")
OBJECT_URL_RE = re.compile(r"\bURL\.createObjectURL\s*\((?P<value>[^;\n]+)\)")
HISTORY_STATE_RE = re.compile(r"\bhistory\.(?P<sink>pushState|replaceState)\s*\((?P<args>[^;\n]+)\)")
BROADCAST_CHANNEL_RE = re.compile(r"\bnew\s+BroadcastChannel\s*\(\s*(?P<name>[^)\n]+)")
BROADCAST_CHANNEL_POSTMESSAGE_RE = re.compile(
    r"\b(?P<sink>broadcastChannel|channel|bc)\.postMessage\s*\(\s*(?P<value>[^)\n]+)",
    re.IGNORECASE,
)
BUS_CHANNEL_CALL_RE = re.compile(
    r"\b(?P<receiver>(?:this\.)?(?:bus|busService|bus_service)|(?:this\.)?env\.services\.bus_service)\."
    r"(?P<method>addChannel|addChannels|subscribe|subscribeTo)\s*\((?P<args>[^;\n]+)",
    re.IGNORECASE,
)
BROAD_BUS_CHANNEL_RE = re.compile(
    r"^(?:global|broadcast|public|public[_-]notifications?|notifications?|mail\.channel|mail_channel)$",
    re.IGNORECASE,
)

RPC_CALL_RE = re.compile(r"\b(?:jsonrpc|rpc|ajax\.jsonRpc)\s*\(")
ORM_SERVICE_CALL_RE = re.compile(
    r"\b(?P<receiver>(?:this\.)?orm|ormService|orm_service)\."
    r"(?P<method>call|silentCall|searchRead|webSearchRead|read|create|write|unlink)\s*\((?P<args>[^;\n]*)",
    re.IGNORECASE,
)
ORM_SERVICE_TAINT_RE = re.compile(
    r"\b(?:event\.data|response\.\w+|data\.\w+|payload(?:\.\w+)?|params(?:\.\w+)?|props(?:\.\w+)?|"
    r"URLSearchParams|location\.(?:search|hash)|document\.referrer|JSON\.parse|requestData|notificationData)\b",
    re.IGNORECASE,
)
RAW_HTTP_REQUEST_RE = re.compile(r"\b(?:fetch|axios\.(?:post|put|patch|delete)|(?:\$|jQuery)\.ajax)\s*\(")
UNSAFE_HTTP_METHOD_RE = re.compile(
    r"(?:method|type)\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|" r"\baxios\.(?:post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)
CSRF_TOKEN_RE = re.compile(r"\b(?:csrf_token|csrfToken|csrf-token|X-CSRFToken|X-CSRF-Token)\b", re.IGNORECASE)
SENSITIVE_STORAGE_RE = re.compile(
    r"\b(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:token|secret|password|api[_-]?key|csrf|session)[^'\"]*['\"]",
    re.IGNORECASE,
)
SENSITIVE_STORAGE_ASSIGNMENT_RE = re.compile(
    r"\b(?:localStorage|sessionStorage)\s*"
    r"(?:\.\s*(?P<property>[A-Za-z_$][\w$]*)|\[\s*['\"](?P<bracket>[^'\"]+)['\"]\s*\])"
    r"\s*=\s*(?P<value>[^;\n]+)",
    re.IGNORECASE,
)
SENSITIVE_URL_PARAM_NAME_RE = re.compile(
    r"(?:access[_-]?token|auth[_-]?token|api[_-]?key|secret|password|session|csrf|jwt|bearer)",
    re.IGNORECASE,
)
SENSITIVE_URL_PARAM_SET_RE = re.compile(r"\.(?:set|append)\s*\(\s*['\"](?P<key>[^'\"]+)['\"]\s*,\s*(?P<value>[^)\n]+)")
SENSITIVE_URL_QUERY_RE = re.compile(
    r"(?:[?#&]|%3[fF]|%26)[^'\"`\s={}]*"
    r"(?:access[_-]?token|auth[_-]?token|api[_-]?key|secret|password|session|csrf|jwt|bearer)"
    r"[^'\"`\s={}]*=",
    re.IGNORECASE,
)
SENSITIVE_URL_DYNAMIC_VALUE_RE = re.compile(
    r"\$\{|(?:^|[^+\w])\+|encodeURIComponent\s*\(|\b(?:response|payload|data|props|params|token|secret|password|session|csrf)\b",
    re.IGNORECASE,
)
POSTMESSAGE_WILDCARD_RE = re.compile(r"\.postMessage\s*\(.*,\s*['\"]\*['\"]")
OBJECT_MERGE_PATTERNS = {
    "Object.assign": re.compile(r"\bObject\.assign\s*\("),
    "extend": re.compile(r"(?:\b_|\$|\bjQuery)\.extend\s*\("),
    "merge": re.compile(r"(?:\b_|\$|\bjQuery)\.merge\s*\("),
}
OBJECT_SPREAD_RE = re.compile(r"\{\s*\.\.\.\s*(?:event\.data|response\.\w+|data\.\w+|payload|params|props)\b")
PROTOTYPE_MUTATION_RE = re.compile(
    r"(?:\[['\"]__proto__['\"]\]|\.__proto__|\bconstructor\.prototype\b|\bprototype\s*\[\s*['\"])",
    re.IGNORECASE,
)
OBJECT_MERGE_TAINT_RE = re.compile(
    r"\b(?:event\.data|response\.\w+|data\.\w+|payload|params|props|URLSearchParams|location\.(?:search|hash)|JSON\.parse)\b",
    re.IGNORECASE,
)
SAFE_MARKUP_RE = re.compile(r"\b(?:markup|Markup)\s*\(")
SAFE_MARKUP_CALL_RE = re.compile(r"\b(?:markup|Markup)\s*\((?P<value>[^)\n]+)\)")
SAFE_MARKUP_TAINT_RE = re.compile(
    r"(?:\b(?:event\.data|response\.\w+|data\.\w+|payload(?:\.\w+)?|params|props|"
    r"URLSearchParams|location\.(?:search|hash)|document\.referrer|JSON\.parse|"
    r"(?:\w+\.)?responseText)\b|\b(?:fetch|axios\.(?:get|post|request))\s*\()",
    re.IGNORECASE,
)
HTML_TAINT_ASSIGNMENT_RE = re.compile(
    r"\b(?:(?:const|let|var)\s+)?(?P<target>(?:this\.)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*=\s*(?P<value>[^;\n]+)"
)
HTML_LIKE_TARGET_RE = re.compile(r"(?:html|markup|fragment|content|body|template)", re.IGNORECASE)
HTML_SANITIZER_RE = re.compile(
    r"\b(?:DOMPurify\.sanitize|sanitizeHTML|sanitizeHtml|html_escape|escapeHtml|_.escape)\s*\(",
    re.IGNORECASE,
)
CLIENT_NAVIGATION_PATTERNS = {
    "location": re.compile(r"\b(?:window\.)?location\s*="),
    "location.href": re.compile(r"\b(?:window\.)?location\.href\s*="),
    "location.assign": re.compile(r"\b(?:window\.)?location\.(?:assign|replace)\s*\("),
    "window.open": re.compile(r"\bwindow\.open\s*\("),
}
WINDOW_OPEN_CALL_RE = re.compile(r"\bwindow\.open\s*\((?P<args>[^;\n]*)\)")
DOM_TARGET_BLANK_RE = re.compile(
    r"\.target\s*=\s*['\"]_blank['\"]|\.setAttribute\s*\(\s*['\"]target['\"]\s*,\s*['\"]_blank['\"]\s*\)",
    re.IGNORECASE,
)
DOM_REL_OPENER_ISOLATION_RE = re.compile(
    r"\.rel\s*=\s*['\"][^'\"]*\b(?:noopener|noreferrer)\b|"
    r"\.setAttribute\s*\(\s*['\"]rel['\"]\s*,\s*['\"][^'\"]*\b(?:noopener|noreferrer)\b",
    re.IGNORECASE,
)
DOM_IFRAME_SANDBOX_LITERAL_RE = re.compile(
    r"\.sandbox\s*=\s*['\"](?P<property>[^'\"]*)['\"]|"
    r"\.setAttribute\s*\(\s*['\"]sandbox['\"]\s*,\s*['\"](?P<attribute>[^'\"]*)['\"]\s*\)",
    re.IGNORECASE,
)
DOM_IFRAME_CREATE_RE = re.compile(
    r"\b(?:const|let|var)?\s*(?P<name>[A-Za-z_$][\w$]*)\s*=\s*document\.createElement\s*\(\s*['\"]iframe['\"]\s*\)",
    re.IGNORECASE,
)
DOM_SCRIPT_CREATE_RE = re.compile(
    r"\b(?:const|let|var)?\s*(?P<name>[A-Za-z_$][\w$]*)\s*=\s*document\.createElement\s*\(\s*['\"]script['\"]\s*\)",
    re.IGNORECASE,
)
DOM_LINK_CREATE_RE = re.compile(
    r"\b(?:const|let|var)?\s*(?P<name>[A-Za-z_$][\w$]*)\s*=\s*document\.createElement\s*\(\s*['\"]link['\"]\s*\)",
    re.IGNORECASE,
)
DOM_URL_ATTRIBUTE_PATTERNS = {
    "element.href": re.compile(r"\.(?:href|src|action)\s*="),
    "setAttribute-url": re.compile(r"\.setAttribute\s*\(\s*['\"](?:href|src|action)['\"]\s*,"),
    "jquery.attr-url": re.compile(r"\.(?:attr|prop)\s*\(\s*['\"](?:href|src|action)['\"]\s*,"),
}
CLIENT_NAVIGATION_TAINT_RE = re.compile(
    r"\b(?:URLSearchParams|location\.(?:search|hash)|document\.referrer|event\.data|"
    r"response\.\w+|data\.\w+|payload\.\w+|redirect(?:_url)?|return_url|next|url)\b",
    re.IGNORECASE,
)
CLIENT_NAVIGATION_TARGET_RE = re.compile(r"(?:=\s*|\(\s*)(?P<target>[^,);\n]+)")
DOM_URL_ATTRIBUTE_TARGET_RE = re.compile(r"(?:=\s*|,\s*)(?P<target>[^,);\n]+)")
DANGEROUS_URL_SCHEMES = (
    "javascript:",
    "vbscript:",
    "data:text/html",
    "data:application/javascript",
    "data:application/xhtml+xml",
    "file:",
)
ACTION_URL_RE = re.compile(r"\b(?:do_action|doAction)\s*\(")
ACTION_CALL_TARGET_RE = re.compile(r"\b(?:do_action|doAction)\s*\(\s*(?P<target>[^,\n;)]+)")
ACTION_URL_TYPE_RE = re.compile(r"(?:['\"]type['\"]|type)\s*:\s*['\"]ir\.actions\.act_url['\"]")
ACTION_URL_TARGET_RE = re.compile(r"(?:['\"]url['\"]|url)\s*:\s*(?P<target>[^,}\n]+)")
ACTION_WINDOW_TYPE_RE = re.compile(r"(?:['\"]type['\"]|type)\s*:\s*['\"]ir\.actions\.act_window['\"]")
ACTION_WINDOW_DYNAMIC_FIELD_RE = re.compile(
    r"(?:['\"](?:res_model|domain|context|res_id|views|view_id)['\"]|"
    r"\b(?:res_model|domain|context|res_id|views|view_id))\s*:",
    re.IGNORECASE,
)
ACTION_WINDOW_UNQUOTED_FIELD_RE = re.compile(
    r"(?:['\"](?P<quoted>res_model|domain|context|res_id|views|view_id)['\"]|"
    r"\b(?P<plain>res_model|domain|context|res_id|views|view_id))\s*:\s*"
    r"(?P<value>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)",
    re.IGNORECASE,
)
ACTION_WINDOW_TAINT_RE = re.compile(
    r"\b(?:event\.data|response\.\w+|data\.\w+|payload(?:\.\w+)?|params(?:\.\w+)?|props(?:\.\w+)?|"
    r"URLSearchParams|location\.(?:search|hash)|document\.referrer|JSON\.parse|requestData|notificationData)\b",
    re.IGNORECASE,
)
MESSAGE_LISTENER_RE = re.compile(
    r"(?:addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=)",
    re.IGNORECASE,
)
MESSAGE_ORIGIN_VALIDATION_RE = re.compile(
    r"\.origin\b.*(?:===|!==|==|!=|includes\s*\(|indexOf\s*\(|startsWith\s*\(|endsWith\s*\(|\.test\s*\(|\.match\s*\()|"
    r"(?:===|!==|==|!=|includes\s*\(|indexOf\s*\(|startsWith\s*\(|endsWith\s*\(|\.test\s*\(|\.match\s*\().*\.origin\b",
    re.IGNORECASE,
)


def scan_web_assets(repo_path: Path) -> list[WebAssetFinding]:
    """Scan JS/TS assets in Odoo static directories."""
    findings: list[WebAssetFinding] = []
    for path in repo_path.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        if path.suffix.lower() not in {".js", ".ts", ".jsx", ".tsx"}:
            continue
        if "static" not in path.parts:
            continue
        findings.extend(WebAssetScanner(path).scan_file())
    return findings


class WebAssetScanner:
    """Line-oriented scanner for one frontend asset."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[WebAssetFinding] = []

    def scan_file(self) -> list[WebAssetFinding]:
        """Scan a frontend file."""
        try:
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return []

        tainted_markup_values: set[str] = set()
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            markup_assignment_match = HTML_TAINT_ASSIGNMENT_RE.search(line)
            if markup_assignment_match and _looks_tainted_markup_assignment(
                markup_assignment_match.group("target"), markup_assignment_match.group("value")
            ):
                tainted_markup_values.add(_normalize_js_reference(markup_assignment_match.group("target")))

            for sink, pattern in DOM_XSS_PATTERNS.items():
                if pattern.search(line):
                    self._add(
                        "odoo-web-dom-xss-sink",
                        "DOM HTML injection sink",
                        "high",
                        line_number,
                        f"{sink} writes HTML in frontend code; verify data is sanitized or generated from trusted templates",
                        sink,
                    )

            event_handler_match = DOM_EVENT_HANDLER_ASSIGNMENT_RE.search(line)
            if event_handler_match and _looks_risky_dom_event_handler_value(event_handler_match.group("value")):
                event_name = event_handler_match.group("event")
                self._add(
                    "odoo-web-dom-xss-sink",
                    "DOM event handler injection sink",
                    "high",
                    line_number,
                    f"{event_name} receives string or request-derived JavaScript in frontend code; use addEventListener with trusted handlers and keep untrusted data out of event attributes",
                    "dom-event-handler",
                )

            event_attribute_match = DOM_EVENT_HANDLER_SETATTRIBUTE_RE.search(line)
            if event_attribute_match and _looks_risky_dom_event_handler_value(event_attribute_match.group("value")):
                event_name = event_attribute_match.group("event")
                self._add(
                    "odoo-web-dom-xss-sink",
                    "DOM event handler injection sink",
                    "high",
                    line_number,
                    f"{event_name} is set through setAttribute with string or request-derived JavaScript; use addEventListener with trusted handlers and keep untrusted data out of event attributes",
                    "setAttribute-event-handler",
                )

            for sink, pattern in STRING_EVAL_PATTERNS.items():
                if pattern.search(line):
                    self._add(
                        "odoo-web-string-code-execution",
                        "String-based JavaScript execution",
                        "high",
                        line_number,
                        f"{sink} executes string code in frontend asset; verify no user-controlled data reaches it",
                        sink,
                    )

            import_match = DYNAMIC_IMPORT_RE.search(line)
            if import_match and _looks_risky_dynamic_import_target(import_match.group("target")):
                self._add(
                    "odoo-web-dynamic-code-import",
                    "Dynamic JavaScript import uses external or request-derived target",
                    "high",
                    line_number,
                    "Frontend code imports JavaScript at runtime from an external or dynamic target; restrict module sources to reviewed bundles or strict allowlists",
                    "import",
                )

            worker_match = DYNAMIC_WORKER_RE.search(line)
            if worker_match and _looks_risky_dynamic_import_target(worker_match.group("target")):
                self._add(
                    "odoo-web-dynamic-worker-script",
                    "Worker script uses external or request-derived target",
                    "high",
                    line_number,
                    "Frontend code starts a Worker from an external or dynamic script target; restrict worker scripts to reviewed bundles or strict allowlists",
                    worker_match.group("kind"),
                )

            import_scripts_match = IMPORT_SCRIPTS_RE.search(line)
            if import_scripts_match and _looks_risky_import_scripts(import_scripts_match.group("args")):
                self._add(
                    "odoo-web-dynamic-import-scripts",
                    "Worker importScripts loads external or request-derived script",
                    "high",
                    line_number,
                    "Worker code imports scripts at runtime from an external or dynamic target; restrict importScripts sources to reviewed same-origin bundles or strict allowlists",
                    "importScripts",
                )

            service_worker_match = SERVICE_WORKER_REGISTER_RE.search(line)
            if service_worker_match and _looks_risky_dynamic_import_target(service_worker_match.group("target")):
                self._add(
                    "odoo-web-dynamic-service-worker",
                    "Service Worker registration uses external or request-derived target",
                    "high",
                    line_number,
                    "Frontend code registers a Service Worker from an external or dynamic script target; keep persistent worker scripts on reviewed local bundles with strict scope control",
                    "serviceWorker.register",
                )

            wasm_match = WASM_DYNAMIC_LOAD_RE.search(line)
            if wasm_match and _looks_risky_wasm_load_target(
                wasm_match.group("target"), fetched=bool(wasm_match.group("fetch"))
            ):
                self._add(
                    "odoo-web-dynamic-wasm-loading",
                    "WebAssembly loads external or request-derived code",
                    "high",
                    line_number,
                    "Frontend code loads WebAssembly from an external, dynamic, or request-derived source; restrict WASM modules to reviewed same-origin assets with integrity controls",
                    f"WebAssembly.{wasm_match.group('sink')}",
                )

            css_match = CSS_STYLE_INJECTION_RE.search(line)
            if css_match and _looks_risky_css_text(css_match.group("css")):
                self._add(
                    "odoo-web-dynamic-css-injection",
                    "Stylesheet injection uses request-derived CSS text",
                    "medium",
                    line_number,
                    "Frontend code writes dynamic or request-derived CSS into a stylesheet; sanitize style text and avoid letting untrusted data hide, overlay, or restyle privileged UI",
                    css_match.group("sink"),
                )

            live_connection_match = LIVE_CONNECTION_RE.search(line)
            if live_connection_match and _looks_risky_live_connection_target(live_connection_match.group("target")):
                self._add(
                    "odoo-web-dynamic-live-connection",
                    "Frontend live connection uses external or request-derived endpoint",
                    "medium",
                    line_number,
                    "Frontend code opens a WebSocket/EventSource connection to an external or dynamic endpoint; keep realtime endpoints same-origin or strictly allowlisted",
                    live_connection_match.group("kind"),
                )

            if DOCUMENT_DOMAIN_ASSIGN_RE.search(line):
                self._add(
                    "odoo-web-document-domain-relaxation",
                    "Frontend relaxes same-origin policy with document.domain",
                    "high",
                    line_number,
                    "Frontend code assigns document.domain, which relaxes browser origin isolation; avoid legacy same-site origin relaxation and use explicit postMessage allowlists instead",
                    "document.domain",
                )

            cookie_match = DOCUMENT_COOKIE_ASSIGN_RE.search(line)
            if cookie_match and _looks_sensitive_document_cookie_write(cookie_match.group("value")):
                self._add(
                    "odoo-web-sensitive-document-cookie",
                    "Frontend writes sensitive value to document.cookie",
                    "high",
                    line_number,
                    "Frontend code writes a session/token/secret-like cookie through document.cookie; avoid JavaScript-readable credential cookies and set sensitive cookies server-side with HttpOnly, Secure, and SameSite controls",
                    "document.cookie",
                )

            window_name_match = WINDOW_NAME_ASSIGN_RE.search(line)
            if window_name_match and _looks_sensitive_window_name_write(window_name_match.group("value")):
                self._add(
                    "odoo-web-sensitive-window-name",
                    "Sensitive frontend value written to window.name",
                    "medium",
                    line_number,
                    "Frontend code writes token/session/secret-like values to window.name; avoid storing credentials in navigation-persistent browser state that can survive cross-origin transitions",
                    "window.name",
                )

            if "Math.random" in line and re.search(r"token|secret|nonce|csrf|password", line, re.IGNORECASE):
                self._add(
                    "odoo-web-weak-random-token",
                    "Weak random token generation in frontend",
                    "medium",
                    line_number,
                    "Math.random() is used around token/secret generation; use cryptographic randomness for security material",
                    "Math.random",
                )

            if RPC_CALL_RE.search(line) and "csrf_token" not in line and "csrfToken" not in line:
                self._add(
                    "odoo-web-rpc-without-visible-csrf",
                    "Frontend RPC call without visible CSRF token",
                    "low",
                    line_number,
                    "RPC call has no visible CSRF token in the call site; verify framework service adds CSRF or endpoint is safe",
                    "rpc",
                )

            orm_call_match = ORM_SERVICE_CALL_RE.search(line)
            if orm_call_match and _looks_risky_orm_service_call(
                orm_call_match.group("method"),
                orm_call_match.group("args"),
            ):
                self._add(
                    "odoo-web-dynamic-orm-service-call",
                    "Frontend ORM service call uses dynamic model, method, domain, or values",
                    "medium",
                    line_number,
                    "OWL/Odoo frontend ORM service call receives request-derived or dynamic model/method/domain/value data; verify client input cannot drive unintended model access or privileged mutations",
                    f"orm.{orm_call_match.group('method')}",
                )

            if SENSITIVE_STORAGE_RE.search(line):
                self._add(
                    "odoo-web-sensitive-browser-storage",
                    "Sensitive value stored in browser storage",
                    "high",
                    line_number,
                    "Frontend code writes token/secret/password-like data to localStorage or sessionStorage; verify XSS cannot persist or steal credentials",
                    "browser-storage",
                )

            storage_assignment_match = SENSITIVE_STORAGE_ASSIGNMENT_RE.search(line)
            if storage_assignment_match and _looks_sensitive_storage_assignment(
                storage_assignment_match.group("property") or storage_assignment_match.group("bracket") or "",
                storage_assignment_match.group("value"),
            ):
                self._add(
                    "odoo-web-sensitive-browser-storage",
                    "Sensitive value stored in browser storage",
                    "high",
                    line_number,
                    "Frontend code writes token/secret/password-like data to localStorage or sessionStorage; verify XSS cannot persist or steal credentials",
                    "browser-storage",
                )

            indexeddb_match = INDEXEDDB_WRITE_RE.search(line)
            if indexeddb_match and _looks_sensitive_indexeddb_write(line, indexeddb_match.group("value")):
                self._add(
                    "odoo-web-sensitive-indexeddb-storage",
                    "Sensitive value stored in IndexedDB",
                    "high",
                    line_number,
                    "Frontend code writes token/secret/session-like data to an IndexedDB object store; verify XSS cannot persist or recover credentials from browser storage",
                    indexeddb_match.group("sink"),
                )

            cache_match = CACHE_API_WRITE_RE.search(line)
            if cache_match and _looks_sensitive_cache_api_write(line, cache_match.group("args")):
                self._add(
                    "odoo-web-sensitive-cache-api-storage",
                    "Sensitive value stored in browser Cache API",
                    "high",
                    line_number,
                    "Frontend code writes token/session-like URLs or responses to the browser Cache API; avoid caching credential-bearing requests and authenticated responses in persistent client storage",
                    cache_match.group("sink"),
                )

            console_match = CONSOLE_CALL_RE.search(line)
            if console_match and _looks_sensitive_console_log(console_match.group("args")):
                self._add(
                    "odoo-web-sensitive-console-logging",
                    "Sensitive frontend value logged to console",
                    "medium",
                    line_number,
                    "Frontend code logs token/session/secret-like values to the browser console; remove credential-bearing debug output before review or release",
                    f"console.{console_match.group('sink')}",
                )

            send_beacon_match = SEND_BEACON_RE.search(line)
            if send_beacon_match and _looks_sensitive_send_beacon(send_beacon_match.group("args")):
                self._add(
                    "odoo-web-sensitive-send-beacon",
                    "Sensitive frontend value sent with sendBeacon",
                    "medium",
                    line_number,
                    "Frontend code sends token/session/secret-like values through navigator.sendBeacon; avoid background credential exfiltration paths and keep telemetry payloads credential-free",
                    "navigator.sendBeacon",
                )

            clipboard_match = CLIPBOARD_WRITE_RE.search(line)
            if clipboard_match and _looks_sensitive_clipboard_write(clipboard_match.group("value")):
                self._add(
                    "odoo-web-sensitive-clipboard-write",
                    "Sensitive frontend value written to clipboard",
                    "medium",
                    line_number,
                    "Frontend code writes token/session/secret-like values to the system clipboard; avoid copying credentials into cross-application paste buffers",
                    f"clipboard.{clipboard_match.group('sink')}",
                )

            notification_match = NOTIFICATION_RE.search(line)
            if notification_match and _looks_sensitive_notification(notification_match.group("args")):
                self._add(
                    "odoo-web-sensitive-notification",
                    "Sensitive frontend value shown in browser notification",
                    "medium",
                    line_number,
                    "Frontend code displays token/session/secret-like values in browser notifications; avoid exposing credentials through OS-level notification history or shared screens",
                    notification_match.group("sink"),
                )

            credential_match = WEB_CREDENTIAL_RE.search(line)
            if credential_match and _looks_sensitive_web_credential(credential_match.group("value")):
                self._add(
                    "odoo-web-sensitive-credential-management",
                    "Sensitive frontend value stored with browser Credential Management API",
                    "high",
                    line_number,
                    "Frontend code passes password/token/session-like data to browser Credential Management APIs; avoid persisting Odoo credentials in client-managed auth stores unless the flow is explicitly reviewed",
                    credential_match.group("sink").replace("new ", ""),
                )

            crypto_import_match = CRYPTO_IMPORT_KEY_RE.search(line)
            if crypto_import_match and _looks_risky_crypto_import_key(crypto_import_match.group("args")):
                self._add(
                    "odoo-web-frontend-raw-crypto-key",
                    "Frontend imports raw or hard-coded cryptographic key material",
                    "high",
                    line_number,
                    "Frontend code imports raw/JWK cryptographic key material from hard-coded or request-derived data; keep signing, encryption, and token keys server-side or use reviewed non-extractable public-key flows",
                    "crypto.subtle.importKey",
                )

            object_url_match = OBJECT_URL_RE.search(line)
            if object_url_match and _looks_sensitive_object_url_blob(object_url_match.group("value")):
                self._add(
                    "odoo-web-sensitive-object-url",
                    "Sensitive frontend value exposed through object URL",
                    "medium",
                    line_number,
                    "Frontend code creates a Blob object URL containing token/session/secret-like data; avoid exposing credentials through downloadable, shareable, or long-lived browser object URLs",
                    "URL.createObjectURL",
                )

            broadcast_channel_match = BROADCAST_CHANNEL_RE.search(line)
            if broadcast_channel_match and _looks_sensitive_broadcast_channel(broadcast_channel_match.group("name")):
                self._add(
                    "odoo-web-sensitive-broadcast-channel",
                    "Sensitive frontend value used in BroadcastChannel",
                    "medium",
                    line_number,
                    "Frontend code uses token/session/secret-like values in BroadcastChannel names or messages; avoid spreading credentials across same-origin tabs and browser contexts",
                    "BroadcastChannel",
                )

            broadcast_message_match = BROADCAST_CHANNEL_POSTMESSAGE_RE.search(line)
            if broadcast_message_match and _looks_sensitive_broadcast_channel(broadcast_message_match.group("value")):
                self._add(
                    "odoo-web-sensitive-broadcast-channel",
                    "Sensitive frontend value used in BroadcastChannel",
                    "medium",
                    line_number,
                    "Frontend code uses token/session/secret-like values in BroadcastChannel names or messages; avoid spreading credentials across same-origin tabs and browser contexts",
                    f"{broadcast_message_match.group('sink')}.postMessage",
                )

            bus_channel_match = BUS_CHANNEL_CALL_RE.search(line)
            if bus_channel_match and _looks_risky_bus_channel_subscription(bus_channel_match.group("args")):
                self._add(
                    "odoo-web-dynamic-bus-channel",
                    "Frontend bus service subscribes to dynamic or broad channel",
                    "medium",
                    line_number,
                    "Odoo frontend bus service subscribes to a request-derived or broad realtime channel; verify users can only receive tenant, company, partner, or record-scoped notifications they are authorized to see",
                    f"bus.{bus_channel_match.group('method')}",
                )

            if _looks_sensitive_url_exposure(line):
                self._add(
                    "odoo-web-sensitive-url-token",
                    "Sensitive frontend value placed in URL",
                    "medium",
                    line_number,
                    "Frontend code places token/secret/password-like data in a URL, query string, or fragment; verify it cannot leak through logs, referrers, browser history, or shared links",
                    "url-token",
                )

            history_match = HISTORY_STATE_RE.search(line)
            if history_match and _looks_sensitive_history_state_url(history_match.group("args")):
                self._add(
                    "odoo-web-sensitive-history-url",
                    "Sensitive frontend URL persisted to browser history",
                    "medium",
                    line_number,
                    "Frontend code writes a token/session/secret-like URL into browser history; avoid persisting credentials in address bars, back/forward history, referrers, or shared links",
                    f"history.{history_match.group('sink')}",
                )

            if POSTMESSAGE_WILDCARD_RE.search(line):
                self._add(
                    "odoo-web-postmessage-wildcard-origin",
                    "postMessage uses wildcard target origin",
                    "medium",
                    line_number,
                    "postMessage(..., '*') can leak payloads to unexpected origins; use an explicit trusted target origin",
                    "postMessage",
                )

            for sink, pattern in OBJECT_MERGE_PATTERNS.items():
                if pattern.search(line) and OBJECT_MERGE_TAINT_RE.search(line):
                    self._add(
                        "odoo-web-prototype-pollution-merge",
                        "Frontend object merge uses untrusted data",
                        "high",
                        line_number,
                        f"{sink} merges request/RPC-derived data into an object; reject __proto__/constructor/prototype keys before merging",
                        sink,
                    )

            if OBJECT_SPREAD_RE.search(line):
                self._add(
                    "odoo-web-prototype-pollution-merge",
                    "Frontend object merge uses untrusted data",
                    "high",
                    line_number,
                    "Object spread copies request/RPC-derived data into an object; reject __proto__/constructor/prototype keys before merging",
                    "object-spread",
                )

            if PROTOTYPE_MUTATION_RE.search(line):
                self._add(
                    "odoo-web-prototype-pollution-merge",
                    "Frontend prototype mutation sink",
                    "high",
                    line_number,
                    "Frontend code writes to prototype-sensitive properties; verify untrusted keys cannot pollute Object prototypes",
                    "prototype",
                )

            markup_match = SAFE_MARKUP_CALL_RE.search(line)
            if markup_match and _looks_unsafe_markup_value(markup_match.group("value"), tainted_markup_values):
                self._add(
                    "odoo-web-owl-unsafe-markup",
                    "Frontend markup() marks untrusted HTML as safe",
                    "high",
                    line_number,
                    "OWL/QWeb markup() receives request/RPC-derived data and marks it as trusted HTML; sanitize before safe-marking",
                    "markup",
                )

            for sink, pattern in CLIENT_NAVIGATION_PATTERNS.items():
                if pattern.search(line) and _uses_dangerous_static_navigation_scheme(line, sink):
                    self._add(
                        "odoo-web-dangerous-url-scheme",
                        "Frontend navigation uses dangerous URL scheme",
                        "high",
                        line_number,
                        "Frontend navigation uses a literal javascript:, data:text/html, vbscript:, or file: URL; avoid executable or local-file schemes in Odoo UI navigation targets",
                        sink,
                    )
                if pattern.search(line) and _looks_dynamic_navigation_target(line):
                    self._add(
                        "odoo-web-client-side-redirect",
                        "Client-side navigation uses dynamic target",
                        "medium",
                        line_number,
                        "Frontend navigation sink uses a dynamic or request-derived target; restrict redirects to local paths or allowlisted hosts",
                        sink,
                    )

            if _window_open_missing_opener_isolation(line):
                self._add(
                    "odoo-web-window-open-no-noopener",
                    "window.open opens a new context without opener isolation",
                    "medium",
                    line_number,
                    "window.open opens a new tab/window without noopener or noreferrer; add opener isolation for external or attacker-influenced destinations",
                    "window.open",
                )

            sandbox_match = DOM_IFRAME_SANDBOX_LITERAL_RE.search(line)
            if sandbox_match and _has_iframe_sandbox_escape_tokens(sandbox_match.group("property", "attribute")):
                self._add(
                    "odoo-web-iframe-sandbox-escape",
                    "DOM iframe sandbox allows script same-origin escape",
                    "high",
                    line_number,
                    "Frontend code sets iframe sandbox to allow-scripts plus allow-same-origin; same-origin content can remove the sandbox or access parent-origin data",
                    "iframe.sandbox",
                )

            for sink, pattern in DOM_URL_ATTRIBUTE_PATTERNS.items():
                if pattern.search(line) and _uses_dangerous_static_dom_url_scheme(line):
                    self._add(
                        "odoo-web-dangerous-url-scheme",
                        "Frontend DOM URL attribute uses dangerous scheme",
                        "high",
                        line_number,
                        "Frontend code assigns a literal javascript:, data:text/html, vbscript:, or file: URL to a DOM URL-bearing attribute; restrict generated links, frames, and forms to safe schemes",
                        sink,
                    )
                if pattern.search(line) and _looks_dynamic_dom_url_target(line):
                    self._add(
                        "odoo-web-client-side-redirect",
                        "Client-side navigation uses dynamic target",
                        "medium",
                        line_number,
                        "Frontend URL-bearing DOM attribute uses a dynamic target; restrict generated links, frames, and form actions to local paths or allowlisted hosts",
                        sink,
                    )

        self._scan_message_listeners(lines)
        self._scan_action_url_navigation(lines)
        self._scan_action_window_navigation(lines)
        self._scan_raw_http_csrf(lines)
        self._scan_dom_target_blank(lines)
        self._scan_dom_iframe_missing_sandbox(lines)
        self._scan_dom_external_script_missing_sri(lines)
        self._scan_dom_external_stylesheet_missing_sri(lines)
        return self.findings

    def _scan_message_listeners(self, lines: list[str]) -> None:
        """Find inbound postMessage handlers without visible origin validation."""
        for index, line in enumerate(lines):
            if not MESSAGE_LISTENER_RE.search(line):
                continue
            context = "\n".join(lines[index : index + 25])
            if MESSAGE_ORIGIN_VALIDATION_RE.search(context):
                continue
            self._add(
                "odoo-web-message-handler-missing-origin-check",
                "Message event handler lacks visible origin validation",
                "high",
                index + 1,
                "message event handler reads cross-window messages without a visible event.origin allowlist or comparison; verify untrusted frames cannot drive privileged UI actions",
                "message",
            )

    def _scan_action_url_navigation(self, lines: list[str]) -> None:
        """Find Odoo frontend act_url actions with dynamic URL targets."""
        for index, line in enumerate(lines):
            if not ACTION_URL_RE.search(line):
                continue
            context = "\n".join(lines[index : index + 15])
            if not ACTION_URL_TYPE_RE.search(context):
                continue
            target_match = ACTION_URL_TARGET_RE.search(context)
            if not target_match:
                continue
            target = target_match.group("target").strip()
            if _is_dangerous_url_literal(target):
                self._add(
                    "odoo-web-dangerous-url-scheme",
                    "Odoo frontend act_url uses dangerous URL scheme",
                    "high",
                    index + 1,
                    "Odoo frontend act_url action uses a literal javascript:, data:text/html, vbscript:, or file: URL; restrict action URLs to safe local routes or reviewed HTTPS destinations",
                    "ir.actions.act_url",
                )
                continue
            if _is_static_navigation_target(target):
                continue
            self._add(
                "odoo-web-client-side-redirect",
                "Client-side navigation uses dynamic target",
                "medium",
                index + 1,
                "Odoo frontend act_url action uses a dynamic URL target; restrict redirects to local paths or allowlisted hosts",
                "ir.actions.act_url",
            )

    def _scan_action_window_navigation(self, lines: list[str]) -> None:
        """Find Odoo frontend act_window actions with dynamic model/domain/context inputs."""
        for index, line in enumerate(lines):
            if not ACTION_URL_RE.search(line):
                continue
            context = "\n".join(lines[index : index + 18])
            direct_target = ACTION_CALL_TARGET_RE.search(line)
            if direct_target and _looks_tainted_action_descriptor(direct_target.group("target")):
                self._add(
                    "odoo-web-dynamic-action-window",
                    "Frontend action service receives request-derived action descriptor",
                    "medium",
                    index + 1,
                    "Odoo frontend action service receives a request/RPC-derived action descriptor; verify browser-controlled data cannot select unintended models, domains, contexts, or privileged views",
                    "doAction",
                )
                continue

            if not ACTION_WINDOW_TYPE_RE.search(context):
                continue
            if not _looks_risky_action_window_context(context):
                continue
            self._add(
                "odoo-web-dynamic-action-window",
                "Frontend act_window uses dynamic model, domain, context, or record selection",
                "medium",
                index + 1,
                "Odoo frontend act_window action carries dynamic or request-derived res_model/domain/context/res_id/view data; verify client input cannot widen model access, archived-record visibility, company scope, or record selection",
                "ir.actions.act_window",
            )

    def _scan_raw_http_csrf(self, lines: list[str]) -> None:
        """Find raw browser HTTP writes without visible CSRF token handling."""
        for index, line in enumerate(lines):
            if not RAW_HTTP_REQUEST_RE.search(line):
                continue
            context = "\n".join(lines[index : index + 10])
            if not UNSAFE_HTTP_METHOD_RE.search(context) or CSRF_TOKEN_RE.search(context):
                continue
            self._add(
                "odoo-web-unsafe-request-without-csrf",
                "Frontend unsafe HTTP request lacks visible CSRF token",
                "medium",
                index + 1,
                "Raw frontend HTTP request uses an unsafe method without a visible CSRF token/header; verify Odoo session-protected endpoints cannot be driven cross-site",
                "http-request",
            )

    def _scan_dom_target_blank(self, lines: list[str]) -> None:
        """Find DOM-created new-tab links without visible opener isolation."""
        for index, line in enumerate(lines):
            if not DOM_TARGET_BLANK_RE.search(line):
                continue
            context = "\n".join(lines[index : index + 8])
            if DOM_REL_OPENER_ISOLATION_RE.search(context):
                continue
            self._add(
                "odoo-web-target-blank-no-noopener",
                "DOM link opens new tab without opener isolation",
                "medium",
                index + 1,
                "Frontend code sets target='_blank' without a nearby rel='noopener' or rel='noreferrer'; add opener isolation for generated links",
                "target",
            )

    def _scan_dom_iframe_missing_sandbox(self, lines: list[str]) -> None:
        """Find DOM-created iframes used without visible sandbox containment."""
        for index, line in enumerate(lines):
            match = DOM_IFRAME_CREATE_RE.search(line)
            if not match:
                continue
            iframe_name = match.group("name")
            context = "\n".join(lines[index : index + 12])
            if _dom_iframe_has_sandbox(context, iframe_name) or not _dom_iframe_is_used(context, iframe_name):
                continue
            self._add(
                "odoo-web-iframe-missing-sandbox",
                "DOM-created iframe lacks sandbox restrictions",
                "medium",
                index + 1,
                "Frontend code creates and uses an iframe without a visible sandbox assignment; constrain embedded content privileges unless the frame is fully trusted",
                "iframe",
            )

    def _scan_dom_external_script_missing_sri(self, lines: list[str]) -> None:
        """Find DOM-created external scripts without visible SRI pinning."""
        for index, line in enumerate(lines):
            match = DOM_SCRIPT_CREATE_RE.search(line)
            if not match:
                continue
            script_name = match.group("name")
            context = "\n".join(lines[index : index + 12])
            if _dom_script_has_integrity(context, script_name) or not _dom_script_external_src(context, script_name):
                continue
            if not _dom_script_is_used(context, script_name):
                continue
            self._add(
                "odoo-web-external-script-missing-sri",
                "DOM-created external script lacks Subresource Integrity",
                "medium",
                index + 1,
                "Frontend code creates and loads an external script without a visible integrity assignment; pin third-party assets with SRI or serve reviewed code from trusted bundles",
                "script",
            )

    def _scan_dom_external_stylesheet_missing_sri(self, lines: list[str]) -> None:
        """Find DOM-created external stylesheets without visible SRI pinning."""
        for index, line in enumerate(lines):
            match = DOM_LINK_CREATE_RE.search(line)
            if not match:
                continue
            link_name = match.group("name")
            context = "\n".join(lines[index : index + 12])
            if not _dom_link_is_stylesheet(context, link_name):
                continue
            if _dom_link_has_integrity(context, link_name) or not _dom_link_external_href(context, link_name):
                continue
            if not _dom_script_is_used(context, link_name):
                continue
            self._add(
                "odoo-web-external-stylesheet-missing-sri",
                "DOM-created external stylesheet lacks Subresource Integrity",
                "low",
                index + 1,
                "Frontend code creates and loads an external stylesheet without a visible integrity assignment; pin third-party CSS with SRI or serve reviewed styles from trusted bundles",
                "stylesheet",
            )

    def _add(self, rule_id: str, title: str, severity: str, line: int, message: str, sink: str) -> None:
        self.findings.append(
            WebAssetFinding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                file=str(self.path),
                line=line,
                message=message,
                sink=sink,
            )
        )


def _should_skip(path: Path) -> bool:
    return bool(set(path.parts) & {"node_modules", "__pycache__", ".venv", "venv", ".git", "htmlcov"})


def _looks_dynamic_navigation_target(line: str) -> bool:
    if CLIENT_NAVIGATION_TAINT_RE.search(line):
        return True
    match = CLIENT_NAVIGATION_TARGET_RE.search(line)
    if not match:
        return False
    target = match.group("target").strip()
    if _is_static_navigation_target(target):
        return False
    return bool(re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", target))


def _uses_dangerous_static_navigation_scheme(line: str, sink: str) -> bool:
    if sink == "window.open":
        match = WINDOW_OPEN_CALL_RE.search(line)
        if not match:
            return _line_has_dangerous_url_literal(line)
        args = _split_js_args(match.group("args"))
        return bool(args and _is_dangerous_url_literal(args[0]))
    match = CLIENT_NAVIGATION_TARGET_RE.search(line)
    if match and _is_dangerous_url_literal(match.group("target")):
        return True
    return _line_has_dangerous_url_literal(line)


def _looks_dynamic_dom_url_target(line: str) -> bool:
    if re.search(r"\b(?:window\.)?location\.href\s*=", line):
        return False
    if CLIENT_NAVIGATION_TAINT_RE.search(line):
        return True
    match = DOM_URL_ATTRIBUTE_TARGET_RE.search(line)
    if not match:
        return False
    target = match.group("target").strip()
    if target.startswith(("'", '"', "`")):
        return False
    return bool(re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", target))


def _uses_dangerous_static_dom_url_scheme(line: str) -> bool:
    match = DOM_URL_ATTRIBUTE_TARGET_RE.search(line)
    if match and _is_dangerous_url_literal(match.group("target")):
        return True
    return _line_has_dangerous_url_literal(line)


def _looks_sensitive_url_exposure(line: str) -> bool:
    param_match = SENSITIVE_URL_PARAM_SET_RE.search(line)
    if param_match and SENSITIVE_URL_PARAM_NAME_RE.search(param_match.group("key")):
        return not _is_static_js_literal(param_match.group("value").strip())
    return bool(SENSITIVE_URL_QUERY_RE.search(line) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(line))


def _looks_sensitive_history_state_url(args: str) -> bool:
    values = _split_js_args(args)
    if len(values) < 3:
        return False
    target = values[2].strip()
    literal = _strip_js_string(target)
    if literal != target:
        return bool(SENSITIVE_URL_QUERY_RE.search(literal) and "${" in target)
    return _looks_sensitive_url_exposure(target)


def _looks_risky_dynamic_import_target(target: str) -> bool:
    target = target.strip()
    literal = _strip_js_string(target)
    if literal != target:
        return _is_external_url(literal)
    if CLIENT_NAVIGATION_TAINT_RE.search(target) or SENSITIVE_URL_DYNAMIC_VALUE_RE.search(target):
        return True
    return bool(re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", target))


def _looks_risky_import_scripts(args: str) -> bool:
    return any(_looks_risky_dynamic_import_target(arg) for arg in _split_js_args(args))


def _looks_risky_css_text(css_text: str) -> bool:
    css_text = css_text.strip()
    if _strip_js_string(css_text) != css_text:
        return False
    return bool(
        SAFE_MARKUP_TAINT_RE.search(css_text)
        or CLIENT_NAVIGATION_TAINT_RE.search(css_text)
        or re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", css_text)
    )


def _looks_risky_live_connection_target(target: str) -> bool:
    target = target.strip()
    literal = _strip_js_string(target)
    if literal != target:
        return bool(re.match(r"^(?:wss?:|https?:)?//", literal.strip(), re.IGNORECASE))
    if CLIENT_NAVIGATION_TAINT_RE.search(target) or SENSITIVE_URL_DYNAMIC_VALUE_RE.search(target):
        return True
    return bool(re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", target))


def _looks_risky_wasm_load_target(target: str, *, fetched: bool) -> bool:
    target = target.strip()
    literal = _strip_js_string(target)
    if literal != target:
        if _is_external_url(literal):
            return True
        return bool(fetched and SENSITIVE_URL_QUERY_RE.search(literal))
    if CLIENT_NAVIGATION_TAINT_RE.search(target) or SENSITIVE_URL_DYNAMIC_VALUE_RE.search(target):
        return True
    return bool(re.search(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\b", target))


def _looks_sensitive_document_cookie_write(value: str) -> bool:
    value = value.strip().rstrip(";")
    literal = _strip_js_string(value)
    if literal != value:
        return bool(SENSITIVE_URL_PARAM_NAME_RE.search(literal))
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) or SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_window_name_write(value: str) -> bool:
    value = value.strip().rstrip(";")
    if _strip_js_string(value) != value and "${" not in value:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_indexeddb_write(line: str, value: str) -> bool:
    if not re.search(r"\b(?:indexedDB|objectStore|store|db\.transaction)\b", line):
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) or SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_cache_api_write(line: str, args: str) -> bool:
    if not re.search(r"\b(?:caches|cache)\b", line):
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(args))


def _looks_sensitive_storage_assignment(key: str, value: str) -> bool:
    value = value.strip()
    if SENSITIVE_URL_PARAM_NAME_RE.search(key):
        return not _is_static_js_literal(value)
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_console_log(args: str) -> bool:
    args = args.strip()
    if _strip_js_string(args) != args and "${" not in args:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(args) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(args))


def _looks_sensitive_send_beacon(args: str) -> bool:
    values = _split_js_args(args)
    if not values:
        return False
    target = values[0].strip()
    if _looks_sensitive_url_exposure(target):
        return True
    payload = ", ".join(values[1:])
    if not payload:
        return False
    if _strip_js_string(payload) != payload and "${" not in payload:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(payload) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(payload))


def _looks_sensitive_clipboard_write(value: str) -> bool:
    value = value.strip()
    if _strip_js_string(value) != value and "${" not in value:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_notification(args: str) -> bool:
    args = args.strip()
    if _strip_js_string(args) != args and "${" not in args:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(args) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(args))


def _looks_sensitive_web_credential(value: str) -> bool:
    value = value.strip()
    if _strip_js_string(value) != value and "${" not in value:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_risky_crypto_import_key(args: str) -> bool:
    values = _split_js_args(args)
    if len(values) < 2:
        return False
    key_format = _strip_js_string(values[0]).lower()
    if key_format not in {"raw", "jwk"}:
        return False
    key_data = values[1].strip()
    if SENSITIVE_URL_PARAM_NAME_RE.search(key_data) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(key_data):
        return True
    if re.search(
        r"\b(?:response|payload|data|props|params)\.\w*(?:key|secret|token|password|session)\w*\b",
        key_data,
        re.IGNORECASE,
    ):
        return True
    return _contains_hardcoded_key_material(key_data)


def _contains_hardcoded_key_material(value: str) -> bool:
    if re.search(r"\b(?:TextEncoder|Uint8Array|ArrayBuffer)\b", value) and re.search(r"['\"][^'\"]{8,}['\"]", value):
        return True
    return bool(
        re.search(r"\b[akxy]\s*:\s*['\"][A-Za-z0-9+/=_-]{12,}['\"]", value)
        or re.search(r"['\"][A-Fa-f0-9]{16,}['\"]", value)
        or re.search(r"['\"][A-Za-z0-9+/=_-]{24,}['\"]", value)
    )


def _looks_sensitive_object_url_blob(value: str) -> bool:
    value = value.strip()
    if not re.search(r"\bBlob\s*\(", value):
        return False
    if _strip_js_string(value) != value and "${" not in value:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_sensitive_broadcast_channel(value: str) -> bool:
    value = value.strip()
    if _strip_js_string(value) != value and "${" not in value:
        return False
    return bool(SENSITIVE_URL_PARAM_NAME_RE.search(value) and SENSITIVE_URL_DYNAMIC_VALUE_RE.search(value))


def _looks_risky_bus_channel_subscription(args: str) -> bool:
    values = _split_js_args(args)
    if not values:
        return False
    joined = ", ".join(values)
    if ACTION_WINDOW_TAINT_RE.search(joined):
        return True
    for value in values:
        value = value.strip().rstrip(")")
        literal = _strip_js_string(value)
        if literal != value and BROAD_BUS_CHANNEL_RE.match(literal.strip()):
            return True
        if _strip_js_string(value) == value and re.search(r"\b(?:channel|channels|topic|topics)\b", value, re.IGNORECASE):
            return True
    return False


def _looks_tainted_markup_assignment(target: str, value: str) -> bool:
    if HTML_SANITIZER_RE.search(value):
        return False
    if not HTML_LIKE_TARGET_RE.search(target):
        return False
    return bool(SAFE_MARKUP_TAINT_RE.search(value))


def _looks_unsafe_markup_value(value: str, tainted_markup_values: set[str]) -> bool:
    if HTML_SANITIZER_RE.search(value):
        return False
    if SAFE_MARKUP_TAINT_RE.search(value):
        return True
    return _normalize_js_reference(value) in tainted_markup_values


def _normalize_js_reference(value: str) -> str:
    return value.strip().rstrip(")").strip()


def _window_open_missing_opener_isolation(line: str) -> bool:
    match = WINDOW_OPEN_CALL_RE.search(line)
    if not match:
        return False
    args = _split_js_args(match.group("args"))
    if len(args) >= 2 and _strip_js_string(args[1]).lower() != "_blank":
        return False
    if len(args) >= 3 and re.search(r"\b(?:noopener|noreferrer)\b", _strip_js_string(args[2]), re.IGNORECASE):
        return False
    return True


def _split_js_args(args: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    quote = ""
    escape = False
    depth = 0
    for char in args:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            current.append(char)
            quote = char
            continue
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth:
            depth -= 1
        if char == "," and depth == 0:
            values.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current or args.strip():
        values.append("".join(current).strip())
    return values


def _strip_js_string(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"', "`"}:
        return value[1:-1]
    return value


def _looks_risky_orm_service_call(method: str, args: str) -> bool:
    """Detect ORM service calls where the client controls routing or query inputs."""
    if ORM_SERVICE_TAINT_RE.search(args):
        return True

    values = _split_js_args(args)
    if not values:
        return False

    method = method.lower()
    if method in {"call", "silentcall"}:
        model = values[0] if values else ""
        call_method = values[1] if len(values) > 1 else ""
        if model and _strip_js_string(model) == model:
            return True
        if call_method and _strip_js_string(call_method) == call_method:
            return True

    dynamic_arg_names = re.compile(
        r"\b(?:domain|payload|params|props|data|values|vals|ids|recordIds|selectedIds|context)\b",
        re.IGNORECASE,
    )
    return any(dynamic_arg_names.search(value) for value in values[1:])


def _looks_tainted_action_descriptor(target: str) -> bool:
    target = target.strip()
    if not target or target.startswith("{") or _strip_js_string(target) != target:
        return False
    return bool(ACTION_WINDOW_TAINT_RE.search(target))


def _looks_risky_action_window_context(context: str) -> bool:
    if not ACTION_WINDOW_DYNAMIC_FIELD_RE.search(context):
        return False
    if ACTION_WINDOW_TAINT_RE.search(context):
        return True

    for match in ACTION_WINDOW_UNQUOTED_FIELD_RE.finditer(context):
        field = (match.group("quoted") or match.group("plain") or "").lower()
        value = match.group("value")
        if value in {"true", "false", "null", "undefined"}:
            continue
        if field in {"res_model", "domain", "context", "res_id", "views", "view_id"}:
            return True
    return False


def _has_iframe_sandbox_escape_tokens(values: tuple[str | None, ...]) -> bool:
    sandbox_value = " ".join(value or "" for value in values).lower()
    tokens = set(sandbox_value.split())
    return {"allow-scripts", "allow-same-origin"}.issubset(tokens)


def _dom_iframe_has_sandbox(context: str, iframe_name: str) -> bool:
    name = re.escape(iframe_name)
    return bool(
        re.search(rf"\b{name}\.sandbox\s*=", context)
        or re.search(rf"\b{name}\.setAttribute\s*\(\s*['\"]sandbox['\"]\s*,", context)
    )


def _dom_iframe_is_used(context: str, iframe_name: str) -> bool:
    name = re.escape(iframe_name)
    return bool(
        re.search(rf"\b{name}\.src\s*=", context)
        or re.search(rf"\b{name}\.setAttribute\s*\(\s*['\"]src['\"]\s*,", context)
        or re.search(rf"\.(?:append|appendChild)\s*\(\s*{name}\s*\)", context)
    )


def _dom_script_has_integrity(context: str, script_name: str) -> bool:
    name = re.escape(script_name)
    return bool(
        re.search(rf"\b{name}\.integrity\s*=", context)
        or re.search(rf"\b{name}\.setAttribute\s*\(\s*['\"]integrity['\"]\s*,", context)
    )


def _dom_script_external_src(context: str, script_name: str) -> bool:
    name = re.escape(script_name)
    src_match = re.search(rf"\b{name}\.src\s*=\s*['\"](?P<src>[^'\"]+)['\"]", context, re.IGNORECASE)
    attr_match = re.search(
        rf"\b{name}\.setAttribute\s*\(\s*['\"]src['\"]\s*,\s*['\"](?P<src>[^'\"]+)['\"]",
        context,
        re.IGNORECASE,
    )
    match = src_match or attr_match
    return bool(match and _is_external_url(match.group("src")))


def _dom_script_is_used(context: str, script_name: str) -> bool:
    name = re.escape(script_name)
    return bool(re.search(rf"\.(?:append|appendChild)\s*\(\s*{name}\s*\)", context))


def _dom_link_is_stylesheet(context: str, link_name: str) -> bool:
    name = re.escape(link_name)
    return bool(
        re.search(rf"\b{name}\.rel\s*=\s*['\"][^'\"]*\bstylesheet\b", context, re.IGNORECASE)
        or re.search(
            rf"\b{name}\.setAttribute\s*\(\s*['\"]rel['\"]\s*,\s*['\"][^'\"]*\bstylesheet\b", context, re.IGNORECASE
        )
    )


def _dom_link_has_integrity(context: str, link_name: str) -> bool:
    return _dom_script_has_integrity(context, link_name)


def _dom_link_external_href(context: str, link_name: str) -> bool:
    name = re.escape(link_name)
    href_match = re.search(rf"\b{name}\.href\s*=\s*['\"](?P<href>[^'\"]+)['\"]", context, re.IGNORECASE)
    attr_match = re.search(
        rf"\b{name}\.setAttribute\s*\(\s*['\"]href['\"]\s*,\s*['\"](?P<href>[^'\"]+)['\"]",
        context,
        re.IGNORECASE,
    )
    match = href_match or attr_match
    return bool(match and _is_external_url(match.group("href")))


def _is_external_url(value: str) -> bool:
    return bool(re.match(r"^(?:https?:)?//", value.strip(), re.IGNORECASE))


def _is_static_js_literal(value: str) -> bool:
    return bool(re.fullmatch(r"""['"`][^'"`]*['"`]""", value))


def _looks_risky_dom_event_handler_value(value: str) -> bool:
    stripped = value.strip()
    if stripped in {"", "null", "undefined", "false", "true"}:
        return False
    return _is_static_js_literal(stripped) or bool(DOM_EVENT_HANDLER_TAINT_RE.search(stripped))


def _is_static_navigation_target(target: str) -> bool:
    return bool(re.fullmatch(r"""['"`](?:/|#)[^'"`]*['"`]""", target))


def _is_dangerous_url_literal(value: str) -> bool:
    stripped = value.strip()
    literal = _strip_js_string(stripped)
    if literal == stripped:
        return False
    normalized = re.sub(r"\s+", "", literal).lower()
    return normalized.startswith(DANGEROUS_URL_SCHEMES)


def _line_has_dangerous_url_literal(line: str) -> bool:
    return any(_is_dangerous_url_literal(match.group(0)) for match in re.finditer(r"""(['"`])[^'"`]*\1""", line))


def findings_to_json(findings: list[WebAssetFinding]) -> list[dict[str, Any]]:
    """Convert findings to JSON-serializable dictionaries."""
    return [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "file": f.file,
            "line": f.line,
            "message": f.message,
            "sink": f.sink,
        }
        for f in findings
    ]
