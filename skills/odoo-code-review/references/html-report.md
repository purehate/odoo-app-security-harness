# findings.html — Single-File Report Spec

The Phase 8 HTML report is a deliverable. Treat it like one. Self-contained, no CDN dependencies, ships in a Slack DM or email and renders identically offline.

## Hard Requirements

- Single `.html` file. No external CSS/JS/font/image. Inline everything.
- No analytics, no tracking pixels, no telemetry.
- No external network requests at render time. Test with browser devtools "Offline" toggle.
- Embedded SVG attack graphs (not `<img src=...>` to PNG).
- Severity color-coding: red (critical), orange (high), yellow (medium), gray (low/info).

## Layout

```
┌──────────────────────────────────────────────────────────┐
│ Header: target repo, commit, generated_at, harness ver   │
│ Lane badges: Claude ✓ Qwen ✓ Codex ✓                     │
├──────────────────────────────────────────────────────────┤
│ Stats strip: modules / routes / LOC / total findings     │
│ Severity heatmap: bar per band                           │
├──────────────────────────────────────────────────────────┤
│ Module Risk Heatmap (from module-risk.json)              │
│ Color cells by band. Click → scroll to module section.   │
├──────────────────────────────────────────────────────────┤
│ Findings Table — sortable, filterable                    │
│ Columns: ID / Severity / Triage / Module / File:Line /   │
│          CWE / Title                                     │
├──────────────────────────────────────────────────────────┤
│ Per-Finding Detail (collapsible <details>)               │
│   - Description                                          │
│   - Attack Path                                          │
│   - PoC (in <pre><code>)                                 │
│   - Reproduction                                         │
│   - Impact                                               │
│   - Fix                                                  │
│   - 6-gate fp-check table                                │
│   - Variants sub-table                                   │
│   - 2nd-opinion verdict                                  │
│   - References                                           │
├──────────────────────────────────────────────────────────┤
│ Chained Attack Paths (with embedded SVGs)                │
├──────────────────────────────────────────────────────────┤
│ Discourse Summary (AGREE/CHALLENGE/CONNECT/SURFACE)      │
├──────────────────────────────────────────────────────────┤
│ Suppressed (if scope.yml accepted_risks matched)         │
├──────────────────────────────────────────────────────────┤
│ Engagement Stats: tokens / wall-clock / hunters table    │
│ Tooling: scanner versions + commands run                 │
│ Footer: harness version, schema version, regen command   │
└──────────────────────────────────────────────────────────┘
```

## Sortable Table — minimal vanilla JS

```html
<script>
  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const idx = [...th.parentNode.children].indexOf(th);
      const tbody = th.closest("table").tBodies[0];
      const rows = [...tbody.rows];
      const dir = th.dataset.dir === "asc" ? -1 : 1;
      th.dataset.dir = dir === 1 ? "asc" : "desc";
      rows.sort(
        (a, b) =>
          dir *
          a.cells[idx].textContent.localeCompare(
            b.cells[idx].textContent,
            undefined,
            { numeric: true },
          ),
      );
      rows.forEach((r) => tbody.appendChild(r));
    });
  });
</script>
```

## Filter Bar

```html
<input type="search" id="filter" placeholder="Filter findings…" />
<script>
  document.getElementById("filter").addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll("tr.finding-row").forEach((r) => {
      r.hidden = q && !r.textContent.toLowerCase().includes(q);
    });
  });
</script>
```

## Severity Color Tokens

```css
:root {
  --sev-critical: #d32f2f;
  --sev-high: #f57c00;
  --sev-medium: #fbc02d;
  --sev-low: #757575;
  --sev-info: #9e9e9e;
}
.sev-critical {
  background: var(--sev-critical);
  color: white;
}
.sev-high {
  background: var(--sev-high);
  color: white;
}
.sev-medium {
  background: var(--sev-medium);
  color: black;
}
.sev-low {
  background: var(--sev-low);
  color: white;
}
```

## Embedding Attack Graph SVGs

```html
<details>
  <summary>Chain C-1: Portal IDOR → ACL bypass → exfil</summary>
  <!-- Inline the SVG content directly; do NOT use <img src="chain-1.svg"> -->
  <svg viewBox="0 0 800 400" xmlns="http://www.w3.org/2000/svg">
    <!-- contents of attack-graphs/chain-1.svg -->
  </svg>
</details>
```

## Print / PDF

Make the report print-friendly:

```css
@media print {
  details {
    open: true;
  } /* expand all collapsibles in print */
  .filter-bar {
    display: none;
  }
  .finding {
    page-break-inside: avoid;
  }
}
```

## Accessibility

- Use semantic landmarks: `<header>`, `<main>`, `<nav>`, `<footer>`.
- Severity must not be color-only — also use a text label or icon.
- Keyboard-navigable: every collapsible reachable by Tab.
- `aria-label` on filter input and sortable headers.

## Interactive Accept-Risk Loop (Required)

The HTML report is the front door of the iterative review loop. Each finding card carries an **Accept Risk** control. Reviewer clicks → finding gets queued for suppression. Bottom toolbar exports the queue as a `scope.yml` snippet. Reviewer merges the snippet into the project `scope.yml` and re-runs `/odoo-code-review`. Each iteration the report gets shorter and the signal-to-noise ratio climbs.

### Per-Finding Control

```html
<div
  class="accept-risk"
  data-finding-id="F-7"
  data-rule="qweb_xss_t_raw"
  data-cwe="CWE-79"
  data-file="addons/portal/controllers/main.py"
  data-line="142"
>
  <label>
    <input type="checkbox" class="ar-toggle" />
    Accept this risk (mark as known/false-positive)
  </label>
  <input
    type="text"
    class="ar-reason"
    placeholder="Reason (required for export)…"
  />
  <select class="ar-expires">
    <option value="">Expires (optional)</option>
    <option value="30d">30 days</option>
    <option value="90d">90 days</option>
    <option value="1y">1 year</option>
    <option value="never">Never</option>
  </select>
</div>
```

### Sticky Toolbar (top of report)

```html
<div class="ar-toolbar">
  <span id="ar-counter">0 accepted</span>
  <button id="ar-download">Download scope.yml additions</button>
  <button id="ar-copy">Copy to clipboard</button>
  <button id="ar-clear">Clear queue</button>
  <details>
    <summary>How to apply</summary>
    <ol>
      <li>
        Save downloaded <code>accepted-risks.yml</code> to repo root (or merge
        into existing <code>scope.yml</code>).
      </li>
      <li>
        Re-run <code>/odoo-code-review --scope ./scope.yml</code> (or
        <code>odoo-review-run . --scope ./scope.yml</code>).
      </li>
      <li>
        Phase 8.6 auto-export will suppress matching findings;
        <code>delta.md</code> will show the new exclusions.
      </li>
    </ol>
  </details>
</div>
```

### Vanilla JS — queue + export

```html
<script>
  const KEY = "odoo-harness-accepted-risks-v1";
  const load = () => JSON.parse(localStorage.getItem(KEY) || "[]");
  const save = (q) => localStorage.setItem(KEY, JSON.stringify(q));
  const refresh = () => {
    document.getElementById("ar-counter").textContent =
      `${load().length} accepted`;
  };

  document.querySelectorAll(".accept-risk").forEach((el) => {
    const id = el.dataset.findingId;
    const toggle = el.querySelector(".ar-toggle");
    const reason = el.querySelector(".ar-reason");
    const expires = el.querySelector(".ar-expires");
    // restore prior state from localStorage
    const prior = load().find((r) => r.id === id);
    if (prior) {
      toggle.checked = true;
      reason.value = prior.reason || "";
      expires.value = prior.expires || "";
    }
    const update = () => {
      const q = load().filter((r) => r.id !== id);
      if (toggle.checked) {
        q.push({
          id,
          rule: el.dataset.rule,
          cwe: el.dataset.cwe,
          file: el.dataset.file,
          line: parseInt(el.dataset.line, 10) || null,
          reason: reason.value.trim(),
          expires: expires.value || null,
        });
      }
      save(q);
      refresh();
    };
    toggle.addEventListener("change", update);
    reason.addEventListener("input", update);
    expires.addEventListener("change", update);
  });

  const toYaml = (queue) => {
    const today = new Date().toISOString().slice(0, 10);
    const lines = [
      "# Generated by findings.html accept-risk UI",
      `# date: ${today}`,
      "accepted_risks:",
    ];
    queue.forEach((r, i) => {
      lines.push(`  - id: AR-${String(i + 1).padStart(3, "0")}`);
      lines.push(`    finding_id: ${r.id}`);
      if (r.rule) lines.push(`    rule: ${r.rule}`);
      if (r.cwe) lines.push(`    cwe: ${r.cwe}`);
      if (r.file) lines.push(`    file: ${r.file}`);
      if (r.line) lines.push(`    line_range: [${r.line}, ${r.line}]`);
      lines.push(
        `    reason: ${JSON.stringify(r.reason || "marked accepted via HTML report")}`,
      );
      if (r.expires && r.expires !== "never")
        lines.push(`    expires: ${r.expires}`);
    });
    return lines.join("\n") + "\n";
  };

  document.getElementById("ar-download").addEventListener("click", () => {
    const yaml = toYaml(load());
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "accepted-risks.yml";
    a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById("ar-copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(toYaml(load()));
  });

  document.getElementById("ar-clear").addEventListener("click", () => {
    if (confirm("Clear the accepted-risk queue?")) {
      save([]);
      document
        .querySelectorAll(".ar-toggle")
        .forEach((t) => (t.checked = false));
      document.querySelectorAll(".ar-reason").forEach((r) => (r.value = ""));
      document.querySelectorAll(".ar-expires").forEach((e) => (e.value = ""));
      refresh();
    }
  });

  refresh();
</script>
```

### Loop Semantics

1. Reviewer opens `findings.html`, walks findings.
2. False-positive or accepted-risk → clicks toggle, enters reason.
3. Bottom toolbar: **Download scope.yml additions** (or copy).
4. Reviewer merges snippet into repo `scope.yml`.
5. Reruns `/odoo-code-review --scope ./scope.yml`.
6. Phase 8.6 auto-export honors `accepted_risks` → SARIF `suppressions`, bounty/F-N.md skipped, finding marked SUPPRESSED in next HTML.
7. `delta.md` shows what got accepted vs new findings introduced. Iteration N+1 is shorter and sharper than N.

The loop is the product. Generator must include this UI; review without iteration is one-shot scanner output, not a harness.

## Generation

Codex drafts the HTML during Phase 8 from `findings.json`. Claude reviews the draft, removes any unsupported claims, verifies offline rendering, and confirms the Accept-Risk UI works (toggle, persist, download, clipboard). The runner does not generate HTML — that's a Codex prompt task referenced from `commands/odoo-code-review.md` Phase 8.
