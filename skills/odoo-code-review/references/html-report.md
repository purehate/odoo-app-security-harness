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

## Two-Bucket Triage Loop (Required)

The HTML report is the front door of the iterative review loop. Every finding card carries **two** mutually-exclusive controls:

1. **Mark as accepted risk** → not a bug / accepted with compensating control. Queued for `<repo>/.audit-accepted-risks.yml`. Next run silently drops the finding (Gate 0 SKIP).
2. **Add to fix-it list** → confirmed bug, team will fix. Queued for `<repo>/.audit-fix-list.yml`. Next run still emits the finding, tags it with `tracked: FIX-NNN`, and reconciles fix status (REGRESSION detection if `status: fixed` but bug returns).

The reviewer's per-finding decision is exactly one of those two buttons. After walking the report, the bottom toolbar exports two YAML snippets — accepted-risks-additions and fix-list-additions — that paste into the respective files at the repo root. Each iteration the report gets shorter and sharper.

Both buttons rely on the per-finding `data-fingerprint` attribute (16-hex, computed by the Phase 5 hunters) so the resulting YAML stanza is byte-stable and Phase 0 of the next run matches it deterministically.

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

## Add-to-Fix-List Loop (Required)

Symmetric companion to the Accept-Risk loop. Same UI shape, different output schema, different reconciliation behaviour. Each finding card MUST carry both controls; the reviewer picks exactly one per card.

### Per-Finding Control

```html
<div
  class="add-to-fix-list"
  data-finding-id="F-7"
  data-fingerprint="7c1f4a9b2e5d8a31"
  data-title="Public events check-in submit allowed for non-conference events"
  data-file="trustedsec_events/controllers/checkin.py"
  data-line="175"
  data-line-end="260"
  data-severity="HIGH"
  data-sink-kind="controller_route"
>
  <button type="button" class="fl-toggle">+ Add to fix-it list</button>
  <input
    type="text"
    class="fl-owner"
    placeholder="Owner email (required)…"
    aria-label="Fix owner"
  />
  <select class="fl-status" aria-label="Fix status">
    <option value="open" selected>open</option>
    <option value="in-progress">in-progress</option>
    <option value="fixed">fixed (regression canary)</option>
    <option value="wontfix">wontfix (documented gap)</option>
  </select>
  <input
    type="date"
    class="fl-target"
    aria-label="Target date (open/in-progress only)"
  />
  <textarea
    class="fl-notes"
    placeholder="Plan-of-attack / sprint / ticket / PR (required for wontfix)…"
    rows="2"
  ></textarea>
</div>
```

### Sticky Toolbar Additions

```html
<div class="fl-toolbar">
  <span id="fl-counter">0 tracked</span>
  <button id="fl-download">Download fix-list.yml additions</button>
  <button id="fl-copy">Copy to clipboard</button>
  <button id="fl-clear">Clear queue</button>
  <details>
    <summary>How to apply</summary>
    <ol>
      <li>
        Save downloaded snippet at repo root as
        <code>.audit-fix-list.yml</code> (or merge into existing).
      </li>
      <li>
        Re-run <code>/odoo-code-review</code>. Phase 0 loads the file, Phase 8
        reconciles against current findings.
      </li>
      <li>
        Findings that match an <code>open</code>/<code>in-progress</code> entry
        get a green <em>tracked</em> pill; <code>fixed</code> entries that
        re-appear get a <strong>red REGRESSION</strong> pill.
      </li>
    </ol>
  </details>
</div>
```

The accept-risk and fix-list toolbars sit side by side in the sticky header so the two queues stay visually separated.

### Vanilla JS — fix-list queue + export

```html
<script>
  const FL_KEY = "odoo-harness-fix-list-v1";
  const flLoad = () => JSON.parse(localStorage.getItem(FL_KEY) || "[]");
  const flSave = (q) => localStorage.setItem(FL_KEY, JSON.stringify(q));
  const flRefresh = () => {
    document.getElementById("fl-counter").textContent =
      `${flLoad().length} tracked`;
  };

  document.querySelectorAll(".add-to-fix-list").forEach((el) => {
    const id = el.dataset.findingId;
    const toggle = el.querySelector(".fl-toggle");
    const owner = el.querySelector(".fl-owner");
    const status = el.querySelector(".fl-status");
    const target = el.querySelector(".fl-target");
    const notes = el.querySelector(".fl-notes");
    const prior = flLoad().find((r) => r.finding_id === id);
    if (prior) {
      el.classList.add("fl-tracked");
      owner.value = prior.owner || "";
      status.value = prior.status || "open";
      target.value = prior.target_date || "";
      notes.value = prior.notes || "";
    }
    const update = (queued) => {
      const q = flLoad().filter((r) => r.finding_id !== id);
      if (queued) {
        q.push({
          finding_id: id,
          fingerprint: el.dataset.fingerprint,
          title: el.dataset.title,
          file: el.dataset.file,
          line: parseInt(el.dataset.line, 10) || null,
          line_end: parseInt(el.dataset.lineEnd, 10) || null,
          severity: el.dataset.severity,
          sink_kind: el.dataset.sinkKind,
          owner: owner.value.trim(),
          status: status.value,
          target_date: target.value || null,
          notes: notes.value.trim(),
        });
      }
      flSave(q);
      flRefresh();
    };
    toggle.addEventListener("click", () => {
      const queued = !el.classList.contains("fl-tracked");
      el.classList.toggle("fl-tracked", queued);
      toggle.textContent = queued
        ? "− Remove from fix-it list"
        : "+ Add to fix-it list";
      update(queued);
    });
    [owner, status, target, notes].forEach((field) =>
      field.addEventListener(
        "input",
        () => el.classList.contains("fl-tracked") && update(true),
      ),
    );
  });

  const flToYaml = (queue) => {
    const today = new Date().toISOString().slice(0, 10);
    const lines = [
      "# Generated by findings.html add-to-fix-list UI",
      `# date: ${today}`,
      "version: 1",
      "fixes:",
    ];
    queue.forEach((r, i) => {
      const fid = `FIX-${String(i + 1).padStart(3, "0")}`;
      lines.push(`  - id: ${fid}`);
      if (r.fingerprint) lines.push(`    fingerprint: ${r.fingerprint}`);
      lines.push(`    title: ${JSON.stringify(r.title || "")}`);
      if (r.file) lines.push(`    file: ${r.file}`);
      if (r.line && r.line_end && r.line_end !== r.line) {
        lines.push(`    lines: [${r.line}, ${r.line_end}]`);
      } else if (r.line) {
        lines.push(`    lines: ${r.line}`);
      }
      if (r.severity) lines.push(`    severity: ${r.severity}`);
      if (r.sink_kind) lines.push(`    sink_kind: ${r.sink_kind}`);
      if (r.owner) lines.push(`    owner: ${r.owner}`);
      lines.push(`    status: ${r.status || "open"}`);
      if (
        r.target_date &&
        (r.status === "open" || r.status === "in-progress")
      ) {
        lines.push(`    target_date: ${r.target_date}`);
      }
      if (r.status === "fixed") lines.push(`    fixed_at: ${today}`);
      if (r.notes) {
        lines.push("    notes: |");
        r.notes.split("\n").forEach((line) => lines.push(`      ${line}`));
      } else if (r.status === "wontfix") {
        lines.push("    notes: |");
        lines.push(
          "      TODO: explain why this gap is acceptable (wontfix requires non-empty notes).",
        );
      }
    });
    return lines.join("\n") + "\n";
  };

  document.getElementById("fl-download").addEventListener("click", () => {
    const yaml = flToYaml(flLoad());
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = ".audit-fix-list.yml";
    a.click();
    URL.revokeObjectURL(url);
  });

  document.getElementById("fl-copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(flToYaml(flLoad()));
  });

  document.getElementById("fl-clear").addEventListener("click", () => {
    if (confirm("Clear the fix-list queue?")) {
      flSave([]);
      document.querySelectorAll(".add-to-fix-list").forEach((el) => {
        el.classList.remove("fl-tracked");
        el.querySelector(".fl-toggle").textContent = "+ Add to fix-it list";
        el.querySelector(".fl-owner").value = "";
        el.querySelector(".fl-status").value = "open";
        el.querySelector(".fl-target").value = "";
        el.querySelector(".fl-notes").value = "";
      });
      flRefresh();
    }
  });

  flRefresh();
</script>
```

### Tracking Pill Renderer

When the next run produces `inventory/fix-list.json` with reconciliation results, the Phase 8 generator renders one of three pills at the top of each ACCEPT card:

```html
<!-- open / in-progress -->
<span class="fl-pill fl-pill-tracked"
  >tracked: FIX-001 · target 2026-06-01</span
>

<!-- fixed but still present (REGRESSION) -->
<span class="fl-pill fl-pill-regression"
  >REGRESSION · FIX-003 marked fixed but bug returned</span
>

<!-- wontfix -->
<span class="fl-pill fl-pill-wontfix">wontfix per FIX-004</span>
```

```css
.fl-pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: 0.85em;
  font-weight: 600;
}
.fl-pill-tracked {
  background: #c8e6c9;
  color: #1b5e20;
}
.fl-pill-regression {
  background: #d32f2f;
  color: white;
}
.fl-pill-wontfix {
  background: #e0e0e0;
  color: #424242;
}
```

### Loop Semantics

1. Reviewer opens `findings.html`, walks findings.
2. Real-bug-we-will-fix → clicks "Add to fix-it list", picks status, owner, optional target date, notes.
3. Bottom toolbar: **Download fix-list.yml additions** (or copy).
4. Reviewer pastes/merges snippet into `<repo>/.audit-fix-list.yml`.
5. Reruns `/odoo-code-review`. Phase 0 validates and loads the file. Hunters tag matching findings with the FIX-NNN id. Phase 8 reconciliation produces `00-fix-list.md` REGRESSION/OVERDUE/TRACKED/CONFIRMED-FIXED/LIKELY-FIXED/WONTFIX/DRIFTED buckets.
6. As fixes ship, owners flip `status: open` → `status: fixed`. The next run's reconciliation reports CONFIRMED-FIXED (✓ archive) or REGRESSION (red — fix didn't hold).

The two-bucket loop (accept-risk OR fix-it) is the product. A finding without a button click stays unresolved on the next run, surfacing the team's actual triage state in the report itself.

## Generation

Codex drafts the HTML during Phase 8 from `findings.json`. Claude reviews the draft, removes any unsupported claims, verifies offline rendering, and confirms the Accept-Risk UI works (toggle, persist, download, clipboard). The runner does not generate HTML — that's a Codex prompt task referenced from `commands/odoo-code-review.md` Phase 8.
