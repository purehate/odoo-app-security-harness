# Variant Analysis — Pattern Fan-Out

Runs **after** an ACCEPT triage in Phase 4. Goal: find sibling bugs of the same shape elsewhere in the codebase before the report ships. One ACCEPTed bug almost always has variants in nearby code.

Distinct from **chaining** (#10 hunter): chaining combines multiple findings into a higher-impact path. Variant analysis fans out a single finding into more findings of the same class.

## When to run

For every finding that triages ACCEPT or DOWNGRADE-but-real. Skip for REJECT and NEEDS-MANUAL.

## Procedure

For each ACCEPTed finding:

1. **Extract the bug shape.** From the source at the cited line, distill:
   - Vulnerable API call or sink (e.g., `Runtime.exec(String)`, `xsltFactory.newTransformer(unsafeSource)`).
   - Tainted-source predicate (e.g., "any value reaching this from `@RequestParam` or `@RequestBody`").
   - Missing safeguard (e.g., "no `setFeature(FEATURE_SECURE_PROCESSING, true)` on the factory").

2. **Build search predicates.** Convert the shape to greppable patterns plus a CodeQL/Semgrep query when the shape is complex enough:
   - `grep` patterns for the API surface (`Runtime.exec`, `ProcessBuilder`, `getRuntime\.exec`).
   - Semgrep rule for the unsafe-config pattern.
   - CodeQL data-flow query if cross-file taint matters.

3. **Search the whole repo.** Not just the module the original finding sits in. Variants frequently live in adjacent modules that copy-pasted the same idiom.

4. **Triage each hit through the 6 gates** (`fp-check.md`). Same rubric. ACCEPT/DOWNGRADE/REJECT/NEEDS-MANUAL.

5. **Group variants under the parent finding.** In the final report, list variants as sub-items of the original. Don't inflate the headline finding count if every variant is the same root-cause bug.

## Output

Append to the original finding:

```
## Variants

Found **N** variants matching pattern: <one-line description>.

| #  | File:Line                                  | Triage  | Note                                    |
|----|--------------------------------------------|---------|-----------------------------------------|
| 1  | spring-oxm/.../Jaxb2Marshaller.java:588    | ACCEPT  | Original finding.                       |
| 2  | spring-oxm/.../Jaxb2HttpMessageConverter.java:204 | ACCEPT | Same factory, same missing FSP.        |
| 3  | spring-test/.../MockJaxb2Marshaller.java:88 | REJECT | Test-only, not reachable in prod.       |

**Search performed:**
  grep -rn "SchemaFactory.newInstance" spring-oxm spring-web spring-webflux
  semgrep -e 'SchemaFactory.newInstance($XSD)' --lang=java
```

## Anti-patterns

- Searching only the module of the original finding. Variants cross modules.
- Marking every grep hit as a finding. Each hit must pass fp-check gates 1-6.
- Listing variants as separate top-level findings. They're the same bug class — the upstream/upstream-PR fix usually covers all of them. Group under the parent.
- Skipping variant analysis because "the original is enough". Clients value coverage; missing a sibling that ships in next quarter's audit is reputational.
- Using only `grep`. Some variants only show up under data-flow analysis (e.g., the same factory used through a wrapper class).

## Tools

| Bug shape                      | Best tool                           |
| ------------------------------ | ----------------------------------- |
| Single-call API misuse         | `grep` / `ripgrep`                  |
| Config flag missing on factory | Semgrep `--config` with custom rule |
| Cross-file taint               | CodeQL data-flow query              |
| ORM query construction pattern | Semgrep with `pattern-either`       |
| Custom-DSL sink                | Joern CPG query                     |

Write the variant search into `<OUT>/variants/<finding-N>.md` with the exact commands run, so the appendix is reproducible.
