# How comparable projects document themselves

*October 2026. Input to the README and docs rewrite.*

We read the README and docs of thirteen open-source projects next to interlock,
looking at three questions: how fast a newcomer sees the tool work, how the docs
are organised, and how honestly each project states its limits. This note keeps
what we learned and what we decided because of it.

## What we looked at

| Project | What it is | README | Docs |
|---|---|---|---|
| [NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails) | LLM guardrails with a dialog DSL | ~230 lines, 3 diagrams | Fern site, pages tagged concept / tutorial / reference |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | Output validators | ~200 lines, output shown | Mintlify, plus a filterable validator hub |
| [LLM Guard](https://github.com/protectai/llm-guard) (archived) | Prompt and output scanners | ~110 lines, no runnable code | MkDocs, one templated page per scanner |
| [LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | Agent firewall | ~160 lines, allow and block output shown | Docusaurus |
| [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant) | Trace-based rules for agents | 135 lines, attack-first example | MkDocs, merged with mcp-scan |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) (was mcp-scan) | MCP config scanner | 438 lines, warning above the fold | Versioned `docs/` folder |
| [Leash](https://github.com/strongdm/leash) | Container sandbox with Cedar policies | 123 lines, demo GIF | Flat markdown + `docs/design/` |
| [Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway) | MCP proxy with plugins | 521 lines, does everything | None beyond README |
| [Superagent](https://github.com/superagent-ai/superagent) | Safety SDK | 192 lines | Hosted site |
| [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) | bubblewrap / Seatbelt sandbox | 901 lines, allow and block output in the first 20 | None beyond README |
| [E2B](https://github.com/e2b-dev/E2B) | Cloud sandboxes for agents | 112 lines | Mintlify, legend on the landing page |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | Policy engine | ~95 lines, no code | Large site; language reference kept apart from guides |
| [Presidio](https://github.com/microsoft/presidio) | PII recognizers | 97 lines, links only | MkDocs; one catalog page grouped into tables |

## What works

1. **Show the tool stopping an attack in the first code block, with the
   output.** LlamaFirewall and sandbox-runtime print both an allowed and a
   blocked result inline. Invariant opens with a rule named after the attack
   it stops ("external email to unknown address"). Readers believe what they
   see run.
2. **Show output after every snippet.** Guardrails AI, E2B, and LlamaFirewall
   do. Presidio calls `print()` and leaves you to imagine the result.
3. **Say what the tool does not stop.** Snyk Agent Scan states it is a
   point-in-time scanner, not a runtime blocker, and names a residual gap.
   sandbox-runtime names each setting that weakens isolation. E2B puts a
   warning on the network page that a blocked connection can look like
   success. These build more trust than any feature list.
4. **Separate tutorials, how-to guides, concepts, and reference.** NeMo tags
   every page with its type. OPA teaches its policy language from the smallest
   unit upward on one page and keeps integration guides elsewhere. E2B's landing
   page tells you what each section is for. None of the thirteen does this fully,
   so doing it well sets interlock apart.
5. **Put a large catalog on one page, grouped into tables.** Presidio groups
   its recognizers by region in `Entity | Description | Detection method`
   tables. Guardrails AI adds risk-category filters. LLM Guard's two flat link
   lists already strain at 35 scanners. A fixed per-entry template (LLM Guard)
   keeps entries comparable.
6. **One integrations table that fans out.** Superagent and Snyk use a matrix
   (language or client against capability) linking to one page each.
7. **Compare yourself to the alternatives.** NeMo has a "How is this different?"
   section that names other projects.

## What to avoid

- A README that is only a link hub (OPA, Presidio, LLM Guard): nothing proves
  value on the first screen.
- A README that tries to be the whole manual (Lasso, 521 lines; sandbox-runtime,
  901 lines).
- A "6 lines to working" quickstart that silently needs a config directory first
  (NeMo).
- Capabilities that are gated or paid, disclosed late in a table (Lasso), and
  mandatory accounts for an "open" tool (Snyk Agent Scan, Superagent).
- Dead links and docs branded after another product (Invariant).

## What we decided for interlock

| Decision | Because |
|---|---|
| README opens with a blocked call and its printed output | Patterns 1 and 2 |
| README stays a landing page (~250 lines) and links into `docs/` | Avoid the link-hub and the do-everything README |
| `docs/` split into getting started, concepts, guides, and reference, with a legend on `docs/overview.md` | Pattern 4 |
| A dedicated [security model](../docs/security-model.md) page, linked from the README | Pattern 3 |
| The detector catalog is one page of grouped tables, **generated from the code** by `scripts/gen_detector_catalog.py` | Pattern 5, and the README's detector count has drifted before |
| The catalog has a "Scoped to" column | 31 detectors only act on named actions; without this column a user cannot tell a detector is silently idle |
| Guides open with the attack or failure, then the API | Pattern 1 |
| "No signup, no network calls, no dependencies" is stated up front | Two of the closest projects now require a vendor account |
| A "How is this different?" section | Pattern 7 |
