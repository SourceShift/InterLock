# UI/UX brief — interlock front page

**For:** a product designer
**From:** engineering
**Scope:** the landing page at `https://interlock.sourceshift.ai/`, and the design
tokens that cascade from it into the docs
**Status:** updated. The **structure is built and live** — a landing page at `/`
with the docs behind it. What we need from you now is the layer on top of it:
identity, tokens, and assets. See §9 for exactly which parts are code and which
are design.

---

## 1. What this page is for

interlock is an open-source (Apache-2.0) Python library. It sits inside an AI
agent's own process and decides on every tool call before it runs — allow it,
block it, or rewrite it. It is pre-1.0, free, and has no company behind it.

This page is **not** a product marketing page. It is the front door to technical
documentation, and its job is to convert one specific reader: an engineer who
has an agent in production, is mildly worried about what it might do, and is
five minutes from deciding whether to spend an afternoon trying this.

That reader's question is not "what is interlock". It is **"does this actually
work, and how much will it cost me to find out?"**

## 2. The single job of the page

> Convince a skeptical engineer, in under thirty seconds, that interlock catches
> a real attack — and that trying it costs three commands and no signup.

Everything below serves that. If a section does not serve it, cut it.

**Success = they copy the install line or click "Get started" — and they believe
the example they just read was real.**

## 3. Audience

| Who | What they need in the first screen | What loses them |
|---|---|---|
| **Platform / security engineer** evaluating guardrails for a real deployment | Proof it catches something specific; that it runs in-process with no proxy | Vague claims, a vendor account wall, "contact sales" |
| **Agent developer** who just had a near-miss (`rm -rf`, a leaked key, an agent that followed instructions from a web page) | The exact failure they fear, shown being stopped, with output | Marketing language; no runnable code |
| **Tech lead / architect** doing a build-vs-buy scan | A one-line honest differentiator and a link to the security model | Hiding the limits; no comparison to alternatives |
| **Curious dev arriving from a link** | A reason to stay for 20 seconds | A wall of features |

Write for the first two. The third reads the "Know the limits" content and the
comparison table. The fourth needs the hero to be legible at a glance.

## 4. Evidence base — please read before designing

We surveyed the READMEs and docs of thirteen comparable projects: NeMo
Guardrails, Guardrails AI, LLM Guard, LlamaFirewall, Invariant, Snyk Agent Scan,
Leash, Lasso MCP Gateway, Superagent, sandbox-runtime, E2B, OPA, and Presidio.
The full note is in [`research/readme-docs-benchmark.md`](../research/readme-docs-benchmark.md).

What the study found, and what it means for this page:

| Finding | Consequence for the design |
|---|---|
| LlamaFirewall and sandbox-runtime show a call **allowed and blocked, with printed output, in the first 20 lines**. Readers believe what they see run. | The hero must contain a **real code block and its real output**, not a diagram or an illustration of one. |
| The highest-trust signal across the set is **naming what the tool does not stop**. Snyk Agent Scan and E2B both do it. | A visible, unrushed "Limits" link above the fold region. It is a feature of the page, not a legal footnote. |
| READMEs that are only a link hub (OPA, Presidio, LLM Guard) prove nothing on the first screen. | No link-grid front page. |
| READMEs that try to be the whole manual (sandbox-runtime, 901 lines; Lasso, 521) exhaust the reader. | The page is a **landing page**, roughly 250 lines of content, and hands off to the docs. |
| Guardrails AI, E2B and LlamaFirewall print output after every snippet. | Every code block on this page carries its result. No orphan snippets. |
| Several competitors now require a vendor account. interlock does not. | "No signup, no account, no network calls" is a **headline claim**, not a bullet. |

## 5. Content hierarchy

> **Built.** The wireframe below is the intent. What shipped differs in two
> places, both noted in §9: the top nav is the theme's header plus the sidebar
> (not a custom bar), and the page ends with a six-card docs hand-off rather
> than the old docs-index tables. Everything else below is accurate.

```
┌──────────────────────────────────────────────────────────────────┐
│  ⬛ logo    Docs   Detectors   Roadmap   GitHub ★        [search] │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Guardrails for what your agent DOES,                           │  ← H1, one line
│   not just what it says.                                         │
│                                                                  │
│   interlock checks every tool call inside your agent's own       │  ← subhead, 2 lines
│   process and allows, blocks, or rewrites it before it runs.     │
│   No proxy. No account. No network calls. No dependencies.       │
│                                                                  │
│   [ Get started → ]   [ GitHub ★ 2.3k ]                          │  ← two CTAs, one primary
│                                                                  │
│   ┌────────────────────────────────────────────────────────────┐ │
│   │ $ pip install "git+https://github.com/SourceShift/…"       │ │  ← the proof block.
│   │                                                            │ │    REAL code, REAL output.
│   │ @guard()                     ← 6–10 lines, not a novel     │ │    This is the centre of
│   │ def http_post(url, body): …                                │ │    the page. Give it room.
│   │                                                            │ │
│   │ ✓ allow    posted to api.acme.com: Card [REDACTED]         │ │
│   │ ✗ block    Blocked: egress to 'evil.example' is not on the │ │
│   │            destination allowlist                           │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│  Why this exists                       ← 3–4 short blocks, one    │
│                                          idea each, no icon soup  │
│  • Three verdicts, not two — block OR rewrite (cap an amount,    │
│    mask a secret, force a dry run) so safety doesn't cost the task│
│  • It checks results too — injected instructions arrive in tool  │
│    output; interlock screens what tools return                   │
│  • 105 detectors, ready-made — prompt injection, SQL/shell       │
│    injection, secret and PII redaction, SSRF, egress, MCP trust, │
│    budgets, loops                                                │
│  • Per-tenant policy scopes, a tamper-evident audit log, and an  │
│    OS sandbox for the subprocesses your agent launches           │
├──────────────────────────────────────────────────────────────────┤
│  Works with                        ← logos/names, one line each  │
│  @guard()  ·  MCP  ·  LangChain  ·  OpenAI/Anthropic tool loops  │
│  ·  Node.js (same Python policy via a local daemon)              │
├──────────────────────────────────────────────────────────────────┤
│  How is this different?            ← the comparison table, kept  │
│                                       honest and un-triumphal    │
├──────────────────────────────────────────────────────────────────┤
│  Know the limits                   ← THE TRUST SECTION.          │
│  Named, specific, in the author's own voice. Not a disclaimer.   │
├──────────────────────────────────────────────────────────────────┤
│  [ Get started → ]  [ Read the security model ]   ← repeat CTA   │
├──────────────────────────────────────────────────────────────────┤
│  footer: Apache-2.0 · GitHub · docs · changelog · contact        │
└──────────────────────────────────────────────────────────────────┘
```

### Above-the-fold contract

On a 1440×900 laptop with no scrolling, the reader must see:

1. the H1 and subhead,
2. at least the **blocked** line of the proof block, with its reason string,
3. one CTA.

If the proof block pushes the blocked line below the fold, the layout is wrong —
commit the code block to fit rather than shrinking the type.

## 6. Copy

### Approved, use verbatim

These strings are already published and consistent across the README, the
package metadata and the v0.0.1 release. Do not rewrite them.

- **H1:** Stop a bad tool call before your AI agent makes it.
- **Positioning line:** interlock checks every tool call your agent makes, inside the agent's own process, and allows, blocks, or rewrites it before anything happens. No proxy, no account, no network calls, and no dependencies.
- **Proof block code + output:** the `network_egress_guard` / `pii_redaction_guard` example in [`README.md`](../README.md) — the output there is what the code really printed.
- **Verdict names:** `allow`, `block`, `rewrite`. Never "deny", "filter", "sanitise".
- **Detector count:** 105. It is generated from the code and checked in CI. Do not round it or write "100+".

### Needs writing (designer may propose)

- The three or four "why" blocks (§5): aim for one sentence each, no bullets inside bullets.
- Section headings — short and plain. "How is this different?", not "Competitive positioning".
- The limits section intro: one sentence framing honesty as the point.

### Voice

Second person, short sentences, plain words. Explain *why* before *how*. Say what
does not work as clearly as what does. The existing README and
[`CONTRIBUTING.md`](../CONTRIBUTING.md) are the reference for tone — read three
paragraphs of each before you write a word.

## 7. Visual direction

**Feeling:** precise, sober, engineering-grade. The visual credibility comes from
the code being legible and the output being real, not from illustration.

**Please avoid:** a shield/lock icon; a robot or an AI-generated 3D blob; a
purple-to-blue gradient; stock "hacker in a hoodie" imagery; floating dashboards
of fake metrics; a mascot. Every one of those is what the other thirteen
projects look like, and none of them conveys "in-process Python library".

**Stronger directions:**

- **Type-led.** A confident grotesk for headings, a high-quality mono for code,
  and let the code block be the visual centrepiece. The `allow` / `block` pair
  is the hero image — treat it as such.
- **Verdict colour as the system.** `allow` / `rewrite` / `block` is the core
  abstraction of the product. Consider making these three the *only* accent
  colours on the page and reusing them everywhere: in the code block, the "why"
  blocks, the docs callouts, the comparison table. That gives the brand a
  system rather than a palette.
- **Dark by default.** This is a tool engineers will read next to a terminal.

**Deliverable shape:** the page itself is built (§9). We need the identity layer
on top of it — tokens, type, assets — not a fresh HTML page.

## 8. Hard constraints

These are non-negotiable, and two of them are brand-critical.

1. **No third-party requests.** No Google Fonts, no analytics, no tag manager,
   no hosted icon set, no CDN. interlock's pitch is "no account, no network
   calls, works offline" — a page that phones home to three vendors to say so
   is self-refuting. **Self-host any webfont, or use a system font stack.** This
   is the constraint most likely to collide with your defaults; raise it early.
2. **It must work with JavaScript disabled.** The site is static HTML generated
   from Markdown. Search and the theme toggle are enhancements, not requirements.
3. **No build step of our own.** The site is generated from Markdown by
   [Zensical](https://zensical.org) (the successor to Material for MkDocs) — no
   npm, no bundler, no React. See §9.
4. **Light and dark both.** The theme ships a light/dark/system toggle. Both
   modes must be designed; dark is the primary.
5. **Contrast:** WCAG AA minimum (4.5:1 body, 3:1 large text and UI). The
   verdict colours in particular must be distinguishable **without relying on
   hue alone** — colour-blind readers and printed output both matter. Pair every
   verdict colour with a mark and a word (`✓ allow`, `✗ block`).
6. **No cookie banner, ever.** There is nothing to consent to; see constraint 1.
7. **Performance budget:** LCP under 1.5s on a cold cache, total page weight
   under 500 KB including fonts. The competitor pages we benchmarked are heavy.

## 9. Technical reality — read this before you design

The page is rendered by Zensical's theme (a Material-for-MkDocs descendant).
We can change:

- **design tokens** — CSS custom properties: colour, type scale, spacing, radii,
  shadows;
- **layout intent** — what sits where, and how it reflows;
- **component behaviour** — e.g. how the code block, code tabs, and callout
  boxes look and behave;
- **assets** — logo, favicon, OG image, and any hero illustration;
- **limited structural overrides** — Zensical supports a `custom_dir` for theme
  overrides and `extra_css`. Small structural changes are cheap; rebuilding the
  page frame is not.

**So a bespoke landing page turned out to be cheap after all.** The earlier draft
of this brief said we could not deliver one. That was wrong, and it was written
before we read the theme's template. Zensical exposes a `{% block hero %}` above
the docs content column and a `{% block content %}` inside it, so the hero can be
full-bleed while the docs keep their stock layout. The page now lives in three
files:

| File | Holds |
|---|---|
| `overrides/main.html` | the hero, the install line, and the proof block. Gated on `page.url == ''`, so it is inert on every docs page. |
| `landing/index.md` | the prose below the hero, as ordinary Markdown: why, the comparison, the limits, the docs hand-off. |
| `docs/assets/stylesheets/landing.css` | every token and rule on this list. |

Genuinely off the table: a client-side framework, and anything needing its own
build step. The site is static HTML generated from Markdown, built in CI by
`zensical build --strict`.

### What is code, and what is yours

Already coded — treat as fixed unless you argue otherwise: the section order, the
copy in §6, the three-verdict colour triad, and the proof block's contents (its
output is real; see §6).

Yours to define:

1. A **token spec** — named values for colour, type scale, spacing, radii, and
   shadows, mapped onto the custom properties already in `landing.css` (`--il-*`)
   and the theme's (`--md-*`). Figma variables or a plain table both work.
2. **Section layout** — a frame per section in §5, annotated with what must stay
   above the fold.
3. **Both themes** — light and dark for the hero and the proof block. Note the
   terminal card is deliberately dark in *both*: it is a terminal.
4. **Assets** — logo (SVG, light + dark), favicon, OG image (1200×630).
5. **States and edge cases** — long code lines, the block reason wrapping,
   hover/focus/active on the CTAs, and the page at 360px.

### Two constraints we already hold, and will not trade

- **No third-party requests.** The theme shipped a Roboto stylesheet from
  `fonts.googleapis.com` on every page view — on the docs site of a library whose
  pitch is "no network calls". We set `font = false` and a system stack in
  `landing.css`. Do not introduce a hosted webfont, an icon CDN, or analytics.
- **No JavaScript.** The page is complete without it, which is verified by
  fetching the HTML rather than assumed. Search and the theme toggle are
  enhancements only.

## 10. Responsive

| Breakpoint | Requirement |
|---|---|
| ≥1440px | Hero copy and proof block side by side, if it fits without cramping the code |
| 1024–1439px | Stacked; proof block full width |
| 768–1023px | Nav collapses to the theme's drawer |
| 360–767px | Proof block scrolls horizontally rather than wrapping code — wrapped code is unreadable. The blocked-reason string may wrap. |

## 11. What we are not asking for

- A redesigned docs interior. Only the front page and the tokens that cascade.
- Illustration or iconography beyond a logo.
- Motion design beyond subtle hover/focus. No scroll-jacking, no animated hero.
- A CMS, a blog design, or a pricing page. There is no pricing — it is free.

## 12. How we will know it worked

Directional, over the first month: install-line copies from the page, click-through
to `getting-started`, and GitHub stars referred from `interlock.sourceshift.ai`.
If you want a measurable target to design against: **a visitor who reaches the
page should hit the "Get started" CTA or the GitHub link in under 45 seconds, or
we have lost them.**

## 13. Open questions for you

1. **Verdict colours as the brand system** — is that a system you would build
   the whole identity on, or too narrow? It is the most distinctive asset we
   have and it comes straight from the product.
2. **We need a logo.** There isn't one. "Interlock" suggests two shapes meeting
   or overlapping. Worth exploring before the page, since the page depends on it.
3. **Self-hosted webfonts or a system stack?** A system stack costs zero
   kilobytes and never FOUTs; a self-hosted grotesk buys distinctiveness. Your
   call, with the performance budget in mind.
4. **How hard should the limits section push?** Our instinct is hard — it is our
   strongest differentiator and the study backs it — but a designer's eye for
   whether it breaks the purchase mood is worth more than ours.
