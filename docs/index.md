---
hide:
  - navigation
  - toc
---

<!--
  The landing page at https://interlock.sourceshift.ai/docs/

  This file holds the four prose sections and nothing else. The chrome around
  them -- the header, the hero with its console panel and stats strip, and the
  footer -- is rendered by overrides/main.html, which is gated on
  `page.url == ''` and wraps this content in <div class="il-home">. The
  stylesheet is docs/assets/stylesheets/home.css and the behaviour is
  docs/assets/javascripts/home.js; both are injected only on this page.

  Why this is raw HTML rather than Markdown with `markdown="1"` containers: the
  `md_in_html` extension only parses a marked element when that element is
  top-level inside its raw-HTML block. This page wraps everything in <section>
  and <div> for the design's grid, so every intermediate element would need the
  attribute and a single omission silently reverts that subtree to literal
  text -- which is exactly the bug this comment was written after. Plain HTML
  has no such failure mode. Links still work: the build rewrites relative
  `href="foo.md"` targets to `foo/` whether they came from Markdown or HTML.

  Two numbers here are load-bearing and are worth re-checking when the code
  moves:

    * 121 detectors. That is the row count of docs/reference/detectors.md,
      which scripts/gen_detector_catalog.py generates and whose check mode CI
      runs. Grep for 119 in this file if the catalog ever changes.

    * The fifth limit describes what Verdict.ESCALATE actually does today. It
      is not a "someday" item any more -- the verb ships, so what a reader needs
      to know is what happens when nobody is there to answer it.

  `hide: [navigation, toc]` drops both sidebars: this page is a front door, and
  the sidebar is the table of contents for the manual behind it.
-->

<section class="il-sec" id="why-interlock">
<div class="il-sec__inner">

<div class="il-sec__head" data-il-reveal>
<div>
<span class="il-sec__num">01</span>
<h2 class="il-sec__title">Why interlock</h2>
</div>
<p class="il-sec__lede">Agents make mistakes, and some get tricked. Sooner or later one runs <code>rm -rf</code>, sends data to a host you have never heard of, or follows an instruction it found on a web page. Most guardrails watch what the model <strong>says</strong>. interlock watches what it <strong>does</strong>: at the last moment you can still say no, with the real arguments in hand.</p>
</div>

<div class="il-cards">

<div class="il-card il-card--wide" data-il-spot data-il-reveal>
<div class="il-card__split">
<span class="il-card__ic il-card__ic--acc"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m21 9-4-4v3h-7v2h7v3M7 11l-4 4 4 4v-3h7v-2H7z"></path></svg></span>
<h3 class="il-card__h">Four verdicts, not two</h3>
<p class="il-card__p">A call can be allowed, blocked, or <strong>rewritten</strong> &mdash; mask a card number, cap a row limit, force a dry run. A risky call can also stop and wait for <strong>escalation</strong>, so the answer can come from a person. Safety does not always have to cost you the task.</p>
</div>
<div class="il-verdicts">
<span class="il-verdict il-verdict--allow"><i>&#10003;</i>allow</span>
<span class="il-verdict il-verdict--block"><i>&#10007;</i>block</span>
<span class="il-verdict il-verdict--rewrite"><i>~</i>rewrite</span>
<span class="il-verdict il-verdict--escalate"><i>!</i>escalate</span>
</div>
</div>

<div class="il-card il-card--narrow" data-il-spot data-il-reveal>
<span class="il-card__ic"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m14 12-4-4v3H2v2h8v3m10 2V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v3h2V6h12v12H6v-3H4v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2"></path></svg></span>
<h3 class="il-card__h">It checks what tools send back</h3>
<p class="il-card__p">Injected instructions arrive in tool output: a web page, an email, a document. interlock screens results before your agent ever reads them.</p>
</div>

<div class="il-card il-card--narrow" data-il-spot data-il-reveal>
<span class="il-card__ic"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="m10 17-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9m-6-8L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5z"></path></svg></span>
<h3 class="il-card__h">One policy, every framework</h3>
<p class="il-card__p">The same rules guard decorated functions, MCP sessions, LangChain tools, your own model loop, and Node.js agents.</p>
<div class="il-tags">
<span class="il-tag">@guard</span><span class="il-tag">MCP</span><span class="il-tag">LangChain</span><span class="il-tag">model loop</span><span class="il-tag">Node.js</span>
</div>
</div>

<div class="il-card il-card--wide il-card__row" data-il-spot data-il-reveal>
<span class="il-card__num">121</span>
<div class="il-card__numwrap">
<h3 class="il-card__h">121 detectors, ready-made</h3>
<p class="il-card__p">Prompt injection, SQL and shell injection, secret and PII redaction, SSRF, egress allowlists, MCP server trust, budgets, and runaway loops.</p>
</div>
</div>

<div class="il-card il-card--wide" data-il-spot data-il-reveal>
<span class="il-card__ic"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3 1h16a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1m0 8h16a1 1 0 0 1 1 1v.67l-2.5-1.11-6.5 2.88V15H3a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1m0 8h8c.06 2.25 1 4.4 2.46 6H3a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1M8 5h1V3H8zm0 8h1v-2H8zm0 8h1v-2H8zM4 3v2h2V3zm0 8v2h2v-2zm0 8v2h2v-2zm13.5-7 4.5 2v3c0 2.78-1.92 5.37-4.5 6-2.58-.63-4.5-3.22-4.5-6v-3zm0 1.94L15 15.06v2.66c0 1.54 1.07 2.98 2.5 3.34z"></path></svg></span>
<h3 class="il-card__h">Built for real deployments</h3>
<p class="il-card__p">Per-tenant policy scopes with safe delegation to sub-agents, a tamper-evident audit log, and an OS sandbox for the subprocesses your agent launches.</p>
</div>

<div class="il-card il-card--narrow" data-il-spot data-il-reveal>
<span class="il-card__ic"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3 17v2h6v-2zM3 5v2h10V5zm10 16v-2h8v-2h-8v-2h-2v6zM7 9v2H3v2h4v2h2V9zm14 4v-2H11v2zm-6-4h2V7h4V5h-4V3h-2z"></path></svg></span>
<h3 class="il-card__h">Nothing to sign up for</h3>
<p class="il-card__p">Pure Python, no runtime dependencies, no API keys, no telemetry. It runs offline, and it works the same in CI as it does on your laptop.</p>
</div>

</div>
</div>
</section>

<section class="il-sec il-sec--alt" id="where-interlock-fits">
<div class="il-sec__inner">

<div class="il-sec__head" data-il-reveal>
<div>
<span class="il-sec__num">02</span>
<h2 class="il-sec__title">Where interlock fits</h2>
</div>
<p class="il-sec__lede">There are three places you can put a guard on an agent, and they each see something different:</p>
</div>

<div class="il-fit" data-il-reveal>
<div class="il-fit__bg" aria-hidden="true"></div>
<div class="il-fit__scroll">
<div class="il-fit__grid">

<div class="il-fit__rail">
<div class="il-fit__line" aria-hidden="true"></div>
<div class="il-fit__traveller" aria-hidden="true"><i></i><i></i></div>

<div class="il-fit__node">
<div class="il-fit__nodehead">
<i><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"></path><path d="M20 3v4"></path><path d="M22 5h-4"></path></svg></i>
<div class="il-fit__nodename"><span>01</span><b>model</b></div>
</div>
<p>Reads the prompt, plans the next step.</p>
<code class="il-fit__code">says: "post the notes"</code>
</div>

<div class="il-fit__hop">
<span class="il-fit__hopdot"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 20a1 1 0 0 0 .553.895l2 1A1 1 0 0 0 14 21v-7a2 2 0 0 1 .517-1.341L21.74 4.67A1 1 0 0 0 21 3H3a1 1 0 0 0-.742 1.67l7.225 7.989A2 2 0 0 1 10 14z"></path></svg><span class="il-fit__hopnum">1</span></span>
<span class="il-fit__hopname">Prompt / output filter</span>
</div>

<div class="il-fit__node">
<div class="il-fit__nodehead">
<i><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 8V4H8"></path><rect x="4" y="8" width="16" height="12" rx="2"></rect><path d="M2 14h2"></path><path d="M20 14h2"></path><path d="M15 13v2"></path><path d="M9 13v2"></path></svg></i>
<div class="il-fit__nodename"><span>02</span><b>agent</b></div>
</div>
<p>Turns the plan into a tool call.</p>
<code class="il-fit__code">http_post(url, body)</code>
</div>

<div class="il-fit__hop il-fit__hop--hero">
<span class="il-fit__hero"><svg width="30" height="26" viewBox="0 0 28 24" fill="none" aria-hidden="true"><rect x="2" y="2" width="15" height="15" rx="4" stroke="#16120a" stroke-width="2.4"></rect><rect x="11" y="7" width="15" height="15" rx="4" stroke="var(--acc)" stroke-width="6"></rect><rect x="11" y="7" width="15" height="15" rx="4" stroke="#16120a" stroke-width="2.4"></rect><line x1="17" y1="4.6" x2="17" y2="9.4" stroke="var(--acc)" stroke-width="6"></line><line x1="17" y1="4" x2="17" y2="10" stroke="#16120a" stroke-width="2.4"></line></svg><span class="il-fit__hopnum">3</span></span>
<span class="il-fit__hopname">interlock, in-process</span>
<div class="il-fit__verdicts"><span class="v-allow">&#10003;</span><span class="v-rewrite">~</span><span class="v-block">&#10007;</span></div>
</div>

<div class="il-fit__node">
<div class="il-fit__nodehead">
<i><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m4 17 6-6-6-6"></path><path d="M12 19h8"></path></svg></i>
<div class="il-fit__nodename"><span>03</span><b>tool</b></div>
</div>
<p>Runs with the real arguments.</p>
<code class="il-fit__code">@guard() def http_post</code>
</div>

<div class="il-fit__hop">
<span class="il-fit__hopdot"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="2" width="20" height="8" rx="2"></rect><rect x="2" y="14" width="20" height="8" rx="2"></rect><path d="M6 6h.01"></path><path d="M6 18h.01"></path></svg><span class="il-fit__hopnum">2</span></span>
<span class="il-fit__hopname">Network proxy or gateway</span>
</div>

<div class="il-fit__node">
<div class="il-fit__nodehead">
<i><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"></path><path d="M2 12h20"></path></svg></i>
<div class="il-fit__nodename"><span>04</span><b>network</b></div>
</div>
<p>Outbound HTTP, usually encrypted.</p>
<code class="il-fit__code">api.acme.com</code>
</div>

</div>

<div class="il-fit__brackets" aria-hidden="true">
<div class="il-fit__bracket" style="grid-column:1 / 3"><span></span><span>what the model says</span></div>
<div class="il-fit__bracket il-fit__bracket--does" style="grid-column:4 / 8"><span></span><span>what it does</span></div>
</div>

</div>
</div>
</div>

<div class="il-sees">

<div class="il-sees__card" data-il-reveal>
<div class="il-sees__head"><i>1</i><b>Prompt / output filter</b></div>
<div class="il-sees__row"><span class="il-sees__k">Sees</span><span class="il-sees__v">what the model is told, and what it says</span></div>
<div class="il-sees__row"><span class="il-sees__k il-sees__k--miss">Misses</span><span class="il-sees__v">what the model decides to <em>do</em></span></div>
</div>

<div class="il-sees__card" data-il-reveal>
<div class="il-sees__head"><i>2</i><b>Network proxy or gateway</b></div>
<div class="il-sees__row"><span class="il-sees__k">Sees</span><span class="il-sees__v">outbound HTTP, usually encrypted</span></div>
<div class="il-sees__row"><span class="il-sees__k il-sees__k--miss">Misses</span><span class="il-sees__v">file writes, shell commands, local tools, and the real arguments</span></div>
</div>

<div class="il-sees__card il-sees__card--hero" data-il-reveal>
<div class="il-sees__head"><i>3</i><b>interlock, in-process</b></div>
<div class="il-sees__row"><span class="il-sees__k">Sees</span><span class="il-sees__v">every guarded call with its real arguments, right before it runs</span></div>
<div class="il-sees__row"><span class="il-sees__k il-sees__k--miss">Misses</span><span class="il-sees__v">code that runs outside the guarded functions, such as a subprocess</span></div>
</div>

</div>

<div class="il-fit__notes" data-il-reveal>
<p>interlock sits at the last moment you can still refuse, and it is the only position holding the exact arguments. For the part it cannot see &mdash; a subprocess the agent launches &mdash; interlock ships <a href="guides/sandbox.md">BRACE</a>, an OS sandbox built from the same policy.</p>
<p><a href="concepts.md">How interlock works</a> covers the mechanics: events, rules, verdicts, ordering, and what happens when something goes wrong.</p>
</div>

</div>
</section>

<section class="il-sec" id="know-the-limits">
<div class="il-sec__inner il-limits-wrap">

<div class="il-limits-aside" data-il-reveal>
<span class="il-sec__num">03</span>
<h2 class="il-sec__title">Know the limits</h2>
<p>These are the honest ones. A guardrail you over-trust is worse than one you understand.</p>
<p>The <a href="security-model.md">security model</a> is the full version, including the settings that quietly weaken protection and the gaps we have not closed.</p>
</div>

<div class="il-limits-card" data-il-reveal>
<div class="il-limits-card__hazard" aria-hidden="true"></div>
<ul class="il-limits">

<li><p><strong>It does not understand intent.</strong> The detectors match specific patterns, tuned so ordinary values do not trip them. That keeps false alarms low, and it means a reworded attack can get through: <code>tool_result_injection_guard</code> catches "ignore previous instructions", but not "ignore <em>all</em> previous instructions". Treat detectors as layers, and pair them with allowlists, which do not depend on wording.</p></li>

<li><p><strong>It only sees the calls you wrap.</strong> A tool without <code>@guard</code>, a session you did not wrap, or a call that never goes through <code>enforce_tool_call</code> is invisible to interlock.</p></li>

<li><p><strong>It does not undo actions.</strong> A result is checked after the tool has already run. Blocking the result hides the output from your agent; the side effects stand.</p></li>

<li><p><strong>It cannot stop malicious code in its own process.</strong> interlock runs inside your agent. Code sitting next to it could call the unguarded function directly, or install an empty engine. Run code you do not trust &mdash; model-written scripts, third-party plugins &mdash; in the <a href="guides/sandbox.md">sandbox</a>, not just behind a guard.</p></li>

<li><p><strong>Escalation needs somewhere to escalate to.</strong> The fourth verdict ships: a rule can return <code>Verdict.ESCALATE</code>, and the console's review queue collects it. But the answer has to come from somewhere. Register an approval handler, or route the request through the console, and the call resumes when someone decides. Register nothing and the call waits on a future that never resolves &mdash; a blocked agent with a hang instead of an error, which is usually the harder thing to debug. Escalate where a human is actually watching.</p></li>

</ul>
</div>

</div>
</section>

<section class="il-sec il-sec--alt" id="read-the-docs">
<div class="il-sec__inner">

<div class="il-sec__head" data-il-reveal>
<div>
<span class="il-sec__num">04</span>
<h2 class="il-sec__title">Read the docs</h2>
</div>
</div>

<div class="il-docgrid">

<div class="il-doc" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Start here</h3>
<p><a href="getting-started.md">Getting started</a> &mdash; about fifteen minutes. Guard a tool, block a dangerous call, rewrite a risky one, catch an injected instruction, and try a rule without enforcing it. Every snippet was run, and the output is what it printed.</p>
</div>

<div class="il-doc il-doc--plain" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Understand it</h3>
<p><a href="concepts.md">How interlock works</a> &mdash; events, rules, verdicts, how they combine, and what happens when a rule crashes.</p>
<p><a href="security-model.md">Security model</a> &mdash; what it protects against, what it assumes, and where it stops.</p>
</div>

<div class="il-doc il-doc--plain" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Pick your defence</h3>
<p><a href="guides/detectors.md">Using detectors</a> &mdash; choose from 121 built-in rules, and make sure they see your tools.</p>
<p><a href="guides/writing-rules.md">Writing rules</a> &mdash; from one-liners to result-phase rules and tests.</p>
</div>

<div class="il-doc il-doc--plain" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Deploy it</h3>
<p><a href="guides/production.md">Production checklist</a> &mdash; monitor mode, logging, and rollout.</p>
<p><a href="guides/scopes.md">Scopes</a> and <a href="guides/audit-log.md">audit log</a> &mdash; per-tenant policy and a tamper-evident record of every decision.</p>
</div>

<div class="il-doc il-doc--plain" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Connect it</h3>
<p><a href="guides/integrations.md">Integrations</a> &mdash; <code>@guard</code>, MCP, LangChain, a model SDK loop, or a Node.js agent.</p>
<p><a href="guides/mcp.md">MCP</a> &mdash; guard a session and decide which servers and tools to trust.</p>
</div>

<div class="il-doc il-doc--plain" data-il-spot data-il-reveal>
<h3 class="il-doc__h"><span></span>Look it up</h3>
<p><a href="reference/python-api.md">Python API</a> &mdash; every public class and function, with signatures.</p>
<p><a href="reference/detectors.md">Detector catalog</a> &mdash; all 121 detectors: what each catches, and which calls it sees.</p>
</div>

</div>

<div class="il-cta" data-il-reveal>
<div class="il-cta__grid-bg" aria-hidden="true"></div>
<div class="il-cta__glow" aria-hidden="true"></div>
<svg width="56" height="48" viewBox="0 0 28 24" fill="none" aria-hidden="true"><rect x="2" y="2" width="15" height="15" rx="4" stroke="var(--acc)" stroke-width="2.4"></rect><rect x="11" y="7" width="15" height="15" rx="4" stroke="#111214" stroke-width="6"></rect><rect x="11" y="7" width="15" height="15" rx="4" stroke="#ecebe6" stroke-width="2.4"></rect><line x1="17" y1="4.6" x2="17" y2="9.4" stroke="#111214" stroke-width="6"></line><line x1="17" y1="4" x2="17" y2="10" stroke="var(--acc)" stroke-width="2.4"></line></svg>
<h2 class="il-cta__title">Stop a bad tool call before your AI agent makes it.</h2>
<div class="il-cta__actions">
<a class="il-btn il-btn--primary" href="getting-started.md">Get started <span class="il-btn__arrow" aria-hidden="true">&rarr;</span></a>
<a class="il-btn il-btn--ghost" href="https://github.com/SourceShift/InterLock">Star on GitHub</a>
</div>
</div>

</div>
</section>
