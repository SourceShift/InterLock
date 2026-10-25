# The mesh's five open decisions: a decision record

*A synthesis of four research lenses on the open decisions in
`research/mesh-shared-policy-network.md` §11.*

> **Provenance.** Produced by the mini-ork `research-synthesis` recipe (run
> `run-1792920000-93111`, 2026-10-25, $13.86): four family-diverse lenses in
> parallel, then one synthesizer, all reading the checkout at `36fbfae`. The lens
> reports are kept verbatim under [`data/mesh-decisions/`](data/mesh-decisions/).
> The recipe's source-completeness verifier counted only `http` URLs and so
> flagged the literature lens (DOIs and arXiv ids) and the code lens (pinned
> `github.com/...@commit` references); both are complete, see §6. The tree facts
> in §0 were re-checked by the operator and hold. The decisions here supersede
> §11 of `mesh-shared-policy-network.md`; each "Implementation" list is an epic.
> **Status 2026-10-25:** all five implementation lists shipped (see `ROADMAP.md`,
> "M0–M3 · The mesh"), including the DAP/Prio3 wire path (R2 step 3, pure Python;
> see R2 "Status"). What remains is operational: the two non-maintainer root
> keyholders and an independent DAP operator, neither of which code can invent.


- **Run:** `run-1792920000-93111` · 2026-10-25 · target checkout at `36fbfae`.
- **Lens inputs, all read in full:**
  - `lens-glm.md`: breadth, web sources 2023–2026.
  - `lens-kimi.md`: rigour, academic literature.
  - `lens-codex.md`: practice, code at pinned commits.
  - `lens-opus.md`: theory, a narrative essay.
- **Tree inputs:**
  - research doc §1–§12, `docs/guides/mesh.md`, and `ROADMAP.md` "M0–M3 · The mesh";
  - `interlock/mesh/{consensus,subscriber,repository,credential,aggregate,bundle,metadata,report}.py`,
    `interlock/cli/mesh.py` and `interlock/approval.py`.
- **Not legal advice.** The GDPR, copyright and database-right points summarise what the
  lenses found. They are not a legal opinion.

**How to read the anchors.**

| Anchor | Points at |
|---|---|
| `GLM-S7` · `GLM-D3` · `GLM-gap-2` | source [S7], "where sources disagree" note 3, and "what's NOT in the literature" item 2 of lens-glm.md |
| `Kimi-4` · `Kimi-Q5` · `Kimi-cav-2` | paper #4, the per-question summary for Q5, and methodological caveat 2 of lens-kimi.md |
| `Codex-10` · `Codex-conv-3` · `Codex-div` · `Codex-R4` · `Codex-ledger` · `Codex-gaps` | lens-codex.md: implementation #10, convergent pattern 3, the divergent-patterns list, decision verdict 4, the licence ledger, and the gaps list |
| `Opus-§4.3` · `Opus-R2` | lens-opus.md section 4 item 3; its recommendation 2 |
| `T3` | a fact this synthesis checked in the tree (§0). Tree facts are evidence but not a lens, so they never count toward a ★. |

Consensus markers count lenses: ★ two lenses, ★★ three, ★★★ all four.

---

## 0. What the tree says (checked before deciding)

Several lens claims are about the shipped code, so I checked each one against the
checkout. Three of these facts change a decision: T1, T3 and T5.

| # | Fact | Where | Bears on |
|---|---|---|---|
| T1 | **The consensus operator receives every node's counts in plaintext.** `report submit` posts the whole signed envelope to `/v1/reports`, counts included, and only *afterwards* secret-shares the counts to aggregators. The consensus engine then adds `body["counts"]` into per-rule totals. This contradicts the module docstring ("Counts are not here", `consensus.py:25`) and the guide. Confirms Opus-§4.3. | `interlock/cli/mesh.py:502`, then `:511-515`; `interlock/mesh/consensus.py:169-174` | Q2, Q3 |
| T2 | Aggregation refuses fewer than two shares. It has no minimum batch before totals are released and no validity proof per share. Confirms Codex-4. | `interlock/mesh/aggregate.py:34-35`, `:120-126`; docstring `:11-17` | Q2 |
| T3 | **The root key cannot be offline.** `load_signers` refuses to publish unless every role, root included, has a key file, and it reads private seeds from those files. There is no path for detached signatures, so keyholders on separate machines cannot reach a threshold. No lens found this. | `interlock/mesh/repository.py:95-130` (refusal at `:124-126`); `publish` at `:231-243` | Q1 |
| T4 | Root metadata expires after 365 days and has no signing period. Confirms Codex-1. | `interlock/mesh/metadata.py:61-66` | Q1 |
| T5 | **A default subscription already enforces a pack's `block` after seven days, with no operator act.** The default ring is `stable`, the stable ceiling is `None` ("the pack's own verdict"), and the monitor window is 7 days. In code, §11.5's "no" means "yes, after a week". Sharpens Codex-R5 and Opus-§4.1. | `interlock/mesh/subscriber.py:44`; `interlock/mesh/bundle.py:55-61`, `:196-210` | Q5 |
| T6 | With no approver installed, an `escalate` becomes `NotApproved`, which is a subclass of `Blocked`. On a headless node the escalate ceiling is therefore a block. Confirms Opus-§4.1. | `interlock/approval.py:324-330`; `docs/guides/approvals.md:26` | Q5 |
| T7 | An expired timestamp leaves the last verified pack installed and enforcing, because `resolve` reads the cache with `allow_expired=True`. Confirms Opus-§4.2. | `interlock/mesh/subscriber.py:459` | Q1, Q5 |
| T8 | Uploading is already a manual act (`report build`, then `report submit`), and the README promises "no network calls". However, `report build` includes digests unless given `--no-digests`, and `report enable` today turns on fingerprint *recording*, not upload consent. | `README.md:13`; `interlock/cli/mesh.py:89`, `:94-100` | Q3 |
| T9 | Code contributions already use a DCO, not a CLA, so Opus-R4's "DCO, no CLA" is already true for code. Only the data warranty would be new. | `CONTRIBUTING.md:125` | Q4 |
| T10 | The design doc's opening scenario says a rule is enforcing "within a day", which contradicts the 7-day window. Confirms Opus-R5. | `research/mesh-shared-policy-network.md:57-58` | Q5 |
| T11 | A local kill switch already exists: the subscriber's `disable` list, plus `locked` being stripped from every mesh rule. In substance, Codex-R5's "ClamAV-style kill switch" has already shipped. | `interlock/mesh/bundle.py:33-34`, `:193`; `docs/guides/mesh.md` "Subscribe" | Q5 |
| T12 | Tests files are not published as signed targets. Sample strings in `*.tests.json` live in the commons' git history, never in the signed site or the log. | `interlock/mesh/repository.py:152` | Q4 |

**One lens claim is wrong.** Codex-2 says `init_keys` "has no refuse-to-overwrite
check". It has one: `interlock/mesh/repository.py:81-82` raises "refusing to overwrite a
key". Codex-2's other point stands: there is no single reviewable ceremony config. T3,
found in the neighbouring `load_signers`, is the bigger gap.

---

## 1. TL;DR

- **Q1, root keys.**
  - *Decision:* a 2-of-3 offline hardware root. The maintainer holds one key; two named
    people at two other employers hold the others. It rotates to ≥3-of-5 across ≥3
    organisations once three member organisations are admitted. Fix T3 first so the root
    can actually be offline.
  - *Lenses:* all four agree on the threshold shape (★★★). Codex and GLM agree custody sits
    with named individuals (★). Choosing 2-of-3 over Opus's maintainer-held root is my
    judgement.
  - *Confidence:* medium.
- **Q2, aggregators.**
  - *Decision:* no count leaves a node until the consensus envelope stops carrying counts
    (T1) and aggregation speaks DAP with a minimum batch. After that, the pair is an
    independent DAP operator as leader and the maintainer as helper.
  - *Lenses:* all four agree on "two aggregators or nothing" (★★★). Codex and Opus agree
    on the batch floor (★). Kimi-4 explains why a maintainer-run helper costs no privacy.
  - *Confidence:* high for the gate, medium for the pair.
- **Q3, reporting.**
  - *Decision:* off by default and local by default. A node builds and shows its report
    locally and uploads only after an explicit `report enable`, never retroactively.
    Digests, fingerprints and samples each need their own enable.
  - *Lenses:* Codex and Opus recommend it (★). Kimi and GLM report a genuine split.
  - *Confidence:* medium. This is a values choice, made out loud.
- **Q4, licence.**
  - *Decision:* packs are Apache-2.0. Indicators, fingerprints and samples are CC0-1.0
    under a new `LICENSE-DATA`. Contributions use the existing DCO plus a three-clause data
    warranty, with no CLA.
  - *Lenses:* all four call for an explicit licence plus a warranty (★★★). Three back CC0
    for indicator-like data (★★). The pack licence is disputed (D4).
  - *Confidence:* medium.
- **Q5, block.**
  - *Decision:* no mesh `block` takes effect without an operator grant, per pack and
    status or per rule. Ungranted blocks are capped at `escalate`, and they run as shadow
    on nodes with no approver.
  - *Lenses:* all four oppose community blocking without the operator's consent (★★★).
    Three describe promotion to enforcement as a local operator act (★★).
  - *Confidence:* high.

---

## 2. Consensus findings

| ID | Finding | Marker | Anchors |
|---|---|---|---|
| C1 | The root is a threshold of offline keys, kept separate from cheap online roles that rotate easily. | ★★★ | Kimi-1/2/3 (threshold maths; TUF role separation); Codex-1, Codex-3, Codex-conv-5 (Sigstore 3-of-5 with KMS online keys; Debian `automatic` keys); GLM-S1/S2 (Sigstore signing events, five keyholders); Opus-§2, Opus-R1 |
| C2 | Foundation or multi-organisation custody is an end state. No surveyed project *started* there, and no source explains how a one-maintainer project gets there. | ★★★ | GLM-S4, GLM-gap-1; Kimi-3, Kimi-cav-2 ("assumes an organised ecosystem"); Codex-R1 ("no surveyed project started there"); Opus-§3 ("plurality is an end state") |
| C3 | In practice, custody rests with named *individuals* from different employers, serving dated terms. Organisations are not the keyholders. | ★ | Codex-1 (`root.json:47-95` lists GitHub handles; the README lists terms and emeritus holders); GLM-S2 ("five keyholders from varying companies and academic institutions") |
| C4 | Secret-shared counts need at least two aggregators that do not collude. With fewer, the honest fallback is to send nothing; a one-server mode is not acceptable. | ★★★ | Kimi-4 (Prio's one-honest-server bound); GLM-S7/S8 (ENPA lessons; DAP non-collusion); Codex-4 (Firefox has no single-aggregator mode); Opus-R2 |
| C5 | A minimum batch size, and ideally a validity proof per share, is needed before an aggregate can be released without exposing individuals. | ★ | Codex-4 (Janus `task.rs:187-188`, `aggregate_share.rs:160-162`); Opus-§4.3 (with three reporters, subtraction recovers a count) |
| C6 | Content (Layers 2–3) is never collected by default, even by systems that collect counts by default. | ★★ | Codex-conv-1 (5 of 5 telemetry systems); GLM-S14 (EDPB: consent does not waive data minimisation); Opus-§3 |
| C7 | Opt-out telemetry is the norm for developer tools distributed by vendors, 2024–2026. | ★★ | GLM-S9/S10/S12/S13; Codex-5/8/9/10; Opus-§3 (Homebrew) |
| C8 | The workable opt-in design is "local by default, upload only after consent, never retroactive". | ★ | Codex-6 (`golang/telemetry` `dir.go:124-131`, `reports.go:134-138`); Opus-R3 (Go 1.23, via go.dev/blog/gotelemetry) |
| C9 | The commons needs an explicit data licence *and* a contributor rights warranty. No existing corpus can be copied for redacted samples. | ★★★ | GLM-gap-4; Kimi-12 (redistribution needs a licence plus a warranty); Codex-ledger ("none accepts raw samples"); Opus-R4 |
| C10 | CC0 is the established licence for indicator-like and knowledge-base data. | ★★ | GLM-S17 (MISP galaxy, CC0); Codex-ledger (`misp-galaxy` CC0/BSD-2, `misp-warninglists` CC0); Opus-R4 |
| C11 | No CLA. Security corpora take contributions inbound=outbound, and a CLA is what enabled relicensing elsewhere. | ★ | Codex-ledger ("none uses a CLA or a DCO sign-off"); Opus-§3, Opus-R4 (HashiCorp, 2023) |
| C12 | False positives through a shared feed are the dominant risk. No source in any lens advocates blocking from a community feed without safeguards. | ★★★ | GLM-S22–S26, GLM-D3; Kimi-10/11 (base-rate arithmetic; non-stationarity); Codex-conv-3; Opus-§1/§3/§4 |
| C13 | In the surveyed content-rule feeds, enforcement is a local, per-rule act by the operator. | ★★ | Codex-11/12 (suricata-update `drop.conf` is entirely commented out; ClamAV `OnAccessPrevention` is off); GLM-S20 (Snort community rules historically disabled); Opus-R5 |
| C14 | CrowdSec's auto-enforced community blocklist is the exception, and it does not carry over. It blocks a remote party's IP reputation, for a limited time, with allowlists applied first. A false block there hurts the remote party; in interlock it would stop the subscriber's own agent. | ★ | Codex-10 (`apic.go:645-694`, "reputation of a remote actor"); Opus-§3 (who bears a false block) |
| C15 | CrowdStrike's Channel File 291 is the defining case of shared *content*, not code, taking down production. It is still a small sample: n=1, or n=2 counting Cloudflare 2025. | ★ | GLM-S22/S23 and GLM's bias note (n=1); Opus-§1 (adds Cloudflare, 18 Nov 2025) |

---

## 3. Disputed findings

These disputes are reported, not voted on: agreement among lenses is not averaged into a
verdict (Nasser 2026, arxiv:2601.05114). Where §5 takes a side, it names the evidence
that decided it.

**D1 · Q1: should the maintainer alone be able to sign the root?**
- **Opus-R1: yes, for now.** A 2-of-3 offline root under the maintainer's control, with
  the third share held in escrow by a named second person. The argument: loss is likelier
  than compromise, and keyholders who never use the system amount to "ceremony theatre".
- **Codex-R1: no.** 2-of-3 across the maintainer and two people from different employers.
- **§11.1 as written:** three organisations before Phase 0.
- **Why they disagree:** they fear different failures, loss versus compromise. They also
  start from different precedents: Opus reasons from the cold start, while Codex copies
  Sigstore's people-not-organisations shape.
- **What would resolve it:** a timed key-loss and succession drill on both shapes. Opus's
  own edge case points one way. In Opus-§4.2 the maintainer is gone, the timestamp
  expires (T7), and nothing can be signed. That is recoverable only if the non-maintainer
  keyholders can reach the threshold without the maintainer. So Opus's own edge case
  favours Codex's shape, and R1 adopts it.

**D2 · Q2: may the maintainer run one of the two aggregators?**
- **Codex-4: yes.** The only production DAP pair it surveyed has exactly this shape (an
  ISRG leader and a Mozilla helper), and it calls this the "credible first step".
- **Opus-R2: no.** If no DAP operator takes the tenant, "publish no counts at all rather
  than run a vendor pair".
- **§11.2's wording** ("organisations that will not collude") reads as excluding the
  vendor, and Codex-4 notes Firefox does not meet it.
- **Why they disagree:** legitimacy versus cryptography. Prio's guarantee needs only one
  honest server (Kimi-4). A pair with one genuinely independent operator therefore gives
  each reporter the same bound as two independent operators would. The real dispute is
  whether users will believe the independent operator is independent.
- **What would resolve it:** the terms an independent DAP operator offers (does it attest
  to non-collusion? publish its own audit?), and the ENPA operator agreements Codex
  could not read (Codex-gaps).

**D3 · Q3: should Layer 0 be on by default, or off?**
- **For on:**
  - Free-riding theory says to lower the cost of the smallest contribution (Kimi-5 Varian,
    Kimi-6 Anderson & Moore).
  - The CTI-incentives literature agrees (GLM-S15).
  - So does industry practice (C7) and research doc §6.6.
- **For off, or local:**
  - Gal-Or & Ghose (Kimi-7): sharing is privately rational, so a meaningful minority opts
    in anyway.
  - Go and popcon (Codex-6/7).
  - The EDPB line on lawful basis (GLM-S14).
  - MITRE's gated AI incident sharing (GLM-S27).
  - Opus-R3.
- **Why they disagree:** different populations and market positions.
  - The free-rider models describe members who *chose* to join a sharing body.
  - The opt-out precedents are products where the person installing is the person
    measured, or where the vendor has market trust.
  - interlock is a library, so a deployer inherits its default without choosing it
    (Opus-§3; GLM-S9).
  - Jurisdiction adds a legal floor that the economic models ignore.
  - Kimi (Kimi-Q3) and GLM (GLM-D1) both judge that the evidence does not settle this.
- **What would resolve it:** two pieces of evidence.
  - Opus-§5's participation-elasticity measurement: does a Go-style prompt reach
    `min_orgs` for most fired rules?
  - A legal reading of DAP-aggregated security counters under GDPR (GLM-gap-5).

**D4 · Q4: which licence for packs?**
- **Opus-R4:** Apache-2.0, "because a rule is code".
- **Codex-R4:** CC-BY-4.0, the most common licence among security data corpora.
- **GLM-S16 and Opus-§3:** DRL 1.1, which Sigma wrote because vendors repackaged rules
  without credit.
- **Why they disagree:** they compare against different kinds of corpus.
  - Codex's CC-BY-4.0 count is dominated by advisory databases: GHSA, and OSV's per-source
    ledger.
  - The *rule* corpora in Codex's own ledger use code-style licences. DRL 1.1 is MIT-like
    plus attribution, Yara-Rules is GPL-2.0, and ATLAS data is Apache-2.0.
  - GLM-S20 adds Snort community rules, under GPLv2.
- **What would resolve it:** evidence of commercial products repackaging commons packs
  without credit. That is the DRL scenario, and Opus-R4's own "wrong if" condition.

**D5 · Q4: may redacted samples be published at all?**
- **Opus-R4:** yes, under CC0 like indicators. Contributors warrant that they possess the
  text, since attackers wrote the payloads.
- **Codex-ledger and GLM-gap-4:** no surveyed corpus accepts samples, so there is no
  precedent.
- **Opus-§5, against its own recommendation:** a GDPR Art. 17 erasure may be impossible
  once a sample sits in an append-only log and in peer caches.
- **Why they disagree:** they don't, really. Nobody has precedent; this is an open
  problem, not a dispute about evidence.
- **What would resolve it:** a legal reading of Art. 17 against git history, plus a
  measured rate of redaction misses on real Layer 3 samples. T12 narrows the problem:
  samples never enter the signed site or the log, only git.

**D6 · Q5: does the time-based monitor window, by itself, count as consent to block?**
- **Kimi-Q5: yes.** Distinct-org consensus, monitor windows and measured FP rates are
  "exactly what the mesh already does", and that mechanism "must stay the default".
- **Opus-§4.1 and Opus-R5: no.** Windows catch frequent false positives and pass rare ones
  (McAfee DAT 5958), and graduating on time alone needs no local evidence.
- **Codex-R5:** add an explicit promotion list first, then decide.
- **GLM-D3:** leans no, without naming a mechanism.
- **Why they disagree:** they evaluate different things. Kimi evaluates the mechanism in
  principle: raise the prior before acting. Opus evaluates the shipped defaults, where T5
  shows the window ends in a block with no human act.
- **What would resolve it:** the randomised-window experiment of Opus-§5 (R8). If false
  blocks don't fall as the window lengthens, the window is not doing the work Kimi
  credits it with.

**D7 · Fact: what licence does abuse.ch data carry?**
- GLM-S18: free to contributing members; non-contributors need a commercial licence via
  Spamhaus, since 2025.
- Opus-§3: abuse.ch was the "poster child for CC0 indicators" and now requires a
  commercial subscription for production use.
- Codex could not read it (`[lookup]`).
- They agree on the direction, away from free-for-all, and differ on the starting point.
  No decision depends on it. Reading https://abuse.ch/terms-of-use/ would settle it.

**D8 · Fact: what is OSV's licence?** GLM-S21 says the site states none, and calls the
secondary "CC BY 4.0" claim low-confidence. Codex-14 says OSV is licence-neutral by
design, with a per-source ledger and a written intake floor. The two are compatible: the
aggregate has no single licence. Codex's in-repo evidence (`docs/new_source.md:37-45`)
supersedes the secondary claim.

---

## 4. Cross-lens gaps

These are aggregated from each lens's own list of gaps. "Synthesis" marks gaps that only
surfaced when the lenses were checked against the tree.

| Gap | Raised by | Blocks |
|---|---|---|
| A credible playbook for a single maintainer holding root keys, and a way to migrate into a foundation without re-keying | GLM-gap-1; Kimi-cav-2; Codex-R1 | revisiting R1 |
| Signing a TUF root with hardware keys from a standard-library-only tool; collecting detached signatures | synthesis (T3) | implementing R1 |
| What happens to privacy when one organisation runs both aggregators as an interim | GLM-gap-2 | R2 (which forbids that interim instead of designing for it) |
| Whether an independent DAP operator will take a tenant this small, and on what terms; the ENPA operator agreements | Codex-gaps; Opus-R2; synthesis | R2 |
| Any precedent for the telemetry default of agent-security sightings specifically | GLM-gap-3 | R3 |
| The GDPR lawful basis for DAP or secret-shared security counters | GLM-gap-5; Kimi-cav-3 | revisiting R3 |
| How participation responds to "local by default, upload on opt-in" | Opus-§5 | revisiting R3 |
| A data licence and rights warranty for privacy-sensitive derived artefacts (fingerprints, redacted samples) | GLM-gap-4; Kimi-12, Kimi-cav-5; Codex-ledger | R4 |
| Erasing a published sample from git history, peer caches and logs | Opus-§5 | revisiting R4 |
| Whether fingerprints leak membership at small N (α = 1.5, few reporters) | Opus-§5 | R3, Layer 2 |
| A public false-positive time series for any community rule feed | GLM-gap-6; Kimi-cav-4; Opus-§5 | revisiting R5 |
| CrowdSec's server-side consensus thresholds, which are closed | Codex-gaps | calibrating R5 |
| Whether DRL-1.1 has an SPDX id; the Snort and abuse.ch licences from primary text | Codex-gaps; D7 | details of R4 |
| Direct measurements of over-blocking by agent guardrails exist only as preprints, with little replication | Kimi-cav-4; GLM-S26 (vendor and preprint quality) | how strong R5's evidence is |
| Non-English and EU foundation practice | GLM's sweep biases; the plan's risk notes | R1, R4 |

---

## 5. Decision record and numbered recommendations

R1–R5 are the five §11 decisions. Each one has the same parts:

- **Decision:** the action.
- **Rationale:** the lens support.
- **Dissent:** the disagreement, reported honestly.
- **Implementation:** repository paths.
- **Revisit when:** the measurable condition under which the decision would be wrong.

R6–R9 are supporting work outside the five questions.

### R1 · Q1: Who holds the root keys

**Decision.** The commons root is a 2-of-3 threshold of offline, hardware-held keys
belonging to three named individuals: the maintainer, plus two people employed by two
different organisations (neither of them the maintainer's). Each serves a recorded term.
Once three member organisations have been admitted, the root rotates to at least 3-of-5
across at least three organisations.

**Rationale.**
- **The shape is uncontested; the holders are not.** All four lenses agree on the shape
  ★★★ (C1). Who holds the keys is the question no source settles (C2, ★★★). §11.1's
  "three organisations before Phase 0" is therefore a precondition no precedent met, and
  Phase 0 has already shipped (`ROADMAP.md:1432`).
- **Real custody means individuals, not organisations** ★ (C3). Sigstore's root names five
  GitHub handles with dated terms and an emeritus list (Codex-1). One maintainer can
  recruit two people; recruiting three organisations is not achievable. GLM-S4 shows the
  foundation route arrived only after multi-vendor funding.
- **Why 2-of-3 with the maintainer holding one key** (D1):
  - It survives losing any one key, which was Opus's main concern.
  - No single compromised laptop can re-root the commons, which was Codex's.
  - Decisively, the two other keyholders can rotate the online keys to a successor if the
    maintainer disappears. That is the only cure for the freeze in Opus-§4.2 (T7).
- **Routine signing events are the key-loss drill.** A 197-day root expiry with a 46-day
  signing window (Codex-1 `root.json:138-139`) makes every keyholder use their key about
  twice a year. That answers Opus-§3's worry about ceremony theatre with practice rather
  than paperwork.
- **Not adopted: Debian-style pre-shipped successor keys** (Codex-3). They stand in for a
  threshold, and this decision has one.
- **Not adopted: borrowing Sigstore's root for the commons, as PyPI did** (GLM-S5).
  Subscribers verify from a pinned root with a standard-library client
  (`docs/guides/mesh.md`, "Subscribe"). Fulcio and Rekor verification would add network
  calls and dependencies. Borrowing Sigstore is still right for signing interlock's own
  releases (roadmap R22).

**Dissent.**
- **Opus-R1** keeps unilateral control with the maintainer and puts the third share in
  escrow. Its argument: the realistic failure is a lost key, not a stolen one. This
  record keeps Opus's commitments (a pre-committed rotation trigger, a public transcript,
  `GOVERNANCE.md`) but not the unilateral control.
- **§11.1 as written** (three organisations first) is set aside on C2's evidence.
- **Kimi-cav-2:** this is a governance judgement. No paper decides it.

**Implementation.**
1. **Let the root stay offline.** In `interlock/mesh/repository.py`, `load_signers`
   (`:95-130`) and `publish` (`:231-243`) should publish targets, snapshot, timestamp and
   log **with no root key present**, as long as the current root is unchanged and
   unexpired (T3). Without this, an offline root is impossible.
2. **Detached root signing**, in `interlock/cli/mesh.py`:
   - `interlock mesh root draft` writes the unsigned next root.
   - `interlock mesh root sign` adds one signature with one key, on that keyholder's own
     machine.
   - `interlock mesh root assemble` checks the old root's threshold and the new root's
     own, the same rule `repository.py:217-222` already enforces.

   Signatures go through a `Signer` in `interlock/mesh/metadata.py` that can call an
   external signing program for a hardware token. The core stays standard-library only.
3. **Expiry and keyholder records**, in `interlock/mesh/metadata.py`:
   - Cut the root expiry at `:61-66` from 365 to 197 days.
   - Add a 46-day root signing period that `publish` warns about and `interlock doctor`
     reports.
   - Have `build_root` (`:260`) record an `x-interlock-keyowner` and a term start for each
     root key (Codex-1 `root.json:47-95`).
4. **`GOVERNANCE.md`** (new, top level) records:
   - a keyholder table with terms and an emeritus list;
   - the 2-of-3 rule;
   - the rotation trigger: three admitted member organisations lead to ≥3-of-5 across ≥3
     organisations;
   - the succession rule: if the timestamp has been expired for 30 days, the two
     non-maintainer keyholders may rotate the online roles;
   - who holds each online key: targets, snapshot, timestamp, log, and the issuer key for
     membership credentials in `interlock/mesh/credential.py`.
5. **A ceremony runbook, `docs/guides/mesh-root-ceremony.md`** (new), linked from the
   "Keys" section of `docs/guides/mesh.md`:
   - each ceremony is a pull request on a `ceremony/YYYY-MM-DD` branch;
   - a failed ceremony is moved aside and never reused (Codex-1 `ORCHESTRATION.md:414`);
   - a single reviewable ceremony file is what a witness checks (Codex-2, Boulder
     `README.md:7`);
   - the transcript is public (Opus-R1).
6. **Tests:** `tests/test_mesh_commons.py` (publish with no root key present) and
   `tests/test_mesh_metadata.py` (detached signatures meet both thresholds).

**Revisit when.**
- A scheduled signing event fails to collect two signatures within its 46-day signing
  period. Custody is then not workable, so reconsider Opus-R1's maintainer-held root.
- Two or more prospective member organisations name root custody as their reason for
  declining (Opus-R1's "wrong if"). Then seek a foundation home before the trigger.
- The ledger of the credential issuer (`interlock/mesh/credential.py`) shows three
  admitted member organisations. Then carry out the rotation. This is the planned exit,
  not a failure.

### R2 · Q2: Who runs the two aggregators

**Decision.** No aggregator is recruited, and no count leaves a node, until the consensus
envelope stops carrying counts and aggregation runs DAP with a minimum batch size. After
that, the first pair is an established independent DAP operator as leader and the
maintainer as helper, on different cloud providers, and the arrangement is disclosed.

**Rationale.**
- **"Two or nothing" is uncontested** ★★★ (C4). The code already refuses a single
  aggregator (`aggregate.py:34-35`; `cli/mesh.py:507-510`).
- **The question is moot until T1 is fixed.** Today the consensus operator sees every
  node's counts, so no choice of aggregators protects anything (Opus-§4.3, verified).
- **A batch floor is needed** ★ (C5). Codex-4 shows Janus refusing `min_batch_size == 0`.
  With three reporters, each can recover another's count by subtraction (Opus-§4.3; T2).
- **The maintainer as helper** (D2). Prio's privacy needs one honest server (Kimi-4), so
  reporters' guarantee rests on the independent leader. Firefox's guarantee rests on ISRG
  in the same way (Codex-4 `all.js:534-541`).
- **DAP, not the bespoke protocol.** Speaking DAP lets an operator already running it at
  scale host the leader (GLM-S6/S7; Opus-R2). The hard part is coordination, not
  cryptography (GLM-S7).
- **Different clouds:** the ENPA lesson that §11.2 cites (GLM-S7).

**Dissent.**
- **Opus-R2** would rather publish no counts than run a vendor pair. This record disagrees
  on the cryptographic merits (Kimi-4), but adopts Opus's fallback if no independent
  operator agrees (see "Revisit when").
- **§11.2's literal wording** excludes the vendor, and Codex-4 notes Firefox does not meet
  it. The defensible reading is that the guarantee comes from having one independent
  operator.
- **GLM-gap-2**, a single organisation running both aggregators "as an interim", is ruled
  out rather than designed for.

**Implementation.**
1. **The leak fix, needed regardless of operators:**
   - `interlock/mesh/report.py` (`build_report` at `:124-203`, `verify_report` at
     `:225-260`): the signed envelope for consensus carries digests, sightings,
     fingerprints and samples, and no counts. Consensus counts distinct organisations per
     rule from the digests and sightings it already receives.
   - `interlock/cli/mesh.py` `_report_submit` (`:490-522`) sends counts only as shares.
   - `interlock/mesh/consensus.py:169-174` stops summing `body["counts"]`, which makes
     `consensus.py:25` true.
   - `/v1/stats` (`interlock/mesh/server.py:144`) takes fire counts from the combined
     aggregator totals.
2. **A batch floor**, in `interlock/mesh/aggregate.py`: `Aggregator.totals` (`:87-96`) and
   `combine_totals` (`:120-126`) refuse to release totals over fewer than
   `min_batch_size` reconciled reports. The floor cannot be zero.
3. **A DAP client, `interlock/mesh/dap.py`** (new): Prio3 counts with validity proofs,
   sent to a leader/helper pair. The field arithmetic lives in the optional Rust
   accelerator under `rust/`, so the default install stays dependency-free. This is the
   route §7.1 proposed for Ed25519.
4. **Disclosure:** `GOVERNANCE.md` names the operators and their cloud providers and
   states the non-collusion assumption plainly. `/v1/stats` names the pair.
5. **Docs:** until step 1 lands, correct the claim in the "Report what your guard stopped"
   section of `docs/guides/mesh.md` that only aggregators see counts.
6. **Tests:** `tests/test_mesh_report.py`, `tests/test_mesh_consensus.py`,
   `tests/test_mesh_aggregate.py`, `tests/test_mesh_server.py`.

**Status (2026-10-25).**
- **Step 3 is implemented, with one deviation from the text above.** The DAP/Prio3 path
  ships as `interlock/mesh/dap/` (wire, messages, task files, client, leader, helper,
  collector, HTTP server) plus `interlock/mesh/vdaf/`, `hpke.py`, `_aesgcm.py` and
  `turboshake.py`, against `draft-ietf-ppm-dap-20`, `draft-irtf-cfrg-vdaf-22`
  (`Prio3SumVec`, codepoint 3) and RFC 9180 base mode
  (X25519 / HKDF-SHA256 / AES-128-GCM). It is **pure Python**, not the Rust
  accelerator: the default install has `dependencies = []` and the DAP path must work
  where the optional `interlock_scopes` build is absent. Correctness rests on the
  official VDAF and HPKE test vectors, the wire codec tests and a local leader↔helper
  end-to-end suite; there is no live interop run against another DAP implementation,
  and the pure-Python crypto is not constant-time (same posture as `ed25519.py`).
  `interlock mesh dap task|submit|collect` and
  `interlock mesh serve --role dap-leader|dap-helper` are the user surface.
  Evidence: `tests/test_mesh_vdaf.py`, `tests/test_mesh_hpke.py`,
  `tests/test_mesh_dap_wire.py`, `tests/test_mesh_dap_task.py`,
  `tests/test_mesh_dap.py`, `tests/test_mesh_dap_cli.py`.
- **Step 4 is partly done.** `GOVERNANCE.md` carries the "Aggregators, clouds and
  non-collusion" disclosure and states that no independent operator has been recruited
  and that the reference deployment is not an independence claim. No operator is named,
  because none has agreed; `/v1/stats` will name the pair once one does.
- **Revisit-when is unchanged.** The clock in the first bullet starts when an
  operator agrees, not when the code landed.

**Revisit when.**
- Two quarters after the DAP path ships, no independent operator has agreed to be leader.
  Counts then stay unsent, and §11.2 closes as "no aggregate counts" (Opus-R2).
- A second independent operator agrees. The maintainer then leaves the helper role.
- Reconciled reports per window stay below `min_batch_size` for two quarters. Widen the
  window before releasing anything.

### R3 · Q3: Default reporting posture

**Decision.** Reporting is off by default. A node builds and displays its report locally,
and nothing is uploaded until the operator runs `interlock mesh report enable`. An enable
never uploads data from before its own date, and digests, fingerprints and samples each
need their own explicit flag.

**Rationale.**
- **Content is never on by default** ★★ (C6). Nobody contests this.
- **Local by default, upload on consent, never retroactive** ★ (C8: Codex-6, Opus-R3).
  Among the surveyed designs, only this one shows the operator the data without sending
  it (Codex-div: Go's `local` mode).
- **A library's default is inherited.** interlock's default passes to deployers who never
  chose it, and an upload default would break the `README.md:13` promise of "no network
  calls" (Opus-§3; T8). The opt-out precedents (C7) are products where the installer is
  the measured user or the vendor has market trust (Opus-§3 table; GLM-S9).
- **The EU floor.** Legitimate interest is not a blanket basis for accessing devices
  (GLM-S14; not legal advice).
- **Participation without a default.** Sharing is privately rational for many (Kimi-7).
  Reciprocity draws reporters: CrowdSec's share-to-receive (Codex-10), and early-ring
  membership for those who report (Opus-R3).
- **Layer 0 on by default is moot today.** Until R2 lands, counts have no private way off
  the node (T1). Choosing "off" now has no measurable cost, and the revisit condition
  decides later, with data.
- **Layer 2 is weakest where it matters.** Its utility is lowest on rare items, and attacks
  are rare items (Kimi-8/9). That is another reason it waits for an operator's choice.

**Dissent.**
- Free-riding theory says the cheapest contribution should be the default (Kimi-5/6;
  GLM-S15; research doc §6.6).
- Industry practice is opt-out (C7).
- Homebrew's notice-before-first-send is a credible middle ground (GLM-S10; Codex-5).
- Opt-in data is biased (GLM-S11, popcon).
- Kimi-Q3 and GLM-D1 judge this a values choice that the evidence does not settle (D3).
  This record makes that choice out loud, as §11.3 asked.

**Implementation.**
1. **One consent point**, in `interlock/cli/mesh.py` (`report enable` at `:94-100`;
   `report build --no-digests` at `:89`):
   - `report enable` turns on counts and sightings, with separate `--digests`, `--alpha`
     (fingerprints) and `--sample <rule>` flags.
   - It records the enable date and the enabled layers in the mesh state.
   - `report submit` refuses any layer that isn't enabled.
   - `report build` still runs without an enable, locally.
2. **An as-of gate**, in `interlock/mesh/report.py:124` (`build_report`): clamp `since`
   to the enable date (Codex-6 `reports.go:134-138`), and leave out digests unless they
   are enabled.
3. **A kill switch at the send site:** `INTERLOCK_MESH_NO_REPORT=1`, checked in `submit`
   in `interlock/mesh/report.py` (Codex-conv-2). The name follows the existing
   `INTERLOCK_MESH_DIR`.
4. **A preview:** `interlock mesh status` and `interlock doctor` show the report a node
   would send, so the operator sees exactly what enabling would upload.
5. **Reciprocity:** `GOVERNANCE.md` states that early-ring membership credentials
   (`interlock/mesh/credential.py`) go to organisations that report.
6. **Docs and tests:** the "Report what your guard stopped" section of
   `docs/guides/mesh.md`; `tests/test_mesh_report.py`.

**Revisit when.** For two consecutive quarters after R2's aggregator pair is live, both
of these hold:
- the maintainer's mirror serves `timestamp.json` to at least 50 distinct subscribers a
  day;
- fewer than `min_orgs` (3) distinct reporters back most of the rules that fired on
  `/v1/stats`.

Together they mean consent, not adoption, is starving the network (Opus-R3's "wrong if").
Then consider a Homebrew-shaped opt-out for Layer 0 alone, after a legal review
(GLM-S14). It would show a notice first, send nothing on the run that shows it, and keep
no persistent identifier (Codex-5).

### R4 · Q4: Data licence for the commons

**Decision.** Packs are Apache-2.0. Indicators, fingerprints and redacted samples,
wherever they appear (including the sample strings in a pack's tests file), are CC0-1.0
under a new top-level `LICENSE-DATA`. Every contribution comes in under the existing DCO
plus a three-clause data warranty: lawfully obtained, no personal data, and no third
party's confidential data. There is no CLA.

**Rationale.**
- **Agreement on the basics.** An explicit licence plus a warranty ★★★ (C9). CC0 for
  indicator-like data ★★ (C10). No CLA ★ (C11), and the DCO is already in place (T9).
- **Packs as Apache-2.0** (D4):
  - Rule corpora use code licences, while advisory databases use CC-BY (Codex-ledger;
    GLM-S20).
  - A pack is a policy document that the engine executes (`interlock/mesh/bundle.py:3-4`).
  - Apache-2.0 is the project's licence (`LICENSE`) and is on OSV's recommended intake
    list (Codex-14 `new_source.md:37-45`).
  - Its notice-retention condition gives credit without DRL's burden of attribution in
    every match (Codex-13).
- **CC0 for facts.** Indicators and fingerprints are machine-generated facts, and CC0
  also waives the EU database right (Opus-R4; one lens only; not legal advice).
- **Contributors warrant possession, not authorship,** because attackers wrote the
  payloads (Opus-R4).
- **Restrictive terms cost reach.** YARA-Forge drops ELv2 content outright (Codex-15).

**Dissent.**
- **Codex-R4** prefers CC-BY-4.0 for packs.
- **Sigma's DRL** exists because vendors repackaged community rules without credit
  (GLM-S16; Opus-§3).
- **abuse.ch** shows open threat data may not pay for itself (GLM-S18; Opus-§3). This is
  set aside: a one-maintainer commons has no paid tier to protect, and reach is what it
  lacks.
- **Samples remain unresolved** (D5). This record does not solve GDPR erasure. T12 narrows
  the problem, since samples never enter the signed site or the log, but git history is
  a publication.

**Implementation.**
1. **`LICENSE-DATA`** (new, top level): the CC0-1.0 text, headed by its scope. It covers:
   - the indicator pack that `interlock/mesh/consensus.py` exports;
   - fingerprints and samples in reports (`interlock/mesh/report.py`);
   - sample strings in a commons' `packs/*.tests.json`.

   Everything else is under `LICENSE`.
2. **The warranty:** the DCO section at `CONTRIBUTING.md:125` gains the three-clause data
   warranty, covered by the same sign-off.
3. **Licence metadata:**
   - In `interlock/mesh/bundle.py`, `normalize_pack` (`:73-112`) accepts a pack-level SPDX
     `license` (default `Apache-2.0`), and `pack_summary` publishes it in the targets
     `custom` field.
   - `interlock/mesh/consensus.py` stamps `CC0-1.0` on the indicator pack.
   - `interlock/mesh/forge.py` writes the licence and provenance into each proposal.
   - A per-rule `license` (Sigma spec `:242-248`) also needs
     `interlock/policy/declarative.py` to accept the key.
4. **Reporter attestation:** in `interlock/cli/mesh.py`, `report enable --sample`
   requires an explicit warranty flag, and `interlock/mesh/report.py` records the
   attestation in the envelope.
5. **`GOVERNANCE.md`** sets two rules:
   - an intake floor for upstream packs: the licence must permit ingest, modification and
     redistribution (Codex-14);
   - an erasure procedure: a sample reported as containing personal data leaves the tree
     and the next release within 30 days.

**Revisit when.**
- Within any 12 months there are two or more documented cases of a commercial product
  redistributing commons packs without attribution, *and* merged external pack pull
  requests fall for two consecutive quarters. Then move packs to CC-BY-4.0 or DRL-1.1
  (Opus-R4's "wrong if").
- An erasure request for a published sample cannot be met within 30 days. Then stop
  publishing samples in tests files and keep them maintainer-only.

### R5 · Q5: Whether `block` ships through the mesh by default

**Decision.** No. A mesh rule's `block` takes effect only on a node whose operator has
granted `block` for that pack and status, or for that rule, in the subscriber config.
Every other mesh `block` is capped at `escalate` after the monitor window. On a node with
no approver installed, that escalation is recorded as a shadow decision instead of being
refused.

**Rationale.**
- **All four lenses oppose community blocking without the operator's consent** ★★★ (C12).
  In the surveyed content-rule feeds, the operator's local act is the safeguard ★★ (C13).
- **Today's default contradicts §11.5.** A stable subscription enforces a pack's `block`
  seven days after first sight, with no human act (T5). This decision makes the
  document's "no" true in the code.
- **Time alone is weak evidence.** A window catches frequent false positives and passes
  rare ones (Opus-§4.1, McAfee DAT 5958). Base-rate arithmetic says a rule on rare
  events needs a false-positive rate below the attack base rate before it may act alone
  (Kimi-10). A rule that was right yesterday is no evidence it is right today (Kimi-11).
- **CrowdSec's exception does not carry over** (C14). A false block in interlock stops the
  subscriber's own agent, the CrowdStrike class of failure (C15; GLM-S22/S23; Opus-§1).
  Even CrowdSec curates its list conservatively, because a false positive reaches every
  subscriber (GLM-S24).
- **The shadow fallback is required.** Without it, the escalate cap would itself block on
  headless nodes (T6; Opus-§4.1).
- **The grant is the only new mechanism.** Operators can already withdraw a community
  rule locally (T11).

**Dissent.**
- **Kimi-Q5** reads the existing distinct-org threshold plus the monitor window as the
  right default (D6). This record agrees the mechanism raises the prior, but not that
  elapsed time is consent. The two readings diverge exactly on rules that fire rarely.
- **Codex-R5** would add a promotion list first and decide later. This record decides now.
- **The speed argument is real:** research doc §12 cites ClawWorm and adaptive worms for
  "why minutes matter". But GLM-D3 found no web source advocating auto-block, and a grant
  takes the operator minutes.
- **A cost, acknowledged:** an operator who never grants gets detection without prevention
  (Codex-11: "protection lags detection").

**Implementation.**
1. **The ceiling**, in `interlock/mesh/bundle.py`: change `DEFAULT_CEILINGS["stable"]` at
   `:55-59` from `None` to `"modify"`. A block then becomes an escalate, and modify is
   untouched. `apply_ring` (`:180-213`) lifts the ceiling only where a grant matches, and
   marks every mesh rule with its origin.
2. **Grants**, in `interlock/mesh/subscriber.py:77-118` (`Config`): a `grants` field in
   `config.json`, for example
   `{"block": [{"pack": "coding-agent", "status": "stable"}, {"rule": "<id>"}]}`.
   `interlock/cli/mesh.py` gains `interlock mesh grant block --pack <p> --status <s>`,
   `--rule <id>`, and `--list`.
3. **The shadow fallback**, in `interlock/approval.py:324-330` (`refuse`): when no
   approver is installed and the escalating rule is an ungranted mesh rule, record a
   shadow decision instead of raising `NotApproved`. `interlock mesh status` and
   `interlock doctor` then report "N mesh rules capped at escalate; no approver: shadow
   only".
4. **Docs:**
   - the ring tables in `docs/guides/mesh.md` and in §7.2 of
     `research/mesh-shared-policy-network.md` ("stable: the pack's verdict, after a
     grant");
   - §11.5;
   - §1's "within a day" (T10).
5. **Tests:** `tests/test_mesh_commons.py` (ceilings and grants) and
   `tests/test_approval.py` (the shadow fallback applies to mesh rules only).

**Revisit when.**
- On consenting canary and early nodes running R8's experiment, exact-digest indicators
  backed by at least three distinct organisations at promotion show fewer than 1 false
  block per 10,000 node-rule-weeks, for two consecutive quarters. That class alone may
  then ship with a default grant on the stable ring (Opus-R5's "wrong if").
- A post-incident review documents three or more subscriber nodes harmed by an attack
  that a published `stable` rule matched while capped at `escalate`. Then reconsider a
  default grant for that rule class.

### Supporting recommendations (not §11 questions)

**R6. Ship in this order:** R2's leak fix and batch floor, then R5, then R1's offline-root
path, then R3, then R4.
- *Support:* my judgement of severity. T1 is a privacy defect in shipped code, T5 is live
  default behaviour, and R1, R3 and R4 matter before adoption rather than during it.
- *Wrong if:* no consensus service is deployed anywhere yet. T1 then has no victims, and
  R5 should go first.

**R7. When trust expires, fail loudly and demote.** Once the timestamp has been expired
for longer than the monitor window, `interlock doctor` fails and granted mesh blocks drop
to `escalate` (`interlock/mesh/subscriber.py:459`, `apply_ring`).
- *Support:* Opus-R6 (one lens only), and T7.
- *Wrong if:* attackers are seen cutting nodes off from every mirror and peer to force
  expiry and strip protection (Opus-R6). Then keep granted blocks and only fail `doctor`.

**R8. Measure the monitor window before trusting it.** On consenting canary and early
nodes, randomise the window per (node, rule) across {1, 3, 7, 14} days. Count false
blocks per 1,000 node-rule-weeks, by rule class and by how many organisations backed the
rule. Layer 1 excludes monitor-mode decisions, so this needs a consented Layer 0 counter
for shadow fires in `interlock/mesh/report.py`.
- *Support:* Opus-§5. GLM-gap-6 and Kimi-cav-4 note that no public FP time series exists.
- *Wrong if:* fewer than about 20 nodes consent within two quarters. The experiment is
  then underpowered, so measure offline instead, with `interlock mesh harness` against a
  benign corpus.

**R9. Make the documents match this record.**
- Edit §11 of `research/mesh-shared-policy-network.md` to point here.
- Fix §1 (T10) and the §7.2 ring table.
- In `docs/guides/mesh.md`, fix the "Keys" paragraph (T3) and the "Report" section (T1).
- Update the "Still open" paragraph under the mesh table in `ROADMAP.md` (`:1438-1442`).
- *Support:* Opus-R5 for the §1 fix; my own findings T1 and T3.
- *Wrong if:* the research doc is meant to stay a dated record. Then add an erratum block
  instead of editing in place.

---

## 6. Source manifest

Every external source below is listed as its lens reported it. This synthesis did not
re-fetch any of them; it checked tree facts at `36fbfae` only. Sources are grouped by the
lens that cited them.

### lens-glm.md (GLM)
- S1: https://github.com/sigstore/root-signing · https://blog.sigstore.dev/a-new-kind-of-trust-root-f11eeeed92ef
- S2: https://docs.sigstore.dev/about/security
- S3: https://www.iana.org/dnssec/ceremonies
- S4: https://github.com/ossf/foundation · https://openssf.org/blog/2026/03/17/leading-tech-coalition-invests-12-5-million-through-openssf-and-alpha-omega-to-strengthen-open-source-security
- S5: https://blog.trailofbits.com/2024/11/14/attestations-a-new-generation-of-signatures-on-pypi · https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations
- S6: https://www.usenix.org/conference/pepr26/presentation/geoghegan
- S7: https://divviup.org/blog/lessons-from-running-mpc-at-scale · https://divviup.org/blog/writing-dap-standards · https://www.abetterinternet.org/post/prio-services-for-covid-en
- S8: https://www.ietf.org/archive/id/draft-ietf-ppm-dap-04.html
- S9: https://github.com/microsoft/vscode/issues/176269
- S10: https://docs.brew.sh/Analytics · https://github.com/Homebrew/brew/issues/142 · https://law.stackexchange.com/questions/31527/gdpr-and-homebrew-analytics
- S11: https://popcon.debian.org · https://news.ycombinator.com/item?id=45107598 · http://www.omgubuntu.co.uk/2020/07/ubuntu-popularity-contest-removed · https://discuss.freedombox.org/t/help-freedombox-by-enabling-popularity-contest/1721
- S12: https://support.mozilla.org/en-US/kb/technical-and-interaction-data · https://www.quippd.com/writing/2025/06/18/mozilla-backs-off-on-data-collection-firefox-labs-to-not-require-telemetry-or-studies-in-future-updates.html · https://discussion.fedoraproject.org/t/how-concerning-is-firefoxs-privacy-preserving-attribution-and-should-it-be-opt-in/125838
- S13: https://cli.sentry.dev/configuration · https://github.com/getsentry/sentry-javascript/issues/13270
- S14: https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202401_legitimateinterest_en.pdf · https://www.edpb.europa.eu/system/files/2024-04/edpb_opinion_202408_consentorpay_en.pdf
- S15: https://link.springer.com/article/10.1007/s10207-025-01165-2 · https://academic.oup.com/cybersecurity/article/11/1/tyaf016/8244123 · https://www.ndss-symposium.org/ndss-paper/sharing-cyber-threat-intelligence-does-it-really-help
- S16: https://github.com/SigmaHQ/sigma · https://archive.hack.lu/media/hack-lu-2024/submissions/MMNTPT/resources/Lessons_Learn_NzXKIVE.pdf
- S17: https://github.com/misp/misp-galaxy · https://www.misp-standard.org/rfc/misp-standard-galaxy-format.html
- S18: https://abuse.ch/blog/creating-sustainability-for-abuse-ch-and-its-community · https://abuse.ch/blog/abuse-ch-appoints-spamhaus-as-a-licensee · https://abuse.ch/blog/moving-forward
- S19: https://www.cve.org/legal/termsofuse · https://spdx.org/licenses/cve-tou.html · https://orca.security/resources/blog/cve-mitre-program-status-2025
- S20: https://www.snort.org/faq/what-are-community-rules
- S21: https://osv.dev · https://google.github.io/osv.dev/faq · https://talk.openmrs.org/t/googles-new-osv-scanner-for-vulnerabilities/38252
- S22: https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf · https://www.crowdstrike.com/en-us/blog/falcon-content-update-preliminary-post-incident-report
- S23: https://www.congress.gov/crs-product/IF12717 · https://www.cisa.gov/news-events/alerts/2024/07/19/widespread-it-outage-due-crowdstrike-update
- S24: https://discourse.crowdsec.net/t/crowdsec-setup-feedback-and-general-questions/1452 · https://github.com/crowdsecurity/crowdsec/issues/4518 · https://www.crowdsec.net/faq
- S25: https://www.spamhaus.org/blocklists/drop-fair-use-policy · https://www.spamhaus.org/blocklists/do-not-route-or-peer · https://www.spamhaus.org/resource-hub/dnsbl/the-return-of-the-asn-drop
- S26: https://www.giskard.ai/knowledge/ai-guardrails-comparison-2026 · https://arxiv.org/html/2601.06366v3 · https://sudoall.com/bedrock-guardrails-truth
- S27: https://www.mitre.org/news-insights/news-release/mitre-launches-ai-incident-sharing-initiative · https://atlas.mitre.org · https://avidml.org/faq
- S28: https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022L2555 · https://www.cognyte.com/blog/nis2-threat-intelligence
- Gaps section: https://blog.sigstore.dev/sigstore-bring-your-own-stuf-with-tuf-40febfd2badd

### lens-kimi.md (Kimi)
- Kimi-1: Shamir (1979), *How to Share a Secret*, CACM 22(11):612–613
- Kimi-2: Shoup (2000), *Practical Threshold Signatures*, EUROCRYPT 2000, LNCS 1807:207–220
- Kimi-3: Samuel, Mathewson, Cappos & Dingledine (2010), DOI 10.1145/1866307.1866315 (ACM CCS 2010)
- Kimi-4: Corrigan-Gibbs & Boneh (2017), *Prio*, arxiv:1703.06255 (NSDI 2017)
- Kimi-5: Varian (2004), DOI 10.1007/1-4020-8090-5_1
- Kimi-6: Anderson & Moore (2006), DOI 10.1126/science.1130992
- Kimi-7: Gal-Or & Ghose (2005), DOI 10.1287/isre.1050.0053
- Kimi-8: Erlingsson, Pihur & Korolova (2014), *RAPPOR*, arxiv:1407.6981 · DOI 10.1145/2660267.2660348
- Kimi-9: Apple Differential Privacy Team (2017), *Learning with Privacy at Scale*, Apple Machine Learning Journal 1(8)
- Kimi-10: Axelsson (2000), DOI 10.1145/357830.357849 (ACM TISSEC 3(3))
- Kimi-11: Sommer & Paxson (2010), *Outside the Closed World*, IEEE S&P 2010, pp. 305–316
- Kimi-12: Henderson et al. (2023), *Foundation Models and Fair Use*, arxiv:2303.15715 (JMLR 24(400))
- Bridging preprints, as the research doc records them: arxiv:2602.17458 · arxiv:2209.02676 · arxiv:2606.14517 · arxiv:2608.27009 · arxiv:2608.29942 · arxiv:2605.18146
- Citation chains:
  - Cappos, Samuel, Baker & Hartman (2008), *Attacks on Package Managers* (U. Arizona TR)
  - Thompson (1984), *Reflections on Trusting Trust*
  - Benaloh (1986), CRYPTO '86
  - Feldman (1987), FOCS '87
  - Denning (1987), IEEE TSE
  - Lippmann et al. (2000), the DARPA 1998 evaluation
  - Kahneman & Tversky (1973)

### lens-codex.md (Codex): repositories at the commits the lens pinned on 2026-10-25
- Codex-1: github.com/sigstore/root-signing @ `f3fce8992cbd` · github.com/theupdateframework/python-tuf @ `2c771a035620`
- Codex-2: github.com/letsencrypt/boulder @ `4e1779d21f9a` (`cmd/ceremony`)
- Codex-3: Debian `debian-archive-keyring` 2025.1 and 2023.3+deb12u2, via https://sources.debian.org
- Codex-4: github.com/divviup/janus @ `5a9cccce842e` · github.com/mozilla-firefox/firefox @ `efd2d1e6f775`
- Codex-5: github.com/Homebrew/brew @ `c5b9f65d0b67`
- Codex-6: github.com/golang/telemetry @ `6cd571d43fbb`
- Codex-7: Debian `popularity-contest` 1.79, via https://sources.debian.org
- Codex-8: github.com/microsoft/vscode @ `7e4e9d83e716`
- Codex-9: github.com/getsentry/sentry-python @ `9e4ba4c0248a` · github.com/getsentry/self-hosted @ `095a9c7ad549` · github.com/getsentry/sentry @ `9f79f84e4787`
- Codex-10: github.com/crowdsecurity/crowdsec @ `725b6659dee5`
- Codex-11: github.com/OISF/suricata-update @ `c2687bbfc1d3`
- Codex-12: github.com/Cisco-Talos/clamav @ `dd3aa1907cf6`
- Codex-13: github.com/SigmaHQ/sigma @ `05d1031f537e` · github.com/SigmaHQ/sigma-specification @ `ba9251aa834b` · github.com/Neo23x0/signature-base
- Codex-14: github.com/google/osv.dev @ `a41aaa122c65` · github.com/github/advisory-database @ `06e8c3919b75`
- Codex-15: github.com/YARAHQ/yara-forge @ `52c7e88e0a79`
- Licence ledger and stack-rank: github.com/MISP/misp-galaxy · github.com/MISP/misp-warninglists · github.com/CVEProject/cvelistV5 · github.com/mitre/cti · github.com/mitre-atlas/atlas-data · github.com/elastic/detection-rules · github.com/Yara-Rules/rules · github.com/pypi/warehouse
- Unresolved lookups the lens recorded:
  - go.dev/blog/gotelemetry (Opus supplies it)
  - CrowdSec's community blocklist criteria
  - `google/exposure-notifications-private-analytics-ingestion` operators
  - DRL-1.1 on the SPDX list
  - the Snort community rules licence
  - abuse.ch's terms of use

### lens-opus.md (Opus)
- https://blog.sigstore.dev/a-new-kind-of-trust-root-f11eeeed92ef
- https://www.crowdstrike.com/wp-content/uploads/2024/08/Executive-Summary_Root-Cause-Analysis_Channel-File-291.pdf
- https://blog.cloudflare.com/18-november-2025-outage/
- https://divviup.org/blog/lessons-from-running-mpc-at-scale
- https://perun.au/insights/crowdsec-production
- https://research.swtch.com/telemetry-intro (Cox 2023)
- https://go.dev/blog/gotelemetry
- https://lwn.net/Articles/707783
- https://docs.brew.sh/Analytics
- https://github.com/SigmaHQ/Detection-Rule-License
- https://abuse.ch/terms-of-use/
- https://misp-project.org/license
- draft-ietf-ppm-dap (the minimum batch size)
- Citations without URLs:
  - Gordon, Loeb & Lucyshyn (2003); Gal-Or & Ghose (2005)
  - Metcalf & Spring (2015)
  - Li et al. (2019), *Reading the Tea Leaves*, USENIX Security
  - Bouwman et al. (2020), USENIX Security
  - Samuel et al. (2010); Corrigan-Gibbs & Boneh (2017)
  - Johnson & Goldstein (2003), *Science*
  - Ostrom (1990), *Governing the Commons*
  - *Feist v. Rural* (1991)
  - Directive 96/9/EC; GDPR Art. 5(1)(c), Recital 49, Art. 17
  - McAfee DAT 5958 (April 2010)
  - HashiCorp's BSL relicensing (2023)

### This synthesis
- arxiv:2601.05114 (Nasser 2026), cited from the recipe for not vote-ruling disputes.
- No new external sources. Tree evidence (target checkout at `36fbfae`):
  - `interlock/mesh/consensus.py`, `aggregate.py`, `repository.py`, `metadata.py`,
    `bundle.py`, `subscriber.py`, `report.py`, `credential.py`, `server.py`, `log.py`
  - `interlock/cli/mesh.py`, `interlock/approval.py`
  - `docs/guides/mesh.md`, `docs/guides/approvals.md`
  - `research/mesh-shared-policy-network.md`, `ROADMAP.md`, `README.md`,
    `CONTRIBUTING.md`, `LICENSE`
