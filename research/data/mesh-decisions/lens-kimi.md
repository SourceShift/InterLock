# Lens: Kimi — academic literature on the five mesh governance questions

**Lens stance:** long-context academic synthesis — read deeply, cite carefully,
trace citation chains. This lens answers the five open questions in
`research/mesh-shared-policy-network.md` §11 by tracing the *intellectual
ancestry* of each question: the canonical peer-reviewed work the 2025–2026
AI-guardrail preprints (already surveyed in §12 of that document) build on.

**What this lens is, and is not.** It is a synthesis of the pre-existing
academic foundations: threat-intelligence (CTI) sharing incentives and
free-riding, key custody and threshold signing, telemetry consent and
local-differential-privacy (LDP) deployments, data licensing of shared
corpora, and the false-positive cost of auto-enforcement. It is **not** a
re-survey of the 2025–2026 agent-guardrail preprints the project already
read (§12 of `mesh-shared-policy-network.md`) — those are cited here only to
bridge, and only for what that document already records about them.

Every canonical citation below was confirmed against its publisher record or
an academic index (DOIs given where they exist). Where an ID could not be
confirmed it is written `[lookup: …]` rather than guessed.

## Question map

| # | Question (§11) | Abbrev | Key literature anchors |
|---|---|---|---|
| 1 | Root-key custody (TUF root role) | **Q1** | Shamir 1979; Shoup 2000; Samuel et al. 2010 (TUF) |
| 2 | Aggregator operators (secret-shared counts) | **Q2** | Shamir 1979; Corrigan-Gibbs & Boneh 2017 (Prio) |
| 3 | Default reporting posture (off vs Layer-0 on) | **Q3** | Varian 2004; Anderson & Moore 2006; Gal-Or & Ghose 2005; RAPPOR 2014; Apple DP 2017 |
| 4 | Data licence for the commons | **Q4** | Henderson et al. 2023 (adjacent) + licence-precedent gap |
| 5 | `block` through the mesh by default | **Q5** | Axelsson 2000; Sommer & Paxson 2010 |

---

## The papers

### 1. Shamir (1979) — *How to Share a Secret*

- **ID**: no arXiv (1979); *Communications of the ACM* 22(11):612–613. Canonical.
- **First author / year**: Adi Shamir, 1979.
- **Bears on**: Q1, Q2.
- **Type**: primary (theoretical).
- **Methodology**: constructive proof — a threshold scheme in which any `k` of
  `n` shares reconstruct the secret and any `k−1` learn nothing.
- **Key claim**: a secret can be distributed so that compromise of fewer than
  `k` custodians reveals nothing, and no single custodian holds the whole key.
- **Effect size + sample**: not reported (proof, no empirical sample).
- **Replication status**: replicated — foundational, thousands of citations;
  basis of essentially all threshold key-custody practice.
- **Why cited here**: this is the mathematical floor under "root is a
  threshold of offline keys" (Q1) and under additive secret sharing of counts
  (Q2). It proves *that* threshold custody is possible; it says nothing about
  *who* should hold the shares — the question the project actually faces.

### 2. Shoup (2000) — *Practical Threshold Signatures*

- **ID**: no arXiv (2000); *EUROCRYPT 2000*, LNCS 1807:207–220.
- **First author / year**: Victor Shoup, 2000.
- **Bears on**: Q1.
- **Type**: primary (theoretical + protocol).
- **Methodology**: cryptographic construction and security proof for threshold
  RSA signatures in the random-oracle model, plus a non-interactive protocol.
- **Key claim**: a signing key can be split so a threshold of parties jointly
  signs *without any party ever reconstructing the full private key*, and the
  signature is indistinguishable from a single-key signature.
- **Effect size + sample**: not reported (proof).
- **Replication status**: replicated — the reference construction for
  threshold signing; deployed in practice (e.g. signing-backend designs).
- **Why cited here**: TUF root thresholds sign, not merely share, so Q1's
  "root role with threshold N" is exactly this primitive. The paper is the
  reason the project can keep root keys offline yet still rotate and sign.

### 3. Samuel, Mathewson, Cappos & Dingledine (2010) — *Survivable Key Compromise in Software Update Systems*

- **ID**: DOI 10.1145/1866307.1866315; *ACM CCS 2010*, pp. 61–72.
- **First author / year**: Justin Samuel, 2010.
- **Bears on**: Q1 (primary anchor).
- **Type**: primary (systems design + prototype).
- **Methodology**: threat-modelling and design of The Update Framework (TUF):
  role separation, offline root keys, and threshold signing, with a working
  implementation.
- **Key claim**: the failure modes that matter in update systems are key
  compromise of the *signing* role, not transport compromise; splitting
  responsibilities across roles whose keys have different compromise
  likelihoods (offline root, threshold targets) makes key compromise
  survivable.
- **Effect size + sample**: not reported (design paper; a prototype, not a
  controlled evaluation).
- **Replication status**: replicated/adopted in production — TUF is the
  substrate of Docker Notary, PyPI (PEP 458), Sigstore, and the project's own
  mesh design.
- **Why cited here**: Q1 is literally "the TUF root role." The paper's central
  insight — *custody follows compromise likelihood, not seniority* — is the
  reason offline threshold root keys and cheap-rotatable online targets keys
  are the right split. It also documents the honest answer to Q1's
  "credibility" sub-question: the paper's model assumes an *organised*
  ecosystem, which a one-maintainer project does not yet have.

### 4. Corrigan-Gibbs & Boneh (2017) — *Prio: Private, Robust, and Scalable Computation of Aggregate Statistics*

- **ID**: arXiv:1703.06255; *USENIX NSDI 2017*.
- **First author / year**: Henry Corrigan-Gibbs, 2017.
- **Bears on**: Q2 (primary anchor).
- **Type**: primary (systems + crypto).
- **Methodology**: secret-shared non-interactive proofs (SNIPs) over
  affine-aggregatable encodings, with benchmarked prototype servers.
- **Key claim**: as long as *at least one* of a small set of servers is
  honest, clients can contribute secret-shared values whose aggregates are
  computed without any server seeing an individual contribution; robustness to
  malformed clients needs all servers honest.
- **Effect size + sample**: 5.7× slowdown vs. a naïve (no-privacy) collection;
  50–100× faster client-side than client-generated NIZKs; a 434-question
  survey costs ~26 ms client compute, <2 ms/server. Sample: synthetic
  workloads + a survey deployment, not a behavioural N.
- **Replication status**: replicated/adopted — direct ancestor of the
  Privacy-Preserving Measurement / DAP deployments (Mozilla, ISRG Divvi Up),
  which the project's §12 already names as the ENPA lesson.
- **Why cited here**: the mesh's "two non-colluding aggregators over additive
  secret shares" is Prio's architecture. The paper's one-honest-server privacy
  bound is precisely why the project needs *two independent organisations*,
  and why the §11 fallback — "with fewer, counts are not sent" — is the
  correct, honest degradation rather than a fake one-aggregator mode.

### 5. Varian (2004) — *System Reliability and Free Riding*

- **ID**: DOI 10.1007/1-4020-8090-5_1; in *Economics of Information Security*
  (Camp & Lewis, eds.), Kluwer, pp. 1–15.
- **First author / year**: Hal R. Varian, 2004.
- **Bears on**: Q3.
- **Type**: primary (theoretical).
- **Methodology**: game-theoretic models of reliability under total-effort,
  weakest-link, and best-shot production functions.
- **Key claim**: when security/reliability is a public good, individual effort
  is below the social optimum — free-riding — and the gap widens with network
  size; liability and due-care rules are the standard corrections.
- **Effect size + sample**: not reported (theoretical model).
- **Replication status**: contested as a description of *observed* behaviour —
  the prediction of under-provision is robust, but real sharing platforms
  nonetheless attract contributors (see #6, #7 and the MISP evidence below).
- **Why cited here**: this is the intellectual origin of the free-riding worry
  that frames Q3. Its policy corollary — *lower the cost of the smallest
  contribution* — is the single strongest theoretical argument for a
  Layer-0-only default: the cheapest possible contribution, counted publicly,
  is what defeats free-riding at the margin.

### 6. Anderson & Moore (2006) — *The Economics of Information Security*

- **ID**: DOI 10.1126/science.1130992; *Science* 314(5799):610–613.
- **First author / year**: Ross Anderson, 2006.
- **Bears on**: Q3.
- **Type**: review (perspective — synthesises a field, not one experiment).
- **Methodology**: field review of security-economics results (incentives,
  externalities, liability, information asymmetries).
- **Key claim**: security failures are driven by misaligned incentives, and
  the market systematically under-invests in security because attacks impose
  externalities and victims under-report.
- **Effect size + sample**: not reported (review; aggregates many studies).
- **Replication status**: replicated as a framework; individual claims
  contested in specifics.
- **Why cited here**: it generalises Varian's free-riding result to the
  concrete case of *under-reporting* — victims don't report because reporting
  is costly and disclosure helps attackers (the project's §6.4). For Q3, it
  says: a default that asks nothing of the operator is the only one that
  escapes the under-reporting equilibrium.

### 7. Gal-Or & Ghose (2005) — *The Economic Incentives for Sharing Security Information*

- **ID**: DOI 10.1287/isre.1050.0053; *Information Systems Research*
  16(2):186–208.
- **First author / year**: Esther Gal-Or, 2005.
- **Bears on**: Q3.
- **Type**: primary (theoretical).
- **Methodology**: game-theoretic (Bertrand-Nash) model of inter-firm security
  information sharing, benchmarked against ISAC-style coordination.
- **Key claim**: security-information sharing and security investment are
  *strategic complements* — sharing is individually rational in competitive
  markets, and its value rises with product substitutability and firm size.
- **Effect size + sample**: not reported (theoretical).
- **Replication status**: single-study (no direct empirical replication; the
  prediction is consistent with ISAC participation but not decisively tested).
- **Why cited here**: this is the *dissenting* free-rider result. Against
  Varian/Anderson–Moore, it says sharing can be privately beneficial, which
  explains why CrowdSec/MISP/abuse.ch get participation at all. For Q3 it
  cuts against a mandatory on-by-default posture: sharing is valuable enough
  that a meaningful minority will opt in, so the *privacy-respecting* default
  (off) does not doom the commons — it merely slows it, and consent is the
  price of trust.

### 8. Erlingsson, Pihur & Korolova (2014) — *RAPPOR: Randomized Aggregatable Privacy-Preserving Ordinal Response*

- **ID**: arXiv:1407.6981; DOI 10.1145/2660267.2660348; *ACM CCS 2014*,
  pp. 1054–1067 (CCS Test-of-Time Award).
- **First author / year**: Úlfar Erlingsson, 2014.
- **Bears on**: Q3.
- **Type**: primary (systems + algorithm + deployment).
- **Methodology**: randomized-response local-DP mechanism with longitudinal
  protection, evaluated on synthetic and real-world Chrome data.
- **Key claim**: client-side randomized response can produce population
  statistics with strong per-user differential-privacy guarantees and usable
  aggregate accuracy, without a trusted server.
- **Effect size + sample**: per-report ε budget (single-digit ε typical);
  aggregate relative error bounded; deployed on real Chrome traffic — N not
  reported as a single figure.
- **Replication status**: replicated in production (Chrome, later superseded);
  test-of-time recognition.
- **Why cited here**: RAPPOR is the proof that "opt-in, local-DP telemetry at
  scale" is not a research fantasy — it is exactly the project's Layer 2
  fingerprint (one randomised bit per SimHash dimension). Its known limit is
  the one that matters for Q3: utility collapses for *rare* items, and attacks
  are the rare items. LDP protects the long tail by destroying it.

### 9. Apple Differential Privacy Team (2017) — *Learning with Privacy at Scale*

- **ID**: no arXiv; *Apple Machine Learning Journal* 1(8), 2017.
- **First author / year**: Apple DP Team, 2017.
- **Bears on**: Q3.
- **Type**: primary (deployment report — not peer-reviewed in the usual sense).
- **Methodology**: report of client-side LDP (Hadamard Count-Mean Sketch,
  Sequence Fragment Puzzle) deployed to production Apple devices.
- **Key claim**: local DP can be run across hundreds of millions of devices to
  discover frequent items (domains, typed words) with per-contribution ε and
  acceptable accuracy, *for heavy hitters*.
- **Effect size + sample**: deployment-scale (hundreds of millions of
  devices); ε per contribution (not a single N; no Cohen's d).
- **Replication status**: single-vendor deployment; contested — external
  researchers have criticised the realised ε and the heavy-hitter-only
  accuracy.
- **Why cited here**: the largest real proof that on-device, opt-in LDP is
  operationally feasible and user-acceptable for a *consumer* product. But it
  is also the cautionary tale for Q3: Apple collects what it does *because*
  the frequent-item use case tolerates noise; a rare-attack commons does not
  inherit that tolerance.

### 10. Axelsson (2000) — *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*

- **ID**: DOI 10.1145/357830.357849; *ACM TISSEC* 3(3):186–205.
- **First author / year**: Stefan Axelsson, 2000.
- **Bears on**: Q5 (primary anchor).
- **Type**: primary (analytic modelling + review of reported IDS performance).
- **Methodology**: Bayesian analysis of intrusion-detection operating points
  against reported detection/false-alarm rates.
- **Key claim**: because attacks are rare, the posterior probability that an
  alarm is a true attack is negligible unless the false-alarm rate is below
  the attack base rate — a bar no general-purpose detector then met.
- **Effect size + sample**: analytic worked examples; reviews published IDS
  results; no single empirical N.
- **Replication status**: replicated as an analytic result; the canonical
  citation for "false positives kill detection."
- **Why cited here**: this is the whole case for Q5's default "no `block`
  through the mesh." It formalises *why* a community rule that fires on rare
  attacks must clear an extraordinary false-positive bar before it may act
  autonomously — and why the mesh's distinct-org threshold, monitor window,
  and `escalate` ceiling are the standard engineering escape from the
  base-rate trap.

### 11. Sommer & Paxson (2010) — *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection*

- **ID**: no arXiv; *IEEE S&P 2010*, pp. 305–316.
- **First author / year**: Robin Sommer, 2010.
- **Bears on**: Q5.
- **Type**: position/analysis (not an experiment).
- **Methodology**: conceptual argument contrasting the closed-world assumption
  of ML with the open, adversarial, non-stationary reality of intrusion
  detection.
- **Key claim**: the gap between ML-in-the-lab and deployed intrusion
  detection exists because attack data violates the closed-world assumption —
  novelty, adversary adaptation, and high false-positive cost make
  auto-classification unsafe as a sole mechanism.
- **Effect size + sample**: not reported (position paper).
- **Replication status**: single-study (position); heavily cited and
  influential as a framing.
- **Why cited here**: the analytical sibling of Axelsson for Q5. Where
  Axelsson gives the arithmetic, Sommer & Paxson give the *epistemic* reason
  auto-enforcement of third-party rules is unsafe: the attack distribution is
  not stationary, so a rule that was correct yesterday is not evidence it is
  correct today — which is the precise rationale for the mesh's status
  lifecycle, `falsepositives` tracking, and monitor-first ingestion.

### 12. Henderson et al. (2023) — *Foundation Models and Fair Use*

- **ID**: arXiv:2303.15715; *JMLR* 24(400):1–79.
- **First author / year**: Peter Henderson, 2023.
- **Bears on**: Q4 (adjacent — flag the gap).
- **Type**: review (legal survey + empirical experiments).
- **Methodology**: survey of US fair-use case law plus experiments measuring
  whether foundation models reproduce copyrighted material.
- **Key claim**: building on copyrighted corpora is often fair use but not
  guaranteed, and the licence/liability status of a *derived shared corpus*
  depends on the market effect of redistribution — exactly the regime a
  published CTI commons sits in.
- **Effect size + sample**: not reported as a single N (survey + model
  outputs).
- **Replication status**: single-study; contested (fair-use is an active
  dispute).
- **Why cited here**: the closest academic anchor for Q4. Its transferable
  point: the *redistribution* of a shared corpus raises different
  licence/liability questions than mere use, so a commons needs both a licence
  on the data (CC0/CC-BY/ODbL/CDLA family) **and** a contributor
  rights-warranty, because the publisher of derived indicators cannot lean on
  fair use the way a private consumer might.

---

## Bridging to the project's own 2025–2026 corpus

These are already summarised in §12/§6 of
`research/mesh-shared-policy-network.md`; cited here only to connect the
classical literature to the AI-guardrail context, with the claims exactly as
that document records them:

- `2602.17458` *The CTI Echo Chamber* — 13,308 reports; "a fragmented
  ecosystem of distinct silos where vendors demonstrate significant geographic
  and sectoral reporting biases." Extends #5–#7 into the CTI record: the
  free-rider problem shows up not as absence of data but as *siloed* data.
- `2209.02676` (MISP designers) — retained information is "only the tip of
  the iceberg"; names the free-rider problem directly. Empirical confirmation
  of #5/#6 in a live sharing platform.
- `2606.14517` *From Shield to Target* — guardrails as DoS targets; keep rules
  cost-bounded. The cost side of #10/#11: auto-enforcement is not only a
  false-positive risk but an induced-load risk.
- `2608.27009`, `2608.29942` — measured over-refusal of agent guardrails. The
  mirror image of #10: over-blocking is the concrete false-positive cost in
  this domain.
- `2605.18146` DARTIC — anonymous-yet-accountable reporters. A post-Prio
  credibility layer relevant to Q2/Q3 (who may report and stay accountable).

---

## What the literature says, per question

**Q1 — root-key custody.** The maths is settled (#1, #2): threshold offline
custody is possible and cheap to implement. The *organisation* is not settled
by any paper: TUF (#3) assumes an organised ecosystem, and no peer-reviewed
work tells a one-maintainer project how to recruit three organisations to hold
root shares. The academic answer to Q1 is therefore "threshold + offline +
role separation" as a *design*, and "foundation vs. multi-vendor" as an
*organisational* question the literature leaves to the governance lenses.

**Q2 — aggregator operators.** Prio (#4) is decisive on the technical shape:
two independent, non-colluding operators is the minimum, one-honest-server
privacy is the bound, and "with fewer, send nothing" is the correct fallback —
sending counts to a single operator would be strictly worse than not sending
them. The *selection* of operators (who, what they attest to) is an
organisational gap the literature does not fill.

**Q3 — default reporting posture.** The literature is genuinely split, which
is the signal. Free-riding theory (#5, #6) recommends the lowest possible
contribution cost → *Layer-0 on by default*. But the anti-free-rider result
(#7) and the LDP deployments (#8, #9) jointly argue that (a) meaningful
opt-in will happen anyway, and (b) the rare-attack utility of LDP is poor —
so an on-by-default posture buys fast uptake *and* weak signal on the exact
items that matter, while an off-by-default posture buys consent and trust at
the price of slower network effects. No paper resolves this; it is a values
choice the decision record must make out loud (as §11 already says).

**Q4 — data licence.** The academic literature does **not** settle this:
there is no peer-reviewed field on licensing CTI indicator corpora. The
closest work (#12) concerns LLM training data and fair use, and transfers only
the one durable lesson — *redistribution* of a derived corpus needs an
explicit licence plus a contributor rights-warranty, and fair use cannot be
assumed for a published commons. The licence choice itself (CC0 vs CC-BY vs
ODbL vs CDLA) is legal, not scientific: `[lookup: open threat-intelligence
corpus licence precedent CDLA ODbL CC-BY]`.

**Q5 — block by default.** The literature is near-unanimous *against*
autonomous blocking of third-party rules, and the reasoning is quantitative
(#10: base-rate arithmetic) plus epistemic (#11: non-stationary adversarial
distribution). The escape hatch that makes auto-enforcement ever acceptable —
raising the prior via distinct-org consensus, monitor windows, and measured
false-positive rates — is exactly what the mesh already does; #10 and #11 are
the reason that mechanism must stay the default and not be inverted.

---

## Citation chain — the top three papers' intellectual ancestry

### Chain A — Samuel et al. 2010 (TUF), for Q1

1. Cappos, Samuel, Baker & Hartman (2008), *Attacks on Package Managers*
   (University of Arizona TR) — the catalogue of package-manager
   key-compromise attacks TUF was designed against.
2. Shamir (1979), *How to Share a Secret* — the threshold primitive TUF's
   root threshold signing instantiates (#1 above).
3. Thompson (1984), *Reflections on Trusting Trust* — the ancestor of
   "trust the signing root, not the transport" thinking.
4. Shoup (2000), *Practical Threshold Signatures* — the concrete threshold
   signing construction behind the root role (#2 above).

### Chain B — Corrigan-Gibbs & Boneh 2017 (Prio), for Q2

1. Shamir (1979), *How to Share a Secret* — additive secret sharing.
2. Benaloh (1986), *Secret Sharing Homomorphisms* (CRYPTO '86) — the
   observation that shares of a secret compose under addition.
3. Feldman (1987), *A Practical Scheme for Non-interactive Verifiable Secret
   Sharing* (FOCS '87) — the robustness/verification lineage.
4. Erlingsson et al. (2014), RAPPOR — the local-DP "no trusted server" design
   Prio generalises (#8 above).

### Chain C — Axelsson 2000, for Q5

1. Denning (1987), *An Intrusion-Detection Model* (IEEE TSE) — the statistical
   anomaly-detection frame Axelsson evaluates.
2. Lippmann et al. (2000), *Evaluating Intrusion Detection Systems: The 1998
   DARPA Off-line Intrusion Detection Evaluation* — the source of the
   detection/false-alarm operating points Axelsson plugs into Bayes.
3. Kahneman & Tversky (1973), *On the Psychology of Prediction* — the
   base-rate-neglect result the paper generalises to detection systems.

---

## Methodological caveats

1. **Security economics is mostly unvalidated theory.** #5–#7 are stylised
   game-theoretic models with no behavioural effect sizes; the *empirical*
   record (MISP `2209.02676`, CTI Echo Chamber `2602.17458`) shows both
   participation *and* siloing, so neither "free-riding kills sharing" nor
   "sharing is self-sustaining" is decisively supported. Recommendations for
   Q3 that lean on either side inherit this uncertainty.
2. **Threshold signing is proof, not deployment science.** #1–#3 establish
   that threshold custody *works*; the failure modes that actually bite —
   key ceremonies, offline-storage discipline, rotation schedules, collusion
   among custodians — are documented in foundation charters and post-mortems
   (the glm/codex lenses' territory), not in peer-reviewed papers. Q1 cannot
   be settled by this literature alone.
3. **Telemetry-consent and LDP papers report aggregate utility, not trust or
   consent outcomes.** #8–#9 measure ε and accuracy, not whether users trust
   the tool or whether opt-in rates were driven by the default. GDPR/data-
   minimisation analysis is legal, not scientific — flag as non-legal-advice.
   And both deployments optimise for *frequent* items, whereas attacks are
   the rare tail where LDP accuracy is worst.
4. **The false-positive literature is dated and network-ID-centric.** #10–#11
   are from 2000–2010 and concern network intrusion detection; the transfer to
   agent-guardrail `block` verdicts is strongly plausible but not directly
   measured. The 2025–2026 over-refusal and DoS-target preprints
   (`2608.27009`, `2608.29942`, `2606.14517`) are the direct measurements and
   are preprints with little independent replication yet.
5. **Q4 has no field.** Data-licensing of security corpora is not a
   peer-reviewed area; the closest anchors concern LLM training data (#12).
   The licence choice is a legal-instrument decision, and this lens contributes
   only the one durable principle (explicit licence + rights-warranty because
   the commons *redistributes*).
6. **Effect-size discipline.** Most entries carry "not reported" for effect
   size and sample — that is honest, not an omission: the load-bearing results
   here are proofs, models, and deployment reports, not RCTs. The synthesis
   should not dress these up as stronger evidence than they are.

---

## Appendix — canonical identifiers confirmed

| Work | Canonical ID |
|---|---|
| Shamir 1979 | CACM 22(11):612–613 |
| Shoup 2000 | EUROCRYPT 2000, LNCS 1807:207–220 |
| Samuel et al. 2010 (TUF) | DOI 10.1145/1866307.1866315 (ACM CCS 2010) |
| Corrigan-Gibbs & Boneh 2017 (Prio) | arXiv:1703.06255 (NSDI 2017) |
| Varian 2004 | DOI 10.1007/1-4020-8090-5_1 (Kluwer, pp. 1–15) |
| Anderson & Moore 2006 | DOI 10.1126/science.1130992 (Science 314:610–613) |
| Gal-Or & Ghose 2005 | DOI 10.1287/isre.1050.0053 (ISR 16(2):186–208) |
| Erlingsson et al. 2014 (RAPPOR) | arXiv:1407.6981; DOI 10.1145/2660267.2660348 |
| Apple DP Team 2017 | Apple Machine Learning Journal 1(8) |
| Axelsson 2000 | DOI 10.1145/357830.357849 (TISSEC 3(3):186–205) |
| Sommer & Paxson 2010 | IEEE S&P 2010, pp. 305–316 |
| Henderson et al. 2023 | arXiv:2303.15715; JMLR 24(400):1–79 |
