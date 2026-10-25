# Lens: GLM — fast broad web sweep (2023–2026)

- **Task:** glm_lens · **Run:** run-1792920000-93111 · **Swept:** 2026-10-25
- **Scope:** the five open decisions in `research/mesh-shared-policy-network.md` §11 —
  Q1 root-key custody · Q2 who runs the two aggregators · Q3 default reporting
  posture · Q4 data licence for the commons · Q5 whether `block` ever ships by default.
- **Method:** ~24 web searches + 4 primary-source spot-checks (Sigma repo, OSV site/FAQ,
  PEPR '26 paper page). Preference for 2024–2026 material; older items kept only as
  flagged background. English-only. **Non-legal-advice:** GDPR notes are a sweep of
  regulator publications, not a legal opinion.

## Sources, ranked by question

### Q1 — Who holds the root keys

**[S1]** https://github.com/sigstore/root-signing — *sigstore/root-signing (TUF repository
for the Sigstore trust root)*, Sigstore/OpenSSF, living repo (accessed 2026-10-25).
TL;DR: the trust root is changed through **public pull-request "signing events"**
signed by keyholders, after an initial public live-streamed ceremony (2021) whose
recording is linked from the repo. Why it matters: the working model for *ceremonies
as routine public process, not one-off events* — directly transplantable to a TUF-signed
commons. Confidence: **high**. *Informs: Q1.* (Background: the 2021 founding post
https://blog.sigstore.dev/a-new-kind-of-trust-root-f11eeeed92ef)

**[S2]** https://docs.sigstore.dev/about/security — *Security Model*, Sigstore docs,
living (accessed 2026-10-25). TL;DR: trust root held by a **rotation of five keyholders
"from varying companies and academic institutions"**, established at a public ceremony.
Why it matters: names the concrete custody shape — m-of-n across independent orgs, not a
foundation legal document. Confidence: **high**. *Informs: Q1.*

**[S3]** https://www.iana.org/dnssec/ceremonies — *Root KSK Ceremonies*, IANA, living.
TL;DR: quarterly public ceremonies with **Trusted Community Representatives**, full
scripts and recordings. Why it matters: the oldest continuously-operating public root-key
custody procedure; the audit/script template any smaller project copies. Confidence:
**high** (background, pre-window but current practice). *Informs: Q1.*

**[S4]** https://github.com/ossf/foundation — *OpenSSF governance & legal docs*
(funding charter, governing board, direct fund agreement), Linux Foundation/OpenSSF,
living. TL;DR: Sigstore's "neutral home" is a Linux Foundation project funded by
Microsoft, Google, Amazon, Citi and others; a Mar 2026 announcement put a further
$12.5M through OpenSSF/Alpha-Omega
(https://openssf.org/blog/2026/03/17/leading-tech-coalition-invests-12-5-million-through-openssf-and-alpha-omega-to-strengthen-open-source-security).
Why it matters: the foundation answer works, but only *after* multi-vendor buy-in — the
chicken-and-egg for a one-maintainer project is visible right here. Confidence: **high**.
*Informs: Q1.*

**[S5]** https://blog.trailofbits.com/2024/11/14/attestations-a-new-generation-of-signatures-on-pypi —
*Attestations: a new generation of signatures on PyPI*, Trail of Bits, 2024-11-14.
TL;DR: PyPI's 2024 signing rollout binds ephemeral keys to Sigstore's free public CA
(Fulcio) instead of operating its own root PKI (official announcement:
https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations). Why it
matters: precedent for **leaning on someone else's neutral trust root** rather than
minting your own — the credible cold-start move. Confidence: **high**. *Informs: Q1.*

### Q2 — Who runs the two aggregators

**[S6]** https://www.usenix.org/conference/pepr26/presentation/geoghegan —
*Production Multi-Party Computation via the Distributed Aggregation Protocol*,
T. Geoghegan & J.C. Jones (ISRG), USENIX PEPR '26. TL;DR: Divvi Up runs DAP "at
internet scale with **multiple independent aggregation servers**", processing billions
of contributions including Firefox telemetry. Why it matters: the first citable
production report on the exact ENPA-lesson architecture the kickoff names, from the
operators themselves. Confidence: **high** (talk page verified; slides linked there).
*Informs: Q2, Q3.*

**[S7]** https://divviup.org/blog/lessons-from-running-mpc-at-scale —
*Exposure Notifications Private Analytics: Lessons Learned from Running Secure MPC at
Scale*, Divvi Up (ISRG), 2022-05-05 *(background, pre-window)*. TL;DR: operational
reality of running one of the two ENPA servers — coordination between independent
operators is the hard part, not the crypto. Companion: DAP standards write-up
https://divviup.org/blog/writing-dap-standards (2024-02-21); the original ISRG role
announcement https://www.abetterinternet.org/post/prio-services-for-covid-en (2021).
Why it matters: documents *why* the two servers must be different orgs and what that
costs operationally. Confidence: **high** (first-party). *Informs: Q2.*

**[S8]** https://www.ietf.org/archive/id/draft-ietf-ppm-dap-04.html —
*Distributed Aggregation Protocol (DAP)*, IETF PPM WG, draft (versioned). TL;DR:
Leader/Helper split of secret-shared measurements; privacy holds only if the two don't
collude. Why it matters: the normative statement of the non-collusion requirement —
still a draft, so cite the version. Confidence: **medium** (draft status).
*Informs: Q2.*

### Q3 — Default reporting posture

**[S9]** https://github.com/microsoft/vscode/issues/176269 —
*Issue #176269: "Require user consent before sending any telemetry"*, microsoft/vscode,
open thread. TL;DR: VS Code telemetry is **opt-out**, no consent gate; years of user
pushback have moved Microsoft to surface an opt-out notification, not to flip the
default. Why it matters: the canonical telemetry-default fight in dev tooling; shows
opt-out survives backlash from a vendor with market power — a one-maintainer project
does not have that reservoir of trust. Confidence: **medium-high** (primary thread).
*Informs: Q3.*

**[S10]** https://docs.brew.sh/Analytics — *Anonymous Analytics*, Homebrew docs, living.
TL;DR: analytics are default-on **but a notice is displayed before the first event is
sent**, so a user can opt out before anything leaves the machine (`brew analytics off`,
`HOMEBREW_NO_ANALYTICS=1`). Why it matters: the *middle-ground* design — default-on for
utility, gated first-send for consent — which nobody else in this sweep ships; the
closest published analogue to "on by default, Layer 0 only, per-detector kill switch".
Original opt-in demand: https://github.com/Homebrew/brew/issues/142 (2016, background);
GDPR question it never fully answered:
https://law.stackexchange.com/questions/31527/gdpr-and-homebrew-analytics. Confidence:
**high** (official docs). *Informs: Q3.*

**[S11]** https://popcon.debian.org — *Debian Popularity Contest*, Debian, living; plus
HN discussion https://news.ycombinator.com/item?id=45107598. TL;DR: popcon is **opt-in**,
participation skews privacy-conscious, and "most people turn it off" making stats
unrepresentative; Ubuntu dropped popcon entirely in 2020
(http://www.omgubuntu.co.uk/2020/07/ubuntu-popularity-contest-removed); privacy-first
FreedomBox won't ship it (https://discuss.freedombox.org/t/help-freedombox-by-enabling-popularity-contest/1721).
Why it matters: the measured cost of opt-in — the dataset everyone cites and nobody
trusts. Confidence: **medium-high**. *Informs: Q3.*

**[S12]** https://support.mozilla.org/en-US/kb/technical-and-interaction-data —
*Technical and interaction data*, Mozilla Support, living; plus
https://www.quippd.com/writing/2025/06/18/mozilla-backs-off-on-data-collection-firefox-labs-to-not-require-telemetry-or-studies-in-future-updates.html
(2025-06-18). TL;DR: Firefox telemetry (Glean) is opt-out by default; in June 2025
Mozilla **backed off requiring telemetry/studies for Firefox Labs** after criticism;
adjacent Fedora thread argues opt-out-by-default is itself the problem
(https://discussion.fedoraproject.org/t/how-concerning-is-firefoxs-privacy-preserving-attribution-and-should-it-be-opt-in/125838,
2024-07). Why it matters: even Mozilla — the most privacy-credible name in the sweep —
retreats when defaults tighten; "we're the good guys" does not license default-on.
Confidence: **medium-high** (official docs + secondary reporting of Mozilla's reversal).
*Informs: Q3.*

**[S13]** https://cli.sentry.dev/configuration — *Sentry CLI configuration*, Sentry,
living. TL;DR: CLI telemetry is default-on under what Sentry itself calls the
"industry-standard opt-out", disabled via `SENTRY_CLI_NO_TELEMETRY=1`; the SDK wizard
is likewise default-on (https://github.com/getsentry/sentry-javascript/issues/13270,
2024-08). Why it matters: confirms opt-out is the *industry norm for dev-facing CLI
telemetry in 2024-2026*, against the EDPB line below — the live tension Q3 sits on.
Confidence: **medium-high** (official docs). *Informs: Q3.*

**[S14]** https://www.edpb.europa.eu/system/files/2024-10/edpb_guidelines_202401_legitimateinterest_en.pdf —
*Guidelines 1/2024 on legitimate interest (Art. 6(1)(f) GDPR)*, EDPB, 2024-10-08; with
Opinion 08/2024 "consent or pay"
(https://www.edpb.europa.eu/system/files/2024-04/edpb_opinion_202408_consentorpay_en.pdf,
2024-04-17). TL;DR: legitimate interest is **not a blanket basis**, is generally
unsuitable for accessing users' devices, and consent does not waive Art. 5
data-minimisation; the older connected-vehicles guidelines (01/2020) already barred
repurposing maintenance telemetry. Why it matters: the EU regulatory floor under any
"on by default" answer for a tool that reports sightings from customer machines —
non-legal-advice flag applies. Confidence: **high** (regulator primary).
*Informs: Q3.*

**[S15]** https://link.springer.com/article/10.1007/s10207-025-01165-2 —
*Share and benefit: incentives for cyber threat intelligence*, T. Reittinger et al.,
Int. J. Information Security, 2025/2026 (cited 10×); with
https://academic.oup.com/cybersecurity/article/11/1/tyaf016/8244123 —
*Promoting research on CTI sharing in ecosystems*, C. Abraham et al., J. Cybersecurity
2025 (cited 15×). TL;DR: the free-rider problem remains the central barrier to CTI
sharing; incentive and low-friction participation mechanisms are what empirical work now
tests. Why it matters: the literature the kickoff cites *for* default-on reporting —
this is the strongest recent statement of that side. Confidence: **medium-high**
(paywalled; abstracts + citations). *Informs: Q3.* (Background:
https://www.ndss-symposium.org/ndss-paper/sharing-cyber-threat-intelligence-does-it-really-help)

### Q4 — Data licence for the commons

**[S16]** https://github.com/SigmaHQ/sigma — *Main Sigma rule repository*, SigmaHQ,
living; DRL 1.1 licence **verified by fetch on 2026-10-25**: "The content of this
repository is released under the Detection Rule License (DRL) 1.1". TL;DR: 3,000+
community detection rules under a purpose-built content licence, neither code-FOSS nor
CC; the hack.lu 2024 "Lessons Learned" talk covers how hard licence-switching a live
detection corpus is
(https://archive.hack.lu/media/hack-lu-2024/submissions/MMNTPT/resources/Lessons_Learn_NzXKIVE.pdf,
2024-10). Why it matters: the closest existing artefact to the commons — a *rules-only*
licence is a real, working precedent. Confidence: **high**. *Informs: Q4.*

**[S17]** https://github.com/misp/misp-galaxy — *MISP galaxies*, MISP Project, living;
format standard https://www.misp-standard.org/rfc/misp-standard-galaxy-format.html.
TL;DR: threat-actor/tool/ransomware knowledge base (~1,000 curated clusters) released
**CC0** — deliberately attribution-free for maximal reuse. Why it matters: the maximal-
open pole for *indicator/knowledge* data that the mesh's fingerprints and packs resemble.
Confidence: **high**. *Informs: Q4.*

**[S18]** https://abuse.ch/blog/creating-sustainability-for-abuse-ch-and-its-community —
*Creating sustainability for abuse.ch and its community*, abuse.ch, 2025-07. TL;DR:
feeds stay free for **contributing** community members; non-contributors now get data
only via commercial licensing through Spamhaus Technology (licensee since 2022:
https://abuse.ch/blog/abuse-ch-appoints-spamhaus-as-a-licensee; the 2020 turn from
fully-free: https://abuse.ch/blog/moving-forward). Why it matters: the strongest recent
*rejection* of pure-open for threat data — sustainability and anti-free-riding enforced
through the licence itself. Confidence: **high** (first-party). *Informs: Q4, Q3.*

**[S19]** https://www.cve.org/legal/termsofuse — *CVE Program Terms of Use*, MITRE/CVE,
living. TL;DR: custom permissive copyright licence (SPDX "CVE-ToU",
https://spdx.org/licenses/cve-tou.html) with a **trademark** restriction — not CC, not
public domain. Why it matters: even the most-reused security dataset chose bespoke terms
over an existing data licence, and single-funder fragility showed in the April 2025
near-shutdown (https://orca.security/resources/blog/cve-mitre-program-status-2025,
2025-04-16; NIST/NVD separately tightened API access terms in 2024). Confidence:
**high** (official terms; medium for the secondary funding reporting). *Informs: Q4, Q1.*

**[S20]** https://www.snort.org/faq/what-are-community-rules — *What are Community
Rules?*, Snort/Cisco Talos, living. TL;DR: the community ruleset is **GPLv2**,
Talos-certified, "free of charge without any Snort Subscriber Rule Set License
restrictions"; community rules historically ship **disabled by default**. Why it matters:
GPL-as-data-licence precedent for rules, plus a shipped-in-off-state default that
rhymes with Q5. Confidence: **medium-high** (official FAQ; the disabled-by-default note
is community-reported, 2016 forum). *Informs: Q4, Q5.*

**[S21]** https://osv.dev — *OSV: Open Source Vulnerabilities*, Google/OpenSSF, living;
FAQ https://google.github.io/osv.dev/faq. TL;DR: **no data licence or terms are stated
on the official site or FAQ** (verified by fetch 2026-10-25); third parties describe the
data as CC BY 4.0 (e.g. https://talk.openmrs.org/t/googles-new-osv-scanner-for-vulnerabilities/38252).
Why it matters: the flagship "open vulnerability database" does not prominently declare
its data licence — evidence that an explicit LICENSE-DATA is *above* current industry
bar, not merely equal to it. Confidence: **high** for the gap itself; the CC BY 4.0
claim is **low-confidence secondary**. *Informs: Q4.*

### Q5 — Whether `block` ships by default

**[S22]** https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf —
*Channel File 291 Incident Root Cause Analysis*, CrowdStrike, 2024-08-06 (preliminary
PIR 2024-07-24:
https://www.crowdstrike.com/en-us/blog/falcon-content-update-preliminary-post-incident-report).
TL;DR: a routine **content configuration update** — not code — caused out-of-bounds
reads and BSODs on ~8.5M Windows hosts (2024-07-19); commitments include staggered
rollout, content-validator checks, and new testing layers. Why it matters: the defining
modern demonstration that shipped-through-the-channel *content* is production-fatal at
scale — the single strongest web datapoint against block-by-default distribution of
community rules. Confidence: **high** (first-party RCA). *Informs: Q5.*

**[S23]** https://www.congress.gov/crs-product/IF12717 — *CRS In Focus IF12717*,
Congressional Research Service, 2024-12; CISA alert of 2024-07-19:
https://www.cisa.gov/news-events/alerts/2024/07/19/widespread-it-outage-due-crowdstrike-update.
TL;DR: public-safety impact (911 dispatch, hospitals) put content-update practices into
congressional oversight. Why it matters: elevates Q5 from engineering preference to
public-trust risk — an independent-government view, not vendor self-reporting.
Confidence: **high**. *Informs: Q5.*

**[S24]** https://discourse.crowdsec.net/t/crowdsec-setup-feedback-and-general-questions/1452 —
CrowdSec team on community-blocklist confidence (living); with
https://github.com/crowdsecurity/crowdsec/issues/4518 — maintainers conceding that
adding `facebookexternalhit` (Facebook's link crawler) IPs to the community blocklist
"is probably not the best idea". TL;DR: CrowdSec requires **high confidence before an IP
enters the community blocklist** precisely because a false positive propagates to every
subscriber; FAQ documents an unban path (https://www.crowdsec.net/faq). Why it matters:
the closest production analogue to the mesh — crowd consensus feeding blocking — and it
is run *conservatively by design*, with a live FP incident on record. Confidence:
**medium-high**. *Informs: Q5, Q3.*

**[S25]** https://www.spamhaus.org/blocklists/drop-fair-use-policy — *DROP Fair Use
Policy*, Spamhaus, living; list page
https://www.spamhaus.org/blocklists/do-not-route-or-peer. TL;DR: DROP "will not include
any IP address space under the control of any legitimate network — even if being used
by persistent and well-known spammers", and Spamhaus itself calls the lists "not a
silver bullet" (https://www.spamhaus.org/resource-hub/dnsbl/the-return-of-the-asn-drop,
2023-09). Why it matters: a quarter-century-old blocklist that *publishes its
conservatism as policy* — the institutional form of "never block from a community feed
without local veto". Confidence: **high** (official policy). *Informs: Q5.*

**[S26]** https://www.giskard.ai/knowledge/ai-guardrails-comparison-2026 —
*Best 9 AI guardrails: how to choose*, Giskard, 2026. TL;DR: per their RealHarm
research, **up to 40% of requests blocked by generic guardrails were false positives**
with no incident report filed; an arXiv preprint reports 40%+ FPs for lightweight
policy-based guardrails (https://arxiv.org/html/2601.06366v3, SafeGPT); practitioner
accounts of Bedrock guardrail FPs echo alert-fatigue costs (https://sudoall.com/bedrock-guardrails-truth).
Why it matters: the FP cost curve for *exactly* interlock-style rules — the direct
counterweight to auto-block, though vendor/preprint quality varies. Confidence:
**medium** (vendor blog + preprint). *Informs: Q5, Q2.*

### Cross-cutting precedent

**[S27]** https://www.mitre.org/news-insights/news-release/mitre-launches-ai-incident-sharing-initiative —
*MITRE launches AI Incident Sharing initiative*, MITRE, 2024-10-02 (ATLAS:
https://atlas.mitre.org; community analogue AVID: https://avidml.org/faq). TL;DR: a
CVE-style **trusted-contributor, anonymised** sharing community for real-world AI
security incidents — gated membership, not open reporting. Why it matters: the nearest
live predecessor to the mesh's reporting plane, and its designers chose *contribution
gates over default-on reporting*. Confidence: **high**. *Informs: Q3, Q1.*

**[S28]** https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022L2555 —
*Directive (EU) 2022/2555 (NIS 2)*, official text; practitioner summary of the threat-
intelligence angle: https://www.cognyte.com/blog/nis2-threat-intelligence (2024-06).
TL;DR: NIS 2 measures apply from 2024-10-17/18, and the implementing regulation
(2024/2690) makes threat-intelligence handling a compliance element for essential
entities (Art. 34 itself is fines: €10M/2% or €7M/1.4%). Why it matters: EU-regulated
deployers now have a *duty to consume* intelligence — a demand-side pull the mesh can
name in its reporting-posture decision. Confidence: **high** for the directive,
**medium** for the vendor summary. *Informs: Q3.*

## Where sources disagree (for the synthesizer)

1. **Q3 is genuinely split.** The incentives literature [S15] and every operator's
   behaviour (VS Code [S9], Homebrew [S10], Sentry [S13], Firefox [S12]) favour
   default-on reporting/analytics for network utility — while the EU regulator line
   [S14] and each project's own backlash threads push opt-in, and the AI-incident
   world [S27] chose gated contribution. No swept source resolves this; Homebrew's
   notice-before-first-send [S10] is the only published middle ground.
2. **Q4 has two poles, both credible.** Maximal-open (MISP CC0 [S17], Sigma DRL [S16])
   vs sustainability-through-licence (abuse.ch/Spamhaus [S18]); CVE [S19] shows a third
   path (bespoke terms + trademark). Sources do not converge on one licence for
   *privacy-sensitive derived artifacts* (fingerprints, redactions).
3. **Q5 leans no, with one honest caveat.** CrowdStrike [S22], CRS [S23], CrowdSec
   [S24], Spamhaus [S25], guardrail FP data [S26] all point away from block-by-default;
   the dissent lives in the kickoff's own corpus (adaptive worms, "minutes matter"),
   not in the swept web sources — none of which advocate auto-block.
4. **Q1/Q2 are precedent-rich but cold-start-poor.** Every neutral-home example
   [S1]–[S6] postdates multi-org participation; no swept source describes a
   one-maintainer interim that later migrated into a foundation without re-keying
   questions (PEP 458's dual-signing rotation is the closest mechanical note, via [S5]).

## What's NOT in the recent literature but feels load-bearing

- **A one-maintainer root-custody playbook.** Nothing in 2024–2026 publishing explains
  how a solo maintainer holds TUF root keys *credibly* while recruiting the ≥3 orgs the
  kickoff wants. The Sigstore self-hosted-TUF tutorial exists but dates to 2022
  (https://blog.sigstore.dev/sigstore-bring-your-own-stuf-with-tuf-40febfd2badd).
  The bootstrap sequence — lean on an existing neutral root à la PyPI/ Fulcio [S5],
  then carve out your own — is assembled here by inference, not cited.
- **A published account of one organisation running both DAP aggregators as an
  explicit interim.** [S6]–[S8] all assume independence; the degradation semantics
  ("temporarily one operator = privacy reduces to that operator's word") is documented
  nowhere I could sweep.
- **Telemetry defaults for agent-security sightings specifically.** No swept project
  ships on-by-default reporting of guard/agent-security telemetry; the nearest thing
  [S27] is gated. The kickoff's "on by default, Layer 0 only" option therefore has no
  directly citable precedent — only analogues [S10], [S12].
- **A data licence covering privacy-sensitive derived artifacts** (fingerprints of
  attacker text, redacted samples) with contributor rights warranties. Existing
  precedents cover indicators [S16]–[S20] or knowledge bases [S17]; none address
  "was derived from a customer's private prompt traffic" as a licensing input.
- **GDPR treatment of MPC-aggregated security sightings.** EDPB output [S14] covers
  telemetry and consent generally; nothing addresses DAP/secret-shared security
  counters as a lawful basis. Flagged non-legal-advice; a real gap for Q3.
- **Published FP-rate time series for community rule feeds.** CrowdSec precision data
  exists internally ([S24] anecdotes, issue #4518) but no citable longitudinal
  measurement — so Q5's monitor-window length cannot be grounded in public data.
- **Sweep biases to discount for:** English-only (EU foundation practice under-
  represented); vendor first-party posts [S22], [S24], [S26] carry self-reporting bias;
  CrowdStrike is one incident (n=1) for Q5; several EU/legal items are pre-window
  background flagged as such.

— *end of lens-glm.md · 28 ranked sources across Q1–Q5 · all URLs as returned by search
or verified by fetch on 2026-10-25; no fabricated URLs.*
