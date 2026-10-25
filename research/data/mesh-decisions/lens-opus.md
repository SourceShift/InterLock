# Lens: Opus — who bears the cost of a default

*Deep-narrative lens on the five open decisions in
`research/mesh-shared-policy-network.md` §11. Thesis: all five questions are the
same question. A one-maintainer commons cannot borrow legitimacy from
institutions it does not have, so it has to earn it through commitments it
cannot later break. And each default should be set by whoever bears the cost
when that default fails.*

## 1. Historical context

Community security feeds started out enforcing by default. The MAPS RBL (1997)
published addresses that subscribing mail servers refused outright. DShield
(2000) pooled firewall logs. Bleeding Snort, later Emerging Threats, and ClamAV
(2002) crowdsourced signatures. MISP (2011) and STIX/TAXII turned sharing into
structured exchange. Ten years ago, around the US Cybersecurity Information
Sharing Act of 2015, the consensus was that **volume was the bottleneck**: more
sharing is better, and the main obstacle is free riding (Gordon, Loeb &
Lucyshyn 2003; Gal-Or & Ghose 2005).

Measurement then took the volume premise apart. Blocklists barely overlap
(Metcalf & Spring 2015). Feeds are slow and cover little (Li et al. 2019,
*Reading the Tea Leaves*, USENIX Security). Paid feeds are not much better than
free ones (Bouwman et al. 2020, USENIX Security). The question moved from "how
do we get more" to "how do we stop a shared feed from hurting its subscribers".

There were two inflection points. SolarWinds (December 2020) made the update
channel itself the attack surface, and TUF (Samuel, Mathewson, Cappos &
Dingledine 2010) went from a paper to Sigstore's production root in 2021
(https://blog.sigstore.dev/a-new-kind-of-trust-root-f11eeeed92ef). Then, on
**19 July 2024**, CrowdStrike's Channel File 291 crashed about 8.5 million
hosts with a *content* update rather than a code update
(https://www.crowdstrike.com/wp-content/uploads/2024/08/Executive-Summary_Root-Cause-Analysis_Channel-File-291.pdf).
Cloudflare's 18 November 2025 outage repeated the pattern: an auto-generated
Bot Management feature file doubled in size and was pushed everywhere at once
(https://blog.cloudflare.com/18-november-2025-outage/). If a non-specialist
asked when this became serious, I would point at July 2024. That was the day it
became undeniable that a shared rule feed is a remote control over every
subscriber's availability.

## 2. Conventional wisdom

The load-bearing assumption is **legitimacy comes from plurality**: a commons
is trustworthy to the extent that no single party controls it. Every question
then answers itself by adding parties. The design document applies this
faithfully:

- **Root keys** go to a threshold of offline keys held by people in different
  organisations, and "the project needs at least three organisations before
  Phase 0 is credible" (§11.1). Sigstore's five keyholders from different
  companies and universities are the template.
- **Aggregators** are two non-colluding operators on different clouds, the
  lesson of ENPA as Divvi Up recorded it
  (https://divviup.org/blog/lessons-from-running-mpc-at-scale), on top of Prio
  (Corrigan-Gibbs & Boneh 2017), whose privacy holds only while at least one
  server is honest.

Next to plurality sits a **network-effects** assumption: the commons' value
grows with participation, and defaults drive participation. The canonical
evidence is the organ-donor gap between opt-in and opt-out countries (Johnson
& Goldstein 2003, *Science*). Hence §11.3's alternative: Layer-0 counts on by
default.

Three sub-claims follow:

1. **Credibility is a headcount.** Until three organisations hold keys and two
   run aggregators, the commons is not ready.
2. **The licence is a formality.** Pick a standard open-data licence plus a
   CLA-style rights warranty and move on, the way the GitHub Advisory Database
   settled on CC-BY-4.0 and MISP galaxies on CC0/BSD-2-Clause.
3. **Time earns enforcement.** Staged rings and a monitor window are enough to
   stop a false-positive cascade, so a rule that survives seven days in shadow
   mode may block. The CrowdStrike RCA asks for rings, and the perun.au review
   of CrowdSec deployments blames missing "decision-only validation windows"
   (https://perun.au/insights/crowdsec-production).

## 3. Dissenting view

**Plurality is an end state, and a one-maintainer project cannot buy it.**
Faking it with keyholders who never use the system produces ceremony theatre
and a likelier failure: lost keys, not compromised ones. Credibility can come
from somewhere else: **commitments the
maintainer cannot later break, and constraints anyone can check.** Ostrom
(1990, *Governing the Commons*): commons survive on monitorable rules and
graduated sanctions, not on spread-out ownership.
interlock already ships most of the needed machinery:

- TUF root rotation makes custody *upgradeable*.
- The transparency log makes misuse *detectable*.
- A DCO without a CLA would make the licence *irrevocable*. HashiCorp's 2023
  relicensing to the BSL rested on its contributor licence agreement.
- Opt-in reporting means no data exists to be misused later.

**On reporting**, the free-rider literature models members who have already
chosen to join an ISAC. interlock is a *library* inside other people's agents.
A default there is inherited by a deployer who never chose it, and it breaks
the README's own promise of "no network calls". Precedents:

- **Go:** the team proposed opt-out telemetry (Cox 2023,
  https://research.swtch.com/telemetry-intro) and shipped it opt-in in Go 1.23,
  with collection kept *local* by default (https://go.dev/blog/gotelemetry,
  2024).
- **Debian popcon** has defaulted to "no" for two decades
  (https://lwn.net/Articles/707783).
- **Homebrew's** opt-out survives because the person who installs brew is the
  person it measures. It still left Google Analytics for EU-hosted InfluxDB
  in 2023 (https://docs.brew.sh/Analytics).

**On the licence**, Sigma's authors wrote their own Detection Rule License
because vendors repackaged community rules without credit. DRL 1.1 requires
attribution even in match output (https://github.com/SigmaHQ/Detection-Rule-License).
abuse.ch, the poster child for CC0 indicators, made Spamhaus its primary
licensee in August 2022 and now requires a commercial subscription for
production use (https://abuse.ch/terms-of-use/). CC0 data did not pay for
itself.

**On block**, the auto-block feeds that worked, DNSBLs and Spamhaus DROP, push
the cost of a false positive onto the *blocked* party. interlock's false block
lands on the subscriber's own agent, which is the CrowdStrike class of failure.

The dissent's rule: **whoever bears a default's failure cost should set it.**
It explains how the surface data clusters:

| Who bears the failure cost | Default that survives |
|---|---|
| The user who chose the tool | Opt-out telemetry (Homebrew) |
| A downstream deployer who did not choose it | Opt-in (Go, Debian) |
| An outside party | Auto-block (DNSBLs) |
| The subscriber itself | Rings and customer control, after the fact (CrowdStrike) |

## 4. Edge cases / failure modes

Three scenarios in the shipped code where the conventional answer gives a bad
outcome:

1. **Without an approver, escalate is a block.** With no approver installed,
   "every escalation is blocked" (`docs/guides/approvals.md:26`). The ring
   ceilings cap experimental rules at `escalate`
   (`interlock/mesh/bundle.py:55-59`). So on a headless canary or early node,
   every community rule starts blocking once its seven days are up. Graduation
   is also purely time-based: a rule that never fired in shadow mode graduates
   with zero local evidence. The monitor window catches *frequent* false
   positives and lets rare ones straight through. McAfee DAT 5958 (April 2010)
   quarantined `svchost.exe`, a file that was everywhere but matched only one
   narrow signature.
2. **The kill switch freezes rather than withdraws.** If the maintainer
   disappears, the one-day timestamp expires and syncs stop
   (`interlock/mesh/metadata.py:61-65`). The last good policy keeps running,
   including any bad `stable` block rule. Nothing new can be signed, so the
   withdrawal that would fix it can never arrive.
3. **Counts are not secret today.** `interlock/cli/mesh.py:502` posts the whole
   signed envelope to the consensus service. `interlock/mesh/consensus.py:169-174`
   then adds the plaintext `body["counts"]` to per-rule totals, which
   contradicts the module's own docstring ("Counts are not here", line 25). Two
   non-colluding aggregators protect nothing the consensus operator does not
   already see. Even once that is fixed, with three reporters each one can
   recover another's count by subtraction, which is why DAP has a minimum batch
   size (draft-ietf-ppm-dap).

## 5. What I'd want to know more about

The one measurement that would settle the conventional-versus-dissent debate
is the **false-block rate of community rules after they graduate**, broken
down by rule class.

**Design.** On canary and early nodes that consent:

- Randomise the monitor-window length per (node, rule) across {1, 3, 7, 14}
  days.
- After graduation, count enforcing decisions and false-positive sightings.
- Stratify by rule class (exact digest, regex, similarity) and by how many
  distinct organisations backed the rule at promotion.
- Outcome: false blocks per 1,000 node-rule-weeks.

**Reading the result.**

- If exact-digest indicators backed by at least three organisations show
  near-zero false blocks at every window length, the dissent on block-by-default
  loses for that class.
- If the false-block rate does not fall as the window gets longer, the
  time-based window is theatre and graduation has to be based on evidence.

Most of the instrumentation exists: `mesh status` already counts what shadow
rules would have done. But Layer 1 deliberately excludes monitor-mode
decisions, so the experiment needs a consented Layer-0 counter for shadow fires.

**Secondary questions:**

- **Participation elasticity.** Under a Go-style "local by default, upload
  opt-in" prompt, does the network reach `min_orgs = 3` for most fired rules?
  Or is the binding constraint the number of deployments rather than consent?
- **Fingerprint leakage at small N.** With a handful of reporters, does a
  fingerprint at α = 1.5 leak membership?
- **Erasure (non-legal analysis).** If a published CC0 sample turns out to hold
  personal data, can a GDPR Art. 17 request be met once its hash sits in an
  append-only log and its bytes sit in peer caches?

## 6. Synthesis recommendations

1. **Root custody: keep the maintainer's root, make it hard to lose, and
   pre-commit the rotation.** Use a 2-of-3 offline hardware root, with the
   third share escrowed with a named second person. Log a public ceremony
   transcript. In `GOVERNANCE.md`, commit to rotating to 3-of-5 across at least
   three organisations once three independent organisations subscribe on the
   stable ring.
   *Evidence:* TUF root rotation (Samuel et al. 2010). Sigstore's five
   keyholders arrived with an already multi-organisation project.
   *Wrong if:* a key-loss drill cannot restore signing within the timestamp
   horizon plus the monitor window, or prospective subscribers name the
   single-maintainer root as the reason they decline.

2. **Aggregators: fix the leak before recruiting anyone, then join an existing
   protocol.**
   - Remove `counts` from the consensus envelope.
   - Move `interlock/mesh/aggregate.py` to DAP/Prio3 so an existing operator
     (ISRG's Divvi Up, Cloudflare) can act as helper.
   - Until then, fewer than two aggregators means counts are not sent.

   *Evidence:* the code finding in §4. Corrigan-Gibbs & Boneh 2017. Divvi Up's
   operational lessons.
   *Wrong if:* no DAP operator will take a tenant this small within two
   quarters. In that case, publish no counts at all rather than run a vendor
   pair.

3. **Reporting: off by default, local by default.**
   - `mesh report build` runs locally and its output appears in `doctor` and
     the console.
   - Uploading needs `mesh report enable`.
   - Use reciprocity rather than a default to attract reporters: membership in
     the early ring goes to those who report, CrowdSec-style.

   *Evidence:* the Go reversal, Debian popcon, the README's "no network calls"
   promise, and GDPR Art. 5(1)(c). Recital 49's legitimate interest in
   network security is the honest counter-argument.
   *Wrong if:* deployments grow while fewer than `min_orgs` reporters exist for
   most fired rules for two quarters. That would mean consent, not adoption, is
   what starves the network.

4. **Licence: one licence per kind of artifact, and no CLA.**
   - Packs: Apache-2.0, because a rule is code.
   - Indicators, fingerprints and samples: CC0-1.0, which also waives the EU
     sui generis database right (Directive 96/9/EC). Facts are not
     copyrightable anyway (*Feist v. Rural*, 1991).
   - Contributions: DCO 1.1 plus a three-line data addendum: lawfully obtained,
     no personal data, no third party's confidential data. Attackers write the
     payloads, so contributors can only warrant possession, not authorship.

   *Evidence:* MISP galaxy is CC0/BSD (https://misp-project.org/license). The
   HashiCorp relicensing shows what a CLA makes possible.
   *Wrong if:* a vendor repackages the packs without credit and contributions
   measurably fall off (the DRL scenario). Then move *packs* to CC-BY-4.0.

5. **Block: no community rule enforces without a local act.**
   - Graduation needs the monitor window **and** a standing operator grant per
     channel and status, set once in `config.json`.
   - When no approver is installed, a mesh-sourced `escalate` is recorded as a
     shadow decision, not converted to `NotApproved`.
   - Fix §1's "enforcing within a day" promise so it matches the seven-day
     window.

   *Evidence:* the CrowdStrike RCA ("customer control"), Cloudflare in 2019 and
   2025, and Snort/Suricata practice, where the operator turns `alert` into
   `drop`.
   *Wrong if:* the §5 experiment shows fewer than 1 false block per 10,000
   node-rule-weeks for exact-digest indicators over two quarters. That class
   alone may then block by default on the stable ring.

6. **Stale trust demotes.** When the timestamp has been expired for longer than
   the monitor window, mesh rules go back to shadow mode and `doctor` fails.
   *Evidence:* first-principles extension of TUF's "trust should expire if not
   renewed".
   *Wrong if:* attackers are seen cutting nodes off from every mirror and peer
   to force expiry and strip protection. Then demote only to `escalate`.
