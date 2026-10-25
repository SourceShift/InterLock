# Lens: Codex — what public implementations actually ship

**Topic.** The five open decisions in `research/mesh-shared-policy-network.md` §11:
(1) root-key custody, (2) aggregator operators, (3) default reporting posture,
(4) data licence for the commons, (5) whether `block` ships through the mesh by default.

**Method.** I read the load-bearing file in each repository, not its README. Every
file was fetched at a pinned commit (`raw.githubusercontent.com/<repo>/<sha>/<path>`)
on 2026-10-25. Two Debian packages were fetched from `sources.debian.org` at a pinned
package version. Line numbers refer to those exact revisions. Star and issue counts
come from the GitHub API on the same day. GitHub's `open_issues_count` includes open
PRs, so treat it as a churn signal, not a bug count. Where I could not read code
(closed-source servers, or data not hosted in git), the gap is marked `[lookup: …]`
rather than filled in from memory.

**Library vs approach.** Several repos import TUF, DAP or debconf. Each entry below
records the *approach*: thresholds, defaults and gates. The library a repo imports
only tells you who it depends on.

---

## Implementations surveyed (15)

### 1. `sigstore/root-signing` @ `f3fce8992cbd` (client-side counterpart: `theupdateframework/python-tuf` @ `2c771a035620`)

- **Signal.** 135★ for the repo, but it is the trust root for every Sigstore client
  (cosign, npm provenance, PyPI attestations). It is pushed daily. python-tuf has 1,731★ and is the reference TUF client.
- **Questions.** Q1.
- **Pattern shape.** Five *named individuals* hold one hardware key each. Root and
  targets need 3 of 5. Timestamp and snapshot are online keys in cloud KMS. Root
  metadata expires after 197 days, with a 46-day re-sign window. Every root change is
  a "signing event" run as a pull request on a `ceremony/YYYY-MM-DD` branch.
- **Key file:line.**
  - `sigstore/root-signing:metadata/root.json:107`: `"threshold": 3` for root. Line 125 does the same for targets.
  - `sigstore/root-signing:metadata/root.json:47,59,71,83,95`: `x-tuf-on-ci-keyowner` is a GitHub handle per key (`@lance`, `@santiagotorres`, `@bobcallaway`, `@joshuagl`, `@mnm678`), not an organisation.
  - `sigstore/root-signing:metadata/root.json:39`: the online key is `gcpkms:projects/sigstore-root-signing/...`. Lines 131-133 give timestamp `expiry-period: 7`, `signing-period: 6`.
  - `sigstore/root-signing:metadata/root.json:138-139`: root `x-tuf-on-ci-expiry-period: 197`, `signing-period: 46`.
  - `sigstore/root-signing:README.md:32-43`: keyholder table with *terms* ("June 2021 –") and an **emeritus** list (Luke Hinds 2021-2022, Dan Lorenc 2021-2025).
  - `sigstore/root-signing:playbooks/ORCHESTRATION.md:21`: each YubiKey ships with a PIV attestation certificate that proves the key was generated in hardware. Line 40: "5 root keyholders each containing one key… threshold of 3".
  - `sigstore/root-signing:playbooks/ORCHESTRATION.md:414`: a failed ceremony is moved to `ceremony/defunct`, never reused.
  - `theupdateframework/python-tuf:tuf/ngclient/_internal/trusted_metadata_set.py:199-209`: a new root is loaded and verified against the *old* root (`_load_data(Root, data, self.root)`). It must then be exactly `version + 1` (202-206) and pass the *new* root's own threshold (209). Expiry is checked only on the final root (241-243).
- **Trade-offs accepted.** Custody rests on people and their employers' goodwill, not on a legal entity. Losing two of the five keyholders still leaves three, enough to sign.
- **Outlier signal.** Keyholder turnover is public, dated and routine: two emeritus
  rotations in four years. Nobody else surveyed treats custody as a *term of office*.
- **Bearing on interlock.** `interlock/mesh/repository.py:22-28` already signs a rotated
  root with both the old and new signers, and `repository.py:219-222` refuses rotation
  below the old threshold. Both match python-tuf. The difference is cadence:
  `interlock/mesh/metadata.py:61-62` sets root expiry to 365 days with no signing
  period, against Sigstore's 197/46.

### 2. `letsencrypt/boulder` — `cmd/ceremony` @ `4e1779d21f9a`

- **Signal.** 5,775★. This tool generated the root and intermediate keys of the largest public CA.
- **Questions.** Q1.
- **Pattern shape.** The whole key ceremony is driven by **one YAML file**, so
  witnesses verify a single document instead of a command transcript. Keys are
  generated on an HSM over PKCS#11 and never leave it. A certificate is linted before
  issuance and again after.
- **Key file:line.**
  - `letsencrypt/boulder:cmd/ceremony/README.md:7`: "there is a single user input, a configuration file… allow for simple verification of a single file".
  - `letsencrypt/boulder:cmd/ceremony/main.go:171-182`: `checkOutputFile` refuses to run if any output file already exists, so a ceremony cannot silently overwrite a key or cert.
  - `letsencrypt/boulder:cmd/ceremony/main.go:151-163`: PKCS#11 module and key label are mandatory, so there is no software-key fallback.
  - `letsencrypt/boulder:cmd/ceremony/main.go:45-57,583-623`: the pre-issuance lint certificate is checked before `rootCeremony` signs, and linting runs again afterwards.
- **Trade-offs accepted.** Requires HSM hardware and a physical ceremony, which is heavy for a one-maintainer project.
- **Outlier signal.** The only surveyed tool that makes the ceremony config *the* audit artefact. Sigstore uses a PR; Debian uses manual GnuPG steps.
- **Bearing on interlock.** `interlock/mesh/repository.py:61-90` (`init_keys`) writes
  keys as 0600 JSON files. It has no refuse-to-overwrite check and no single
  ceremony config that a second person can review.

### 3. Debian `debian-archive-keyring` 2025.1 (sources.debian.org)

- **Signal.** Trust root for every Debian and derivative apt install. It has run
  under the same custody model for decades.
- **Questions.** Q1.
- **Pattern shape.** **No threshold signing at all.** Each release gets three keys:
  an offline `stable` release key, plus `automatic` and `security-automatic` keys
  that sign daily. Keys reach users *inside a package*, so rotation rides normal
  package upgrades. The **next release's keys are pre-shipped one release early**.
- **Key file:line.**
  - `debian-archive-keyring/2025.1:active-keys/index:1-9`: three keys × three releases (bullseye, bookworm, trixie).
  - `debian-archive-keyring/2023.3+deb12u2:active-keys/`: bookworm's own package already contains `add-trixie-automatic`, `add-trixie-security-automatic` and `add-trixie-stable`, i.e. successor keys shipped about two years ahead.
  - `debian-archive-keyring/2025.1:README:13-24`: active keys sit in `trusted.gpg.d`; retired keys move to a separate `removed-keys` keyring.
  - `debian-archive-keyring/2025.1:README.maintainer:20-23`: key removal is a manual file move, annotated "[There should be a better way of doing this]".
- **Trade-offs accepted.** A single online key can sign the archive. Compromise is
  handled by shipping a new package, not by threshold metadata.
- **Outlier signal.** Pre-shipping the *successor* key is how Debian handles
  rotation and loss without a threshold. It suits a project that cannot yet recruit
  enough keyholders.

### 4. DAP in production — `divviup/janus` @ `5a9cccce842e` (server) + `mozilla-firefox/firefox` @ `efd2d1e6f775` (client)

- **Signal.** Janus has only 70★ but is the ISRG/Divvi Up production aggregator.
  Firefox (13.6k★ mirror, hundreds of millions of installs) ships it as a default
  pref.
- **Questions.** Q2, Q3.
- **Pattern shape.** Two aggregators, a **leader run by an independent nonprofit
  (ISRG/Divvi Up)** and a **helper run by the vendor itself (Mozilla)**. Each pins an
  HPKE key in client prefs. Reports are sent only if the user's general telemetry
  switch is on. The server **refuses to release an aggregate below a minimum batch
  size**, and the minimum cannot be zero.
- **Key file:line.**
  - `mozilla-firefox/firefox:modules/libpref/init/all.js:534-536`: "DAP protocol Leader endpoint. Operated by DivviUp/ISRG", `https://dap-09-3.api.divviup.org`.
  - `mozilla-firefox/firefox:modules/libpref/init/all.js:538-541`: "DAP protocol Helper endpoint. Operated by Mozilla", `https://dap.services.mozilla.com`, with its HPKE key pinned.
  - `mozilla-firefox/firefox:toolkit/components/dap/DAPTelemetrySender.sys.mjs:23-27,136-138`: `sendDAPMeasurement` returns early unless `datareporting.healthreport.uploadEnabled`.
  - `mozilla-firefox/firefox:toolkit/components/dap/DAPSender.sys.mjs:83-88`: leader and helper URLs and keys come from those prefs, optionally sent over an OHTTP relay (lines 157-159).
  - `divviup/janus:aggregator_core/src/task.rs:187-188`: `if min_batch_size == 0 { return Err(InvalidParameter("min_batch_size")) }`.
  - `divviup/janus:aggregator/src/aggregator/aggregate_share.rs:160-162`: `validate_batch_size(total_report_count)` must pass before an aggregate share leaves the server.
  - `divviup/janus:aggregator_core/src/task.rs:337-342`: the same binary runs as either `Leader` or `Helper`, so one codebase serves both operators.
- **Trade-offs accepted.** Non-collusion rests on one independent party, not two.
  The vendor holds the other share. Privacy holds only if ISRG does not collude with
  Mozilla.
- **Outlier signal.** The most widely deployed DAP setup openly makes the
  data-collecting vendor one of the two aggregators, which §11's "organisations that
  will not collude" wording rules out.
- **Bearing on interlock.** `interlock/mesh/aggregate.py:34-35` refuses fewer than two
  aggregators, which matches DAP. But `combine_totals` (`aggregate.py:120-127`) has
  **no minimum batch floor**, and shares carry no validity proof. A node can submit
  any value below `PRIME` (`aggregate.py:36-37`); Prio3/VDAF exists to rule that out.

### 5. `Homebrew/brew` @ `c5b9f65d0b67`

- **Signal.** 50,098★. Probably the most-run developer CLI on macOS.
- **Questions.** Q3.
- **Pattern shape.** **On by default, but never on the first run.** A notice prints
  on a TTY, and the run that prints it sends nothing. The persistent UUID was
  removed (deleted on every run). Data goes to an EU-hosted InfluxDB with
  low-cardinality tags. Opt-out is one environment variable or `brew analytics off`.
- **Key file:line.**
  - `Homebrew/brew:Library/Homebrew/utils/analytics.sh:23-28`: if the notice has not been seen, `HOMEBREW_NO_ANALYTICS_THIS_RUN=1`.
  - `Homebrew/brew:Library/Homebrew/cmd/update-report.rb:455-471`: rings the terminal bell, prints "Homebrew collects anonymous analytics… No analytics have been recorded yet (nor will be during this `brew` run)", and marks the notice seen only `if $stdout.tty?`.
  - `Homebrew/brew:Library/Homebrew/utils/analytics.rb:33-34`: every report goes through `return if not_this_run? || disabled?`.
  - `Homebrew/brew:Library/Homebrew/utils/analytics.rb:187-191`: `disabled?` is the env var or the stored setting. Lines 212-226: both `enable!` and `disable!` call `delete_uuid!`.
  - `Homebrew/brew:Library/Homebrew/utils/analytics.rb:13-14,36-37`: `INFLUX_HOST = "https://analytics.brew.sh"`; "Tags… must have low cardinality".
  - `Homebrew/brew:Library/Homebrew/env_config.rb:533-537`: `HOMEBREW_NO_ANALYTICS`, "Google Analytics were destroyed".
- **Trade-offs accepted.** Opt-out rather than opt-in, in exchange for maintainer-visible usage data (`brew info` install counts).
- **Outlier signal.** The "notice run sends nothing" rule plus "not a TTY means the notice may have been missed" is a cheap, testable consent proxy that no one else copies.

### 6. `golang/telemetry` @ `6cd571d43fbb`

- **Signal.** 55★, but it is the telemetry inside the `go` command and gopls.
- **Questions.** Q3.
- **Pattern shape.** **Three modes, default `local`.** Counters are written to disk
  but **never uploaded** until the user runs `go telemetry on`. Turning it on records
  an *as-of date*, and no data from before that date is ever uploaded. An upload
  contains only counters named in a public, versioned upload config, and is
  sampled.
- **Key file:line.**
  - `golang/telemetry:internal/telemetry/dir.go:124-131`: no modefile returns `"local"` ("// default"). An uninitialised directory returns `"off"`.
  - `golang/telemetry:internal/telemetry/dir.go:79-96`: modes are exactly `"on"`, `"off"` or `"local"`, and `SetMode` stamps the date.
  - `golang/telemetry:internal/upload/reports.go:125-129`: `if mode != "on" { uploadOK = false }`.
  - `golang/telemetry:internal/upload/reports.go:134-138`: "don't upload if the report includes any data on or before the asof date". The opt-in is never retroactive.
  - `golang/telemetry:internal/upload/reports.go:147-149,217-219`: per-report sampling (`X > SampleRate` is not uploadable). Only counters with `cfg.HasCounter(program, k)` are copied into the upload.
- **Trade-offs accepted.** Upload volume depends on opt-in rates. The Go team
  accepted far less data than its originally proposed opt-out design. The history
  of that switch is outside this lens's evidence: `[lookup: go.dev/blog/gotelemetry 2024 opt-in]`.
- **Outlier signal.** `local` is a third state between on and off. Operators can
  inspect exactly what *would* be sent before they consent. Nothing else surveyed
  has it.
- **Bearing on interlock.** Interlock's receipts already accumulate locally
  (`interlock/mesh/report.py:124`, `build_report(receipts, since, until, …)`). An
  as-of gate on `since` would bring the Go pattern over almost unchanged.

### 7. Debian `popularity-contest` 1.79 (sources.debian.org)

- **Signal.** Has shipped in Debian since 2003. popcon.debian.org is the reference
  "opt-in usage survey".
- **Questions.** Q3.
- **Pattern shape.** **Opt-in, asked loudly.** The debconf question defaults to
  `false` and is asked at priority `high`, so it is shown in a default install. The
  host ID is a random secret used only to overwrite your own previous submission.
  Reports are encrypted when possible.
- **Key file:line.**
  - `popularity-contest/1.79:debian/templates:1-4`: `Template: popularity-contest/participate`, `Default: false`.
  - `popularity-contest/1.79:debian/config:29`: `db_input high popularity-contest/participate`.
  - `popularity-contest/1.79:default.conf:11`: `PARTICIPATE="no"`. Line 20: `ENCRYPT="maybe"`.
  - `popularity-contest/1.79:default.conf:68-70`: `MY_HOSTID` "is a secret number… Whenever you send in a new entry, it overwrites the last one that had the same HOSTID".
- **Trade-offs accepted.** Results are a biased sample of opt-in hosts, which Debian accepts as the cost of consent.
- **Outlier signal.** Compare the debconf *priority* with CrowdSec (#10): the same mechanism, used the opposite way.

### 8. `microsoft/vscode` @ `7e4e9d83e716`

- **Signal.** 194k★. The kickoff's telemetry reference case.
- **Questions.** Q3.
- **Pattern shape.** A **four-level enum (`all`/`error`/`crash`/`off`) defaulting to
  `all`**, settable by enterprise policy. The open-source build *cannot* send
  telemetry: sending requires `enableTelemetry` in `product.json`, which only the
  Microsoft-branded build has. Payloads pass through path anonymisation and PII
  scrubbing.
- **Key file:line.**
  - `microsoft/vscode:src/vs/platform/telemetry/common/telemetryService.ts:337-347`: `'enum': [ON, ERROR, CRASH, OFF]`, `'default': TelemetryConfiguration.ON`. Lines 351-354 add an admin `policy` hook.
  - `microsoft/vscode:src/vs/platform/telemetry/common/telemetryUtils.ts:96-101`: `supportsTelemetry` returns false unless `productService.enableTelemetry` is set (OSS dev builds log locally only).
  - `microsoft/vscode:product.json` (250 lines): contains no `enableTelemetry` key, so the OSS product cannot send.
  - `microsoft/vscode:src/vs/platform/telemetry/common/telemetryUtils.ts:479-507`: `cleanData` runs `anonymizeFilePaths` and `removePropertiesWithPossibleUserInfo` on every property.
  - `microsoft/vscode:src/vs/platform/telemetry/common/telemetryService.ts:383,399-401`: deprecated `telemetry.enableTelemetry` and `enableCrashReporter` settings are still honoured as kill switches.
- **Trade-offs accepted.** Opt-out by default in the distributed product, and the
  setting carries legacy surface (three generations of switches).
- **Outlier signal.** "The open-source build is dark, the vendor build is on" splits
  the *code's* default from the *distribution's* default. That split is available to
  any Apache-2.0 project with a vendor build.

### 9. Sentry — `getsentry/sentry-python` @ `9e4ba4c0248a`, `getsentry/self-hosted` @ `095a9c7ad549`, `getsentry/sentry` @ `9f79f84e4787`

- **Signal.** sentry-python has 2.2k★ and self-hosted 9.6k★. Sentry is a de-facto standard for error telemetry.
- **Questions.** Q3.
- **Pattern shape.** Three postures in one vendor:
  - The SDK collects **no PII by default**.
  - The self-hosted installer forces a **choice with no default**, listing the exact fields collected and the retention period.
  - The server's version beacon is **on by default**.
- **Key file:line.**
  - `getsentry/sentry-python:sentry_sdk/consts.py:1394`: `send_default_pii: "Optional[bool]" = None` (treated as off). Line 1426: `include_local_variables = True`, so content capture is on even though PII is off.
  - `getsentry/self-hosted:install/error-handling.sh:139-191`: if `REPORT_SELF_HOSTED_ISSUES` is unset, the installer prints the fields ("OS username, IP address, install log, runtime errors, performance data"), "Thirty (30) day retention", and loops `until` it gets y or n. Lines 181-190 tell the user how to pre-answer non-interactively.
  - `getsentry/sentry:src/sentry/conf/server.py:1526-1527`: `# Should we send the beacon to the upstream server?` `SENTRY_BEACON = True`.
- **Trade-offs accepted.** A forced choice blocks unattended installs unless a flag
  is passed. The CLI accepts that friction in return for unambiguous consent.
- **Outlier signal.** The forced choice with no default, which lists every field and
  the retention period, is the only one of its kind in this survey.

### 10. `crowdsecurity/crowdsec` @ `725b6659dee5`

- **Signal.** 15.3k★. The closest production analogue to the mesh: a crowd-sourced
  security network with a central consensus service.
- **Questions.** Q3, Q5.
- **Pattern shape.**
  - **Reporting.** Joining the central API defaults to **on**. The Debian package
    asks at priority `medium`, which a default debconf (priority `high`) does not
    show, so it is accepted silently. Signal sharing is on once registered.
    Manual decisions and alert context are **off** by default.
  - **Exclusions.** Simulated alerts are never shared. Custom and tainted scenarios
    are shared.
  - **Enforcement.** The community blocklist is **pulled and enforced by default**.
    Allowlists are applied *before* new decisions and retroactively to existing
    ones.
- **Key file:line.**
  - `crowdsecurity/crowdsec:build/debian/templates:17-23`: `Template: crowdsec/capi`, `Default: true`, "If you don't know what to do, answer yes."
  - `crowdsecurity/crowdsec:build/debian/postinst:36,44-46`: `db_input medium crowdsec/capi`, then `cscli capi register`.
  - `crowdsecurity/crowdsec:build/docker/docker_start.sh:413-423`: Docker registers with the online API unless `DISABLE_ONLINE_API` is set.
  - `crowdsecurity/crowdsec:pkg/csconfig/api.go:401-412`: `PullConfig.Community = new(true)`, `PullConfig.Blocklists = new(true)`, `Sharing = new(true)`.
  - `crowdsecurity/crowdsec:pkg/csconfig/console.go:88-105`: `share_custom` and `share_tainted` are true; `share_manual_decisions` and `share_context` are false.
  - `crowdsecurity/crowdsec:pkg/apiserver/apic.go:346-361`: scenario trust is `certified`, `custom` (no hash), `tainted` (no version) or `manual`.
  - `crowdsecurity/crowdsec:pkg/apiserver/apic.go:363-394`: `shouldShareAlert`. `*alert.Simulated` is never sent (369-372); each trust class is gated by its console flag.
  - `crowdsecurity/crowdsec:pkg/apiserver/apic.go:614-616,666-668`: `GetStreamV3(… CommunityPull: a.pullCommunity …)`, and the pulled decisions are saved as local alerts and decisions (origin `CAPI`).
  - `crowdsecurity/crowdsec:pkg/apiserver/apic.go:645-655,686-694`: allowlists are updated before decisions are processed, then `ApplyAllowlistsToExistingDecisions` deletes already-active matches.
  - `crowdsecurity/crowdsec:config/simulation.yaml:1`: `simulation: false`. Shadow mode exists but is off by default.
- **Trade-offs accepted.** Reciprocity, "share signals to receive the blocklist",
  makes the network useful quickly. It also means a default install reports
  attacker IPs without a visible prompt, and it auto-enforces a centrally computed
  list.
- **Outlier signal.** The **only surveyed system that auto-enforces community output
  by default**. What it enforces is *reputation of a remote actor* (an IP, time-bound,
  with a delete stream), not *content rules over the operator's own traffic*. The
  consensus algorithm runs server-side and is not public:
  `[lookup: CrowdSec community blocklist consensus criteria docs]`.

### 11. `OISF/suricata-update` @ `c2687bbfc1d3`

- **Signal.** The official Suricata rule manager. ET Open is its zero-config source.
- **Questions.** Q5.
- **Pattern shape.** A **community ruleset is enabled by default, but its rules arrive
  as `alert`**. Turning a rule into `drop` is a *local operator decision*, expressed
  in `drop.conf` by SID or regex. The shipped `drop.conf` is entirely commented out.
- **Key file:line.**
  - `OISF/suricata-update:suricata/update/main.py:1025-1031`: "if there are no URLs, default to ET/Open"; "No sources configured, will use Emerging Threats Open".
  - `OISF/suricata-update:suricata/update/sources.py:38`: `DEFAULT_ETOPEN_URL`.
  - `OISF/suricata-update:suricata/update/configs/drop.conf:1-11`: "Rules matching specifiers in this file will be converted to drop rules". Every example is a comment.
  - `OISF/suricata-update:suricata/update/matchers.py:302-317`: `DropRuleFilter.run` rewrites `^\w+` to `drop` on matching rules only, and skips `noalert` rules (308-311).
  - `OISF/suricata-update:suricata/update/main.py:1221-1227`: `drop-conf` is loaded only if configured.
- **Trade-offs accepted.** IPS users must curate their own drop list, so protection lags detection.
- **Outlier signal.** Promotion is *by local list, per rule*, not by status or ring. It is the cleanest "operator owns the block" design surveyed.

### 12. `Cisco-Talos/clamav` @ `dd3aa1907cf6`

- **Signal.** 7.4k★. The reference open-source AV signature feed (freshclam/CVD).
- **Questions.** Q5.
- **Pattern shape.** Signatures **detect by default**, but **blocking at access time
  is off by default**, and the noisiest category (PUA) is off by default. A local
  ignore list (`.ign`/`.ign2`) is loaded **before every other database**, so an
  operator can kill a false-positive signature by name before a vendor fix ships.
- **Key file:line.**
  - `Cisco-Talos/clamav:etc/clamd.conf.sample:320-322`: "Detect Possibly Unwanted Applications. Default: no".
  - `Cisco-Talos/clamav:etc/clamd.conf.sample:796-800`: `OnAccessPrevention`, "If off, fanotify will only notify… and not perform any blocking. Default: no".
  - `Cisco-Talos/clamav:libclamav/readdb.c:5095-5105`: "load .ign and .ign2 files first… the daily ign & ign2 signatures prevent ign'ored signatures in all databases from being loaded".
  - `Cisco-Talos/clamav:libclamav/readdb.c:2722,4832-4833`: `cli_loadign`. Lines 4769-4770: `.fp` whole-file false-positive hashes.
- **Trade-offs accepted.** On-demand scanning flags immediately. Only *prevention* is opt-in.
- **Outlier signal.** The kill switch is loaded first and is name-addressed. It is
  also the vendor's own FP channel: the daily database ships `.ign2` entries.

### 13. `SigmaHQ/sigma` @ `05d1031f537e` + `SigmaHQ/sigma-specification` @ `ba9251aa834b`

- **Signal.** 11.3k★. The lingua franca for detection rules. Interlock's status vocabulary comes from here.
- **Questions.** Q4, Q5.
- **Pattern shape.**
  - **Licence.** The specification is public domain; the rules are under the
    **Detection Rule License (DRL) 1.1**, which is MIT-like plus mandatory author
    attribution, including in *match output*. Each rule may carry its own SPDX
    `license` field.
  - **Status.** Advisory only: no tooling in the repo enforces it.
  - **Contributions.** No licence attestation in the PR template; inbound terms come
    from GitHub's terms of service.
- **Key file:line.**
  - `SigmaHQ/sigma:LICENSE:5-6`: "The Sigma specification… are public domain"; "The rules… are released under the Detection Rule License (DRL) 1.1".
  - `Neo23x0/signature-base:LICENSE:1,24-30` (the same DRL text): "If you use the Rules… on data, messages based on matches with the Rules must retain… identification of the author(s)".
  - `SigmaHQ/sigma-specification:specification/sigma-rules-specification.md:227-232`: `stable` "may be used in production systems"; `test` "could require some slight adjustments"; `experimental` "could lead to false positives".
  - `SigmaHQ/sigma-specification:specification/sigma-rules-specification.md:242-248`: `license` is an optional SPDX ID per rule.
  - `SigmaHQ/sigma:.github/PULL_REQUEST_TEMPLATE.md` (47 lines): no licence or rights attestation.
- **Trade-offs accepted.** The attribution-in-output clause is unusual. It burdens
  every consumer that renders a match, and it is not an OSI or CC licence, so
  aggregators must special-case it.
- **Outlier signal.** Attribution that travels with each *match* is something no CC licence requires.

### 14. `google/osv.dev` @ `a41aaa122c65` (+ `github/advisory-database` @ `06e8c3919b75`)

- **Signal.** OSV.dev aggregates 28+ vulnerability feeds and has 3k★. GHSA has 2.5k★ and is a major upstream.
- **Questions.** Q4.
- **Pattern shape.** **The aggregator stays licence-neutral and each source keeps its
  own licence.** The intake rule is that a source's licence must *at minimum* permit
  ingest, modification (enrichment) and public redistribution, with CC0, CC-BY-4.0,
  Apache-2.0 or MIT recommended. GHSA itself is **CC-BY-4.0**, and contributions are
  inbound=outbound under GitHub's terms of service.
- **Key file:line.**
  - `google/osv.dev:docs/new_source.md:37-45`: "the license for any contributed data source **must** at minimum permit OSV.dev to ingest, index, modify (enrich), and publicly redistribute… we strongly recommend… CC0 1.0, CC-BY 4.0, Apache 2.0, or MIT".
  - `google/osv.dev:docs/data.md:32-70`: per-source licence ledger. A tally of that file at this SHA gives CC-BY-4.0 ×9, MIT ×5, Apache-2.0 ×5, CC0 ×4, CC-BY-SA-4.0 ×2, BSD ×1, CC-BY-NC-ND-4.0 ×1. There is **no ODbL, CDLA-Permissive or CDLA-Sharing**.
  - `github/advisory-database:LICENSE.md:1`: "Attribution 4.0 International".
  - `github/advisory-database:CONTRIBUTING.md:10`: "Contributions to this project are released to the public under the project's open source license", via GitHub ToS §D.6.
- **Trade-offs accepted.** Downstream users must honour a patchwork of attribution requirements, and one NC-ND source sits inside an "open" aggregate.
- **Outlier signal.** OSV writes its licence floor down as an intake requirement, which no other corpus surveyed does.

### 15. `YARAHQ/yara-forge` @ `52c7e88e0a79`

- **Signal.** 346★. It aggregates about 40 public YARA repos into curated packs used by Velociraptor, THOR and others.
- **Questions.** Q4, Q5.
- **Pattern shape.**
  - **Licences.** Each repo's LICENSE file is recorded, and `license_url` is stamped
    into **every rule's metadata**. Sources whose licence forbids redistribution
    (Elastic ELv2) are excluded.
  - **Tiers.** Packs are tiered by a quality score, with **`core` requiring a minimum
    rule age of 1 day**, which acts as a monitor window.
- **Key file:line.**
  - `YARAHQ/yara-forge:yara-forge-config.yml:9-19`: "Elastic repository currently disabled due to licensing concerns. The Elastic License v2 restricts redistribution via hosted services or products".
  - `YARAHQ/yara-forge:main/rule_collector.py:108-125`: walks the source for `LICENSE`, `LICENSE.txt` or `LICENSE.md` and records `license_url` pinned to `commit_hash`. Line 110 defaults to `"NO LICENSE SET"`.
  - `YARAHQ/yara-forge:yara-forge-config.yml:287-299`: `license_url` is a mandatory metadata field on every output rule.
  - `YARAHQ/yara-forge:yara-forge-config.yml:274-279`: issue levels subtract −2, −25, −70 or −1000 from quality.
  - `YARAHQ/yara-forge:yara-forge-config.yml:305-328`: the `core` pack needs `minimum_quality: 70`, `minimum_score: 65` and `minimum_age: 1` (days, per line 343). `full` needs 20/40/0.
- **Trade-offs accepted.** Licence detection is a filename heuristic. A repo with its licence in its README falls through to "NO LICENSE SET".
- **Outlier signal.** A machine-enforced *quality floor plus minimum age* per tier is the closest public analogue to interlock's ring × status × monitor window.

---

## Licence ledger: threat-intel and detection corpora (Q4)

| Corpus | Licence in-tree | Evidence |
|---|---|---|
| Sigma rules | DRL 1.1 (spec: public domain) | `SigmaHQ/sigma:LICENSE:5-6` |
| signature-base (YARA, Neo23x0) | DRL 1.1 | `Neo23x0/signature-base:LICENSE:1` |
| MISP galaxy | dual CC0-1.0 **or** BSD-2-Clause | `MISP/misp-galaxy:LICENSE.md:1-3` |
| MISP warninglists | CC0-1.0, with per-list exceptions via PR | `MISP/misp-warninglists:README.md:229-231` |
| GitHub Advisory DB | CC-BY-4.0 | `github/advisory-database:LICENSE.md:1` |
| OSV.dev sources | modal CC-BY-4.0; floor = ingest+modify+redistribute | `google/osv.dev:docs/data.md:32-70`, `docs/new_source.md:45` |
| CVE List V5 | CVE Program *Terms of Use* (no standard licence file) | `CVEProject/cvelistV5:README.md:31` |
| MITRE ATT&CK (cti) | bespoke MITRE grant with copyright-notice condition | `mitre/cti:LICENSE.txt:5-7` |
| MITRE ATLAS data | Apache-2.0 | `mitre-atlas/atlas-data:LICENSE:1-3` |
| Elastic detection-rules | Elastic License 2.0 (not open; no hosted service) | `elastic/detection-rules:LICENSE.txt:1,16-18` |
| Yara-Rules/rules | GPL-2.0 (GitHub API SPDX); last push 2024-04-17 | `[github:Yara-Rules/rules]` |
| Snort community rules | not in a GitHub repo I could read | `[lookup: snort.org community rules licence GPLv2]` |
| abuse.ch (URLhaus, ThreatFox, MalwareBazaar) | not in git | `[lookup: abuse.ch terms of use CC0]` |

**Contributor terms.** Among the corpora I could read, **none uses a CLA or a DCO
sign-off**. Contributions arrive inbound=outbound under GitHub's terms of service,
stated explicitly by GHSA (`CONTRIBUTING.md:10`) and left implicit by Sigma (silent
PR template). **None of them accepts raw samples or redacted payloads**; they publish
rules, identifiers and advisories. So there is no precedent in code for the
rights-warranty that interlock's opt-in redacted samples (Layer 3) need. This is a
real gap, not something I overlooked.

---

## Convergent patterns (≥3 implementations)

1. **Content is never collected by default, even where counters are.** Sentry SDK
   (`send_default_pii=None`), CrowdSec (`share_context=false`,
   `share_manual_decisions=false`), VS Code (`cleanData` scrubbing), Homebrew
   (low-cardinality tags, UUID deleted) and Go (only allowlisted counter names
   upload). Five of five telemetry systems draw a hard line between *counts* and
   *content*. This maps directly onto interlock's Layer 0 versus Layers 2-3.
2. **The opt-out switch is one environment variable, checked at the send site.**
   `HOMEBREW_NO_ANALYTICS` (`analytics.rb:33-34`),
   `REPORT_SELF_HOSTED_ISSUES=0`, `DISABLE_ONLINE_API` (`docker_start.sh:409-414`),
   `datareporting.healthreport.uploadEnabled` gating DAP
   (`DAPTelemetrySender.sys.mjs:136`), and Go's `mode != "on"`
   (`reports.go:125-129`).
3. **Community rules arrive below enforcement strength; the operator promotes them.**
   - Suricata-update: `alert`, with `drop` only via local `drop.conf`.
   - ClamAV: detection on, `OnAccessPrevention` off, PUA off.
   - Sigma: `status` is advisory and nothing auto-enforces.
   - YARA-Forge: tiers plus a minimum age.

   The exception is CrowdSec, which enforces *IP reputation*. Four implementations
   do not auto-block on community *content* rules.
4. **A local override beats the feed, and loads first.** ClamAV `.ign2`
   (`readdb.c:5095-5105`), CrowdSec allowlists applied before and retroactively
   (`apic.go:645-694`), and suricata-update's `disable.conf` and `drop.conf` (local
   files layered over the remote set).
5. **Root custody is a small, named, hardware-backed set, with routine rotation.**
   - Sigstore: 5 people, 3-of-5, YubiKeys with attestation, 197-day expiry.
   - Debian: three keys per release, successors pre-shipped.
   - Let's Encrypt: HSM-only, one-config ceremony.

   All three separate *offline root material* from *online signing keys*: Sigstore
   uses KMS for timestamp and snapshot, Debian `automatic` keys. Interlock's role
   split in `metadata.py` already has the same shape.
6. **Data corpora pick permissive or attribution licences.** CC-BY-4.0, CC0 and
   DRL/MIT-like licences dominate. Share-alike is rare (2 of 28 OSV sources), and
   **ODbL and CDLA appear in none of the surveyed security corpora**. Restrictive
   licences cost reach: YARA-Forge excludes ELv2 content outright.

## Divergent patterns (one implementation, not copied)

- **Go's `local` mode with a non-retroactive as-of date** (`dir.go:124-131`,
  `reports.go:134-138`). No one else gives the operator a "collect, show, don't send"
  state. This looks like an outlier with good reason, not a dead end: it is the only
  design that reconciles "useful by default" with "nothing leaves until consent".
- **Sentry self-hosted's forced choice with no default** (`error-handling.sh:139-191`).
  It is unambiguous, but it blocks unattended installs, which is likely why
  installer-driven projects (CrowdSec, Homebrew) avoid it.
- **CrowdSec's silent default-on via debconf `medium` priority**
  (`postinst:36`, `templates:19`). It achieves opt-out while technically
  "asking". Popcon uses the same mechanism the opposite way (`config:29`,
  priority `high`, default false). No other surveyed project hides the question this
  way.
- **Firefox/ISRG's vendor-as-helper aggregator pair** (`all.js:534-541`). It is the
  only production two-server deployment surveyed, and it does *not* meet "two
  organisations that will not collude, neither the vendor". It is the credible first
  step, not the end state.
- **Debian's threshold-free custody with pre-shipped successor keys.** Useful exactly
  where a project cannot field a threshold yet. Nobody else does it because everybody
  else has TUF.
- **DRL's attribution-in-match-output clause** (`signature-base:LICENSE:24-30`).
  Only DRL corpora carry it, and aggregators (OSV-style) would need to special-case it.
- **VS Code's "OSS build dark, vendor build on" split** (`telemetryUtils.ts:96-101`).
  It keeps the code's default and the distribution's default separate.

## Stack-rank by maintainability

From push recency, open issue/PR count relative to size, and code smell in the files read.

**Top 3, cleanest:**
1. **`golang/telemetry`**: 3 open issues/PRs, pushed 2026-10-21. Mode logic is a few
   dozen readable lines (`dir.go:79-146`), and the upload gate is explicit and logged
   per condition (`reports.go:125-149`).
2. **`Homebrew/brew`**: 8 open on 50k★, pushed 2026-10-25. Sorbet-typed analytics
   module, every send through one gate (`analytics.rb:33-34`), and dead Google
   Analytics paths deleted rather than left behind.
3. **`sigstore/root-signing`**: 26 open, pushed daily. Custody state is
   machine-readable in `root.json` (owner, expiry and signing-period per role), and
   tuf-on-ci automation replaces hand-run scripts.

**Bottom 3, most rot or churn in the paths that matter here:**
1. **`pypi/warehouse` (TUF path)**: 555 open issues/PRs. At this SHA the TUF
   integration is a 64-line RSTUF bootstrap client (`warehouse/tuf/__init__.py:24-25`,
   `warehouse/cli/tuf.py:19-23`) plus a **dev-only, threshold-1** payload
   (`dev/rstuf/bootstrap.json:68,74`). I found no production root metadata in-tree.
   Even with a foundation behind it, the custody step is the one that stalls.
2. **`Cisco-Talos/clamav`**: 413 open. The database loader is a 6,217-line C file
   (`libclamav/readdb.c`) with load order encoded as priority `#define`s
   (`readdb.c:5087-5093`).
3. **`microsoft/vscode` (telemetry settings)**: 22,228 open issues/PRs. The
   telemetry setting still honours two deprecated predecessors as kill switches
   (`telemetryService.ts:383,399-401`): three generations of consent surface.

Honourable rot mention: Debian keyring removal is manual, annotated
"[There should be a better way of doing this]" (`README.maintainer:23`).
`OISF/suricata-update` is small and clean, but its last push was 2026-07-07.

---

## What the code says about each decision (this lens's position)

These are inputs for the synthesizer. Each verdict comes from the code above, not
from advocacy.

1. **Root-key custody.** In code, custody is held by **named individuals with terms,
   3-of-5, on attested hardware keys**, with online roles split off (Sigstore). It is
   not held by "three organisations". A **credible first step for one maintainer**
   is 2-of-3 individual keyholders: the maintainer plus two people from different
   employers. They would use hardware keys, run a ceremony-as-PR, and record
   keyholder terms in `root.json` `x-` fields. Combine that with Debian's
   *pre-shipped successor key* to cover loss. Concrete deltas:
   - Shorten root expiry from 365 days (`interlock/mesh/metadata.py:62`) towards
     Sigstore's 197 days.
   - Add a signing period.
   - Make `init_keys` refuse to overwrite (Boulder `main.go:171-182`).

   Foundation custody is the end state; no surveyed project *started* there.
2. **Aggregator operators.** The only production pair is **independent nonprofit
   (ISRG/Divvi Up) + vendor**. Interlock already refuses a single aggregator
   (`aggregate.py:34-35`), and Firefox has no single-aggregator mode either, so
   "counts are not sent" with one aggregator matches practice. Two code gaps should
   close **before** any operator is recruited:
   - a **minimum batch floor** before `combine_totals` releases totals (Janus
     `task.rs:187-188`, `aggregate_share.rs:160-162`);
   - **bounded-value proofs** on shares (Prio3/VDAF), which interlock lacks.
3. **Default reporting posture.** The code splits by business model.
   - **Default on:** Homebrew, VS Code (vendor build), Firefox, CrowdSec, Sentry beacon.
   - **Default off:** popcon, Go, Sentry self-hosted reporting, VS Code OSS build.

   No surveyed project sends **content** by default. This lens recommends **Go's
   shape**: Layer 0 counts accumulate *locally* by default, operators can inspect
   exactly what would be sent, and an explicit enable uploads only data newer than
   the enable date (an as-of gate in `interlock/mesh/report.py`). Layers 1-3 stay
   separately opt-in. Fully opt-out (Homebrew or CrowdSec style) is defensible only
   with the Homebrew safeguards: notice first, nothing sent on the notice run, no
   persistent ID.
4. **Data licence.** **CC-BY-4.0** is the modal licence for security data corpora
   (OSV ledger, GHSA). **CC0** covers indicator-like lists (MISP warninglists,
   galaxy). Neither ODbL nor CDLA appears anywhere surveyed. Recommendation:
   - **CC-BY-4.0** for packs and rules;
   - **CC0-1.0** for indicators and fingerprints, which are factual and machine-generated;
   - a per-rule SPDX `license` field, as in the Sigma spec (`:242-248`);
   - a per-rule provenance URL, as in YARA-Forge (`rule_collector.py:108-125`);
   - an OSV-style written intake floor for upstream packs.

   Contributor terms: corpora rely on GitHub ToS inbound=outbound with no CLA. **No
   precedent exists for samples**, so Layer 3 needs an explicit rights warranty
   written for interlock, and no surveyed corpus can be copied for it.
5. **`block` by default.** Four of five rule-feed implementations never auto-enforce
   community *content* rules. Promotion is a local, per-rule act: suricata-update's
   `drop.conf`, ClamAV's `OnAccessPrevention`. CrowdSec is the exception, and it
   enforces time-boxed *IP reputation* with allowlists applied first.
   - **Today:** interlock lets `stable` rules carry `block` after a 7-day shadow
     window that resets on digest change (`interlock/mesh/bundle.py:55-61,200-209`).
     That is already stricter than YARA-Forge's 1-day `core` floor. It is looser
     than Suricata, which never drops by default.
   - **Lens recommendation:** keep the shadow window. Add a ClamAV-style local
     kill-switch list, loaded before packs. Add a Suricata-style explicit
     `block`-promotion list in the subscriber config (`interlock/mesh/subscriber.py`
     `Config`). Only then decide whether `stable` should default to its pack verdict
     or to `escalate`.

   The CrowdStrike channel-file incident is not code-readable and is left to the
   web lens.

## Gaps this lens could not close

- CrowdSec's server-side consensus thresholds (closed): `[lookup: CrowdSec community blocklist curation criteria]`.
- ENPA's ingestion and aggregation code and its operator agreements (ISRG/MITRE?): `[lookup: google/exposure-notifications-private-analytics-ingestion operators]`.
- Snort community and abuse.ch licences: not in readable git (see ledger).
- Whether DRL-1.1 is on the SPDX list (it affects Sigma's per-rule `license` field): `[lookup: SPDX license list DRL-1.1]`.

## Reference index (repo:path:line)

- `sigstore/root-signing:metadata/root.json:107`
- `sigstore/root-signing:metadata/root.json:138-139`
- `sigstore/root-signing:playbooks/ORCHESTRATION.md:21`
- `theupdateframework/python-tuf:tuf/ngclient/_internal/trusted_metadata_set.py:199-209`
- `letsencrypt/boulder:cmd/ceremony/main.go:171-182`
- `debian-archive-keyring/2025.1:active-keys/index:1-9`
- `pypi/warehouse:dev/rstuf/bootstrap.json:68`
- `mozilla-firefox/firefox:modules/libpref/init/all.js:534-541`
- `mozilla-firefox/firefox:toolkit/components/dap/DAPTelemetrySender.sys.mjs:136-138`
- `divviup/janus:aggregator_core/src/task.rs:187-188`
- `divviup/janus:aggregator/src/aggregator/aggregate_share.rs:160-162`
- `Homebrew/brew:Library/Homebrew/cmd/update-report.rb:455-471`
- `Homebrew/brew:Library/Homebrew/utils/analytics.sh:23-28`
- `golang/telemetry:internal/telemetry/dir.go:124-131`
- `golang/telemetry:internal/upload/reports.go:134-138`
- `popularity-contest/1.79:debian/templates:1-4`
- `microsoft/vscode:src/vs/platform/telemetry/common/telemetryService.ts:337-347`
- `microsoft/vscode:src/vs/platform/telemetry/common/telemetryUtils.ts:96-101`
- `getsentry/sentry-python:sentry_sdk/consts.py:1394`
- `getsentry/self-hosted:install/error-handling.sh:139-191`
- `getsentry/sentry:src/sentry/conf/server.py:1527`
- `crowdsecurity/crowdsec:build/debian/templates:17-23`
- `crowdsecurity/crowdsec:pkg/csconfig/api.go:401-412`
- `crowdsecurity/crowdsec:pkg/apiserver/apic.go:363-394`
- `crowdsecurity/crowdsec:pkg/apiserver/apic.go:645-694`
- `OISF/suricata-update:suricata/update/matchers.py:302-317`
- `OISF/suricata-update:suricata/update/main.py:1025-1031`
- `Cisco-Talos/clamav:etc/clamd.conf.sample:796-800`
- `Cisco-Talos/clamav:libclamav/readdb.c:5095-5105`
- `SigmaHQ/sigma:LICENSE:5-6`
- `SigmaHQ/sigma-specification:specification/sigma-rules-specification.md:227-232`
- `Neo23x0/signature-base:LICENSE:24-30`
- `google/osv.dev:docs/new_source.md:37-45`
- `github/advisory-database:CONTRIBUTING.md:10`
- `YARAHQ/yara-forge:yara-forge-config.yml:9-19`
- `YARAHQ/yara-forge:yara-forge-config.yml:305-328`
- `MISP/misp-galaxy:LICENSE.md:1-3`
- `elastic/detection-rules:LICENSE.txt:16-18`
- interlock (target checkout): `interlock/mesh/aggregate.py:34-35`, `interlock/mesh/aggregate.py:120-127`, `interlock/mesh/bundle.py:55-61`, `interlock/mesh/bundle.py:200-209`, `interlock/mesh/metadata.py:61-62`, `interlock/mesh/repository.py:22-28`, `interlock/mesh/repository.py:219-222`
- `[github:Yara-Rules/rules]` · `[github:CVEProject/cvelistV5]` · `[github:mitre/cti]` · `[github:mitre-atlas/atlas-data]` · `[github:MISP/misp-warninglists]`
