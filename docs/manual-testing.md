# Phylax manual acceptance checklist

Run from the repository root. Allow about **2–3 hours** for the functional checks,
plus feed/provider waiting time and optional recovery checks. Record actual
results; a command completing is not proof that the displayed evidence is correct.

Use a **new isolated database** throughout. Fixtures and the Docker site are
synthetic; they describe no real TNI infrastructure or incident. Do not substitute
real network targets. Only the individually approved Docker IT endpoint is scanned.

## 1. Prepare and start

```bash
python3 --version
docker version
docker compose version
nmap --version
python3 scripts/prepare_release_demo.py --output-dir data/manual-test
python3 -m phylax --db data/manual-test/phylax-demo.db serve
```

Keep that terminal running. Open http://127.0.0.1:8765. Stop any other Phylax
dashboard first so you do not accidentally view the wrong database. The preparation
command refuses existing directories; choose a new name for a clean repeat.

**Expected initial state:**

- Synthetic dataset banner; six inventory assets.
- Four findings for fictional `CVE-2099-99999`: one each confirmed, potential,
  excluded and needs review. Their identity/version evidence explains the difference.
- No network events or unmanaged endpoint alerts yet.
- The IT discovery target exists with permission disabled.
- The simulated cooling process is linked to the controller.

Keep a results sheet: `ID | Pass/Fail/Blocked | Actual result | Screenshot/log | Notes`.
Save screenshots with the dataset banner visible, and record counts before/after
imports. Use the sections below as test IDs.

### Simplified navigation and review checks

- Confirm seven primary pages: Overview, Assets, Monitoring, Intelligence, Triage,
  Reports and Settings. At mobile widths, expand Navigation to reach them.
- Under Assets, visit Inventory, Approvals, IT discovery, Software, Changes and
  Operational context. The current tool and Assets must remain highlighted.
- Under Monitoring, visit Events and Attack surface. Under Settings, visit sources,
  network policy and the glossary. Existing bookmarked URLs must still work.
- Overview must summarize alerts and link to Triage. Acknowledge there; retain the
  current filters and verify finding, risk, approval and scan permission stay unchanged.
- Import inventory or intelligence: applicability updates automatically. Manual
  reassessment is an optional recovery action in Settings → Advanced assessment tools.
- On a saved plan use Regenerate plan to reveal the explicit replacement action.
  Confirm its warning and check archived history after a successful regeneration.

### Topology diagram checks

- Open **Monitoring → Attack surface** after importing logs. Only observed
  endpoints should appear in the main graph; expand **Inventory without observed
  traffic** to review other assets. Counts must match stored data and active filters.
- Select a known node and an unknown peer. Confirm identity confidence, management,
  observed UTC times and applicability remain evidence-based. Follow a communication
  link to its original event, and a finding link to its assessment.
- Find an inventory-only asset, a known observed asset, and an unknown peer, then select **Apply view**. Find covers all known eligible assets and peers, even beyond the relationship cap. Confirm matching details and the explicit result count. A zero-result search must leave no unrelated selection. A missing result does not establish device absence.
- Choose **Hidden** for Process support and apply. Dashed process links and process
  nodes disappear from the diagram; the confirmed-support evidence table remains.
- Use Zoom in, Zoom out and Reset zoom; active filters and selection must remain.
  On mobile, focus the diagram and use arrow keys or horizontal scrolling to explore.
  Controls must remain readable and the page itself must not overflow horizontally. Selected details must appear before the graph on narrow screens. Empty filtered views must show recovery links without a forced-width canvas or graph legend.
- Use a future observation window. The empty graph should suggest importing logs
  or widening filters while keeping inventory available. Long labels must fit in
  nodes with full names accessible in their labels and detail panel.

### UI hardening regression checks

- Enter an invalid inventory IP alongside other draft values. Submission should
  keep the editor and values, focus “Changes were not saved,” and identify the IP
  field. Correct the IP and retry. Existing stored inventory must not change on
  the rejected submission.
- Submit malformed policy JSON. The policy editor must retain the draft and show
  its error; the active policy must stay unchanged.
- On Overview, use **Review plan** for a saved plan. It must open that specific
  plan under **Triage → Remediation plans**, including plans beyond the first page.
  Overview shows status only; the dedicated review form has visible labels and
  only valid next statuses. A Recommended plan first enters
  Under Review; approval requires a reviewer, and verification requires evidence.
  Invalid transitions must retain draft notes without changing the finding,
  urgency or acknowledgement.
- Expand and collapse a metric definition using Enter. At 320 px width it must
  remain in the page flow without covering other content or adding page overflow.
  Check form text and keyboard focus at mobile, tablet and desktop sizes.
- Check negative KEV wording before synchronization and with stale cached data.
  It must distinguish unknown/catalog membership and never say “no known
  exploitation.” Synthetic findings must label their KEV association as synthetic.
- On Discovery, search eligible assets and use the result pages when available.
  Control endpoints must stay excluded. Searching, selecting and paging must not
  grant permission, queue a run or send discovery traffic.

## 2. Inventory and data validation

Import `demo/manual-fixtures/inventory.csv` through the inventory upload or CLI:

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db import-assets demo/manual-fixtures/inventory.csv
```

| Action | Expected |
|---|---|
| Inspect import result | Two valid rows accepted; malformed IP reported with its row |
| Inspect `.61` | Unknown product/firmware stays unknown; no invented exact identity |
| Import the same CSV again | No duplicate assets; asset IDs remain stable |
| Add/edit an asset in the UI | Changes persist after refresh; malformed values rejected |
| Export inventory CSV and reopen it | Identity fields, IDs, notes and unknown fields retained |
| Open every navigation page | No traceback, broken links, raw HTML injection or unexplained counts |

The inventory now has eight assets. Later observations may add more; do not keep
using the initial six-asset expectation after importing new endpoints.

## 3. Passive replay and all three policy rules

Use the locally installed pinned Zeek image. If absent, install it first:

```bash
docker pull zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-pcap data/manual-test/replay-captures/synthetic-benign-read.pcap --docker-image zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0 --policy data/manual-test/policy.json
```

Expected: three network events (connection plus request/response), no network
policy alerts, and the approved reader/controller relationship in topology.

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-pcap data/manual-test/replay-captures/synthetic-unauthorized-write.pcap --docker-image zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0 --policy data/manual-test/policy.json
```

Expected cumulative result: **six events, three network alerts, one unmanaged
endpoint alert for `.99`**. Inspect each alert, not just the totals:

- Unauthorized Modbus writer: `.99` is not an authorized writer to `.10`.
- Unexpected communication: the connection violates the protected asset allowlist.
- Write outside maintenance: the explicit empty maintenance list permits no writes.
- Response PDUs remain stored without creating duplicate write alerts.
- Each alert has timestamp, original event/capture reference, policy evidence,
  explanation and distinct severity/urgency fields.

Repeat the write-PCAP command. Counts must remain unchanged. Acknowledge one
alert, repeat again, and confirm acknowledgement persists.

In Network Policy, temporarily add `.99` as an authorized writer **and** allowed
communication, and permit a maintenance window covering the capture's recorded
UTC day/time. Apply it. Matching violations should resolve with history retained.
Restore `data/manual-test/policy.json` with `apply-policy` to reactivate them.
Changing policy is a local assessment; it does not change a firewall or controller.

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db apply-policy data/manual-test/policy.json
```

## 4. Management approval, blocking and revocation

Use Device Approvals with the existing `172.30.77.0/24` monitored subnet.

| Action | Expected |
|---|---|
| Acknowledge `.99` | Still unmanaged; acknowledgement does not approve it |
| Approve `.99` by IP with operator/reason | Management alert resolves; Modbus policy alerts remain |
| Inspect discovery permission | Approval has not enabled scanning or created a new target |
| Open “Revoke this decision” on its history row and record operator/reason | Stored observations are reevaluated; unmanaged alert returns |
| Explicitly block `.99` | Status becomes unauthorized because of the block decision |
| Revoke the block | Returns to unmanaged unless another active decision applies |
| Add overlapping subnet `172.30.77.0/25` | Rejected |

An empty collector or an unseen device must never be displayed as proof of absence.

## 5. DHCP identity and changes

In Device Approvals, approve IP `.88` **bound to MAC `02:00:00:00:00:88`** first.
Import these one at a time:

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-zeek demo/manual-fixtures/dhcp-request-only.jsonl --kind dhcp
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-zeek demo/manual-fixtures/dhcp-assigned.jsonl --kind dhcp
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-zeek demo/manual-fixtures/dhcp-changed.jsonl --kind dhcp
```

Check between commands:

1. Requested-only address does not establish an assigned endpoint or MAC binding.
2. Assigned `.88` with the matching MAC satisfies the approval.
3. Different MAC `.89` produces identity review and a change record, not silent merging.
4. Reimport the older assigned file: current identity must not revert to the older MAC.
5. Observation and ingestion timestamps are separate. These are fixed historical
   fixtures, not newly captured incidents.

## 6. Software inventory, correlation and review

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db load-fixture demo/manual-fixtures/software-advisory.json
python3 -m phylax --db data/manual-test/phylax-demo.db analyze-zeek demo/manual-fixtures/software-affected.jsonl --kind software
```

On Software Evidence, inspect `lab-it` / `.40`, Apache `2.4.41`.

1. It starts unverified; fictional `CVE-2099-99998` should be **potential**.
2. Verify this synthetic component with operator/note: **confirmed**.
3. Record the finding ID. Import the changed version:

   ```bash
   python3 -m phylax --db data/manual-test/phylax-demo.db analyze-zeek demo/manual-fixtures/software-changed.jsonl --kind software
   ```

4. Previous verification is invalidated; competing active versions require review.
   Change history identifies both versions. Finding ID stays stable.
5. Retire `2.4.41`; verify `2.4.42`: **no match to this advisory**. This exact
   synthetic advisory lists only `2.4.41`; it does not prove the device is safe.
6. Import `software-unmapped.jsonl`. `LAB-HTTP` has no automatic fuzzy mapping.
   Add exact mapping `LAB-HTTP` → vendor `apache`, product `http_server`.
   Inspect its new component evidence; verify only as an explicitly synthetic test.
7. Import `software.tsv` with `--kind software`: a separate `LAB-TSV` component
   should appear. Multiple components must coexist without replacing firmware.
8. Import `software-malformed.jsonl`: expect a clear failure and **no partial
   observations from that file**. Compare counts before/after via reports.

## 7. Context, topology, triage and priority

- Save owner/location/lifecycle/tags/criticality rationale in Operational Context.
  Choose the asset and click “Load asset context” first; existing values must be
  prefilled. Change only the owner and confirm location, lifecycle and tags remain.
  Open two copies, save one, then save the stale other copy: it must reject the
  overwrite and retain your input for review. Add and remove a process relationship with a
  named decision. Saving a form replaces its fields; fill fields you want to retain.
- Open Attack Surface. Check time, subnet, zone, approval and criticality filters.
  Click assets/edges to inspect evidence. Fixed November 4 fixtures disappear if
  your time filter excludes that date.
- Solid links represent observed communication; dashed links represent confirmed
  process relationships. Active scan probes must not become operational traffic edges.
- Unknown endpoints stay visibly unknown. Graph limits/visibility gaps stay visible.
- In Triage, open score factors. The high-severity communication/write alerts to
  critical protected `.10` score `2 + 3 + 1 = 6`, therefore critical urgency.
- Edit destination criticality to low through inventory. The same network score
  becomes `2 + 0 + 1 = 3`, medium urgency. Acknowledgement must persist.
- Restore criticality. Adding a process link alone must not silently change it.
- Filter triage by category, urgency, acknowledgement or a hostname/CVE. Check
  that counts and pagination apply to the filtered results. Acknowledge a row:
  current filters should remain, and the original event link should open evidence.
- Inspect at 390px and desktop width. Navigation should collapse on narrow
  screens; the page itself must not scroll horizontally. Wide tables may scroll
  inside their panels. Owner, process support and policy facts precede raw JSON.
- Vulnerability urgency continues using rule 2, separately from network rule 1.

## 8. Live collector and finalized-file watcher

For clean exact counts, prepare a **second dataset**:

```bash
python3 scripts/prepare_release_demo.py --output-dir data/manual-live
mkdir -p demo/runtime/logs/current demo/runtime/logs/finalized
chmod g+rwx demo/runtime/logs/current demo/runtime/logs/finalized
export PHYLAX_LAB_GID="$(id -g)"
docker compose -f demo/compose.yaml up --build -d plc it sensor reader
docker compose -f demo/compose.yaml ps
```

Stop the previous dashboard, then use separate terminals:

```bash
python3 -m phylax --db data/manual-live/phylax-demo.db serve
python3 -m phylax --db data/manual-live/phylax-demo.db watch-zeek --directory demo/runtime/logs/finalized --interval-seconds 5
```

Old files already in `finalized` will also be imported. For a clean run, use a new
lab log directory or archive old finalized logs **while the lab is stopped**.

- Wait for rotation (configured every ten seconds). Reader traffic should appear;
  record file finalization and ingestion times. Target: within 30 seconds of finalization.
- Run `docker compose -f demo/compose.yaml run --rm rogue` once. This driver writes
  only to its fixed simulator. Inspect all three alerts plus unmanaged `.99`.
- Stop/restart watcher: unchanged successful files must not duplicate observations.
- Stop watcher: collector status should show stopped, or stale after the heartbeat
  expires if abruptly killed; inventory must not claim devices were removed.

For watcher error checks, use a **separate finalized folder** and the manual-test
database. Copy one fixture as `software.test.jsonl`, wait two polls, then repeat:
unchanged success is skipped. Replace it with malformed JSON: Settings shows failure.
Replace it with valid changed content: it retries. A symlink should be ignored.
Do not copy all ordered software fixtures into one watched folder simultaneously.

## 9. Active IT discovery, schedules and cancellation

Keep the isolated Docker lab running. Verify the IT container address is `.40`
before granting permission. Use **manual-live** consistently in this section.

1. Queue its initially disabled target: expect rejection.
2. Attempt permission for `lab-plc`, `lab-reader`, or an unknown inventory entry:
   expect rejection. No scan should run.
3. Grant only `lab-it`, port 8080:

   ```bash
   python3 -m phylax --db data/manual-live/phylax-demo.db scan-target save --asset-id lab-it --ports 8080 --identify --permit --actor "Manual tester" --note "Verified isolated Docker IT endpoint 172.30.77.40"
   python3 -m phylax --db data/manual-live/phylax-demo.db scan-target list
   ```

4. Copy its printed target ID into the following commands:

   ```bash
   python3 -m phylax --db data/manual-live/phylax-demo.db scan --target TARGET_ID
   python3 -m phylax --db data/manual-live/phylax-demo.db worker --once
   ```

5. Execution history should report an open 8080 port, actual Python HTTP server
   header, tool version, timestamp, permission revision and outcome. It must not
   fabricate Apache or a confirmed installed package version.
6. Queue twice before starting worker: one pending run, no duplicate execution.
7. Queue then cancel before execution: history shows cancellation; worker does not probe it.
8. Queue then disable target permission: queued work becomes invalid/cancelled.
9. Try port 0, 65536, more than 32 distinct ports, and a schedule interval of 14
   minutes: reject all. The UI accepts selected integer ports, not Nmap flags/CIDRs.
10. Reenable the approved target, opt into a **15-minute** schedule and run `worker`.
    Verify one due execution. Stop worker through a missed interval and restart:
    no catch-up burst. Disable the schedule afterward.
11. With queued work, start two workers against this same database: only one run
    should execute. Revoke permission while work is pending/running; no subsequent
    probes should continue after the next cancellation check.

Scans can finish too quickly to manually observe a running cancellation. Repeatable
timeout, lease-expiry, crash-recovery and mid-run revocation cases are covered by
the deterministic test suite; do not manufacture an unapproved slow network target.
An optional crash rehearsal uses only this database/lab, waits for the lease to
expire, and checks that an interrupted run is retained rather than silently replayed.

## 10. Public intelligence and resumable updates

Return to the manual-test database. Feed sync may take much longer than the UI checks.

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db sync-feeds
```

- Read progress and source health. NVD, KEV, RSS and any configured CSAF sources
  have independent outcomes; failures retain cached records.
- Interrupt NVD only **after a page has been persisted**, then rerun. It should
  resume the saved window/page rather than discard the whole cache.
- After success, rerun routine sync: it uses its incremental window. Explicit
  `--backfill-days 7` requests a broader modified-record window; a pending checkpoint wins.
- Search an actual stored CVE; inspect source timestamps, references, severity,
  KEV and applicability evidence. Vendor mention alone must not confirm exposure.
- Configure one official CSAF URL, then sync twice:

  ```bash
  python3 -m phylax --db data/manual-test/phylax-demo.db csaf-source https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-004-01.json
  python3 -m phylax --db data/manual-test/phylax-demo.db sync-csaf
  ```

  Inspect cached provenance and reviewable unsupported conditions. Repeat retrieval
  must not duplicate records. Unsupported expressions are not invented ranges.
- Disconnect internet and sync: clear failures, previous success/cache retained.
  Staleness appears after the actual 24-hour threshold; disconnecting alone does
  not immediately make recently retrieved intelligence stale.

## 11. Hosted AI and manual remediation lifecycle

Synthetic CVEs intentionally do **not** call hosted models. Test them first: the
UI should explain their ineligibility/local behavior, not claim hosted generation.

For a hosted check use a separate public-data exercise. Configure `.env` as in
the main README and restart. Provider/model availability depends on your account.

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db refresh-cve CVE-2026-0322
python3 scripts/prepare_ai_test_data.py --source-db data/manual-test/phylax-demo.db --output-db data/manual-ai.db
```

The helper expects a specific public product/range. If current official data no
longer satisfies it, treat that as a changed prerequisite; do not fake the advisory
or force a confirmed match. Stop the other dashboard and serve `data/manual-ai.db`.

| Action | Expected |
|---|---|
| Open a finding without clicking generate | No model request |
| Request eligible guidance | Job progress; generated text has model/time/references and unverified label |
| Inspect citations | Only supplied public source URLs accepted |
| Compare finding before/after | Applicability, severity, priority and acknowledgement unchanged |
| Review/approve plan | Named human decision required; no equipment action |
| Exercise implementation/verification states | Record clearly labeled test evidence; missing required evidence rejected |
| Regenerate | Previous plan archived; previous review cleared |
| Temporarily unset/invalid provider key, restart, regenerate | Explicit unavailable/disabled behavior; existing hosted guidance preserved on provider failure |
| Restore settings | Valid configuration works again; secret never appears in UI/export |

Save a copy of your `.env` privately before configuration changes; never commit it.
The UI alone cannot prove outbound privacy. The offline provider-contract tests
check the public-only payload, invalid citations, timeouts and malformed responses.
No asset, network, policy or process context should be supplied to hosted models.

## 12. Reports, restart, offline use and upgrade

On each dataset, export JSON, CSV and Markdown via Reports or CLI:

```bash
python3 -m phylax --db data/manual-test/phylax-demo.db export-report --format json --output data/manual-test/report.json
python3 -m phylax --db data/manual-test/phylax-demo.db export-report --format csv --output data/manual-test/report.csv
python3 -m phylax --db data/manual-test/phylax-demo.db export-report --format markdown --output data/manual-test/report.md
```

- Open all formats. Check generation time, synthetic label, IDs, source references,
  applicability, component evidence, management status, context and scoring factors.
- Reconcile report counts with UI; resolved/acknowledged records are not accidentally
  presented as new active incidents. Confirmed/potential/review remain distinct.
- Restart dashboard: data, decisions, acknowledgements, scan history, cached guidance
  and checkpoints persist. Browser forms from before restart need reloading.
- Disconnect internet: stored pages, reports and offline PCAP analysis still work.
- Rehearse upgrade only on a SQLite-backup copy of an older database; compare IDs,
  counts, `PRAGMA integrity_check` and `PRAGMA foreign_key_check`. Confirm the
  `.pre-asset-intelligence.sqlite` backup exists. Never copy a live SQLite file
  with ordinary `cp` while writers are running; use SQLite backup or stop all writers.
- Try malformed uploads and an expired browser form: clear validation/CSRF errors,
  no traceback or partial malformed-file import. Dashboard remains loopback-only.

## 13. Finish and record defects

Stop watcher, worker and dashboard with Ctrl-C, then:

```bash
docker compose -f demo/compose.yaml down
```

Retain datasets and exports for inspection. For every failure record the test ID,
database path, exact action, expected/actual result, timestamp, screenshot and
terminal traceback with keys/tokens redacted. Mark unavailable provider/tool cases
as blocked, not passed.

Optional repeatable companions (these execute checks rather than manual steps):

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify_release_http.py
python3 scripts/verify_release_replay.py --output-dir data/manual-replay-check --docker-image zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
```

The existing [lab walkthrough](../demo/README.md) explains Docker topology and capture
boundaries. Record current measurements and limitations using the [testing guide](testing.md#rehearsal-record).
