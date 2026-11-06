# Fictional TNI AD support-site lab

This is an explicitly synthetic training environment. It contains no real TNI
assets, incidents, network architecture, mission data, or endorsement. The
simulated cooling controller represents facility support, not a weapon system.

## Prerequisites

- Linux with Docker bridge networking, Python 3.12+, Docker Engine/Compose, and Nmap on the Phylax host.
- The host must be able to reach the lab containers on their Docker bridge network.
  Check host-to-container connectivity for your Docker installation before
  attempting the optional IT discovery exercise.
- Internet is needed for the first image build. The base Zeek image and
  PyModbus 3.11.4 wheel are pinned; the wheel's SHA-256 is checked before use.
  PyModbus is installed only inside the lab image. Phylax needs no pip packages.
- Do not use the lab if `172.30.77.0/24` overlaps another network you use.
  The offline replay below does not transmit packets and remains available.

## 1. Prepare a new local dataset

Run from the repository root:

```bash
python3 scripts/prepare_release_demo.py --output-dir data/support-lab
mkdir -p demo/runtime/logs/current demo/runtime/logs/finalized
chmod g+rwx demo/runtime/logs/current demo/runtime/logs/finalized
export PHYLAX_LAB_GID="$(id -g)"
docker compose -f demo/compose.yaml up --build -d plc it sensor reader
```

The preparation command refuses an existing output directory. It creates:

- A dedicated database with a synthetic banner in every HTML page/report.
- Four inventory-only applicability cases: confirmed, potential, excluded,
  and review-required. `CVE-2099-99999` is **fictional and synthetic**, never
  eligible for hosted AI. No public CVE or vendor mitigation is asserted.
- A supporting IT server at `172.30.77.40`, simulated PLC at `.10`, and approved
  engineering client at `.30`. Silent inventory cases do not represent running
  devices. Device management approvals do not grant scan permission.
- Operator-confirmed process context and a passive policy. The explicit empty
  maintenance list prohibits writes at every time for this test.
- Two labeled replay PCAPs using the same facility addresses.

The live collector shares only the simulator's network namespace and captures
its interface with `NET_RAW`. It rotates logs every 10 seconds. Its supplemental
group grants access only to the lab log directories. The internal Docker network
has no external connectivity. No PLC port is published to the host.

## 2. Run the dashboard and passive watcher

In separate terminals:

```bash
python3 -m phylax --db data/support-lab/phylax-demo.db serve
python3 -m phylax --db data/support-lab/phylax-demo.db watch-zeek --directory demo/runtime/logs/finalized --interval-seconds 5
```

Open http://127.0.0.1:8765. The reader issues benign requests to the fixed
simulator. Inspect Inventory, Network Events, Attack Surface, Operational Context,
and Sources/Settings. Missing traffic does not establish absence of a device.

The watcher imports only finalized uncompressed log files, after two stable
polls. Do not point it at Zeek's `current/` directory. Production polling defaults
to 30 seconds; the five-second interval is for this lab.

## 3. Grant and demonstrate IT discovery

Verify `docker compose -f demo/compose.yaml ps` and the IT service address before
granting permission. The prepared target starts disabled.

```bash
python3 -m phylax --db data/support-lab/phylax-demo.db scan-target save --asset-id lab-it --ports 8080 --identify --permit --actor "Lab operator" --note "Verified isolated Docker IT service at 172.30.77.40"
python3 -m phylax --db data/support-lab/phylax-demo.db scan-target list
```

Copy the printed target ID into `TARGET_ID` below, or select the target in
**Approved IT Discovery**:

```bash
python3 -m phylax --db data/support-lab/phylax-demo.db scan --target TARGET_ID
python3 -m phylax --db data/support-lab/phylax-demo.db worker --once
python3 -m phylax --db data/support-lab/phylax-demo.db scan-target schedule TARGET_ID --interval-minutes 60
python3 -m phylax --db data/support-lab/phylax-demo.db worker
```

Manual and scheduled requests use the same permission checks and global
per-database worker lease. The server's actual header identifies Python's simple
HTTP server; it must not be described as Apache or automatically confirmed
vulnerable. For software correlation, import a separately labeled software fixture
or real authorized observations. Review product mapping, version evidence and
installation scope before verifying a component.

## 4. Trigger one passive policy violation

```bash
docker compose -f demo/compose.yaml run --rm rogue
```

This separate test driver has no target argument and can only address the fixed
Compose simulator after validating its address. It writes a harmless simulated
register once and exits. Phylax does not issue the write.

After log rotation and watcher ingestion, expect:

- One unmanaged endpoint review for `.99`.
- One unauthorized Modbus writer alert.
- One unexpected communication alert.
- One write-outside-maintenance alert.

Response PDUs are retained without duplicate write alerts. In Triage, inspect
source severity, applicability, urgency factors, process context and evidence.
Acknowledgement does not approve a device or execute remediation. An endpoint
approval can resolve its management alert while the write-policy violation remains.

## 5. Guidance, reports and disconnected operation

Use a **real official advisory refresh** and a clearly identified lab asset for
hosted guidance; the synthetic test CVE is intentionally ineligible. The existing
`scripts/prepare_ai_test_data.py` supports a separate real-advisory exercise.
Only public advisory fields leave Phylax; facility context and observations stay
local. Keep provider configuration in the host `.env`, never in the lab image.

Demonstrate human review and record implementation/verification evidence only
when those actions were actually performed externally. A manual lifecycle status
is not proof that Phylax changed infrastructure.

```bash
python3 -m phylax --db data/support-lab/phylax-demo.db export-report --format json --output data/support-lab/report.json
python3 -m phylax --db data/support-lab/phylax-demo.db export-report --format csv --output data/support-lab/report.csv
python3 -m phylax --db data/support-lab/phylax-demo.db export-report --format markdown --output data/support-lab/report.md
```

With internet disabled after setup, inspect stored records, stale source health,
local reports and offline analysis. Hosted generation is optional; previously
saved output retains its real model and generation timestamp.

## Deterministic replay fallback

This command creates its own new dataset, analyzes both generated PCAPs in a
network-disabled Zeek container, verifies findings/alerts/deduplication and
acknowledgement, and exports all reports:

```bash
python3 scripts/verify_release_replay.py --output-dir data/support-replay --docker-image zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
```

Do not mix the live and replay datasets for exact alert-count assertions.
Different real Zeek connection UIDs can represent separate observations of the
same training exercise. Completed PCAPs themselves are deduplicated by digest.

## Ten-minute presentation

| Minute | Workflow |
|---|---|
| 0–1 | Fictional facility, operator purpose, collection/permission boundaries |
| 1–2 | Inventory, incomplete identity, criticality and process context |
| 2–3 | Approved IT discovery and passive OT observations |
| 3–4 | Unmanaged endpoint and change evidence |
| 4–5 | Four applicability states, source provenance and intelligence health |
| 5–6 | Three Modbus policy rules and original event evidence |
| 6–7 | Triage priority, topology and confirmed process relationships |
| 7–8 | Eligible public guidance and human review |
| 8–9 | Offline access and reports |
| 9–10 | Measured results, installation steps and honest limitations |

Use the appendix/video for CSV errors, provider failures, scheduler recovery,
software version conflicts and the full review lifecycle. All dashboard numbers
must come from the current dataset.

## Stop

Stop the watcher/worker/dashboard with Ctrl-C, then:

```bash
docker compose -f demo/compose.yaml down
```

The image, generated logs and separate dataset remain local for review. No real
TNI deployment or production OT behavior is validated by this lab.
