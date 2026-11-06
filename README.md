# Phylax

Lightweight, local IT/OT asset intelligence and cybersecurity monitoring for the **Kartika Cyber Hackathon 2026**.

Phylax combines asset inventory, public vulnerability intelligence, passive Zeek observations, evidence-backed alerts, and optional AI remediation guidance. Data is stored locally in SQLite; stored evidence and reports remain available offline.

## Quick start

Run from the repository root with **Python 3.12+ recommended**. Phylax uses the Python standard library; no pip packages are required.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The dashboard accepts loopback connections only. Stop with Ctrl+C.

**Zeek, Docker, and Nmap are optional.** Zeek or a locally installed Zeek Docker image is needed to analyze PCAPs. Existing Zeek logs can be imported without them. Nmap is required only for explicitly permitted IT discovery.

## What you can do

- Import or edit inventory, record ownership and process context, and review unmanaged endpoints.
- Import Zeek connection, Modbus, DHCP, and software logs; track observed changes and communication.
- Correlate inventory and software evidence with NVD, CISA KEV, ICS RSS, and selected CISA CSAF advisories.
- Review applicability, source evidence, severity, confidence, and deterministic urgency separately.
- Investigate passive topology and policy alerts, acknowledge findings, and export JSON, CSV, or Markdown reports.
- Run bounded discovery against individually approved supporting IT endpoints.
- Request optional hosted guidance from public advisory data, then review it locally.

## First workflow

Use your own validated inventory and logs; these paths are placeholders:

```bash
python3 -m phylax --db data/phylax.db import-assets /path/to/assets.csv
python3 -m phylax --db data/phylax.db sync-feeds
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/conn.log --kind conn
python3 -m phylax --db data/phylax.db export-report --format json --output data/report.json
```

Imports reassess applicable findings automatically. For an isolated, reproducible example without external feeds or device access, follow the [testing guide](docs/testing.md).

## Safety and privacy

OT control endpoints remain passive-only. Active discovery requires separate permission for each eligible IT target and its selected TCP ports. Management approval, identity verification, and scan permission are independent decisions.

Phylax does not exploit devices, patch systems, isolate endpoints, issue controller writes, or change firewalls. AI output is advisory, unverified, and never executed. Hosted requests contain eligible public advisory fields; local inventory, network evidence, policies, and risk context stay on the host.

A vulnerability match does not establish compromise. Missing traffic or findings do not establish absence or safety.

## Documentation

Start with the [documentation index](docs/README.md).

| Guide | Contents |
|---|---|
| [Setup and configuration](docs/setup.md) | Requirements, storage, keys, backups, upgrades, troubleshooting |
| [Operator guide](docs/operator-guide.md) | Inventory, approvals, software, topology, triage, reports |
| [Intelligence and applicability](docs/intelligence.md) | Sources, sync/resume, offline imports, matching and scoring |
| [Monitoring and discovery](docs/monitoring.md) | Zeek, PCAPs, policy format, watcher, approved IT discovery |
| [Architecture and security](docs/architecture.md) | Modules, persistence, trust boundaries, AI, limitations |
| [Testing and demonstration](docs/testing.md) | Offline checks, manual acceptance, isolated Docker lab |
| [Workflow diagrams](docs/workflows/README.md) | Offline atlas and Mermaid workflows |

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The offline suite mocks feeds, providers, and external processes. Real lab rehearsals are separate and optional. See the testing guide for coverage and limitations.
