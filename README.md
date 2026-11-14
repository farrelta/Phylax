# Phylax

Phylax is a local dashboard for tracking IT and operational technology (OT) assets. It brings device inventory, observed network traffic, and public security advisories into one place so operators can investigate what happened and see which devices may be affected.

## Features

- Import device inventory and offline Zeek and Wazuh exports. Review observed identities and software before verifying them.
- Match inventory against cached vulnerability advisories and investigate observed traffic that violates a configured network policy.
- Trace alerts back to their source evidence and export JSON, CSV, or Markdown reports.
- Create a Markdown investigation report from selected findings. Optional Local or Hosted AI organizes the report using recorded statuses and evidence counts. Hosted requests require confirmation.

## Getting started

Run from the repository root on Linux or WSL. Python 3.12 or newer is recommended. Phylax uses the Python standard library, SQLite for local storage, and server-rendered HTML and SVG for the dashboard.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The first run creates an empty database. Use the same `--db` path for the dashboard and CLI commands. Stop the server with Ctrl+C.

The dashboard runs on loopback for one local operator. Basic use requires no package installation, build step, or environment variables. See [local operations](docs/local-operations.md) for optional tools, keys, and backups.

## Usage

1. In **Assets → Inventory**, add a device or import a CSV with an `ip_address` column. Leave unknown identity fields blank.
2. Use **Monitoring** to import recorded Zeek logs. To check devices against public advisories, sync public sources or import a saved advisory JSON in **Intelligence → CVEs**.
3. Open **Triage** to review an alert and its evidence. Use **Reports** to export the results.

Network alerts describe traffic seen by the sensor. Vulnerability matches describe which advisories may apply to a device. Open the source evidence to investigate further.

### Try the offline demo

Use a new output directory. This creates a separate database with a fictional inventory and four advisory applicability cases.

```bash
python3 scripts/prepare_release_demo.py --output-dir data/first-demo
python3 -m phylax --db data/first-demo/phylax-demo.db serve --port 8766
```

Open [http://127.0.0.1:8766](http://127.0.0.1:8766) to inspect the simulated findings. The [three-minute presentation](docs/demo-script.md) prepares every dashboard tab with saved Zeek and Wazuh evidence. The [sensor rehearsal](docs/local-operations.md#offline-sensor-rehearsal) starts with an empty inventory and verifies the imports and review.

## Project structure

```text
phylax/    CLI, dashboard, ingestion, and SQLite storage
scripts/   Demo preparation and release checks
tests/     Offline regression suite and sample inputs
docs/      Optional local setup and workflows
```

Run `python3 -m phylax --help` to list commands.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite runs offline with test doubles for feeds, providers, and external processes.

## Documentation

[Local operations](docs/local-operations.md) covers supported import formats, optional configuration, the offline sensor rehearsal, and SQLite backups.
