# Setup and configuration

[Documentation index](README.md)

## Requirements

| Component | Needed for |
|---|---|
| Python 3.12+ recommended | Application, SQLite persistence, offline tests |
| Zeek executable **or** installed Zeek Docker image | Offline PCAP analysis |
| Docker Engine and Compose | Optional isolated live lab |
| Nmap at `/usr/bin/nmap` or `/usr/local/bin/nmap` | Optional approved IT discovery |
| Internet connection | Feed refresh, hosted guidance, initial lab image installation |

Phylax has no pip dependencies. Docker runs the optional Zeek analyzer or lab; the dashboard itself runs with Python.

```bash
python3 --version
python3 -m phylax --help
python3 -m phylax --db data/phylax.db serve
```

Use the printed loopback URL. `serve --port 8766` changes the port. Do not expose the dashboard through a public tunnel or unauthenticated proxy; it has no multi-user authentication.

## Storage and offline operation

`--db data/phylax.db` selects the local SQLite file. Relative paths resolve from the working directory. Keep all processes on the same absolute or consistently resolved database path. Data includes inventory, intelligence cache, source provenance, findings, events, policy versions, approvals, scan history, checkpoints, audit records, and remediation plans.

SQLite may create journal/WAL sidecar files; these are part of live database operation. Generated reports go to the explicit `--output` path. The watcher reads its configured directory; Phylax does not provide a live sensor. PCAP processing uses a temporary directory and retains normalized evidence and capture hashes.

Offline access includes stored inventory, assessments, event review, reporting, and PCAP analysis if Zeek/the Docker image is already installed. New public-feed and hosted-model requests need connectivity. Source freshness and collector inactivity remain visible.

## Feed key

The optional NVD key is read from the **process environment**:

```bash
export NVD_API_KEY='your-key'
python3 -m phylax --db data/phylax.db sync-feeds
```

Only supported AI settings are automatically read from project `.env`; placing `NVD_API_KEY` there alone does not configure NVD. Do not commit keys or paste them into reports.

## Optional hosted AI

Copy `.env.example` to `.env` in the directory from which you start Phylax. Choose one provider and a model enabled for that account:

```dotenv
PHYLAX_AI_PROVIDER=openrouter
OPENROUTER_API_KEY=your-key
PHYLAX_AI_MODEL=your-enabled-model
PHYLAX_AI_TIMEOUT_SECONDS=90
```

| Provider setting | Key variable |
|---|---|
| `gemini` | `GEMINI_API_KEY` |
| `groq` | `GROQ_API_KEY` |
| `openrouter` | `OPENROUTER_API_KEY` |
| `custom` | `PHYLAX_AI_API_KEY` plus `PHYLAX_AI_BASE_URL` and `PHYLAX_AI_MODEL` |

The custom endpoint must be compatible with the adapter's chat-completion format. HTTPS is required except for loopback development. Existing environment values take precedence over `.env`. The file is parsed as data, never executed. Timeout accepts 5–180 seconds, default 90. Restart after edits. Quotas, available models, and provider terms must be checked with the provider; no free availability is guaranteed.

Generation requires an operator action and eligible trusted public evidence. Synthetic fixtures do not call a hosted model. See [AI boundaries](architecture.md#ai-guidance-and-human-review).

## Upgrades, backup, and rollback

1. Stop dashboard, watcher, and scanner workers.
2. Back up the database using SQLite's backup API or a complete copy made after all writers stop. Retain the corresponding code revision and configuration.
3. Start the new code on a **copy** first. Opening the database applies additive migrations.
4. Inspect preserved identifiers, record counts, and `PRAGMA integrity_check` before using the original database.
5. Restart processes and reload browser forms; old form tokens are invalid.

Automatic pre-migration backups use `<database>.pre-hardening.sqlite` and `<database>.pre-asset-intelligence.sqlite`. They are upgrade snapshots, not a recurring backup policy. Legacy NVD records missing applicability conditions require a public refresh before confirmation. Never reconstruct those conditions from an IP or product name.

Rollback: stop every writer, preserve the failed-upgrade database for inspection, restore the backup to a separate path, and run the matching older code against it. Do not point older code at a newer schema and assume compatibility.

## Troubleshooting

| Symptom | Check |
|---|---|
| Cross-origin request denied | Open the printed URL directly in a regular tab and reload after restart. `localhost`, `127.0.0.1`, and `[::1]` are distinct origins. Keep Host/Origin and form-token protections enabled. |
| Empty dashboard | Confirm every command uses the same `--db` and working directory; no data is loaded automatically. |
| Feed appears stalled | Check timestamped CLI progress and source health. NVD windows can contain many pages; cancellation preserves saved pages. |
| AI unavailable or no hosted output | Check provider/key/model in the server process, timeout, account quota, public eligibility, and displayed error. Existing saved guidance may remain. |
| Missing Zeek/Docker | Import existing Zeek logs, install the tool separately, or supply an already installed image with `--docker-image`. |
| Queued scan never executes | Start the separate `worker`; verify current permission and eligible target identity. |
| Stale collector | Check watcher process, finalized log directory, file rotation, and ingestion errors. Silence does not prove a device is offline. |
