# Monitoring, policies, and approved IT discovery

[Documentation index](README.md)

## Passive evidence collection

Phylax imports observations; it does not capture a whole network itself. An external Zeek sensor needs visibility from an appropriate TAP, SPAN/mirror port, or isolated lab interface. It can only report traffic reaching that sensor. Quiet devices, encrypted payloads, other segments, and unsupported protocols can remain unidentified.

Install Zeek separately only if analyzing PCAPs or operating an external sensor. Existing logs require neither Zeek nor Docker on the Phylax host.

```bash
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/conn.log --kind conn
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/modbus.log --kind modbus --policy /path/to/policy.json
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/dhcp.log --kind dhcp
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/software.log --kind software
```

Supported formats are Zeek JSON Lines and TSV. Connection records preserve peers, ports, protocol, timestamps, and original evidence. Modbus logs supply operations when present; a connection service label alone is not a decoded operation. DHCP/software have dedicated models. Requested DHCP addresses alone do not establish assigned IP/MAC identity.

CLI log inputs are bounded to 500 MB; web uploads to 5 MB. Missing metadata produces uncertainty or rule diagnostics. Numeric Modbus writes 5, 6, 15, 16, 21, 22, and 23 and supported names are recognized. Response PDUs remain evidence but are excluded from writer/maintenance detections. Other OT protocols are not claimed as decoded.

## Watch finalized logs

```bash
python3 -m phylax --db data/phylax.db watch-zeek --directory /path/to/finalized-logs --interval-seconds 30
```

Use finalized, uncompressed logs rather than Zeek's active `current/` directory. Two stable polls precede a snapshot import. Changing/malformed files roll back individually. Successful hashes and outcomes persist; changed contents can retry, unchanged processed files are not reimported repeatedly. Symlinks are skipped. Keep the directory bounded: at most 1,000 entries are considered per poll, and files are capped at 500 MB.

Polling supports 1–60 seconds, default 30. Collector heartbeats become stale after 180 seconds. A five-second rehearsal interval is supported; actual latency also depends on collector rotation and processing. Keep the watcher separate from the scanner worker.

## Offline PCAPs

Use a local Zeek executable:

```bash
python3 -m phylax --db data/phylax.db analyze-pcap /path/to/capture.pcap --policy /path/to/policy.json
```

Or an already installed, explicitly tagged/digested Zeek image:

```bash
python3 -m phylax --db data/phylax.db analyze-pcap /path/to/capture.pcap --docker-image zeek/zeek:YOUR_INSTALLED_VERSION --policy /path/to/policy.json
```

The Docker runner never pulls an image. Install it separately before disconnected use. Analysis uses offline `-r`, fixed argument arrays, temporary files, and a 60-second timeout. Captures must have a supported PCAP/PCAPNG header and be 24 bytes–500 MB. Docker mode disables networking, drops capabilities, uses a non-root user/read-only root, and bounds resources.

Supported conn/Modbus/DHCP/software logs are imported when produced. Capture SHA-256 and original log provenance remain attached; completed captures are deduplicated. A supplied policy can reevaluate a duplicate capture's stored events. Built-in Zeek Modbus and available ICSNPP fields are supported; the runner does not install or certify ICSNPP.

## Configure passive rules

Example policy using documentation-only addresses:

```json
{
  "protected_assets": ["192.0.2.10"],
  "allowed_communications": [
    {"source_ip": "192.0.2.30", "destination_ip": "192.0.2.10", "destination_port": 502, "protocol": "tcp"}
  ],
  "authorized_writers": {"192.0.2.10": ["192.0.2.30"]},
  "maintenance_windows_utc": [
    {"days": [0, 1, 2, 3, 4], "start": "01:00", "end": "02:00"}
  ]
}
```

Save and apply after adapting it to an authorized environment:

```bash
python3 -m phylax --db data/phylax.db apply-policy /path/to/policy.json
```

| Rule | Evaluates |
|---|---|
| Unauthorized Modbus writer | Observed write source is outside the destination's configured writer allowlist |
| Unexpected communication | Communication to a protected destination violates the configured allowlist |
| Write outside maintenance window | Observed write is outside approved UTC periods |

Days are Monday 0 through Sunday 6. Windows use UTC `HH:MM`, end-exclusive. Overnight windows belong to their start day; equal start/end is empty. An omitted section leaves its rule unconfigured; explicit `maintenance_windows_utc: []` means no approved write period. Missing fields and unsupported operations produce diagnostics rather than fabricated violations.

Policies are versioned. Applying a policy reevaluates stored events; resolved violations remain historical. Later imports reuse the latest configured policy. Policies never block traffic or command devices. AI policy drafting is a proposal, **not an implemented feature**.

## Approved active IT discovery

Only individually permitted literal IPv4 supporting IT hosts or network management IPs are eligible. PLCs, RTUs, HMIs, engineering workstations, unknown identities, and observed-only records remain passive-only. No CIDR expansion, DNS, UDP, scripts, OS fingerprinting, arbitrary Nmap arguments, or general version-probe mode.

Select an eligible inventory asset in Assets → IT discovery. The CLI equivalent is:

```bash
python3 -m phylax --db data/phylax.db scan-target save --asset-id ASSET_ID --ports 80 443 --identify --permit --actor "Operator" --note "Recorded permission for this individual IT target"
python3 -m phylax --db data/phylax.db scan-target list
python3 -m phylax --db data/phylax.db scan --target TARGET_ID
python3 -m phylax --db data/phylax.db worker --once
```

Replace IDs from your authorized inventory and command output. The `--permit` option grants scan permission; omit it to save without permission. `scan` queues work; only `worker` executes it. `--identify` is optional and enables only supported HTTP(S) headers or SSH banners on selected supported ports.

Limits: ≤32 selected TCP ports, unprivileged Nmap connect scan, no additional discovery probes, 30-second host timeout, one retry, 180-second whole-run deadline. Identification uses bounded reads and deadlines, no redirects/authentication, and preserves TLS failures. Results and versions remain unverified observations. No response is not proof of an offline device. Probe evidence remains distinct from operational communication.

```bash
python3 -m phylax --db data/phylax.db scan --status RUN_ID
python3 -m phylax --db data/phylax.db scan --cancel RUN_ID
python3 -m phylax --db data/phylax.db scan-target schedule TARGET_ID --interval-minutes 60
python3 -m phylax --db data/phylax.db worker
python3 -m phylax --db data/phylax.db scan-target revoke TARGET_ID --actor "Operator" --note "Permission withdrawn"
```

Schedules are opt-in, default 60 minutes, minimum 15; add `--disable` to the schedule command to disable one. One worker lease allows one active run per database. Permission revisions invalidate queued work; running work checks cancellation. Expired executions become interrupted; missed intervals are skipped rather than replayed in bursts. Each process owns its SQLite connection.
