"""Passive Zeek log normalization and policy-based network detections."""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO

from .core import Store, utc_now


WRITE_FUNCTIONS = {5, 6, 15, 16, 22, 23}
WRITE_WORDS = {"write", "write_single_coil", "write_single_register", "write_multiple_coils", "write_multiple_registers", "write_file_record", "mask_write_register", "read_write_multiple_registers"}


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: str
    source_ip: str = ""
    source_port: int | None = None
    destination_ip: str = ""
    destination_port: int | None = None
    protocol: str = ""
    operation: str = ""
    event_type: str = "connection"
    event_ref: str = ""
    source_file: str = ""
    raw: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"timestamp": self.timestamp, "source_ip": self.source_ip, "source_port": self.source_port, "destination_ip": self.destination_ip, "destination_port": self.destination_port, "protocol": self.protocol, "operation": self.operation, "event_type": self.event_type, "event_ref": self.event_ref, "source_file": self.source_file, "raw": self.raw or {}}


@dataclass(frozen=True)
class Detection:
    rule_id: str
    severity: str
    explanation: str
    policy_evidence: dict[str, Any]


def _clean(value: Any) -> str:
    if value is None or value in {"-", "(empty)", "(unset)"}:
        return ""
    return str(value).strip()


def _port(value: Any) -> int | None:
    try:
        port = int(value)
        return port if 0 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def normalize_row(row: dict[str, Any], *, kind: str, source_file: str = "") -> NetworkEvent:
    timestamp = _clean(row.get("ts") or row.get("timestamp"))
    if not timestamp:
        raise ValueError("Zeek row has no timestamp")
    if timestamp.replace(".", "", 1).isdigit():
        timestamp = datetime.fromtimestamp(float(timestamp), timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    else:
        try:
            parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp is not a Unix timestamp or ISO 8601 value") from exc
        if parsed_time.tzinfo is None:
            parsed_time = parsed_time.replace(tzinfo=timezone.utc)
        timestamp = parsed_time.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    source = _clean(row.get("source_h") or row.get("id.orig_h") or row.get("id_orig_h") or row.get("source_ip") or row.get("src"))
    destination = _clean(row.get("destination_h") or row.get("id.resp_h") or row.get("id_resp_h") or row.get("destination_ip") or row.get("dst"))
    for address in (source, destination):
        if address:
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError(f"invalid IP address: {address}") from exc
    source_port = _port(row.get("source_p") or row.get("id.orig_p") or row.get("id_orig_p") or row.get("source_port"))
    destination_port = _port(row.get("destination_p") or row.get("id.resp_p") or row.get("id_resp_p") or row.get("destination_port"))
    operation = _clean(row.get("operation") or row.get("function_name") or row.get("func_name") or row.get("function") or row.get("function_code") or row.get("func"))
    # A conn.log service label is protocol metadata, not a decoded Modbus operation.
    is_modbus = kind.casefold() in {"modbus", "modbus.log"} or bool(operation)
    uid = _clean(row.get("uid") or row.get("event_ref"))
    event_type = "modbus" if is_modbus else "connection"
    direction = _clean(row.get("request_response") or row.get("network_direction"))
    event_ref = f"{uid}:{event_type}:{timestamp}:{operation}:{direction}" if uid else str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([timestamp, source, source_port, destination, destination_port, event_type, operation, direction], sort_keys=True)))
    return NetworkEvent(timestamp, source, source_port, destination, destination_port, _clean(row.get("proto") or row.get("protocol") or row.get("service")).casefold(), operation, event_type, event_ref, source_file, row)


def parse_zeek(stream: TextIO, *, kind: str = "conn", source_file: str = "") -> Iterable[NetworkEvent]:
    """Stream JSON Lines or Zeek tab-separated logs; silently skip metadata lines."""
    fields: list[str] | None = None
    for line_number, line in enumerate(stream, start=1):
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        try:
            if line.startswith("{"):
                row = json.loads(line)
            else:
                if not fields:
                    raise ValueError("TSV record has no preceding #fields header")
                values = line.split("\t")
                if len(values) != len(fields):
                    raise ValueError(f"Expected {len(fields)} tab-separated fields, got {len(values)}")
                row = dict(zip(fields, values))
            yield normalize_row(row, kind=kind, source_file=source_file)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Malformed Zeek row {line_number}: {exc}") from exc


def is_modbus_write(event: NetworkEvent) -> bool | None:
    if event.event_type != "modbus" or not event.operation:
        return None
    value = event.operation.casefold().replace("function code ", "").replace("fc", "").strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
    try:
        return int(value, 0) in WRITE_FUNCTIONS
    except ValueError:
        if value.isdigit():
            return int(value) in WRITE_FUNCTIONS
        if any(token in normalized for token in ("read", "diagnostic", "identify", "encapsulated")) and "read_write" not in normalized:
            return False
        return any(word in normalized for word in WRITE_WORDS)


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate user supplied addresses, peers and UTC maintenance windows."""
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    protected = policy.get("protected_assets", [])
    communications = policy.get("allowed_communications", [])
    writers = policy.get("authorized_writers", {})
    windows = policy.get("maintenance_windows_utc", [])
    if not isinstance(protected, list) or not isinstance(communications, list) or not isinstance(writers, dict) or not isinstance(windows, list):
        raise ValueError("Policy sections must use arrays/objects: protected_assets, allowed_communications, authorized_writers, maintenance_windows_utc")
    def validate_ip(value: Any, label: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except (ValueError, TypeError):
            raise ValueError(f"{label} must be an IPv4 or IPv6 address")
    for address in protected:
        validate_ip(address, "protected asset")
    for index, rule in enumerate(communications):
        if not isinstance(rule, dict):
            raise ValueError(f"allowed_communications[{index}] must be an object")
        validate_ip(rule.get("source_ip"), f"allowed_communications[{index}].source_ip")
        validate_ip(rule.get("destination_ip"), f"allowed_communications[{index}].destination_ip")
        if rule.get("destination_port") is not None and _port(rule["destination_port"]) is None:
            raise ValueError(f"allowed_communications[{index}].destination_port must be 0-65535")
    for controller, sources in writers.items():
        validate_ip(controller, "authorized_writers controller")
        if not isinstance(sources, list):
            raise ValueError(f"authorized_writers[{controller}] must be an array")
        for source in sources:
            validate_ip(source, f"authorized_writers[{controller}] source")
    for index, window in enumerate(windows):
        if not isinstance(window, dict) or not isinstance(window.get("days"), list):
            raise ValueError(f"maintenance_windows_utc[{index}] requires a days array")
        if any(not isinstance(day, int) or day < 0 or day > 6 for day in window["days"]):
            raise ValueError(f"maintenance_windows_utc[{index}].days values must be 0 (Monday) through 6 (Sunday)")
        for name in ("start", "end"):
            value = str(window.get(name, ""))
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                raise ValueError(f"maintenance_windows_utc[{index}].{name} must use HH:MM in UTC")
    return policy


def _is_maintenance(timestamp: str, windows: list[dict[str, Any]]) -> bool | None:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
    minute = dt.hour * 60 + dt.minute
    for window in windows:
        try:
            days = {int(day) for day in window["days"]}
            start_h, start_m = (int(part) for part in window["start"].split(":"))
            end_h, end_m = (int(part) for part in window["end"].split(":"))
            start, end = start_h * 60 + start_m, end_h * 60 + end_m
        except (KeyError, ValueError, TypeError):
            continue
        if dt.weekday() not in days:
            continue
        if start <= minute < end if start <= end else (minute >= start or minute < end):
            return True
    return False


def evaluate(event: NetworkEvent, policy: dict[str, Any]) -> tuple[list[Detection], list[str]]:
    """Return alerts and explicit diagnostics for rules that lack required evidence."""
    detections: list[Detection] = []
    diagnostics: list[str] = []
    protected = set(policy.get("protected_assets", []))
    if event.event_type == "connection":
        allowed = policy.get("allowed_communications", [])
        matching_rules = [rule for rule in allowed if rule.get("destination_ip") == event.destination_ip]
        if event.destination_ip in protected:
            if not event.source_ip or not event.destination_ip:
                diagnostics.append("unexpected_communication: missing source or destination address")
            elif not matching_rules:
                diagnostics.append("unexpected_communication: no communication policy is defined for protected destination")
            elif not any(rule.get("source_ip") == event.source_ip and (not rule.get("protocol") or rule.get("protocol", "").casefold() == event.protocol.casefold()) and (rule.get("destination_port") is None or rule.get("destination_port") == event.destination_port) for rule in matching_rules):
                evidence = {"expected_communications": matching_rules, "observed": {"source_ip": event.source_ip, "destination_ip": event.destination_ip, "protocol": event.protocol, "destination_port": event.destination_port}}
                detections.append(Detection("unexpected_communication", "medium", f"Observed communication to protected asset {event.destination_ip} is not permitted by the configured communication policy.", evidence))
    if event.event_type == "modbus":
        direction = _clean((event.raw or {}).get("request_response") or (event.raw or {}).get("network_direction")).casefold()
        if direction in {"response", "reply", "responder"}:
            return detections, diagnostics
        write = is_modbus_write(event)
        if write is None:
            diagnostics.append("modbus_write_rules: missing Modbus function/operation metadata")
        elif write:
            if not event.source_ip or not event.destination_ip:
                diagnostics.append("modbus_write_rules: missing source or destination address")
            else:
                writers = policy.get("authorized_writers", {}).get(event.destination_ip)
                if writers is None:
                    diagnostics.append(f"unauthorized_modbus_writer: no writer policy for destination {event.destination_ip}")
                elif event.source_ip not in writers:
                    evidence = {"configured_authorized_writers": writers, "observed_source": event.source_ip, "controller": event.destination_ip, "modbus_operation": event.operation}
                    detections.append(Detection("unauthorized_modbus_writer", "high", f"Modbus write operation from {event.source_ip} to {event.destination_ip} is not in the configured authorized-writer policy.", evidence))
                maintenance = _is_maintenance(event.timestamp, policy.get("maintenance_windows_utc", []))
                if maintenance is None:
                    diagnostics.append("write_outside_maintenance_window: timestamp cannot be evaluated")
                elif not maintenance:
                    evidence = {"approved_maintenance_windows_utc": policy.get("maintenance_windows_utc", []), "observed_timestamp_utc": event.timestamp, "modbus_operation": event.operation, "source_ip": event.source_ip, "destination_ip": event.destination_ip}
                    detections.append(Detection("write_outside_maintenance_window", "high", f"Modbus write operation was observed outside configured UTC maintenance windows.", evidence))
    return detections, diagnostics


def ingest_file(store: Store, path: str | Path, *, kind: str | None = None, policy: dict[str, Any] | None = None, source_file: str | None = None) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > 500_000_000:
        raise ValueError("Zeek log exceeds 500 MB limit")
    kind = kind or ("modbus" if "modbus" in path.name.casefold() else "conn")
    source_file = source_file or path.name
    if policy is not None:
        policy = validate_policy(policy)
    inserted = duplicate = alert_count = 0
    diagnostics: list[str] = []
    store.connection.execute("SAVEPOINT network_import")
    try:
        with path.open(encoding="utf-8", errors="strict") as stream:
            for event in parse_zeek(stream, kind=kind, source_file=source_file):
                event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "phylax:" + event.event_ref))
                cursor = store.connection.execute("""INSERT OR IGNORE INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (event_id, event.event_ref, event.timestamp, event.source_ip, event.source_port, event.destination_ip, event.destination_port, event.protocol, event.operation, event.event_type, event.source_file, json.dumps(event.raw, sort_keys=True)))
                if cursor.rowcount == 0:
                    duplicate += 1
                    continue
                inserted += 1
                store.observe_ip(event.source_ip, event.timestamp)
                store.observe_ip(event.destination_ip, event.timestamp)
                if policy is not None:
                    detections, notes = evaluate(event, policy)
                    diagnostics.extend(notes)
                    for detection in detections:
                        alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{detection.rule_id}:{event_id}"))
                        store.connection.execute("""INSERT OR IGNORE INTO network_alerts VALUES (?,?,?,?,?,?,0,?,?)""", (alert_id, detection.rule_id, event_id, detection.severity, detection.explanation, json.dumps(detection.policy_evidence), utc_now(), utc_now()))
                        alert_count += 1
        store.connection.execute("RELEASE SAVEPOINT network_import")
    except Exception:
        store.connection.execute("ROLLBACK TO SAVEPOINT network_import")
        store.connection.execute("RELEASE SAVEPOINT network_import")
        raise
    store.connection.commit()
    return {"events_inserted": inserted, "duplicates_skipped": duplicate, "alerts_created": alert_count, "diagnostics": diagnostics}
