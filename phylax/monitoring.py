"""Passive Zeek log normalization and policy-based network detections."""

from __future__ import annotations

import ipaddress
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable, TextIO

from .core import Store, utc_now


WRITE_FUNCTIONS = {5, 6, 15, 16, 21, 22, 23}
READ_FUNCTIONS = {1, 2, 3, 4, 7, 8, 11, 12, 17, 20, 24, 43}
READ_WORDS = {"read", "read_coils", "read_discrete_inputs", "read_holding_registers", "read_input_registers", "read_exception_status", "diagnostics", "get_comm_event_counter", "get_comm_event_log", "report_slave_id", "read_file_record", "read_fifo_queue", "encapsulated_interface_transport"}
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
    if value is not None and (isinstance(value, bool) or not isinstance(value, (str, int, float))):
        raise ValueError("Zeek field must be a string or number, not an array/object")
    if value is None or value in {"-", "(empty)", "(unset)"}:
        return ""
    return str(value).strip()


def _port(value: Any) -> int | None:
    try:
        if isinstance(value,bool) or isinstance(value,float) or (isinstance(value,str) and not value.isdigit()):
            return None
        port = int(value)
        return port if 0 <= port <= 65535 else None
    except (ValueError, TypeError):
        return None


def normalize_row(row: dict[str, Any], *, kind: str, source_file: str = "") -> NetworkEvent:
    if not isinstance(row, dict):
        raise ValueError("Zeek record must be an object")
    if any(isinstance(v, (list, dict)) for k,v in row.items() if k in {"operation","function","function_code","func","ts","timestamp","source_ip","destination_ip","id.orig_h","id.resp_h"}):
        raise ValueError("Zeek identity, timestamp, and operation fields must be scalar values")
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
    source=str(ipaddress.ip_address(source)) if source else ""
    destination=str(ipaddress.ip_address(destination)) if destination else ""
    source_port = _port(row.get("source_p") or row.get("id.orig_p") or row.get("id_orig_p") or row.get("source_port"))
    destination_port = _port(row.get("destination_p") or row.get("id.resp_p") or row.get("id_resp_p") or row.get("destination_port"))
    operation = _clean(row.get("operation") or row.get("function_name") or row.get("func_name") or row.get("function") or row.get("function_code") or row.get("func"))
    # A conn.log service label is protocol metadata, not a decoded Modbus operation.
    is_modbus = kind.casefold() in {"modbus", "modbus.log"} or bool(operation and _clean(row.get("service") or row.get("proto") or row.get("protocol")).casefold()=="modbus")
    uid = _clean(row.get("uid") or row.get("event_ref"))
    # Distinguish separate transactions/addresses sharing a connection timestamp.
    discriminator = hashlib.sha256(json.dumps(row,sort_keys=True,separators=(",", ":")).encode()).hexdigest()[:16]
    event_type = "modbus" if is_modbus else "connection"
    direction = _clean(row.get("request_response") or row.get("network_direction"))
    event_ref = f"{uid}:{event_type}:{timestamp}:{operation}:{direction}:{discriminator}" if uid else str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([timestamp, source, source_port, destination, destination_port, event_type, operation, direction], sort_keys=True)))
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
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            raise ValueError(f"Malformed Zeek row {line_number}: {exc}") from exc


def is_modbus_write(event: NetworkEvent) -> bool | None:
    if event.event_type != 'modbus' or not event.operation:
        return None
    value = event.operation.casefold().replace('function code ', '').removeprefix('fc').strip()
    try:
        code = int(value,0) if not value.isdigit() else int(value)
        return True if code in WRITE_FUNCTIONS else False if code in READ_FUNCTIONS else None
    except ValueError:
        normalized = re.sub(r'[^a-z0-9]+','_',value).strip('_')
        return True if normalized in WRITE_WORDS else False if normalized in READ_WORDS else None


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate user supplied addresses, peers and UTC maintenance windows."""
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    policy=json.loads(json.dumps(policy))
    protected = policy.get("protected_assets", [])
    communications = policy.get("allowed_communications", [])
    writers = policy.get("authorized_writers", {})
    windows = policy.get("maintenance_windows_utc", [])
    if not isinstance(protected, list) or not isinstance(communications, list) or not isinstance(writers, dict) or not isinstance(windows, list):
        raise ValueError("Policy sections must use arrays/objects: protected_assets, allowed_communications, authorized_writers, maintenance_windows_utc")
    def validate_ip(value: Any, label: str) -> str:
        try:
            if not isinstance(value,str):raise ValueError("IP must be a string")
            return str(ipaddress.ip_address(value))
        except (ValueError, TypeError):
            raise ValueError(f"{label} must be an IPv4 or IPv6 address")
    if len(protected)>10000 or len(communications)>10000 or len(writers)>10000 or len(windows)>10000:
        raise ValueError("Policy contains too many entries")
    if "protected_assets" in policy:policy["protected_assets"]=[validate_ip(address,"protected asset") for address in protected]
    for index, rule in enumerate(communications):
        if not isinstance(rule, dict):
            raise ValueError(f"allowed_communications[{index}] must be an object")
        rule["source_ip"]=validate_ip(rule.get("source_ip"), f"allowed_communications[{index}].source_ip")
        rule["destination_ip"]=validate_ip(rule.get("destination_ip"), f"allowed_communications[{index}].destination_ip")
        if rule.get("protocol") is not None and not isinstance(rule["protocol"],str):
            raise ValueError("Policy protocol must be a string")
        if rule.get("protocol"):rule["protocol"]=rule["protocol"].casefold()
        if rule.get("destination_port") is not None and _port(rule["destination_port"]) is None:
            raise ValueError(f"allowed_communications[{index}].destination_port must be 0-65535")
        if rule.get("destination_port") is not None:rule["destination_port"]=_port(rule["destination_port"])
    normalized_writers={}
    for controller, sources in writers.items():
        controller=validate_ip(controller, "authorized_writers controller")
        if not isinstance(sources, list):
            raise ValueError(f"authorized_writers[{controller}] must be an array")
        normalized_writers[controller]=[validate_ip(source,f"authorized_writers[{controller}] source") for source in sources]
    if "authorized_writers" in policy:policy["authorized_writers"]=normalized_writers
    for index, window in enumerate(windows):
        if not isinstance(window, dict) or not isinstance(window.get("days"), list):
            raise ValueError(f"maintenance_windows_utc[{index}] requires a days array")
        if any(not isinstance(day, int) or isinstance(day,bool) or day < 0 or day > 6 for day in window["days"]):
            raise ValueError(f"maintenance_windows_utc[{index}].days values must be 0 (Monday) through 6 (Sunday)")
        for name in ("start", "end"):
            value = str(window.get(name, ""))
            if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value):
                raise ValueError(f"maintenance_windows_utc[{index}].{name} must use HH:MM in UTC")
    return json.loads(json.dumps(policy))


def _is_maintenance(timestamp: str, windows: list[dict[str, Any]]) -> bool | None:
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if dt.tzinfo is None:return None
        dt=dt.astimezone(timezone.utc)
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
        if start < end:
            if dt.weekday() in days and start <= minute < end:
                return True
        elif start > end:
            if (dt.weekday() in days and minute >= start) or ((dt.weekday()-1)%7 in days and minute < end):
                return True
        # start == end is an empty window, never an implicit 24-hour approval.
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
            elif any((rule.get('protocol') and not event.protocol) or (rule.get('destination_port') is not None and event.destination_port is None) for rule in matching_rules):
                diagnostics.append('unexpected_communication: missing protocol or destination port required by policy')
            elif not any(rule.get("source_ip") == event.source_ip and (not rule.get("protocol") or rule.get("protocol", "").casefold() == event.protocol.casefold()) and (rule.get("destination_port") is None or rule.get("destination_port") == event.destination_port) for rule in matching_rules):
                evidence = {"expected_communications": matching_rules, "observed": {"source_ip": event.source_ip, "destination_ip": event.destination_ip, "protocol": event.protocol, "destination_port": event.destination_port}}
                detections.append(Detection("unexpected_communication", "medium", f"Observed communication to protected asset {event.destination_ip} is not permitted by the configured communication policy.", evidence))
    if event.event_type == "modbus":
        direction = _clean((event.raw or {}).get("request_response") or (event.raw or {}).get("network_direction")).casefold()
        if direction in {"response", "reply", "responder"}:
            return detections, diagnostics
        write = is_modbus_write(event)
        if write is None:
            diagnostics.append("modbus_write_rules: missing Modbus function/operation metadata or unsupported operation")
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
                if "maintenance_windows_utc" not in policy:
                    diagnostics.append("write_outside_maintenance_window: no maintenance policy configured")
                    return detections, diagnostics
                maintenance = _is_maintenance(event.timestamp, policy["maintenance_windows_utc"])
                if maintenance is None:
                    diagnostics.append("write_outside_maintenance_window: timestamp cannot be evaluated")
                elif not maintenance:
                    evidence = {"approved_maintenance_windows_utc": policy.get("maintenance_windows_utc", []), "observed_timestamp_utc": event.timestamp, "modbus_operation": event.operation, "source_ip": event.source_ip, "destination_ip": event.destination_ip}
                    detections.append(Detection("write_outside_maintenance_window", "high", f"Modbus write operation was observed outside configured UTC maintenance windows.", evidence))
    return detections, diagnostics


def register_policy(store: Store, policy: dict[str, Any]) -> str:
    normalized = validate_policy(policy)
    raw = json.dumps(normalized,sort_keys=True,separators=(',',':'))
    policy_id = hashlib.sha256(raw.encode()).hexdigest()
    store.connection.execute('INSERT OR IGNORE INTO network_policies VALUES(?,?,?)',(policy_id,raw,utc_now()))
    store.connection.execute("INSERT INTO schema_meta VALUES('active_policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(policy_id,))
    return policy_id


def active_policy(store: Store) -> dict[str, Any] | None:
    row = store.connection.execute("SELECT policy_json FROM network_policies WHERE policy_id=(SELECT value FROM schema_meta WHERE key='active_policy')").fetchone()
    return json.loads(row[0]) if row else None


def evaluate_stored_event(store: Store, event_id: str, event: NetworkEvent, policy: dict[str, Any], policy_id: str) -> tuple[int,list[str]]:
    detections, notes = evaluate(event,policy)
    previous = store.connection.execute('SELECT * FROM event_evaluations WHERE event_id=?',(event_id,)).fetchone()
    if previous and previous['policy_id'] != policy_id:
        store.audit('policy_reevaluation',event_id,{'previous_policy':previous['policy_id'],'policy':policy_id})
    old_states={r['alert_id']:r['state'] for r in store.connection.execute('SELECT l.* FROM network_alert_lifecycle l JOIN network_alerts a USING(alert_id) WHERE a.event_id=?',(event_id,))}
    store.connection.execute("UPDATE network_alert_lifecycle SET state='resolved',policy_id=?,updated_at=? WHERE alert_id IN (SELECT alert_id FROM network_alerts WHERE event_id=?)",(policy_id,utc_now(),event_id))
    # Legacy alerts without lifecycle metadata are migrated on evaluation.
    store.connection.execute("INSERT OR IGNORE INTO network_alert_lifecycle SELECT alert_id,'resolved',?,? FROM network_alerts WHERE event_id=?",(policy_id,utc_now(),event_id))
    created = 0
    for detection in detections:
        alert_id = str(uuid.uuid5(uuid.NAMESPACE_URL,f'{detection.rule_id}:{event_id}'))
        existed = store.connection.execute('SELECT 1 FROM network_alerts WHERE alert_id=?',(alert_id,)).fetchone()
        evidence = detection.policy_evidence | {'policy_id':policy_id}
        store.connection.execute("""INSERT INTO network_alerts VALUES(?,?,?,?,?,?,0,?,?) ON CONFLICT(rule_id,event_id)
            DO UPDATE SET severity=excluded.severity,explanation=excluded.explanation,policy_evidence=excluded.policy_evidence,updated_at=excluded.updated_at""",
            (alert_id,detection.rule_id,event_id,detection.severity,detection.explanation,json.dumps(evidence),utc_now(),utc_now()))
        if old_states.get(alert_id)=='resolved':
            store.connection.execute('UPDATE network_alerts SET acknowledged=0 WHERE alert_id=?',(alert_id,))
            store.audit('network_alert_reactivated',alert_id,{'policy_id':policy_id})
        store.connection.execute("INSERT INTO network_alert_lifecycle VALUES(?,'active',?,?) ON CONFLICT(alert_id) DO UPDATE SET state='active',policy_id=excluded.policy_id,updated_at=excluded.updated_at",(alert_id,policy_id,utc_now()))
        created += not bool(existed)
    store.connection.execute('INSERT INTO event_evaluations VALUES(?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET policy_id=excluded.policy_id,diagnostics_json=excluded.diagnostics_json,evaluated_at=excluded.evaluated_at',
        (event_id,policy_id,json.dumps(notes),utc_now()))
    return created,notes


def reevaluate_events(store: Store, policy: dict[str, Any]) -> dict[str, Any]:
    count = alerts = diagnostic_count = 0
    with store.atomic('policy_review'):
        policy_id = register_policy(store,policy)
        # Cursor iteration keeps event processing bounded in memory.
        for row in store.connection.execute('SELECT * FROM network_events'):
            event = NetworkEvent(row['timestamp'],row['source_ip'],row['source_port'],row['destination_ip'],row['destination_port'],row['protocol'],row['operation'],row['event_type'],row['event_ref'],row['source_file'],json.loads(row['raw_json']))
            created,notes = evaluate_stored_event(store,row['event_id'],event,policy,policy_id)
            count += 1; alerts += created; diagnostic_count += len(notes)
        store.audit('policy_change',policy_id,{'events_evaluated':count})
    store.connection.commit()
    return {'policy_id':policy_id,'events_evaluated':count,'alerts_created':alerts,'diagnostic_count':diagnostic_count}


def ingest_file(store: Store, path: str | Path, *, kind: str | None = None, policy: dict[str, Any] | None = None, source_file: str | None = None, commit: bool = True) -> dict[str, Any]:
    path = Path(path)
    if path.stat().st_size > 500_000_000:
        raise ValueError('Zeek log exceeds 500 MB limit')
    kind = kind or ('modbus' if 'modbus' in path.name.casefold() else 'conn')
    source_file = source_file or path.name
    policy = validate_policy(policy) if policy is not None else active_policy(store)
    inserted = duplicate = alert_count = diagnostic_count = 0
    diagnostics: list[str] = []
    with store.atomic('network_import'):
        policy_id = register_policy(store,policy) if policy is not None else None
        with path.open(encoding='utf-8',errors='strict') as stream:
            for event in parse_zeek(stream,kind=kind,source_file=source_file):
                event_id = str(uuid.uuid5(uuid.NAMESPACE_URL,'phylax:'+event.event_ref))
                cursor = store.connection.execute('INSERT OR IGNORE INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (event_id,event.event_ref,event.timestamp,event.source_ip,event.source_port,event.destination_ip,event.destination_port,event.protocol,event.operation,event.event_type,event.source_file,json.dumps(event.raw,sort_keys=True)))
                if cursor.rowcount:
                    inserted += 1
                    store.observe_ip(event.source_ip,event.timestamp)
                    store.observe_ip(event.destination_ip,event.timestamp)
                else:
                    duplicate += 1
                # Deduplicating storage never skips policy evaluation.
                if policy is not None:
                    created,notes = evaluate_stored_event(store,event_id,event,policy,policy_id)
                    alert_count += created; diagnostic_count += len(notes)
                    diagnostics.extend(notes[:max(0,100-len(diagnostics))])
        store.audit('network_import',source_file,{'events':inserted,'duplicates':duplicate,'policy_id':policy_id})
    if commit:
        store.connection.commit()
    return {'events_inserted':inserted,'duplicates_skipped':duplicate,'alerts_created':alert_count,'diagnostics':diagnostics,'diagnostic_count':diagnostic_count}
