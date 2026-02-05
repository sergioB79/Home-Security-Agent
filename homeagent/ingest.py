import json
import win32evtlog
import win32evtlogutil

from .config import EVENT_IDS
from .normalize import parse_sysmon_xml
from .scoring import score_event
from .allowlist import load_allowlist
from .correlation import correlate
from .db import insert_event
from .utils import json_dumps, basename, normalize_path

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def _evt_query(last_record_id):
    conditions = " or ".join([f"EventID={i}" for i in sorted(EVENT_IDS)])
    if last_record_id:
        xpath = f"*[System[({conditions}) and (EventRecordID>{last_record_id})]]"
    else:
        xpath = f"*[System[({conditions})]]"

    handle = win32evtlog.EvtQuery(CHANNEL, win32evtlog.EvtQueryForwardDirection, xpath)
    return handle


def ingest_once(db, last_record_id):
    allowlist = load_allowlist()
    handle = _evt_query(last_record_id)
    new_last = last_record_id
    processed = 0

    while True:
        events = win32evtlog.EvtNext(handle, 32)
        if not events:
            break
        for e in events:
            xml = win32evtlog.EvtRender(e, win32evtlog.EvtRenderEventXml)
            parsed = parse_sysmon_xml(xml)
            data = parsed["data"]

            event = {
                "event_id": parsed["event_id"],
                "record_id": parsed["record_id"],
                "ts": parsed["ts"],
                "kind": _map_kind(parsed["event_id"]),
                "image": data.get("Image") or data.get("ProcessName"),
                "target": data.get("TargetFilename") or data.get("TargetObject"),
                "pid": _to_int(data.get("ProcessId")),
                "command_line": data.get("CommandLine"),
                "parent_image": data.get("ParentImage"),
                "user": data.get("User"),
                "integrity": data.get("IntegrityLevel"),
                "signature": data.get("Signature"),
                "hash": _extract_sha256(data.get("Hashes")),
                "network": {
                    "destination_ip": data.get("DestinationIp"),
                    "destination_port": data.get("DestinationPort"),
                    "destination_hostname": data.get("DestinationHostname"),
                    "protocol": data.get("Protocol"),
                },
            }

            score, severity, reasons = score_event(event, allowlist)
            event["score"] = score
            event["severity"] = severity
            event["reasons"] = reasons
            event["data_json"] = json_dumps(event)

            insert_event(db, event)
            correlate(db, event)

            if score >= 80:
                from .db import insert_finding
                insert_finding(db, event["ts"], severity, score, "High-signal single event", event["data_json"], f"single|{event['record_id']}")

            if parsed["record_id"] > new_last:
                new_last = parsed["record_id"]

            processed += 1

    return processed, new_last


def _map_kind(event_id):
    if event_id == 1:
        return "process"
    if event_id == 3:
        return "network"
    if event_id == 11:
        return "file_create"
    if event_id in (12, 13, 14):
        return "registry"
    if event_id == 16:
        return "config"
    return "other"


def _extract_sha256(hashes):
    if not hashes:
        return None
    for part in hashes.split(";"):
        if "SHA256=" in part:
            return part.split("=", 1)[1].strip()
    return None


def _to_int(value):
    try:
        return int(value)
    except Exception:
        return None
