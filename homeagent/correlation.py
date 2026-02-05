import json
from datetime import timedelta
from .db import insert_finding
from .utils import parse_ts, json_dumps


def correlate(db, event):
    kind = event.get("kind")
    ts = event.get("ts")
    if not ts:
        return

    if kind == "file_create" and event.get("target"):
        _drop_execute(db, event)
    elif kind == "registry":
        _execute_persist(db, event)
    elif kind == "network":
        _script_network(db, event)


def _drop_execute(db, event):
    target = event.get("target")
    ts = event.get("ts")
    row = db.execute(
        """
        SELECT ts, image, data_json FROM events_raw
        WHERE kind='process' AND image=? AND ts >= datetime(?, '-5 minutes')
        ORDER BY ts DESC LIMIT 1
        """,
        (target, ts),
    ).fetchone()
    if not row:
        return

    evidence = {
        "rule": "Drop → Execute",
        "file_created": event,
        "process": json.loads(row[2]) if row[2] else {},
    }
    dedupe_key = f"drop_exec|{target}|{ts[:16]}"
    insert_finding(db, ts, "High", 70, "Drop → Execute", json_dumps(evidence), dedupe_key)


def _execute_persist(db, event):
    target = event.get("target")
    ts = event.get("ts")
    if not target:
        return
    row = db.execute(
        """
        SELECT ts, image, data_json FROM events_raw
        WHERE kind='process' AND ts >= datetime(?, '-10 minutes')
        ORDER BY ts DESC LIMIT 1
        """,
        (ts,),
    ).fetchone()
    if not row:
        return

    evidence = {
        "rule": "Execute → Persist",
        "persistence": event,
        "process": json.loads(row[2]) if row[2] else {},
    }
    dedupe_key = f"exec_persist|{target}|{ts[:16]}"
    insert_finding(db, ts, "High", 70, "Execute → Persist", json_dumps(evidence), dedupe_key)


def _script_network(db, event):
    image = event.get("image") or ""
    if not image:
        return
    ts = event.get("ts")
    evidence = {
        "rule": "Script → Network",
        "network": event,
    }
    dedupe_key = f"script_net|{image}|{ts[:16]}"
    insert_finding(db, ts, "Medium", 45, "Script → Network", json_dumps(evidence), dedupe_key)
