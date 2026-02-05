import json
from datetime import datetime, timezone

from .config import (
    ALERT_MIN_SEVERITY,
    ALERT_CHANNELS,
    ALERT_THROTTLE_MAX,
    ALERT_THROTTLE_WINDOW_SEC,
    ALERT_INCLUDE_EVIDENCE,
    ALERT_SOUND_CRITICAL,
    ALERT_LOG_PATH,
)
from .utils import json_dumps, normalize_path, basename


SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def alert_config():
    return {
        "min_severity": ALERT_MIN_SEVERITY,
        "channels": list(ALERT_CHANNELS),
        "throttle_max": ALERT_THROTTLE_MAX,
        "throttle_window_sec": ALERT_THROTTLE_WINDOW_SEC,
        "include_evidence": ALERT_INCLUDE_EVIDENCE,
        "sound_critical": ALERT_SOUND_CRITICAL,
    }


def should_alert(finding, cfg):
    if not finding:
        return False
    if finding.get("status") != "open":
        return False
    sev = finding.get("severity")
    if sev not in SEVERITY_ORDER:
        return False
    min_sev = cfg.get("min_severity", "Medium")
    return SEVERITY_ORDER[sev] >= SEVERITY_ORDER.get(min_sev, 1)


def already_alerted(db, finding_id):
    row = db.execute("SELECT 1 FROM alerts_sent WHERE finding_id=?", (str(finding_id),)).fetchone()
    return row is not None


def throttle_ok(db, cfg):
    max_n = int(cfg.get("throttle_max", 3))
    window = int(cfg.get("throttle_window_sec", 600))
    row = db.execute(
        "SELECT COUNT(*) FROM alerts_sent WHERE sent_ts >= datetime('now', ?) AND channel NOT IN ('throttled','failed')",
        (f"-{window} seconds",),
    ).fetchone()
    return int(row[0]) < max_n if row else True


def send_toast(title, body):
    try:
        from win11toast import toast
    except Exception:
        _log_alert_error("toast import failed")
        return False
    try:
        toast(title, body, duration="short")
        return True
    except Exception:
        _log_alert_error("toast send failed")
        return False


def write_eventlog(title, body, severity):
    try:
        import win32evtlog
        import win32evtlogutil
    except Exception:
        return False

    source = "HomeSecurityAgent"
    event_id = 1000

    level_map = {
        "Medium": win32evtlog.EVENTLOG_INFORMATION_TYPE,
        "High": win32evtlog.EVENTLOG_WARNING_TYPE,
        "Critical": win32evtlog.EVENTLOG_ERROR_TYPE,
    }
    etype = level_map.get(severity, win32evtlog.EVENTLOG_INFORMATION_TYPE)

    try:
        win32evtlogutil.AddSourceToRegistry(source, "Application")
    except Exception:
        pass

    try:
        win32evtlogutil.ReportEvent(source, event_id, eventCategory=0, eventType=etype, strings=[title, body])
        return True
    except Exception:
        _log_alert_error("eventlog write failed")
        return False


def mark_alerted(db, finding_id, channel, message):
    ts = _utcnow_sql()
    db.execute(
        "INSERT OR REPLACE INTO alerts_sent(finding_id, sent_ts, channel, message) VALUES (?, ?, ?, ?)",
        (str(finding_id), ts, channel, message),
    )
    db.execute(
        "INSERT INTO alerts_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        ("last_alert_ts", ts),
    )
    db.commit()


def alert_new_findings(db, cfg):
    if cfg is None:
        cfg = alert_config()

    rows = db.execute(
        """
        SELECT id, ts, severity, score, title, evidence_json, status
        FROM findings
        WHERE status='open'
        ORDER BY ts DESC
        LIMIT 100
        """
    ).fetchall()

    sent = 0
    for row in rows:
        finding = dict(row)
        fid = finding.get("id")
        if not should_alert(finding, cfg):
            continue
        if already_alerted(db, fid):
            continue

        if not throttle_ok(db, cfg):
            mark_alerted(db, fid, "throttled", "suppressed by throttle")
            continue

        title, body = _format_alert(finding, cfg.get("include_evidence", False))
        ok_any = False
        for channel in cfg.get("channels", []):
            if channel == "toast":
                ok_any = send_toast(title, body) or ok_any
            elif channel == "eventlog":
                ok_any = write_eventlog(title, body, finding.get("severity")) or ok_any

        if cfg.get("sound_critical") and finding.get("severity") == "Critical":
            _play_sound()

        if ok_any:
            mark_alerted(db, fid, "multi", body)
            sent += 1
        else:
            mark_alerted(db, fid, "failed", body)

    return sent


def _format_alert(finding, include_evidence):
    severity = finding.get("severity", "Medium")
    title = f"Home Security Agent — {severity}"
    body_lines = [finding.get("title", "Finding")]

    evidence = _extract_evidence(finding.get("evidence_json"))
    if evidence:
        body_lines.append(evidence)
    if include_evidence:
        body_lines.append(f"Score: {finding.get('score')}")
    else:
        body_lines.append(f"Score: {finding.get('score')}")

    return title, "\n".join(body_lines)


def _extract_evidence(evidence_json):
    if not evidence_json:
        return ""
    try:
        data = json.loads(evidence_json)
    except Exception:
        return ""

    # Correlation structures or single-event structures
    for key in ("network", "process", "file_created", "persistence"):
        if key in data and isinstance(data[key], dict):
            ev = data[key]
            return _short_event_line(ev)

    if isinstance(data, dict):
        return _short_event_line(data)

    return ""


def _short_event_line(ev):
    image = ev.get("image") or ev.get("Image") or ""
    target = ev.get("target") or ev.get("TargetFilename") or ev.get("TargetObject") or ""
    net = ev.get("network") or {}
    dest = net.get("destination_hostname") or net.get("destination_ip") or ""

    parts = []
    if image:
        parts.append(basename(image))
    if target:
        parts.append(basename(target))
    if dest:
        parts.append(dest)
    return " → ".join([p for p in parts if p][:3])


def _play_sound():
    try:
        import winsound
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except Exception:
        pass


def _utcnow_sql():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _log_alert_error(message):
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{ts} {message}\n")
    except Exception:
        pass
