import json
from datetime import datetime, timezone


def utcnow_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(ts):
    if not ts:
        return None
    if ts.endswith("Z"):
        ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts)


def to_dt(ts):
    return parse_ts(ts)


def json_dumps(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def normalize_path(path):
    return (path or "").strip().lower()


def basename(path):
    if not path:
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()
