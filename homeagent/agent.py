import time
from datetime import datetime, timezone

from .config import INGEST_POLL_SECONDS, RETENTION_DAYS
from .db import init_db, connect, get_state, set_state, cleanup_old_events
from .ingest import ingest_once
from .snapshots import run_daily_snapshots
from .utils import utcnow_iso
from .allowlist import ensure_allowlist
from .alerts import alert_new_findings, alert_config


def run():
    init_db()
    ensure_allowlist()
    db = connect()

    while True:
        last_record = get_state(db, "last_record_id")
        last_record_id = int(last_record) if last_record else 0

        try:
            processed, new_last = ingest_once(db, last_record_id)
            if new_last != last_record_id:
                set_state(db, "last_record_id", str(new_last))
            set_state(db, "last_ingest_ts", utcnow_iso())
        except Exception:
            # Fail closed: keep loop alive and try next cycle
            pass

        try:
            alert_new_findings(db, alert_config())
        except Exception:
            pass

        _maybe_run_daily(db)
        _maybe_run_weekly(db)

        time.sleep(INGEST_POLL_SECONDS)


def _maybe_run_daily(db):
    last = get_state(db, "last_daily_snapshot")
    today = datetime.now(timezone.utc).date().isoformat()
    if last != today:
        try:
            run_daily_snapshots(db)
            set_state(db, "last_daily_snapshot", today)
        except Exception:
            pass


def _maybe_run_weekly(db):
    last = get_state(db, "last_weekly_cleanup")
    week = datetime.now(timezone.utc).isocalendar().week
    key = f"{datetime.now(timezone.utc).year}-W{week}"
    if last != key:
        try:
            cleanup_old_events(db, RETENTION_DAYS)
            set_state(db, "last_weekly_cleanup", key)
        except Exception:
            pass
