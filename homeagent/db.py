import sqlite3
from pathlib import Path
from .config import BASE_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS events_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    record_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    image TEXT,
    target TEXT,
    pid INTEGER,
    data_json TEXT,
    score INTEGER,
    severity TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events_raw(ts);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events_raw(kind);
CREATE INDEX IF NOT EXISTS idx_events_image ON events_raw(image);
CREATE INDEX IF NOT EXISTS idx_events_target ON events_raw(target);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    title TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    dedupe_key TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE INDEX IF NOT EXISTS idx_findings_sev_status ON findings(severity, status);

CREATE TABLE IF NOT EXISTS alerts_sent (
    finding_id TEXT PRIMARY KEY,
    sent_ts TEXT NOT NULL,
    channel TEXT NOT NULL,
    message TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_sent_ts ON alerts_sent(sent_ts);

CREATE TABLE IF NOT EXISTS alerts_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    data_json TEXT,
    PRIMARY KEY (entity_type, entity_key)
);

CREATE TABLE IF NOT EXISTS state (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = connect()
    db.executescript(SCHEMA)
    _ensure_schema(db)
    db.commit()
    db.close()


def _ensure_schema(db):
    _ensure_columns(
        db,
        "findings",
        {
            "ignore_reason": "TEXT",
            "ignore_notes": "TEXT",
            "ignored_ts": "TEXT",
        },
    )


def _ensure_columns(db, table, columns):
    try:
        existing = {row[1] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
    except Exception:
        existing = set()
    for name, col_type in columns.items():
        if name not in existing:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}")


def get_state(db, key):
    row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def set_state(db, key, value):
    db.execute("INSERT INTO state(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    db.commit()


def insert_event(db, event):
    db.execute(
        """
        INSERT INTO events_raw(ts, record_id, event_id, kind, image, target, pid, data_json, score, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("ts"),
            event.get("record_id"),
            event.get("event_id"),
            event.get("kind"),
            event.get("image"),
            event.get("target"),
            event.get("pid"),
            event.get("data_json"),
            event.get("score"),
            event.get("severity"),
        ),
    )
    db.commit()


def insert_finding(db, ts, severity, score, title, evidence_json, dedupe_key=None):
    try:
        db.execute(
            """
            INSERT INTO findings(ts, severity, score, title, evidence_json, status, dedupe_key)
            VALUES (?, ?, ?, ?, ?, 'open', ?)
            """,
            (ts, severity, score, title, evidence_json, dedupe_key),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def upsert_baseline(db, key, ts, data_json):
    db.execute(
        """
        INSERT INTO baseline(key, ts, data_json) VALUES(?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET ts=excluded.ts, data_json=excluded.data_json
        """,
        (key, ts, data_json),
    )
    db.commit()


def cleanup_old_events(db, retention_days):
    db.execute("DELETE FROM events_raw WHERE ts < datetime('now', ?)", (f"-{retention_days} day",))
    db.commit()
