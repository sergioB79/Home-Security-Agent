import json
import io
import zipfile
import subprocess
import yaml
from datetime import datetime
import streamlit as st
import pandas as pd
from homeagent.db import connect, get_state, init_db
from homeagent.config import ALERT_MIN_SEVERITY, ALERT_LOG_PATH, ALLOWLIST_PATH
from homeagent.alerts import send_toast, write_eventlog
from homeagent.utils import parse_ts, to_dt, utcnow_iso

st.set_page_config(page_title="Home Security Agent", layout="wide")

st.title("Home Security Agent")

try:
    init_db()
    db = connect()
except Exception as exc:
    st.error(f"Database not available: {exc}")
    st.stop()

last_ingest = get_state(db, "last_ingest_ts")
status_col1, status_col2, status_col3, status_col4, status_col5 = st.columns(5)

with status_col1:
    st.metric("Agent status", "Running" if last_ingest else "Unknown")
with status_col2:
    st.metric("Last ingest", last_ingest or "Never")
with status_col3:
    row = db.execute("SELECT COUNT(*) AS c FROM events_raw WHERE ts >= datetime('now','-1 day')").fetchone()
    st.metric("Events (24h)", int(row[0]) if row else 0)
with status_col4:
    row = db.execute("SELECT COUNT(*) FROM findings WHERE status='open' AND (severity='High' OR severity='Critical')").fetchone()
    st.metric("Open High/Critical", int(row[0]) if row else 0)
with status_col5:
    row = db.execute("SELECT sent_ts FROM alerts_sent WHERE channel!='throttled' ORDER BY sent_ts DESC LIMIT 1").fetchone()
    st.metric("Last alert sent", row[0] if row else "Never")

st.divider()

tabs = st.tabs(["Overview", "Telemetry", "Findings", "Process Chains", "File Drops", "Persistence", "Network", "Allowlist", "Export"])

with tabs[0]:
    st.subheader("Overview")
    st.write("System health and key numbers.")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Latest findings**")
        latest = pd.read_sql_query(
            "SELECT ts, severity, title FROM findings ORDER BY ts DESC LIMIT 5",
            db,
        )
        if latest.empty:
            st.write("No findings yet.")
        else:
            st.dataframe(latest, use_container_width=True, hide_index=True)
    with col_b:
        st.markdown("**Noisiest processes (24h)**")
        noisy = pd.read_sql_query(
            "SELECT image, COUNT(*) AS c FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY image ORDER BY c DESC LIMIT 5",
            db,
        )
        if noisy.empty:
            st.write("No recent events.")
        else:
            noisy["image"] = noisy["image"].fillna("(unknown)")
            st.dataframe(noisy, use_container_width=True, hide_index=True)
    st.markdown("**Open High/Critical findings (priority)**")
    priority = pd.read_sql_query(
        "SELECT id, ts, severity, score, title, status, evidence_json FROM findings WHERE status='open' AND (severity='High' OR severity='Critical') ORDER BY ts DESC LIMIT 50",
        db,
    )
    sel_row = None
    if priority.empty:
        st.write("No open High/Critical findings.")
    else:
        def _extract_details(evidence_json):
            try:
                data = json.loads(evidence_json) if evidence_json else {}
            except Exception:
                data = {}

            def _get(d, *keys):
                for k in keys:
                    if isinstance(d, dict) and k in d and d[k]:
                        return d[k]
                return ""

            process = data.get("process") if isinstance(data, dict) else {}
            persistence = data.get("persistence") if isinstance(data, dict) else {}

            image = _get(process, "image") or _get(data, "image") or _get(data, "Image")
            parent_image = _get(process, "parent_image") or _get(data, "parent_image") or _get(data, "ParentImage")
            persistence_target = _get(persistence, "target") or _get(data, "target") or _get(data, "TargetObject")
            return image or "", parent_image or "", persistence_target or ""

        details = priority["evidence_json"].apply(lambda s: _extract_details(s))
        priority["image"] = details.apply(lambda x: x[0])
        priority["parent_image"] = details.apply(lambda x: x[1])
        priority["persistence_target"] = details.apply(lambda x: x[2])
        view_cols = ["id", "ts", "severity", "score", "title", "image", "parent_image", "persistence_target"]
        st.dataframe(priority[view_cols], use_container_width=True, hide_index=True)

        st.markdown("**Run key lookup (HKCU/HKLM)**")
        search = st.text_input("Filter findings (id, title, image)", value="", key="priority_filter")
        if search:
            mask = (
                priority["id"].astype(str).str.contains(search, case=False, na=False)
                | priority["title"].str.contains(search, case=False, na=False)
                | priority["image"].str.contains(search, case=False, na=False)
            )
            filtered = priority[mask]
        else:
            filtered = priority
        if filtered.empty:
            st.warning("No findings match the filter.")
            sel_row = None
        else:
            labels = filtered.apply(
                lambda r: f"{r['id']} | {r['severity']} | {r['title']} | {r['image']}", axis=1
            ).tolist()
            sel_idx = st.selectbox("Select a finding", list(range(len(labels))), format_func=lambda i: labels[i], key="priority_select")
        sel_row = filtered.iloc[sel_idx]
        sel_image = sel_row["image"] if sel_row is not None else ""
    if sel_row is not None:
        st.markdown("**Ignore finding**")
        reason = st.selectbox(
            "Reason",
            ["Benign updater", "Expected startup", "My software", "Other"],
            index=0,
            key="ignore_reason",
        )
        notes = st.text_input("Notes (optional)", value="", key="ignore_notes")
        if st.button("Mark finding ignored"):
            try:
                db.execute(
                    "UPDATE findings SET status='ignored', ignore_reason=?, ignore_notes=?, ignored_ts=datetime('now') WHERE id=?",
                    (reason, notes, int(sel_row["id"])),
                )
                db.commit()
                st.success("Marked as ignored.")
            except Exception as exc:
                st.error(f"Failed to update finding: {exc}")

        st.markdown("**Targeted allowlist (for this finding)**")
    if sel_row is not None:
        rule_name = st.text_input("Rule name", value="targeted allowlist", key="al_rule_name")
        rule_kind = st.selectbox("Kind", ["registry", "process", "network", "file_create"], index=0, key="al_rule_kind")
        image_equals = st.text_input("image_equals", value="powershell.exe", key="al_image_equals")
        persistence_target = st.text_input("persistence_target_contains", value=sel_row.get("persistence_target", ""), key="al_persist_contains")
        score_delta = st.number_input("score_delta", value=-40, step=5, key="al_score_delta")
        rule_note = st.text_input("Rule note (optional)", value="", key="al_rule_note")

        if st.button("Add targeted allowlist rule"):
            try:
                data = yaml.safe_load(ALLOWLIST_PATH.read_text(encoding="utf-8")) if ALLOWLIST_PATH.exists() else {}
                if not isinstance(data, dict):
                    data = {}
                rules = data.get("targeted_rules", []) or []
                new_rule = {
                    "name": rule_name,
                    "kind": rule_kind,
                    "image_equals": image_equals,
                    "persistence_target_contains": persistence_target,
                    "score_delta": int(score_delta),
                    "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                    "created_from_finding_id": int(sel_row["id"]),
                    "note": rule_note,
                }
                # Avoid exact duplicates
                if new_rule not in rules:
                    rules.append(new_rule)
                    data["targeted_rules"] = rules
                    ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
                    ALLOWLIST_PATH.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
                    auto_ignore = bool(image_equals and persistence_target)
                    if auto_ignore:
                        auto_note = notes or rule_note or "Auto-ignored after targeted allowlist rule"
                        db.execute(
                            "UPDATE findings SET status='ignored', ignore_reason=?, ignore_notes=?, ignored_ts=datetime('now') WHERE id=?",
                            ("Allowlist rule", auto_note, int(sel_row["id"])),
                        )
                        db.commit()
                        st.success("Rule added and finding auto-ignored.")
                    else:
                        st.success("Targeted allowlist rule added. Finding not auto-ignored (rule too broad).")
                else:
                    st.info("Rule already exists.")
            except Exception as exc:
                st.error(f"Failed to update allowlist: {exc}")
        if st.button("Query HKCU Run entries for this process"):
            if not sel_image:
                st.warning("No image path available for this finding.")
            else:
                try:
                    cmd = [
                        "powershell",
                        "-Command",
                        "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | ConvertTo-Json",
                    ]
                    output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
                    data = json.loads(output) if output else {}
                    matches = {}
                    for k, v in data.items():
                        if isinstance(v, str) and sel_image.lower() in v.lower():
                            matches[k] = v
                    if not matches:
                        st.info("No matching Run entries found for this process.")
                    else:
                        st.json(matches)
                except Exception as exc:
                    st.error(f"Run key query failed: {exc}")

        if st.button("Query HKLM Run/RunOnce (and Wow6432Node)"):
            if not sel_image:
                st.warning("No image path available for this finding.")
            else:
                try:
                    ps = """
$paths = @(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
$out = @()
foreach ($p in $paths) {
  try {
    $props = Get-ItemProperty $p
    $props.PSObject.Properties | ForEach-Object {
      if ($_.Name -notlike 'PS*') {
        $out += [PSCustomObject]@{ Path=$p; Name=$_.Name; Value=$_.Value }
      }
    }
  } catch {}
}
$out | ConvertTo-Json
"""
                    output = subprocess.check_output(["powershell", "-Command", ps], text=True, stderr=subprocess.STDOUT)
                    data = json.loads(output) if output else []
                    if isinstance(data, dict):
                        data = [data]
                    matches = [r for r in data if isinstance(r, dict) and sel_image.lower() in str(r.get("Value", "")).lower()]
                    if not matches:
                        st.info("No matching HKLM Run/RunOnce entries found.")
                    else:
                        st.json(matches)
                except Exception as exc:
                    st.error(f"HKLM Run query failed: {exc}")

        st.markdown("**Scheduled Tasks lookup (targeted)**")
        if st.button("Find scheduled tasks that reference this process"):
            if not sel_image:
                st.warning("No image path available for this finding.")
            else:
                try:
                    output = subprocess.check_output(["schtasks", "/Query", "/FO", "CSV", "/V"], text=True, stderr=subprocess.STDOUT)
                    import csv
                    from io import StringIO
                    reader = csv.DictReader(StringIO(output))
                    image_l = sel_image.lower()
                    dir_l = "\\".join(sel_image.lower().split("\\")[:-1])
                    matches = []
                    for row in reader:
                        action = (row.get("Task To Run") or "").lower()
                        if image_l in action or (dir_l and dir_l in action):
                            matches.append({
                                "TaskName": row.get("TaskName"),
                                "Triggers": row.get("Schedule"),
                                "Action": row.get("Task To Run"),
                                "Principal": row.get("Run As User"),
                            })
                    if not matches:
                        st.info("No scheduled tasks matched this process.")
                    else:
                        st.json(matches)
                except Exception as exc:
                    st.error(f"Scheduled tasks query failed: {exc}")

        st.markdown("**Startup folder lookup**")
        if st.button("Find startup shortcuts referencing this process"):
            if not sel_image:
                st.warning("No image path available for this finding.")
            else:
                try:
                    ps = """
$paths = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
$shell = New-Object -ComObject WScript.Shell
$out = @()
foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-ChildItem -Path $p -Filter *.lnk | ForEach-Object {
      try {
        $sc = $shell.CreateShortcut($_.FullName)
        $out += [PSCustomObject]@{
          Path = $_.FullName
          Target = $sc.TargetPath
        }
      } catch {}
    }
  }
}
$out | ConvertTo-Json
"""
                    output = subprocess.check_output(["powershell", "-Command", ps], text=True, stderr=subprocess.STDOUT)
                    data = json.loads(output) if output else []
                    if isinstance(data, dict):
                        data = [data]
                    matches = [r for r in data if isinstance(r, dict) and sel_image.lower() in str(r.get("Target", "")).lower()]
                    if not matches:
                        st.info("No startup shortcuts matched this process.")
                    else:
                        st.json(matches)
                except Exception as exc:
                    st.error(f"Startup folder query failed: {exc}")

    st.markdown("**Recent activity (24h)**")
    recent = pd.read_sql_query(
        "SELECT event_id, COUNT(*) AS count FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY event_id ORDER BY count DESC",
        db,
    )
    if recent.empty:
        st.write("No recent events.")
    else:
        st.bar_chart(recent.set_index("event_id"))
    if st.button("Send test alert"):
        title = "Home Security Agent — Medium"
        body = "Test Alert\nDashboard test\nScore: 45"
        toast_ok = send_toast(title, body)
        event_ok = write_eventlog(title, body, "Medium")
        if toast_ok or event_ok:
            st.success("Test alert sent.")
        else:
            st.error("Test alert failed. Check alerts.log.")

with tabs[1]:
    st.subheader("Telemetry")
    df = pd.read_sql_query(
        "SELECT ts, event_id FROM events_raw WHERE ts >= datetime('now','-1 day')",
        db,
    )
    if df.empty:
        st.info("No recent events.")
    else:
        df["ts"] = pd.to_datetime(df["ts"])
        by_hour = df.set_index("ts").groupby([pd.Grouper(freq="1H"), "event_id"]).size().unstack(fill_value=0)
        st.line_chart(by_hour)
        by_type = df.groupby("event_id").size().reset_index(name="count")
        st.bar_chart(by_type.set_index("event_id"))

with tabs[2]:
    st.subheader("Findings")
    only_alerting = st.checkbox("Show only alerting severities", value=False)
    show_ignored = st.checkbox("Show ignored findings only", value=False, disabled=only_alerting)
    if only_alerting:
        min_sev = ALERT_MIN_SEVERITY
        sev_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        allowed = [k for k, v in sev_order.items() if v >= sev_order.get(min_sev, 1)]
        placeholders = ",".join(["?"] * len(allowed))
        if show_ignored:
            status_clause = "AND status='ignored'"
        else:
            status_clause = "AND status='open'"
        query = f"SELECT id, ts, severity, score, title, status, ignore_reason, ignore_notes FROM findings WHERE severity IN ({placeholders}) {status_clause} ORDER BY ts DESC LIMIT 200"
        fdf = pd.read_sql_query(query, db, params=allowed)
    else:
        status_clause = "WHERE status='ignored'" if show_ignored else "WHERE status='open'"
        fdf = pd.read_sql_query(
            f"SELECT id, ts, severity, score, title, status, ignore_reason, ignore_notes FROM findings {status_clause} ORDER BY ts DESC LIMIT 200",
            db,
        )
    total_row = db.execute("SELECT COUNT(*) FROM findings").fetchone()
    total_count = int(total_row[0]) if total_row else 0
    open_row = db.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()
    open_count = int(open_row[0]) if open_row else 0
    ignored_row = db.execute("SELECT COUNT(*) FROM findings WHERE status='ignored'").fetchone()
    ignored_count = int(ignored_row[0]) if ignored_row else 0

    if only_alerting:
        placeholders = ",".join(["?"] * len(allowed))
        status_clause = "AND status='ignored'" if show_ignored else "AND status='open'"
        count_query = f"SELECT COUNT(*) FROM findings WHERE severity IN ({placeholders}) {status_clause}"
        count_row = db.execute(count_query, tuple(allowed)).fetchone()
        filter_desc = f"alerting≥{ALERT_MIN_SEVERITY}, status=" + ("ignored" if show_ignored else "open")
    else:
        status_clause = "WHERE status='ignored'" if show_ignored else "WHERE status='open'"
        count_query = f"SELECT COUNT(*) FROM findings {status_clause}"
        count_row = db.execute(count_query).fetchone()
        filter_desc = "all severities, status=" + ("ignored" if show_ignored else "open")

    filtered_count = int(count_row[0]) if count_row else 0
    limit = 200
    shown = len(fdf)
    st.caption(f"Filter: {filter_desc} | Open: {open_count} | Ignored: {ignored_count} | Total: {total_count}")
    if shown >= limit:
        st.caption(f"Showing first {shown} of {filtered_count} filtered findings")
    else:
        st.caption(f"Showing {shown} of {filtered_count} filtered findings")

    if fdf.empty:
        st.info("No findings yet.")
    else:
        st.dataframe(fdf, use_container_width=True)
        fid = st.selectbox("Select a finding", fdf["id"].tolist())
        row = db.execute("SELECT evidence_json FROM findings WHERE id=?", (int(fid),)).fetchone()
        if row:
            st.code(row[0], language="json")

with tabs[3]:
    st.subheader("Process Chains")
    cdf = pd.read_sql_query(
        "SELECT ts, title, evidence_json FROM findings WHERE title LIKE 'Script → Network%' OR title LIKE 'Drop → Execute%' ORDER BY ts DESC LIMIT 50",
        db,
    )
    if cdf.empty:
        st.info("No correlated chains yet.")
    else:
        st.dataframe(cdf, use_container_width=True)

with tabs[4]:
    st.subheader("File Drops")
    df = pd.read_sql_query(
        "SELECT ts, image, target, score, severity FROM events_raw WHERE kind='file_create' ORDER BY ts DESC LIMIT 200",
        db,
    )
    if df.empty:
        st.info("No file drops yet.")
    else:
        st.dataframe(df, use_container_width=True)

with tabs[5]:
    st.subheader("Persistence")
    row = db.execute("SELECT data_json FROM baseline WHERE key='persistence'").fetchone()
    if not row:
        st.info("No baseline yet. Wait for the daily snapshot.")
    else:
        st.code(row[0], language="json")

with tabs[6]:
    st.subheader("Network (filtered)")
    df = pd.read_sql_query(
        "SELECT ts, image, target, score, severity FROM events_raw WHERE kind='network' ORDER BY ts DESC LIMIT 200",
        db,
    )
    if df.empty:
        st.info("No network events yet.")
    else:
        st.dataframe(df, use_container_width=True)

with tabs[7]:
    st.subheader("Allowlist")
    try:
        allowlist = yaml.safe_load(ALLOWLIST_PATH.read_text(encoding="utf-8")) if ALLOWLIST_PATH.exists() else {}
        if not isinstance(allowlist, dict):
            allowlist = {}
    except Exception as exc:
        st.error(f"Failed to load allowlist: {exc}")
        allowlist = {}

    hashes = allowlist.get("hashes", []) or []
    publishers = allowlist.get("publishers", []) or []
    rules = allowlist.get("targeted_rules", []) or []

    st.markdown("**Hashes**")
    if hashes:
        st.dataframe(pd.DataFrame({"hash": hashes}), use_container_width=True, hide_index=True)
    else:
        st.write("No hashes allowlisted.")

    st.markdown("**Publishers**")
    if publishers:
        st.dataframe(pd.DataFrame({"publisher": publishers}), use_container_width=True, hide_index=True)
    else:
        st.write("No publishers allowlisted.")

    st.markdown("**Targeted rules**")
    if rules:
        df_rules = pd.DataFrame(rules)
        if "note" not in df_rules.columns:
            df_rules["note"] = ""
        st.dataframe(df_rules.fillna(""), use_container_width=True, hide_index=True)
    else:
        st.write("No targeted rules allowlisted.")

with tabs[8]:
    st.subheader("Export")
    st.write("Export data for sharing or offline review.")
    export_type = st.selectbox(
        "Choose what to export",
        ["All", "Overview summary", "Priority (High/Critical findings)", "Telemetry (events_raw)", "Findings", "Baseline", "Observations", "Alert log"],
    )

    def _export_dataframe(query, filename):
        df = pd.read_sql_query(query, db)
        if df.empty:
            st.info("No data available for this export.")
            return
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV", data=csv, file_name=filename, mime="text/csv")

    def _zip_export(file_map, zip_name):
        if not file_map:
            st.info("No data available for this export.")
            return
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in file_map.items():
                if content:
                    zf.writestr(name, content)
        st.download_button("Download ZIP", data=buf.getvalue(), file_name=zip_name, mime="application/zip")

    if export_type == "Overview summary":
        overview = {
            "latest_findings": pd.read_sql_query(
                "SELECT ts, severity, title FROM findings ORDER BY ts DESC LIMIT 5",
                db,
            ).to_dict(orient="records"),
            "noisiest_processes_24h": pd.read_sql_query(
                "SELECT image, COUNT(*) AS c FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY image ORDER BY c DESC LIMIT 5",
                db,
            ).to_dict(orient="records"),
            "recent_activity_24h": pd.read_sql_query(
                "SELECT event_id, COUNT(*) AS count FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY event_id ORDER BY count DESC",
                db,
            ).to_dict(orient="records"),
        }
        payload = json.dumps(overview, ensure_ascii=True).encode("utf-8")
        _zip_export({"overview_summary.json": payload}, "overview_summary.zip")
    elif export_type == "Priority (High/Critical findings)":
        df = pd.read_sql_query(
            "SELECT * FROM findings WHERE status='open' AND (severity='High' OR severity='Critical') ORDER BY ts DESC",
            db,
        )
        if df.empty:
            st.info("No open High/Critical findings.")
        else:
            def _extract_details(evidence_json):
                try:
                    data = json.loads(evidence_json) if evidence_json else {}
                except Exception:
                    data = {}

                def _get(d, *keys):
                    for k in keys:
                        if isinstance(d, dict) and k in d and d[k]:
                            return d[k]
                    return ""

                process = data.get("process") if isinstance(data, dict) else {}
                persistence = data.get("persistence") if isinstance(data, dict) else {}

                image = _get(process, "image") or _get(data, "image") or _get(data, "Image")
                parent_image = _get(process, "parent_image") or _get(data, "parent_image") or _get(data, "ParentImage")
                persistence_target = _get(persistence, "target") or _get(data, "target") or _get(data, "TargetObject")
                return image or "", parent_image or "", persistence_target or ""

            details = df["evidence_json"].apply(lambda s: _extract_details(s))
            df["image"] = details.apply(lambda x: x[0])
            df["parent_image"] = details.apply(lambda x: x[1])
            df["persistence_target"] = details.apply(lambda x: x[2])
            _zip_export({"priority_findings.csv": df.to_csv(index=False).encode("utf-8")}, "priority_findings.zip")
    elif export_type == "Alert log":
        if not ALERT_LOG_PATH.exists():
            st.info("No alert log available.")
        else:
            content = ALERT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").encode("utf-8")
            _zip_export({"alerts.log": content}, "alerts_log.zip")
    elif export_type == "Telemetry (events_raw)":
        df = pd.read_sql_query("SELECT * FROM events_raw ORDER BY ts DESC", db)
        if df.empty:
            st.info("No data available for this export.")
        else:
            _zip_export({"telemetry_events_raw.csv": df.to_csv(index=False).encode("utf-8")}, "telemetry_export.zip")
    elif export_type == "Findings":
        df = pd.read_sql_query("SELECT * FROM findings ORDER BY ts DESC", db)
        if df.empty:
            st.info("No data available for this export.")
        else:
            _zip_export({"findings.csv": df.to_csv(index=False).encode("utf-8")}, "findings_export.zip")
    elif export_type == "Baseline":
        df = pd.read_sql_query("SELECT * FROM baseline ORDER BY ts DESC", db)
        if df.empty:
            st.info("No data available for this export.")
        else:
            _zip_export({"baseline.csv": df.to_csv(index=False).encode("utf-8")}, "baseline_export.zip")
    elif export_type == "Observations":
        df = pd.read_sql_query("SELECT * FROM observations ORDER BY last_seen DESC", db)
        if df.empty:
            st.info("No data available for this export.")
        else:
            _zip_export({"observations.csv": df.to_csv(index=False).encode("utf-8")}, "observations_export.zip")
    else:
        files = {}
        df = pd.read_sql_query("SELECT * FROM events_raw ORDER BY ts DESC", db)
        if not df.empty:
            files["telemetry_events_raw.csv"] = df.to_csv(index=False).encode("utf-8")
        df = pd.read_sql_query("SELECT * FROM findings ORDER BY ts DESC", db)
        if not df.empty:
            files["findings.csv"] = df.to_csv(index=False).encode("utf-8")
        df = pd.read_sql_query("SELECT * FROM baseline ORDER BY ts DESC", db)
        if not df.empty:
            files["baseline.csv"] = df.to_csv(index=False).encode("utf-8")
        df = pd.read_sql_query("SELECT * FROM observations ORDER BY last_seen DESC", db)
        if not df.empty:
            files["observations.csv"] = df.to_csv(index=False).encode("utf-8")
        overview = {
            "latest_findings": pd.read_sql_query(
                "SELECT ts, severity, title FROM findings ORDER BY ts DESC LIMIT 5",
                db,
            ).to_dict(orient="records"),
            "noisiest_processes_24h": pd.read_sql_query(
                "SELECT image, COUNT(*) AS c FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY image ORDER BY c DESC LIMIT 5",
                db,
            ).to_dict(orient="records"),
            "recent_activity_24h": pd.read_sql_query(
                "SELECT event_id, COUNT(*) AS count FROM events_raw WHERE ts >= datetime('now','-1 day') GROUP BY event_id ORDER BY count DESC",
                db,
            ).to_dict(orient="records"),
        }
        files["overview_summary.json"] = json.dumps(overview, ensure_ascii=True).encode("utf-8")
        if ALERT_LOG_PATH.exists():
            files["alerts.log"] = ALERT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").encode("utf-8")
        _zip_export(files, "homeagent_export_all.zip")
