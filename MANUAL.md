# Home Security Agent — User Manual (Windows 11)

This document describes setup, operation, dashboard features, alerting, allowlisting, exports, and maintenance.

---

## 1) What this is
A lightweight host integrity and threat visibility system. It **observes and explains**. It does not block.

Core questions it helps answer:
- What changed?
- What executed?
- What persisted?
- What talked to the network when it shouldn’t?

---

## 1.1) What this will NOT detect (explicit checklist)

This tool intentionally does **not** cover:
- Kernel rootkits / kernel‑mode malware
- Memory‑only implants with no disk or registry footprint
- Signed driver abuse
- Live credential theft in trusted processes
- Nation‑state or APT‑grade tradecraft

This is a **home / power‑user** visibility tool, not an EDR.

---

## 2) Requirements

### Windows
- Windows 11
- Sysmon installed and configured with your tuned “quiet” config

### Python
- Python 3.11+

### Python packages
Installed via:

```
pip install -r requirements.txt
```

Packages include:
- pywin32 (Event Log / system access)
- streamlit (dashboard)
- pandas (visualization)
- PyYAML (allowlist)
- win11toast (Windows notifications)

---

## 3) Folder layout

Project root:
- `agent.py` — entry point for the agent loop
- `dashboard.py` — Streamlit dashboard
- `homeagent/` — core modules
- `requirements.txt`
- `README.md`

System data:
- Database: `C:\ProgramData\HomeAgent\state.db`
- Allowlist: `C:\ProgramData\HomeAgent\allowlist.yml`
- Alerts log: `C:\ProgramData\HomeAgent\alerts.log`

---

## 4) Install & run

### Install dependencies
```
pip install -r requirements.txt
```

### Run the agent (manual)
```
python agent.py
```

### Run the dashboard (manual)
```
streamlit run dashboard.py
```

---

## 5) Start at boot (always-on)

We use Task Scheduler for reliable startup and restart.

Run the installer script as admin:
```
powershell -ExecutionPolicy Bypass -File install_task.ps1
```

This creates a task named **Home Security Agent** that runs at startup as SYSTEM.

### One‑click installer (deploy package)
If you’re using the `deploy` folder on a new PC, run:
```
powershell -ExecutionPolicy Bypass -File install_oneclick.ps1
```
This will:
- Install Python dependencies
- Register the startup task
- Create a desktop shortcut for the dashboard

---

## 6) Architecture overview

```
Sysmon → Windows Event Log → Agent (Python) → SQLite DB → Dashboard (on‑demand)
```

The agent:
- Polls Sysmon log every ~20s
- Normalizes events
- Scores + correlates
- Stores in SQLite
- Triggers alerts for new findings

The dashboard:
- Reads SQLite only
- Does not run continuously unless you open it

---

## 7) What data is ingested

From Sysmon:
- Event ID 1 — Process execution
- Event ID 3 — Network connections (filtered by config)
- Event ID 11 — File creation (executables/scripts)
- Event ID 12/13/14 — Registry persistence
- Event ID 16 — Config changes (meta only)

Additionally, daily snapshots:
- Startup folders
- Run / RunOnce keys
- Scheduled tasks
- Services
- Hashes of new executables in writable paths

---

## 8) Findings, scoring & correlation

### Scoring (additive, explainable)
Examples:
- Executable launched from writable path → +50
- Office/browser spawning script engine → +35
- PowerShell encoded command → +40
- Persistence pointing to writable path → +60

Dampeners:
- Microsoft‑signed binary → −40
- Allowlisted publisher → −30
- Allowlisted hash → −30

Severity:
- ≥80 Critical
- 60–79 High
- 35–59 Medium
- <35 Low

### Correlation rules
- **Drop → Execute** (file created then launched)
- **Execute → Persist** (process then persistence)
- **Script → Network** (script engine + outbound net)

Each correlation produces one finding.

---

## 9) Alerts & notifications

Alerts trigger for new findings when:
- status == `open`
- severity ≥ ALERT_MIN_SEVERITY (default Medium)
- not already alerted
- throttle not exceeded

Default channels:
- Windows toast
- Windows Event Log (Application)

Note: Default is Medium; many users choose High for quieter operation.

Dedup:
- Each finding is alerted once (tracked in `alerts_sent` table)

Throttle:
- Default max 3 alerts per 10 minutes

If a toast or event log fails, the error is recorded in:
`C:\ProgramData\HomeAgent\alerts.log`

### Configurable alert settings
`homeagent/config.py`:
- `ALERT_MIN_SEVERITY`
- `ALERT_CHANNELS`
- `ALERT_THROTTLE_MAX`
- `ALERT_THROTTLE_WINDOW_SEC`
- `ALERT_INCLUDE_EVIDENCE`
- `ALERT_SOUND_CRITICAL`

---

## 10) Dashboard guide

### Overview tab
- Latest findings
- Noisiest processes (24h)
- Open High/Critical (priority table)
- Recent activity chart
- Test alert button

Priority table includes:
- id, timestamp, severity, score, title
- image, parent_image, persistence_target

Actions (for selected finding):
- Ignore with reason + notes
- Add targeted allowlist rule (auto‑ignore if rule is specific)
- Lookups:
  - HKCU Run
  - HKLM Run/RunOnce (+ Wow6432Node)
  - Scheduled tasks (targeted)
  - Startup folder shortcuts

### Findings tab
- Full table of findings
- Filter to alerting severities
- Show ignored findings

### Telemetry / Process Chains / File Drops / Persistence / Network
- Raw event visibility by category

### Allowlist tab
- Shows hashes
- Shows publishers
- Shows targeted rules with metadata

### Export tab
- Export everything or specific slices as ZIP
- Includes overview summary, findings, telemetry, baseline, observations, alerts.log

---

## 11) Allowlist

Location:
`C:\ProgramData\HomeAgent\allowlist.yml`

### Supported allowlist types
- `hashes` — allow by SHA256
- `publishers` — allow by signed publisher
- `targeted_rules` — narrow suppressions

### Targeted rule format
```
targeted_rules:
  - name: discord run key updates
    kind: registry
    image_equals: powershell.exe
    persistence_target_contains: \Run\Discord
    score_delta: -40
    created_at: 2026-02-05 14:22:00
    created_from_finding_id: 123
    note: Discord updater wrote Run key
```

### Auto‑ignore guardrails
Auto‑ignore only happens when the rule includes both:
- `image_equals`
- `persistence_target_contains`

Broad rules will **not** auto‑ignore.

---

## 12) Ignoring findings

“Ignored” means:
- Status changes to `ignored`
- No longer counts in “Open High/Critical”
- No longer triggers alerts
- Evidence remains in DB (audit trail)

You can ignore from the Overview tab with a reason + note.

---

## 12.1) Incident response playbook (simple)

### If you get a High or Critical alert
1) **Do not click or execute unknown files.**\n
2) In the dashboard, open the finding and review:\n
   - `image`, `parent_image`, `persistence_target`\n
   - Correlation context (Drop→Execute, Execute→Persist, Script→Network)\n
3) If it’s unfamiliar:\n
   - Disconnect from the network (optional but safest)\n
   - Check HKCU/HKLM Run, Tasks, and Startup shortcuts (built‑in buttons)\n
4) If it’s a known app update or expected startup:\n
   - Add a **targeted allowlist** rule (image + persistence target)\n
   - Auto‑ignore will close the finding\n
5) If it looks malicious:\n
   - Quarantine the file manually (do not run it)\n
   - Run Windows Defender full scan\n
   - Export the finding + logs for offline review\n

---

## 13) Troubleshooting

### “Agent status: Unknown / Last ingest: Never”
- Agent not running
- Sysmon not installed or no events
- Permission issue reading Sysmon logs

Fix:
- Run agent as admin or via Task Scheduler (SYSTEM)
- Check Sysmon Operational log in Event Viewer

### Toasts not showing
- Focus Assist / Do Not Disturb may suppress notifications
- Ensure `win11toast` is installed

### Errors in dashboard
- Restart Streamlit after changes
- If DB schema changed, dashboard runs `init_db()` automatically

---

## 13.1) Sysmon health monitoring

To keep telemetry reliable:\n
- Ensure Sysmon service is running\n
- Ensure Sysmon Operational log is receiving events\n
- If events stop for hours, restart Sysmon service\n
- Unexpected Sysmon stoppage is rare and may indicate system instability\n

Quick checks:\n
1) Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational\n
2) Confirm recent events exist\n
3) If empty, verify Sysmon is installed and configuration is active\n

Optional CLI check:\n
```\nsc query sysmon\n```\n
```\nGet-WinEvent -LogName \"Microsoft-Windows-Sysmon/Operational\" -MaxEvents 5\n```\n

---

## 14) Maintenance

- Database retention: 14 days (events_raw)
- Weekly cleanup runs automatically
- Daily snapshots run automatically

---

## 15) Safe operating practices

- Do not disable Defender or OS protections; this tool complements them
- Use targeted allowlists instead of blanket suppressions
- Keep “High/Critical” clean so they stay meaningful

---

## 16) Quick reference

Start agent:
```
python agent.py
```

Start dashboard:
```
streamlit run dashboard.py
```

Task install:
```
powershell -ExecutionPolicy Bypass -File install_task.ps1
```

Data paths:
- `C:\ProgramData\HomeAgent\state.db`
- `C:\ProgramData\HomeAgent\allowlist.yml`
- `C:\ProgramData\HomeAgent\alerts.log`
