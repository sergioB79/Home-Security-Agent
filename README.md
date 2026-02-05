# Home Security Agent

## What this is
Home Security Agent is a personal EDR-lite built on top of Sysmon.

It continuously ingests high-signal telemetry and answers questions like:
- What executed on my system?
- What changed recently?
- What tried to persist across reboots?
- What scripts talked to the network?
- Why is this behavior suspicious?

It turns raw system events into explainable findings with:
- Scoring
- Correlation
- Context
- Human-in-the-loop allowlisting

## What this is NOT
This project intentionally does not try to be a full antivirus or enterprise EDR.

It does not provide:
- Real-time blocking or prevention
- Kernel-mode detection
- Memory-only implant detection
- Credential theft detection inside trusted processes
- Nation-state / APT-grade coverage

If you want prevention, keep Windows Defender enabled.

## Recommended security posture (important)
This tool is designed to run alongside Windows Defender.

✅ Recommended
- Windows Defender enabled
- Defender AMSI + memory protections on
- Windows Hello + TPM
- Credential Guard (if supported)

Not recommended
- Disabling Defender
- Using this as your only protection
- Treating this as malware prevention

Think of Home Security Agent as:

“An always-on forensic lens, not a shield.”

## High-level architecture
```
Sysmon (kernel + service)
        ↓
Windows Event Log
        ↓
Home Security Agent (Python, user-space)
        ↓
SQLite state database
        ↓
Streamlit dashboard (on-demand)
```

- Sysmon captures telemetry (always running as a service)
- Agent polls, normalizes, scores, and correlates events
- Dashboard is read-only and only runs when opened
- No cloud. No telemetry uploads. No additional drivers.

## Key features
Behavioral correlation (not signatures)

Detects suspicious chains such as:
- Drop → Execute
- Execute → Persist
- Script → Network

Single events are cheap.
Correlated behavior is signal.

Explainable scoring

Each finding includes:
- Additive score
- Clear reasons
- Dampeners for signed binaries and allowlists

Severity bands:
- Critical (≥80)
- High (60–79)
- Medium (35–59)
- Low (<35)

Human-friendly dashboard
- Priority queue for High / Critical findings
- Process chains, file drops, persistence, and network views
- One-click registry and scheduled task lookups
- Exports for offline analysis

Targeted allowlisting (no blind spots)
- Allowlisting affects future scoring only.
- Supported allowlists:
  - File hashes
  - Signed publishers
  - Targeted behavioral rules
    (e.g. PowerShell writing a specific Run key)
- Existing findings remain visible until explicitly ignored.

Alerting (quiet but real)
- Windows toast notifications
- Windows Event Log entries
- Deduplication and throttling
- Alert failure logging

You are notified only when correlated behavior crosses severity thresholds.

## Requirements
OS
- Windows 11

Telemetry
- Sysmon installed and configured (quiet, signal-focused config)

Runtime
- Python 3.11+

Python dependencies

Install with:
```
pip install -r requirements.txt
```

## Quick start (manual)
Run the agent:
```
python agent.py
```

Run the dashboard:
```
streamlit run dashboard.py
```

## Always-on operation
The agent is designed to run via Task Scheduler:
- Runs at system startup
- Runs with highest privileges (SYSTEM)
- Restarts automatically if stopped

Sysmon itself:
- Runs as a Windows service + kernel driver
- Starts automatically at boot
- Does not use Task Scheduler

## Data & privacy
- All data stays local
- SQLite database stored under `C:\ProgramData\HomeAgent`
- No cloud uploads
- No telemetry collection
- No background dashboard process

If you open the Streamlit UI, you can disable Streamlit usage statistics
(as documented in Streamlit’s privacy policy).

## Typical workflow
- Agent runs quietly in the background
- Sysmon logs raw telemetry
- Agent correlates behavior
- Only meaningful findings surface
- You inspect, allowlist, or investigate
- System returns to a quiet state

If everything is quiet — that’s a good sign.

## Who this is for
This project is for:
- Power users
- Developers
- Security-curious users
- People who want visibility instead of guesswork

It is not intended for:
- Non-technical users
- Enterprise environments
- Automated response scenarios

## Why this exists
Most consumer antivirus software:
- Hides evidence
- Explains nothing
- Encourages blind trust

Home Security Agent exists to do the opposite:
- Show you what happened
- Explain why it matters
- Let you decide what’s normal on your machine

## Status
Stable (v1.x)
Actively used on a daily Windows 11 system.

The project favors clarity and restraint over feature creep.
