import os
from pathlib import Path

PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))
BASE_DIR = PROGRAM_DATA / "HomeAgent"
DB_PATH = BASE_DIR / "state.db"
ALLOWLIST_PATH = BASE_DIR / "allowlist.yml"

INGEST_POLL_SECONDS = 20
RETENTION_DAYS = 14

EVENT_IDS = {1, 3, 11, 12, 13, 14, 16}

WRITEABLE_EXTS = {".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".bat", ".cmd"}

OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
BROWSER_PROCS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
SCRIPT_ENGINES = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe"}

WRITABLE_PATH_HINTS = [
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Local\\",
    "\\AppData\\Roaming\\",
    "\\Users\\Public\\",
    "\\Downloads\\",
    "\\Desktop\\",
]

ALERT_MIN_SEVERITY = "Medium"
ALERT_CHANNELS = ["toast", "eventlog"]
ALERT_THROTTLE_MAX = 3
ALERT_THROTTLE_WINDOW_SEC = 600
ALERT_INCLUDE_EVIDENCE = False
ALERT_SOUND_CRITICAL = False
ALERT_LOG_PATH = BASE_DIR / "alerts.log"
