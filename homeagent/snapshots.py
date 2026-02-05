import os
import json
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .config import WRITEABLE_EXTS
from .db import upsert_baseline
from .utils import json_dumps, utcnow_iso


def run_daily_snapshots(db):
    persistence = snapshot_persistence()
    upsert_baseline(db, "persistence", utcnow_iso(), json_dumps(persistence))

    inventory = snapshot_executables()
    upsert_baseline(db, "executables", utcnow_iso(), json_dumps(inventory))


def snapshot_persistence():
    return {
        "startup_folders": list_startup_files(),
        "run_keys": list_run_keys(),
        "scheduled_tasks": list_scheduled_tasks(),
        "services": list_services(),
    }


def list_startup_files():
    items = []
    for path in _startup_paths():
        try:
            for entry in Path(path).glob("*"):
                items.append(str(entry))
        except Exception:
            continue
    return sorted(set(items))


def _startup_paths():
    paths = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
    if appdata:
        paths.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
    paths.append(os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
    return paths


def list_run_keys():
    import winreg

    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ]

    results = []
    for root, path in keys:
        try:
            with winreg.OpenKey(root, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        results.append({"key": path, "name": name, "value": value})
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return results


def list_scheduled_tasks():
    try:
        output = subprocess.check_output(["schtasks", "/Query", "/FO", "CSV", "/V"], text=True, stderr=subprocess.STDOUT)
    except Exception:
        return []

    import csv
    from io import StringIO

    reader = csv.DictReader(StringIO(output))
    tasks = []
    for row in reader:
        tasks.append({
            "task_name": row.get("TaskName"),
            "status": row.get("Status"),
            "author": row.get("Author"),
            "run_as_user": row.get("Run As User"),
            "task_to_run": row.get("Task To Run"),
        })
    return tasks


def list_services():
    try:
        cmd = ["powershell", "-Command", "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
        data = json.loads(output) if output else []
        if isinstance(data, dict):
            data = [data]
        return data
    except Exception:
        return []


def snapshot_executables():
    roots = _writable_roots()
    items = {}
    count = 0
    max_files = 2000

    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                if count >= max_files:
                    return items
                path = os.path.join(dirpath, name)
                ext = os.path.splitext(path)[1].lower()
                if ext not in WRITEABLE_EXTS:
                    continue
                try:
                    items[path] = {
                        "sha256": _hash_file(path),
                        "mtime": os.path.getmtime(path),
                    }
                    count += 1
                except Exception:
                    continue

    return items


def _writable_roots():
    roots = []
    userprofile = os.environ.get("USERPROFILE")
    if userprofile:
        roots.extend([
            os.path.join(userprofile, "Downloads"),
            os.path.join(userprofile, "Desktop"),
            os.path.join(userprofile, "AppData", "Local", "Temp"),
            os.path.join(userprofile, "AppData", "Local"),
            os.path.join(userprofile, "AppData", "Roaming"),
        ])
    roots.append(os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
    return [r for r in roots if os.path.isdir(r)]


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
