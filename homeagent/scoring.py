from .config import WRITABLE_PATH_HINTS, OFFICE_PROCS, BROWSER_PROCS, SCRIPT_ENGINES
from .utils import basename, normalize_path


def score_event(event, allowlist):
    score = 0
    reasons = []

    image = normalize_path(event.get("image"))
    target = normalize_path(event.get("target"))
    cmd = (event.get("command_line") or "").lower()
    parent = normalize_path(event.get("parent_image"))
    publisher = normalize_path(event.get("signature"))
    proc_name = basename(image)

    if event.get("kind") == "process":
        if any(hint.lower() in image for hint in WRITABLE_PATH_HINTS):
            score += 50
            reasons.append("Executable launched from writable path")

        if any(p in parent for p in OFFICE_PROCS.union(BROWSER_PROCS)) and proc_name in SCRIPT_ENGINES:
            score += 35
            reasons.append("Office/Browser spawning script engine")

        if "-enc" in cmd or "encodedcommand" in cmd or "frombase64string" in cmd:
            score += 40
            reasons.append("PowerShell encoded command")

    if event.get("kind") == "file_create":
        if any(hint.lower() in target for hint in WRITABLE_PATH_HINTS):
            score += 20
            reasons.append("File created in writable path")

    if event.get("kind") == "registry":
        if any(hint.lower() in target for hint in WRITABLE_PATH_HINTS):
            score += 60
            reasons.append("Persistence pointing to writable path")

    if event.get("kind") == "network":
        if proc_name in SCRIPT_ENGINES:
            score += 30
            reasons.append("Script engine with outbound network")

    # Dampeners
    if "microsoft" in (event.get("signature") or "").lower():
        score -= 40
        reasons.append("Microsoft-signed binary")

    if (event.get("hash") or "").lower() in allowlist.get("hashes", set()):
        score -= 30
        reasons.append("Allowlisted hash")

    if publisher and publisher in allowlist.get("publishers", set()):
        score -= 30
        reasons.append("Allowlisted publisher")

    # Targeted allowlist rules
    for rule in allowlist.get("targeted_rules", []):
        if _rule_matches(rule, event):
            delta = int(rule.get("score_delta", -30))
            score += delta
            name = rule.get("name") or "targeted rule"
            reasons.append(f"Allowlisted rule: {name}")

    if score < 0:
        score = 0

    severity = "Low"
    if score >= 80:
        severity = "Critical"
    elif score >= 60:
        severity = "High"
    elif score >= 35:
        severity = "Medium"

    return score, severity, reasons


def _rule_matches(rule, event):
    if not isinstance(rule, dict):
        return False

    kind = rule.get("kind")
    if kind and event.get("kind") != kind:
        return False

    image = normalize_path(event.get("image"))
    target = normalize_path(event.get("target"))
    parent = normalize_path(event.get("parent_image"))
    cmd = (event.get("command_line") or "").lower()

    img_eq = normalize_path(rule.get("image_equals"))
    if img_eq:
        if "\\" in img_eq:
            if image != img_eq:
                return False
        else:
            if basename(image) != basename(img_eq):
                return False

    parent_eq = normalize_path(rule.get("parent_image_equals"))
    if parent_eq:
        if "\\" in parent_eq:
            if parent != parent_eq:
                return False
        else:
            if basename(parent) != basename(parent_eq):
                return False

    tgt_contains = normalize_path(rule.get("persistence_target_contains"))
    if tgt_contains and tgt_contains not in target:
        return False

    cmd_contains = (rule.get("command_line_contains") or "").lower()
    if cmd_contains and cmd_contains not in cmd:
        return False

    return True
