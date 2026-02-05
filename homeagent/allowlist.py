import yaml
from .config import ALLOWLIST_PATH
from .utils import normalize_path


def ensure_allowlist():
    if not ALLOWLIST_PATH.exists():
        ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        default = {"hashes": [], "publishers": [], "targeted_rules": []}
        ALLOWLIST_PATH.write_text(yaml.safe_dump(default), encoding="utf-8")


def load_allowlist():
    ensure_allowlist()
    data = yaml.safe_load(ALLOWLIST_PATH.read_text(encoding="utf-8")) or {}
    hashes = {normalize_path(h) for h in data.get("hashes", [])}
    publishers = {normalize_path(p) for p in data.get("publishers", [])}
    targeted_rules = data.get("targeted_rules", []) or []

    # Backward compatibility for older keys (ignored but preserved on disk)
    return {"hashes": hashes, "publishers": publishers, "targeted_rules": targeted_rules}
