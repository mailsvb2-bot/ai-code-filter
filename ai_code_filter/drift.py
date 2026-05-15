from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .analyzers.python_contract import PythonContractFingerprint
from .filesystem import validate_text_file
from .models import Issue, Severity

HISTORY_FILE = "drift_history.json"


def _history_path(state_dir: Path) -> Path:
    return state_dir / HISTORY_FILE


def load_history(state_dir: Path) -> dict:
    path = _history_path(state_dir)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_history(state_dir: Path, history: dict) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    _history_path(state_dir).write_text(json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8")


def compute_drift(old_fp: dict, new_fp: dict) -> dict:
    score = 0.0
    details: list[str] = []
    old_sigs = {sig["name"]: sig for sig in old_fp["signatures"]}
    new_sigs = {sig["name"]: sig for sig in new_fp["signatures"]}
    for name, old_sig in old_sigs.items():
        if name not in new_sigs:
            score += 1.0
            details.append(f"Function removed: {name}")
        elif old_sig != new_sigs[name]:
            score += 0.5
            details.append(f"Signature changed: {name}")
    for name in set(new_sigs) - set(old_sigs):
        score += 0.3
        details.append(f"Function added: {name}")
    removed_checks = set(old_fp["safety_checks"]) - set(new_fp["safety_checks"])
    if removed_checks:
        score += len(removed_checks) * 1.2
        details.append(f"Safety checks removed: {', '.join(sorted(removed_checks))}")
    return {"score": score, "details": details}


def record_drift(file_path: Path, project_root: Path, state_dir: Path, verdict: str = "UNKNOWN") -> list[Issue]:
    if file_path.suffix != ".py":
        return []
    code = validate_text_file(file_path)
    fp = PythonContractFingerprint(code).fingerprint()
    try:
        rel = str(file_path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        rel = str(file_path.resolve())
    now = datetime.now(timezone.utc).isoformat()
    history = load_history(state_dir)
    entry = history.get(rel)
    if not entry:
        history[rel] = {"snapshots": [{"timestamp": now, "fingerprint": fp, "verdict": verdict}], "cumulative_score": 0.0, "consecutive_negative": 0}
        save_history(state_dir, history)
        return []
    last = entry["snapshots"][-1]
    drift = compute_drift(last["fingerprint"], fp)
    negative = any("removed" in detail.lower() for detail in drift["details"])
    entry["cumulative_score"] = entry.get("cumulative_score", 0.0) + drift["score"]
    entry["consecutive_negative"] = entry.get("consecutive_negative", 0) + 1 if negative else 0
    entry["snapshots"].append({"timestamp": now, "fingerprint": fp, "verdict": verdict})
    history[rel] = entry
    save_history(state_dir, history)
    issues: list[Issue] = []
    if entry["cumulative_score"] > 3.0 or entry["consecutive_negative"] >= 3:
        issues.append(Issue(file=rel, category="Cumulative drift", severity=Severity.HIGH, detector="drift", description=f"Drift score {entry['cumulative_score']:.2f}; consecutive negative changes {entry['consecutive_negative']}.", recommendation="Review recent changes and restore removed contracts/safety checks."))
    if any(snap["fingerprint"].get("interface_hash") == fp.get("interface_hash") and snap.get("verdict") == "REJECTED" for snap in entry["snapshots"][:-1]):
        issues.append(Issue(file=rel, category="Regression", severity=Severity.CRITICAL, detector="drift", description="File returned to a previously rejected interface state.", recommendation="Do not revert to a known bad interface; investigate the regression."))
    return issues
