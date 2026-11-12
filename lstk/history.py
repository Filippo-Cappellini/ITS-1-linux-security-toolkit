"""Storico delle scansioni e confronto tra due assessment (nuovi, risolti, peggiorati, migliorati).

Ogni scansione completata dalla console viene salvata (JSON sigillato con SHA-256, file 0600) in
<LSTK_REPORT_DIR>/history, o in LSTK_HISTORY_DIR. Si può disattivare con LSTK_NO_HISTORY=1.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .report import ReportError, _write_exclusive, canonical, reports_dir, secure_dir
from .risk import LEVELS

SPARK = "▁▂▃▄▅▆▇█"
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unverified": 0, "none": 0}


def enabled() -> bool:
    return os.environ.get("LSTK_NO_HISTORY", "").strip().lower() not in ("1", "true", "yes", "si", "sì")


def history_dir() -> Path:
    custom = os.environ.get("LSTK_HISTORY_DIR")
    return secure_dir(Path(custom)) if custom else secure_dir(reports_dir() / "history")


def save(payload: dict, directory: Path | None = None) -> Path:
    d = directory or history_dir()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = d / f"scan-{stamp}-{payload['run']['id'][:8]}.json"
    try:
        _write_exclusive(path, json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except OSError as exc:
        raise ReportError(f"Salvataggio nello storico fallito: {exc}") from exc
    return path


@dataclass
class Entry:
    path: Path
    run_id: str
    finished_at: str
    hostname: str
    platform: str
    mode: str
    profile: str
    grade: str
    posture: int
    counts: dict
    intact: bool

    @property
    def short(self) -> str:
        return self.run_id[:8]


def _intact(payload: dict) -> bool:
    integ = payload.get("integrity") or {}
    body = {k: v for k, v in payload.items() if k != "integrity"}
    return bool(integ.get("payload_sha256")) and hmac.compare_digest(integ["payload_sha256"], hashlib.sha256(canonical(body)).hexdigest())


def load(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReportError(f"Impossibile leggere {path}: {exc}") from exc
    if not isinstance(data, dict) or "findings" not in data or "summary" not in data:
        raise ReportError(f"{path} non è un rapporto LSTK")
    return data


def entries(directory: Path | None = None) -> list[Entry]:
    d = directory or history_dir()
    out: list[Entry] = []
    for p in sorted(d.glob("scan-*.json")):
        try:
            data = load(p)
        except ReportError:
            continue
        run, s, host = data.get("run", {}), data.get("summary", {}), data.get("run", {}).get("host", {})
        out.append(Entry(p, str(run.get("id", "")), str(run.get("finished_at", "")), str(host.get("hostname", "")),
                         str(host.get("platform", "")), str(run.get("mode", "")), str(run.get("profile", "")),
                         str(s.get("grade", "?")), int(s.get("posture_score", 0)), dict(s.get("counts", {})), _intact(data)))
    out.sort(key=lambda e: (e.finished_at, e.path.name))
    return out


def find(ref: str, items: list[Entry]) -> Entry | None:
    """ref: indice (1 = più vecchia, -1 = ultima), prefisso dell'ID di run o nome del file."""
    if not items:
        return None
    try:
        i = int(ref)
        if i < 0:
            return items[i] if -i <= len(items) else None
        return items[i - 1] if 1 <= i <= len(items) else None
    except ValueError:
        pass
    ref = ref.lower()
    return next((e for e in items if e.run_id.lower().startswith(ref) or e.path.name.lower() == ref), None)


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    if hi == lo:
        return SPARK[len(SPARK) // 2] * len(values)
    return "".join(SPARK[round((v - lo) / (hi - lo) * (len(SPARK) - 1))] for v in values)


@dataclass
class Diff:
    old: dict
    new: dict
    added: list = field(default_factory=list)        # nuovi rischi
    resolved: list = field(default_factory=list)     # rischi spariti
    worse: list = field(default_factory=list)        # (vecchio, nuovo)
    better: list = field(default_factory=list)
    posture_delta: int = 0
    grade_change: tuple = ("", "")
    comparable: bool = True
    notes: list = field(default_factory=list)


def compare(old: dict, new: dict) -> Diff:
    def issues(p):
        return {f["id"]: f for f in p["findings"] if f.get("risk_level") in LEVELS}
    o, n = issues(old), issues(new)
    d = Diff(old, new)
    d.added = sorted((n[i] for i in n.keys() - o.keys()), key=lambda f: (-f["risk_score"], f["id"]))
    d.resolved = sorted((o[i] for i in o.keys() - n.keys()), key=lambda f: (-f["risk_score"], f["id"]))
    for i in o.keys() & n.keys():
        a, b = o[i], n[i]
        if b["risk_score"] > a["risk_score"]:
            d.worse.append((a, b))
        elif b["risk_score"] < a["risk_score"]:
            d.better.append((a, b))
    d.worse.sort(key=lambda ab: -ab[1]["risk_score"])
    d.better.sort(key=lambda ab: -ab[0]["risk_score"])
    so, sn = old["summary"], new["summary"]
    d.posture_delta = int(sn.get("posture_score", 0)) - int(so.get("posture_score", 0))
    d.grade_change = (so.get("grade", "?"), sn.get("grade", "?"))
    ho, hn = old["run"]["host"].get("hostname"), new["run"]["host"].get("hostname")
    if ho != hn:
        d.comparable = False
        d.notes.append(f"host diversi ({ho} → {hn}): il confronto ha poco senso")
    if old["run"].get("mode") != new["run"].get("mode"):
        d.notes.append(f"modalità diverse ({old['run'].get('mode')} → {new['run'].get('mode')}): alcune differenze dipendono dai moduli eseguiti")
    if old["run"].get("privileged") != new["run"].get("privileged"):
        d.notes.append("privilegi diversi tra le due scansioni: la copertura non è la stessa")
    return d
