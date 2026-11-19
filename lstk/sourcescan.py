"""Analisi STATICA del codice sorgente di una web application (sola lettura).

Due fonti, come chiede la consegna:
1. euristiche interne di LSTK (sempre disponibili): pattern di segreti scritti nel codice e di chiamate rischiose;
2. Semgrep, se installato: regole della community (`--config auto`), importate come finding.

Non esegue mai il codice analizzato: legge soltanto i file di testo. Salta cartelle generate
(node_modules, .git, venv, dist, build, …) e file troppo grandi o binari.
Ogni finding è pensato per il risk engine di LSTK: rischio = impatto × probabilità.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .models import Finding
from .runner import Runner

MAX_FILES = 4000
MAX_FILE_BYTES = 1_000_000
MAX_MATCHES = 400
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__",
             ".next", ".nuxt", "vendor", "target", ".cache", "coverage", ".idea", ".mypy_cache"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".php", ".rb", ".go", ".java", ".cs",
            ".env", ".sh", ".sql", ".yml", ".yaml", ".json", ".ini", ".cfg", ".toml", ".html", ".conf"}

# (id, regex, severità, titolo, raccomandazione). Pattern volutamente conservativi per limitare i falsi positivi.
SECRET_RULES = [
    ("CODE-SECRET-PRIVKEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical",
     "Chiave privata nel codice", "Rimuovere la chiave dal repository, ruotarla e tenerla fuori dal codice (segreti in variabili d'ambiente o vault)."),
    ("CODE-SECRET-AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical",
     "Possibile AWS Access Key ID nel codice", "Revocare la chiave e spostarla in un gestore di segreti."),
    ("CODE-SECRET-ASSIGN", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|client[_-]?secret)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "high",
     "Credenziale o segreto scritto nel codice", "Non mettere segreti nel codice: usare variabili d'ambiente o un gestore di segreti; ruotare quello esposto."),
]
# chiamate/costrutti rischiosi (possibile code/command injection o XSS)
CALL_RULES = [
    ("CODE-EXEC-SHELL", re.compile(r"(?i)(subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\s*\(|child_process\.(exec|execSync)\s*\(|Runtime\.getRuntime\(\)\.exec)"), "high",
     "Esecuzione di comandi di sistema (possibile command injection)", "Evitare la shell; passare gli argomenti come lista e validare gli input non fidati."),
    ("CODE-EVAL", re.compile(r"(?i)(^|[^.\w])(eval|exec)\s*\(|new Function\s*\("), "high",
     "Uso di eval/exec (possibile code injection)", "Evitare eval/exec su dati non fidati; usare alternative sicure (parser, mappe di funzioni)."),
    ("CODE-XSS-DOM", re.compile(r"(?i)(dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()"), "medium",
     "Scrittura diretta nel DOM (possibile XSS)", "Non inserire HTML da input non fidato; usare testo o sanificare (es. DOMPurify)."),
    ("CODE-SQL-CONCAT", re.compile(r"(?i)(select|insert|update|delete)\s+.*(\+\s*\w+|%\s*\(|f['\"].*\{|\|\|\s*\w+).*(from|into|set|where)?"), "high",
     "Query SQL costruita per concatenazione (possibile SQL injection)", "Usare query parametrizzate / prepared statement, mai concatenare input nelle query."),
    ("CODE-TLS-OFF", re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0|InsecureSkipVerify\s*:\s*true)"), "medium",
     "Verifica del certificato TLS disabilitata", "Non disabilitare la verifica TLS: espone a man-in-the-middle."),
]


class SourceScanError(ValueError):
    pass


@dataclass
class SourceOutcome:
    status: str                 # ok | partial | failed
    detail: str
    findings: list = field(default_factory=list)
    info: dict = field(default_factory=dict)


def _iter_files(root: str):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in TEXT_EXT or name in (".env", "Dockerfile", ".npmrc"):
                yield os.path.join(dirpath, name)
                n += 1
                if n >= MAX_FILES:
                    return


def _rel(root: str, path: str) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def heuristic_findings(root: str) -> tuple[list[Finding], int]:
    """Fonte 1: euristiche interne. Ritorna (findings, file_analizzati)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()        # (regola, file:riga) per non duplicare
    files = 0
    for path in _iter_files(root):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        files += 1
        rel = _rel(root, path)
        for lineno, line in enumerate(lines, 1):
            if len(line) > 1000:
                continue
            for fid, rx, sev, title, reco in SECRET_RULES + CALL_RULES:
                if rx.search(line):
                    key = (fid, f"{rel}:{lineno}")
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = line.strip()[:160]
                    conf = "medium" if fid in ("CODE-SQL-CONCAT", "CODE-SECRET-ASSIGN") else "high"
                    findings.append(Finding(f"{fid}-{len(findings) + 1}", f"{title} ({rel}:{lineno})", sev, "warn",
                                            "codice", f"{rel}:{lineno}: {snippet}", reco, confidence=conf, source="code"))
                    if len(findings) >= MAX_MATCHES:
                        return findings, files
    return findings, files


SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def parse_semgrep(data: dict, root: str) -> list[Finding]:
    """Fonte 2: risultati Semgrep (JSON) importati come finding."""
    out: list[Finding] = []
    for i, r in enumerate(data.get("results", [])[:MAX_MATCHES], 1):
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        sev = SEMGREP_SEV.get(str(extra.get("severity", "WARNING")).upper(), "medium")
        rel = _rel(root, r.get("path", "?"))
        line = (r.get("start", {}) or {}).get("line", "?")
        rule = str(r.get("check_id", "semgrep"))[:80]
        msg = (extra.get("message") or rule)[:300]
        refs = [u for u in (meta.get("references") or [])][:3]
        out.append(Finding(f"SG-{i}", f"{msg.splitlines()[0][:120]} ({rel}:{line})", sev, "warn", "codice",
                           f"{rel}:{line} — regola {rule}", "Seguire la raccomandazione della regola Semgrep e correggere il punto indicato.",
                           confidence="medium", source="semgrep", references=refs))
    return out


def run_semgrep(runner: Runner, root: str, timeout: int = 600) -> list[Finding]:
    exe = runner.which("semgrep")
    if not exe:
        return []
    res = runner.run([exe, "--config", "auto", "--json", "--quiet", "--timeout", "0",
                      "--max-target-bytes", str(MAX_FILE_BYTES), root], timeout=timeout)
    if not res.out:
        return []
    try:
        return parse_semgrep(json.loads(res.out), root)
    except (ValueError, KeyError):
        return []


def run_sourcescan(path: str, *, runner: Runner | None = None, use_semgrep: bool = True) -> SourceOutcome:
    if not os.path.isdir(path):
        return SourceOutcome("failed", f"cartella del sorgente non trovata: {path}", [], {"path": path})
    runner = runner or Runner()
    findings, files = heuristic_findings(path)
    sources = ["euristiche interne"]
    notes: list[str] = []
    sg: list[Finding] = []
    if use_semgrep:
        if runner.which("semgrep"):
            try:
                sg = run_semgrep(runner, path)
                sources.append("Semgrep")
            except Exception as exc:          # pragma: no cover - dipende dall'ambiente
                notes.append(f"Semgrep non completato: {type(exc).__name__}")
        else:
            notes.append("Semgrep non installato: usata solo l'euristica interna (installa 'semgrep' per la seconda fonte)")
    findings += sg
    issues = sum(1 for f in findings if f.status in ("fail", "warn"))
    detail = (f"{files} file analizzati, {issues} potenziali problemi; fonti: {', '.join(sources)}"
              + (f"; {'; '.join(notes)}" if notes else ""))
    status = "ok" if files else "partial"
    return SourceOutcome(status, detail, findings, {"path": path, "files": files, "sources": sources, "notes": notes})
