"""Controllo della configurazione e dei permessi del database (PostgreSQL), in SOLA LETTURA.

Non si connette al database e non usa credenziali: legge i file di configurazione indicati
(`postgresql.conf`, `pg_hba.conf`) e, su Linux, i permessi dei file. Pensato per l'analisi
interna sulla macchina che ospita la web app (es. il Raspberry di Tono).

Ogni finding è pensato per il risk engine di LSTK: rischio = impatto × probabilità.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field

from .models import Finding

MAX_BYTES = 2_000_000


class DbCheckError(ValueError):
    pass


@dataclass
class DbOutcome:
    status: str                 # ok | partial | failed
    detail: str
    findings: list = field(default_factory=list)
    info: dict = field(default_factory=dict)


def _resolve(path: str) -> dict:
    """Da un file o una cartella ricava i percorsi di postgresql.conf e pg_hba.conf."""
    found: dict = {}
    if os.path.isdir(path):
        for name, key in (("postgresql.conf", "conf"), ("pg_hba.conf", "hba")):
            p = os.path.join(path, name)
            if os.path.isfile(p):
                found[key] = p
    elif os.path.isfile(path):
        base = os.path.basename(path).lower()
        found["hba" if "hba" in base else "conf"] = path
        other = os.path.join(os.path.dirname(path), "pg_hba.conf" if "hba" not in base else "postgresql.conf")
        if os.path.isfile(other):
            found["hba" if "hba" not in base else "conf"] = other
    return found


def _read(path: str) -> list[str]:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise DbCheckError(f"file troppo grande: {path}")
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.readlines()
    except OSError as exc:
        raise DbCheckError(f"impossibile leggere {path}: {exc}") from exc


def _settings(lines: list[str]) -> dict:
    """Ultima assegnazione non commentata per ogni chiave di postgresql.conf."""
    out: dict = {}
    for line in lines:
        s = line.split("#", 1)[0].strip()
        m = re.match(r"([a-zA-Z_.]+)\s*=\s*(.+)", s)
        if m:
            out[m.group(1).lower()] = m.group(2).strip().strip("'\"")
    return out


def check_postgresql_conf(path: str) -> list[Finding]:
    s = _settings(_read(path))
    F: list[Finding] = []

    def add(fid, title, sev, status, evidence, reco, impact=0, likelihood=0, conf="high"):
        F.append(Finding(fid, title, sev, status, "database", evidence, reco, confidence=conf, source="db",
                         impact=impact, likelihood=likelihood,
                         references=["https://www.postgresql.org/docs/current/runtime-config-connection.html"]))

    listen = s.get("listen_addresses", "localhost")
    if listen in ("*", "0.0.0.0", "::") or "0.0.0.0" in listen:
        add("DB-LISTEN", "PostgreSQL in ascolto su tutte le interfacce", "high", "warn",
            f"listen_addresses = {listen}", "Limitare a 'localhost' (o alla sola rete necessaria) e proteggere con firewall.",
            impact=4, likelihood=3)
    else:
        add("DB-LISTEN", "PostgreSQL in ascolto solo locale", "info", "pass",
            f"listen_addresses = {listen}", "Configurazione corretta: non esposto in rete.")

    ssl = s.get("ssl", "off").lower()
    if ssl not in ("on", "true", "1"):
        add("DB-SSL", "TLS/SSL del database disattivato", "medium", "warn", f"ssl = {s.get('ssl', 'off')}",
            "Abilitare SSL se il DB accetta connessioni di rete; con solo 'localhost' il rischio è ridotto.")
    pw = s.get("password_encryption", "").lower()
    if pw in ("md5",):
        add("DB-PWENC", "Cifratura password del DB debole (md5)", "medium", "warn", f"password_encryption = {pw}",
            "Usare 'scram-sha-256' per le password degli utenti PostgreSQL.")
    return F


HBA_CONN = ("local", "host", "hostssl", "hostnossl")


def _hba_fields(line: str) -> tuple[str, list[str]] | None:
    """Ritorna (metodo, token_indirizzo) da una riga di pg_hba.conf, o None se non è una regola."""
    toks = line.split()
    if len(toks) < 3 or toks[0].lower() not in HBA_CONN:
        return None
    method = toks[-1].lower()
    addr = [] if toks[0].lower() == "local" else toks[3:-1]   # ADDRESS [MASK] tra USER e METODO
    return method, addr


def check_pg_hba(path: str) -> list[Finding]:
    F: list[Finding] = []
    for lineno, raw in enumerate(_read(path), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        parsed = _hba_fields(line)
        if not parsed:
            continue
        method, addr_toks = parsed
        addr = " ".join(addr_toks)
        wide = any(a in ("0.0.0.0/0", "::/0") or a.endswith("/0") for a in addr_toks) or addr_toks[:2] == ["0.0.0.0", "0.0.0.0"]
        if method == "trust":
            F.append(Finding(f"DB-HBA-TRUST-{lineno}", f"pg_hba.conf: autenticazione 'trust' (riga {lineno})",
                             "critical" if wide else "high", "warn" if not wide else "fail", "database",
                             f"{path} r{lineno}: {line.strip()[:160]}",
                             "'trust' consente l'accesso senza password: sostituire con 'scram-sha-256' (o 'peer' in locale).",
                             confidence="high", source="db", impact=5, likelihood=5 if wide else 3,
                             references=["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"]))
        elif method == "password":
            F.append(Finding(f"DB-HBA-PW-{lineno}", f"pg_hba.conf: password in chiaro (riga {lineno})", "high", "warn",
                             "database", f"{path} r{lineno}: {line.strip()[:160]}",
                             "'password' invia la password in chiaro: usare 'scram-sha-256'.", confidence="high", source="db"))
        if wide and method != "trust":
            F.append(Finding(f"DB-HBA-WIDE-{lineno}", f"pg_hba.conf: regola aperta a tutta Internet (riga {lineno})", "high", "warn",
                             "database", f"{path} r{lineno}: {line.strip()[:160]}",
                             "Restringere l'intervallo di indirizzi agli host che devono davvero connettersi.",
                             confidence="high", source="db", impact=4, likelihood=3))
    if not F:
        F.append(Finding("DB-HBA-OK", "pg_hba.conf senza metodi di autenticazione deboli evidenti", "info", "pass",
                         "database", f"{path}: nessuna riga trust/password/0.0.0.0/0 trovata",
                         "Nessun problema evidente nelle regole di autenticazione.", source="db"))
    return F


def check_permissions(paths: list[str]) -> list[Finding]:
    """Su Linux: i file di config del DB non devono essere leggibili/scrivibili da 'altri'."""
    if os.name == "nt":
        return []
    F: list[Finding] = []
    for p in paths:
        try:
            mode = os.stat(p).st_mode
        except OSError:
            continue
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            F.append(Finding(f"DB-PERM-{os.path.basename(p)}", f"Permessi troppo aperti su {os.path.basename(p)}",
                             "medium", "warn", "database", f"{p}: modo {stat.filemode(mode)}",
                             "Rendere i file di configurazione leggibili solo dall'utente del database (es. chmod 640).",
                             confidence="high", source="db"))
    return F


def run_dbcheck(path: str) -> DbOutcome:
    found = _resolve(path)
    if not found:
        return DbOutcome("failed", f"nessun postgresql.conf / pg_hba.conf trovato in {path}", [], {"path": path})
    findings: list[Finding] = []
    checked: list[str] = []
    try:
        if "conf" in found:
            findings += check_postgresql_conf(found["conf"])
            checked.append(os.path.basename(found["conf"]))
        if "hba" in found:
            findings += check_pg_hba(found["hba"])
            checked.append(os.path.basename(found["hba"]))
        findings += check_permissions(list(found.values()))
    except DbCheckError as exc:
        return DbOutcome("failed", str(exc), findings, {"path": path})
    issues = sum(1 for f in findings if f.status in ("fail", "warn"))
    status = "partial" if "conf" not in found or "hba" not in found else "ok"
    detail = f"analizzati: {', '.join(checked)}; {issues} potenziali problemi" + ("" if status == "ok" else "; alcuni file non trovati")
    return DbOutcome(status, detail, findings, {"path": path, "checked": checked})
