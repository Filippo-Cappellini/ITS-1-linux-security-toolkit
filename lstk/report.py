"""Rapporti JSON/HTML/SARIF/CSV/Markdown con garanzie di integrità (SHA-256, HMAC opzionale) e scrittura sicura."""
from __future__ import annotations

import csv
import hashlib
import hmac
import html
import io
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from . import __version__
from .fixes import suggestions
from .osinfo import IS_WINDOWS
from .risk import LEVELS
from .scan import MODE_TABLE, Assessment

SCHEMA_VERSION = "1.1"
FORMATS = ("json", "html", "sarif", "csv", "md")
EXT = {"json": "json", "html": "html", "sarif": "sarif", "csv": "csv", "md": "md"}
LIMITATIONS = [
    "Valutazione tecnica automatizzata e best-effort: NON è una certificazione né una verifica di conformità (ISO 27001, CIS, PCI-DSS, ecc.) e non sostituisce un penetration test o una revisione professionale.",
    "I controlli dipendono da privilegi, sistema operativo e strumenti installati; gli esiti 'manual' e 'unknown' sono lacune di copertura e NON equivalgono a 'sicuro'.",
    "Nmap: l'esposizione osservata dipende dal punto di scansione; il rilevamento di versione non implica vulnerabilità e non è effettuata alcuna correlazione CVE. Solo IPv4.",
    "Lynis (solo Linux): i finding sono importati e mappati con una severità definita da LSTK (warning=high, suggestion=low); i testi originali restano in inglese.",
    "Trivy: la presenza di una CVE nel database non implica che sia sfruttabile nel proprio contesto. I segreti sono rilevati per pattern (falsi positivi/negativi possibili) e il loro contenuto non è riportato. Su Windows analizza il profilo utente (librerie e segreti), non i componenti del sistema operativo, coperti dal controllo Windows Update.",
    "Integrità: su Linux dpkg/rpm confrontano i file con il database dei pacchetti (non rilevano file aggiunti); su Windows si verifica la firma Authenticode degli eseguibili dei servizi, non tutti i file di sistema (usare 'sfc /scannow').",
    "I comandi di correzione suggeriti sono indicativi: LSTK non li esegue; vanno compresi, adattati e provati prima dell'uso.",
    "Il punteggio di postura è indicativo (metodologia in docs/METHODOLOGY.md) e non confrontabile tra strumenti diversi.",
    "Hash e firma HMAC dimostrano che il rapporto non è stato alterato dopo la generazione, non che l'host fosse integro durante la scansione.",
]
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unverified": 4, "none": 5}


class ReportError(RuntimeError):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_payload(a: Assessment) -> dict:
    findings = sorted(a.findings, key=lambda f: (ORDER.get(f.risk_level, 9), -f.risk_score, f.id))
    platform_name = (a.host or {}).get("platform", "windows" if IS_WINDOWS else "linux")
    body = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "LSTK Security Toolkit", "version": __version__},
        "run": {"id": a.run_id, "started_at": a.started_at, "finished_at": a.finished_at, "profile": a.options.profile,
                "mode": a.options.mode, "mode_description": MODE_TABLE[a.options.mode], "privileged": a.privileged, "host": a.host},
        "scope": a.scope,
        "summary": a.summary.to_dict(),
        "modules": [asdict(m) for m in a.modules],
        "findings": [{**f.to_dict(), "fix": suggestions(f.id, platform_name)} for f in findings],
        "installs": list(a.installs),
        "executions": [e.to_dict() for e in a.executions],
        "limitations": LIMITATIONS,
    }
    return seal(body)


def seal(body: dict) -> dict:
    integ = {"algorithm": "sha256", "payload_sha256": hashlib.sha256(canonical(body)).hexdigest()}
    key = os.environ.get("LSTK_SIGNING_KEY", "").encode()
    if len(key) >= 16:
        integ["hmac_sha256"] = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    return {**body, "integrity": integ}


# --------------------------------------------------------------------------- HTML
LEVEL_COLORS = {"critical": "#e03131", "high": "#f76707", "medium": "#f2a900", "low": "#1c9dbb", "none": "#2f9e44", "unverified": "#7950f2"}
LEVEL_IT = {"critical": "critico", "high": "alto", "medium": "medio", "low": "basso", "none": "nessuno", "unverified": "non verificato"}
GRADE_COLORS = {"A": "#2f9e44", "B": "#66a80f", "C": "#f2a900", "D": "#f76707", "F": "#e03131"}


def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _cell_color(lik: int, imp: int) -> str:
    s = lik * imp
    return LEVEL_COLORS["critical" if s >= 20 else "high" if s >= 12 else "medium" if s >= 8 else "low"]


CSS = """
:root{--bg:#f6f7fb;--panel:#fff;--ink:#1d2330;--muted:#5d6779;--line:#e3e7ef;--accent:#3b5bdb;--chip:#eef1f8;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0f131a;--panel:#171c25;--ink:#e6e9ef;--muted:#99a3b5;--line:#283041;--accent:#748ffc;--chip:#202838;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 64px}
header.hero{background:linear-gradient(135deg,#1b2a4e,#3b5bdb 60%,#5f3dc4);color:#fff;border-radius:18px;padding:28px;display:flex;gap:28px;align-items:center;flex-wrap:wrap}
.hero h1{margin:0 0 4px;font-size:26px}.hero p{margin:2px 0;opacity:.9;font-size:14px}
.ring{--p:0;--c:#2f9e44;width:132px;height:132px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),rgba(255,255,255,.18) 0);display:grid;place-items:center;flex:none}
.ring>div{width:104px;height:104px;border-radius:50%;background:#16213e;display:grid;place-items:center;text-align:center}
.ring b{font-size:42px;line-height:1}.ring small{font-size:12px;opacity:.85}
.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.meta span{background:rgba(255,255,255,.15);padding:3px 10px;border-radius:99px;font-size:12.5px}
h2{font-size:19px;margin:34px 0 12px}h3{font-size:16px;margin:18px 0 8px}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.kpi b{display:block;font-size:28px}.kpi span{color:var(--muted);font-size:13px}
.kpi.l-critical b{color:#e03131}.kpi.l-high b{color:#f76707}.kpi.l-medium b{color:#c98f00}.kpi.l-low b{color:#1c9dbb}
.two{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
.donut{width:150px;height:150px;border-radius:50%;margin:6px auto;display:grid;place-items:center}
.donut>div{width:96px;height:96px;border-radius:50%;background:var(--panel);display:grid;place-items:center;font-weight:700;font-size:22px}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;justify-content:center;font-size:13px;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px}
table{border-collapse:collapse;width:100%}td,th{padding:7px 9px;text-align:left;vertical-align:top;font-size:13px;border-bottom:1px solid var(--line);word-break:break-word}
th{color:var(--muted);font-weight:600}
table.m{width:auto;margin:auto}table.m td{width:44px;height:36px;text-align:center;color:#fff;font-weight:700;border:2px solid var(--panel);border-radius:6px}
.b{color:#fff;border-radius:99px;padding:2px 9px;font-size:12px;white-space:nowrap;font-weight:600}
.warn{background:#fff4e6;color:#a64b00;border:1px solid #ffd8a8;border-radius:12px;padding:10px 14px}
@media (prefers-color-scheme:dark){.warn{background:#3a2a12;color:#ffc078;border-color:#5c3d0e}}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 14px}.filters input{display:none}.filters .list{flex-basis:100%;margin-top:6px}
.filters label{cursor:pointer;background:var(--chip);border:1px solid var(--line);padding:5px 12px;border-radius:99px;font-size:13px}
.filters input:checked+label{background:var(--accent);border-color:var(--accent);color:#fff}
details.f{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--lc,#888);border-radius:12px;margin:8px 0;padding:0 14px}
details.f summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:center;padding:11px 0;flex-wrap:wrap}
details.f summary::-webkit-details-marker{display:none}
details.f summary .id{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted)}
details.f summary .t{flex:1;min-width:200px;font-weight:600}details.f summary .s{font-size:12px;color:var(--muted)}
details.f .body{padding:0 0 12px;font-size:14px}details.f .body p{margin:6px 0}
pre{background:var(--chip);border-radius:8px;padding:10px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
#all:checked~.list details{display:block}
#critical:checked~.list details:not(.lv-critical),#high:checked~.list details:not(.lv-high),#medium:checked~.list details:not(.lv-medium),
#low:checked~.list details:not(.lv-low),#unverified:checked~.list details:not(.lv-unverified),#ok:checked~.list details:not(.lv-none),
#issues:checked~.list details.lv-none,#issues:checked~.list details.lv-unverified{display:none}
footer{color:var(--muted);font-size:12.5px;margin-top:40px}
@media print{.filters{display:none}details.f{break-inside:avoid}header.hero{background:#1b2a4e;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def _finding_html(f: dict) -> str:
    lvl = f["risk_level"]
    pi = f"P{f['likelihood']} × I{f['impact']} = {f['risk_score']}" if f["risk_score"] else "non valutato" if lvl == "unverified" else "—"
    refs = "".join(f'<li><code>{_e(r)}</code></li>' for r in f.get("references") or [])
    fix = f.get("fix") or {}
    fix_html = ""
    if fix.get("commands"):
        fix_html = ("<p><strong>Comandi suggeriti</strong> (non eseguiti da LSTK; verificarli prima dell'uso):</p><pre>"
                    + _e("\n".join(fix["commands"])) + "</pre>" + (f"<p><em>{_e(fix['note'])}</em></p>" if fix.get("note") else ""))
    return (f'<details class="f lv-{_e(lvl)}" style="--lc:{LEVEL_COLORS.get(lvl, "#888")}"><summary>'
            f'<span class="b" style="background:{LEVEL_COLORS.get(lvl, "#666")}">{_e(LEVEL_IT.get(lvl, lvl))}</span>'
            f'<span class="t">{_e(f["title"])}</span><span class="s">{_e(pi)} · {_e(f["status"])} · {_e(f["source"])}</span>'
            f'<span class="id">{_e(f["id"])}</span></summary><div class="body">'
            f'<p><strong>Categoria:</strong> {_e(f["category"])} · <strong>Gravità:</strong> {_e(f["severity"])} · <strong>Confidenza:</strong> {_e(f["confidence"])}</p>'
            f'<p><strong>Evidenza</strong></p><pre>{_e(f["evidence"])}</pre>'
            f'<p><strong>Raccomandazione:</strong> {_e(f["recommendation"])}</p>{fix_html}'
            + (f"<p><strong>Riferimenti</strong></p><ul>{refs}</ul>" if refs else "") + "</div></details>")


def render_html(p: dict) -> str:
    s, run = p["summary"], p["run"]
    host = run["host"]
    badge = lambda lvl, txt=None: f'<span class="b" style="background:{LEVEL_COLORS.get(lvl, "#666")}">{_e(txt or LEVEL_IT.get(lvl, lvl))}</span>'  # noqa: E731
    fs = p["findings"]
    n_issues = sum(1 for f in fs if f["risk_level"] in LEVELS)
    n_unv = sum(1 for f in fs if f["risk_level"] == "unverified")
    n_ok = sum(1 for f in fs if f["risk_level"] == "none")
    counts = s["counts"]
    total = sum(counts.get(l, 0) for l in LEVELS)
    stops, acc = [], 0.0
    for l in LEVELS:
        if counts.get(l):
            start = acc
            acc += 100 * counts[l] / total
            stops.append(f"{LEVEL_COLORS[l]} {start:.2f}% {acc:.2f}%")
    donut_bg = f"conic-gradient({', '.join(stops)})" if stops else "conic-gradient(#2f9e44 0 100%)"
    legend = "".join(f'<span><i style="background:{LEVEL_COLORS[l]}"></i>{LEVEL_IT[l]} {counts.get(l, 0)}</span>' for l in LEVELS)
    matrix = ""
    for lik in range(5, 0, -1):
        cells = "".join(f'<td style="background:{_cell_color(lik, imp)};opacity:{1 if s["matrix"][lik - 1][imp - 1] else .35}">'
                        f'{s["matrix"][lik - 1][imp - 1] or ""}</td>' for imp in range(1, 6))
        matrix += f"<tr><th>{lik}</th>{cells}</tr>"
    plural = {"critical": "rischi critici", "high": "rischi alti", "medium": "rischi medi", "low": "rischi bassi"}
    kpis = "".join(f'<div class="card kpi l-{l}"><b>{counts.get(l, 0)}</b><span>{plural[l]}</span></div>' for l in LEVELS)
    kpis += (f'<div class="card kpi"><b>{s["coverage_pct"]}%</b><span>copertura conclusiva</span></div>'
             f'<div class="card kpi"><b>{s["unverified"]}</b><span>non verificati</span></div>'
             f'<div class="card kpi"><b>{s["passed"]}</b><span>controlli superati</span></div>')
    if s.get("lynis_hardening_index") is not None:
        kpis += f'<div class="card kpi"><b>{s["lynis_hardening_index"]}</b><span>indice Lynis</span></div>'
    mod_icon = {"ok": "✅", "partial": "🟡", "skipped": "⏭️", "failed": "❌", "n/a": "➖"}
    mods = "".join(f"<tr><td>{mod_icon.get(m['status'], '•')} {_e(m['name'])}</td><td>{_e(m['status'])}</td><td>{_e(m['detail'])}</td></tr>"
                   for m in p["modules"])
    reasons = "".join(f"<li>{_e(r)}</li>" for r in s["partial_reasons"] + s["grade_notes"])
    execs = "".join(f"<tr><td><code>{_e(' '.join(map(str, e['argv'])))}</code></td><td>{e['returncode']}</td><td>{e['duration_s']}s</td></tr>"
                    for e in p["executions"])
    inst = "".join(f"<tr><td>{_e(i.get('tool'))}</td><td>{'ok' if i.get('ok') else 'ERRORE'}</td><td>{_e(i.get('method'))}</td><td>{_e(i.get('detail'))}</td><td>{_e(i.get('at'))}</td></tr>"
                   for i in p.get("installs", []))
    inst_html = ('<h2>Installazioni eseguite prima della scansione</h2><div class="card"><table><tr><th>Strumento</th><th>Esito</th><th>Metodo</th>'
                 '<th>Dettaglio</th><th>Quando</th></tr>' + inst + '</table></div>') if inst else ""
    lims = "".join(f"<li>{_e(x)}</li>" for x in p["limitations"])
    partial = ('<p class="warn">⚠ <strong>Valutazione PARZIALE</strong>: alcuni controlli non sono stati eseguiti o non sono conclusivi, '
               'quindi il voto è limitato. Motivi in fondo alla sintesi.</p>') if s["partial"] else ""
    top = [f for f in fs if f["id"] in s.get("top_risks", [])][:5]
    top_html = "".join(f"<tr><td>{badge(f['risk_level'])}</td><td><strong>{_e(f['title'])}</strong><br><span style='color:var(--muted)'>{_e(f['recommendation'])}</span></td>"
                       f"<td><code>{_e(f['id'])}</code></td></tr>" for f in top) or "<tr><td colspan=3>Nessun rischio rilevato tra i controlli conclusivi.</td></tr>"
    filters = "".join(f'<input type="radio" name="flt" id="{k}"{" checked" if k == "issues" else ""}><label for="{k}">{lab}</label>'
                      for k, lab in (("issues", f"Rischi ({n_issues})"), ("critical", f"Critici ({counts.get('critical', 0)})"),
                                     ("high", f"Alti ({counts.get('high', 0)})"), ("medium", f"Medi ({counts.get('medium', 0)})"),
                                     ("low", f"Bassi ({counts.get('low', 0)})"), ("unverified", f"Non verificati ({n_unv})"),
                                     ("ok", f"Superati/info ({n_ok})"), ("all", f"Tutti ({len(fs)})")))
    gcol = GRADE_COLORS.get(s["grade"], "#868e96")
    os_label = "Windows" if host.get("platform") == "windows" else "Linux" if host.get("platform") == "linux" else host.get("platform", "")
    return f"""<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Rapporto LSTK – {_e(host.get('hostname', ''))}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header class="hero"><div class="ring" style="--p:{s['posture_score']};--c:{gcol}"><div><span><b>{_e(s['grade'])}</b><br><small>{s['posture_score']}/100</small></span></div></div>
<div style="flex:1;min-width:260px"><h1>Rapporto di sicurezza · {_e(host.get('hostname', ''))}</h1>
<p>{_e(host.get('os', ''))}</p><p>Rischio complessivo: <strong>{_e(LEVEL_IT.get(s['overall_level'], s['overall_level']))}</strong> · {n_issues} rischi da trattare</p>
<div class="meta"><span>{_e(os_label)}</span><span>profilo {_e(run['profile'])}</span><span>modalità {_e(run['mode'])}</span>
<span>{'privilegi completi' if run['privileged'] else 'senza privilegi elevati'}</span><span>{_e(run['started_at'])}</span><span>LSTK {_e(p['tool']['version'])}</span></div></div></header>
<h2>Sintesi</h2>{partial}<div class="grid">{kpis}</div>
<div class="two" style="margin-top:14px"><div class="card"><h3>Distribuzione dei rischi</h3><div class="donut" style="background:{donut_bg}"><div>{total}</div></div><div class="legend">{legend}</div></div>
<div class="card"><h3>Matrice probabilità × impatto</h3><table class="m"><tr><th>P\\I</th>{''.join(f'<th style="text-align:center">{i}</th>' for i in range(1, 6))}</tr>{matrix}</table></div></div>
<h2>Da fare per primo</h2><div class="card"><table>{top_html}</table></div>
{('<h3>Motivi di parzialità e note sul voto</h3><div class="card"><ul>' + reasons + '</ul></div>') if reasons else ''}
<h2>Tutti i controlli</h2><p style="color:var(--muted)">Ambito: <strong>{_e(p['scope']['type'])}</strong> ({_e(', '.join(p['scope']['targets']))}). {_e(p['scope']['authorization']['note'])} Clic su un controllo per evidenza, raccomandazione e comandi suggeriti.</p>
<div class="filters">{filters}<div class="list">{''.join(_finding_html(f) for f in fs)}</div></div>
<h2>Moduli eseguiti</h2><div class="card"><table><tr><th>Modulo</th><th>Stato</th><th>Dettaglio</th></tr>{mods}</table></div>
{inst_html}<h2>Comandi eseguiti (sola lettura)</h2><details class="card"><summary>{len(p['executions'])} comandi</summary><table><tr><th>Comando</th><th>Exit</th><th>Durata</th></tr>{execs}</table></details>
<h2>Limiti</h2><div class="card"><ul>{lims}</ul></div>
<footer>Integrità: SHA-256 del contenuto <code>{_e(p['integrity']['payload_sha256'])}</code>{' · firma HMAC-SHA256 presente' if 'hmac_sha256' in p['integrity'] else ''}.
Verifica con <code>lstk verify FILE.json</code>. Run {_e(run['id'])}. Il rapporto contiene dati sensibili: trattarlo come riservato.</footer>
</div></body></html>"""


# --------------------------------------------------------------------------- SARIF / CSV / Markdown
def render_sarif(p: dict) -> str:
    """SARIF 2.1.0 (GitHub code scanning, Azure DevOps, IDE). Solo i rischi conclusivi e i non verificati."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "unverified": "note"}
    rules, results = [], []
    host = p["run"]["host"].get("hostname", "host")
    for f in p["findings"]:
        if f["risk_level"] not in level:
            continue
        sev = round(f["risk_score"] / 25 * 10, 1) if f["risk_score"] else 0.0
        rules.append({"id": f["id"], "name": f["id"], "shortDescription": {"text": f["title"]},
                      "fullDescription": {"text": f["recommendation"]}, "help": {"text": f["recommendation"]},
                      "properties": {"category": f["category"], "source": f["source"], "security-severity": str(sev),
                                     "tags": ["security", f["category"], f["source"]]}})
        results.append({"ruleId": f["id"], "level": level[f["risk_level"]],
                        "message": {"text": f"{f['title']}: {f['evidence'][:1000]}"},
                        "locations": [{"logicalLocations": [{"name": host, "kind": "host"}]}],
                        "properties": {"risk_level": f["risk_level"], "likelihood": f["likelihood"], "impact": f["impact"],
                                       "risk_score": f["risk_score"], "status": f["status"]}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "LSTK", "version": p["tool"]["version"],
                                         "informationUri": "https://github.com/Filippo-Cappellini/ITS-1-linux-security-toolkit", "rules": rules}},
                     "results": results,
                     "properties": {"grade": p["summary"]["grade"], "posture_score": p["summary"]["posture_score"],
                                    "payload_sha256": p["integrity"]["payload_sha256"]}}]}
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _csv_cell(v) -> str:
    """Neutralizza la 'formula injection' quando il CSV viene aperto in Excel/LibreOffice."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_csv(p: dict) -> str:
    cols = ("id", "risk_level", "likelihood", "impact", "risk_score", "status", "severity", "confidence", "source", "category",
            "title", "evidence", "recommendation")
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    w.writerow(cols)
    for f in p["findings"]:
        w.writerow([_csv_cell(f[c]) for c in cols])
    return "\ufeff" + buf.getvalue()      # BOM: Excel riconosce l'UTF-8 (accenti)


def _md(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render_markdown(p: dict) -> str:
    s, run = p["summary"], p["run"]
    lines = [f"# Rapporto LSTK · {_md(run['host'].get('hostname', ''))}", "",
             f"**Voto {s['grade']}** · postura {s['posture_score']}/100 · rischio complessivo **{LEVEL_IT.get(s['overall_level'], s['overall_level'])}**  ",
             f"{_md(run['host'].get('os', ''))} · profilo {run['profile']} · modalità {run['mode']} · {run['started_at']}", ""]
    if s["partial"]:
        lines += ["> ⚠ Valutazione parziale: " + _md("; ".join(s["partial_reasons"])), ""]
    lines += ["| Livello | Numero |", "|---|---|"] + [f"| {LEVEL_IT[l]} | {s['counts'].get(l, 0)} |" for l in LEVELS] + ["",
              "## Registro dei rischi", "", "| Rischio | P×I | ID | Controllo | Raccomandazione |", "|---|---|---|---|---|"]
    for f in p["findings"]:
        if f["risk_level"] in LEVELS:
            lines.append(f"| {LEVEL_IT[f['risk_level']]} | {f['likelihood']}×{f['impact']}={f['risk_score']} | `{_md(f['id'])}` | {_md(f['title'])} | {_md(f['recommendation'])} |")
    unv = [f for f in p["findings"] if f["risk_level"] == "unverified"]
    if unv:
        lines += ["", "## Non verificati", ""] + [f"- `{_md(f['id'])}` {_md(f['title'])}: {_md(f['evidence'][:200])}" for f in unv]
    lines += ["", f"_SHA-256 del contenuto: `{p['integrity']['payload_sha256']}`_", ""]
    return "\n".join(lines)


RENDER = {"json": lambda p: json.dumps(p, indent=2, ensure_ascii=False), "html": render_html, "sarif": render_sarif,
          "csv": render_csv, "md": render_markdown}


# --------------------------------------------------------------------------- scrittura sicura
def secure_dir(d: Path) -> Path:
    if d.is_symlink() or getattr(os.path, "isjunction", lambda _p: False)(d):
        raise ReportError(f"{d} è un link simbolico o una junction: rifiutato.")
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    if IS_WINDOWS:
        # NTFS non usa i bit di modo POSIX: la cartella eredita i permessi (ACL) della cartella padre, di norma il profilo utente.
        return d
    st = d.stat()
    if st.st_mode & 0o022:
        raise ReportError(f"{d} è scrivibile da altri utenti (modo {oct(st.st_mode & 0o777)}): correggere con chmod 700.")
    if hasattr(os, "geteuid") and st.st_uid not in (0, os.geteuid()):
        raise ReportError(f"{d} appartiene a un altro utente.")
    return d


def reports_dir() -> Path:
    return secure_dir(Path(os.environ.get("LSTK_REPORT_DIR") or (Path.cwd() / "lstk-reports")))


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def write_report(payload: dict, fmt: str = "json", directory: Path | None = None) -> Path:
    if fmt not in FORMATS:
        raise ReportError(f"Formato non supportato (disponibili: {', '.join(FORMATS)})")
    d = directory or reports_dir()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = d / f"audit-{stamp}-{payload['run']['id'][:8]}.{EXT[fmt]}"
    data = RENDER[fmt](payload).encode("utf-8")
    try:
        _write_exclusive(path, data)
        _write_exclusive(Path(str(path) + ".sha256"), f"{hashlib.sha256(data).hexdigest()}  {path.name}\n".encode())
    except OSError as exc:
        raise ReportError(f"Scrittura rapporto fallita: {exc}") from exc
    return path


@dataclass
class VerifyResult:
    ok: bool
    checks: list   # (True|False|None, messaggio)


def verify_report(path: str | Path) -> VerifyResult:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        return VerifyResult(False, [(False, f"Impossibile leggere il file: {exc}")])
    checks, ok, any_proof = [], True, False
    side = Path(str(p) + ".sha256")
    if side.is_file():
        any_proof = True
        parts = side.read_text().split()
        match = bool(parts) and hmac.compare_digest(parts[0], hashlib.sha256(data).hexdigest())
        ok &= match
        checks.append((match, "Hash SHA-256 del file coerente con il file .sha256" if match else "Hash SHA-256 del file NON coerente: file alterato"))
    else:
        checks.append((None, "Nessun file .sha256 accanto al rapporto"))
    if p.suffix == ".json":
        try:
            payload = json.loads(data)
            integ = payload.get("integrity")
            body = {k: v for k, v in payload.items() if k != "integrity"}
        except (ValueError, AttributeError):
            return VerifyResult(False, checks + [(False, "JSON non valido")])
        if integ and "payload_sha256" in integ:
            any_proof = True
            good = hmac.compare_digest(integ["payload_sha256"], hashlib.sha256(canonical(body)).hexdigest())
            ok &= good
            checks.append((good, "Hash interno del contenuto coerente" if good else "Hash interno NON coerente: contenuto alterato"))
            if "hmac_sha256" in integ:
                key = os.environ.get("LSTK_SIGNING_KEY", "").encode()
                if len(key) < 16:
                    checks.append((None, "Firma HMAC presente ma LSTK_SIGNING_KEY non impostata: non verificabile"))
                    ok = False
                else:
                    good = hmac.compare_digest(integ["hmac_sha256"], hmac.new(key, canonical(body), hashlib.sha256).hexdigest())
                    ok &= good
                    checks.append((good, "Firma HMAC valida" if good else "Firma HMAC NON valida"))
        else:
            checks.append((False, "Sezione integrity assente"))
            ok = False
    if not any_proof:
        ok = False
    return VerifyResult(ok, checks)
