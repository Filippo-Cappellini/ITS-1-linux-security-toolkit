from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import sys
import webbrowser
from pathlib import Path
from typing import List, Optional

# L'output usa glifi Unicode (✔, ▲, box). Su console Windows non-UTF-8 (code page 1252) print andrebbe in
# UnicodeEncodeError se LSTK non viene avviato tramite run.ps1. Forziamo UTF-8 così parte da qualsiasi shell.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

import typer
from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from . import __version__, history, installer, malware, quarantine, theme
from .fixes import suggestions
from .nmapscan import TargetError
from .osinfo import IS_WINDOWS, admin_word, system_name
from .report import FORMATS, RENDER, ReportError, build_payload, verify_report, write_report
from .risk import LEVELS
from .runner import Runner, is_root
from .scan import MODE_TABLE, MODES, PROFILES, Assessment, AuthorizationError, ModuleResult, ScanOptions, resolve_targets, run_assessment
from .webscan import WebScanError, host_is_loopback, normalize_url, run_webscan

app = typer.Typer(add_completion=False, no_args_is_help=False, help="LSTK Security Toolkit (Linux e Windows)")
console = Console(highlight=False)
STATE: dict = {"profile": "desktop", "assessment": None, "last_scan": None, "installs": [], "last_html": None,
               "av_findings": [], "web_findings": []}

OS_LABEL = "Windows" if IS_WINDOWS else "Linux"
LOGO_LINES, GRADIENT = theme.LOGO_LINES, theme.GRADIENT

LEVEL_STYLE = {"critical": "bold white on #c92a2a", "high": "bold white on #e8590c", "medium": "bold black on #fab005",
               "low": "bold white on #1c7ed6", "none": "bold white on #2f9e44", "unverified": "bold white on #7048e8", "info": "dim"}
LEVEL_FG = {"critical": "#ff6b6b", "high": "#ff922b", "medium": "#fcc419", "low": "#4dabf7", "none": "#51cf66", "unverified": "#9775fa"}
LEVEL_IT = {"critical": "critico", "high": "alto", "medium": "medio", "low": "basso", "none": "ok", "unverified": "non verif."}
GRADE_COLOR = {"A": "#51cf66", "B": "#94d82d", "C": "#fcc419", "D": "#ff922b", "F": "#ff6b6b"}
STATUS_ICON = {"fail": "[#ff6b6b]✘ fail[/]", "warn": "[#fcc419]▲ warn[/]", "pass": "[#51cf66]✔ pass[/]", "info": "[dim]• info[/]",
               "manual": "[#9775fa]? manual[/]", "unknown": "[#9775fa]? unknown[/]"}
MODULE_ICON = {"ok": "[#51cf66]✔[/]", "partial": "[#fcc419]◐[/]", "skipped": "[#fcc419]⏭[/]", "failed": "[#ff6b6b]✘[/]", "n/a": "[dim]–[/]"}
BIG = {"A": [" ▄▀▀▄ ", " █▄▄█ ", " █  █ "], "B": [" █▀▀▄ ", " █▀▀▄ ", " █▄▄▀ "], "C": [" ▄▀▀▀ ", " █    ", " ▀▄▄▄ "],
       "D": [" █▀▀▄ ", " █  █ ", " █▄▄▀ "], "F": [" █▀▀▀ ", " █▀▀  ", " █    "]}
STYLE = LEVEL_STYLE   # nome storico

HELP_GROUPS = [
    ("Operazioni di ricognizione", [
        ("/scan [quick|deep|full]", "Risk assessment completo del sistema (default: full)"),
        ("   --target IP|CIDR|host", "Scansiona anche bersagli non locali (serve autorizzazione)"),
        ("   --no-nmap --no-trivy --no-malware --no-integrity" + ("" if IS_WINDOWS else " --no-lynis"), "Esclude un modulo (valutazione parziale)"),
        ("   --offline", "Trivy usa solo il database in cache"),
        ("/vuln · /integrity" + ("" if IS_WINDOWS else " · /lynis"), "Esegue un singolo modulo"),
        ("/web URL [--insecure]", "Analisi esterna NON intrusiva di una web app (header, TLS, cookie, metodi)"),
        ("   /scan --web URL", "Include l'analisi web nella stessa tabella e nello stesso report dello scan"),
        ("/profile desktop|server", "Mostra o cambia profilo"),
    ]),
    ("Controspionaggio (antivirus)", [
        ("/av [quick|full|PERCORSO…]", "Cerca malware (quick: percorsi a rischio, full: tutto il disco)"),
        ("/quarantine [add FILE|restore ID|delete ID]", "Quarantena: elenco, sposta, ripristina, elimina"),
    ]),
    ("Dossier", [
        ("/risk", "Cruscotto: voto, postura, matrice 5×5, rischi principali"),
        ("/findings [filtro|TESTO]", "issues (default) · all · critical|high|medium|low · unverified · oppure un testo da cercare"),
        ("/details ID · /fix ID", "Dettaglio di un controllo · comandi di correzione suggeriti"),
    ]),
    ("Archivio", [
        ("/report [json|html|sarif|csv|md|all] [--open]", "Esporta (hash SHA-256, HMAC opzionale); --open apre l'HTML"),
        ("/history · /diff [A] [B]", "Scansioni precedenti con trend · confronto (default: le ultime due)"),
        ("/verify FILE", "Verifica l'integrità di un rapporto"),
    ]),
    ("Arsenale", [
        ("/doctor", "Strumenti presenti, percorsi e privilegi"),
        ("/install [nome|all]", "Installa gli strumenti mancanti"),
        ("/update", "Aggiorna strumenti installati, database Trivy, firme antivirus e librerie Python"),
        ("/clear · /help · /exit", "Pulisce · guida · esce"),
    ]),
]
HELP = [row for _, rows in HELP_GROUPS for row in rows]


def _e(x) -> str:
    return escape(str(x))


def chip(level: str, text: str | None = None) -> str:
    return f"[{LEVEL_STYLE.get(level, 'white')}] {_e(text or LEVEL_IT.get(level, level))} [/]"


def logo() -> Text:
    return theme.logo(1.0, __version__)


def tool_chips(runner: Runner) -> str:
    return "  ".join(f"[{theme.OK}]◉[/] {n}" if runner.which(t.binary) else f"[#ff6b6b]○[/] [dim]{n}[/]" for n, t in installer.TOOLS.items())


def banner(animate: bool = False):
    runner = Runner()
    if animate:
        theme.intro(console, __version__)
    info = Table.grid(padding=(0, 2))
    info.add_column(style=theme.MUTED, justify="right")
    info.add_column()
    info.add_row("Sistema", _e(f"{OS_LABEL} · {platform.platform(terse=True)}"))
    info.add_row("Nodo", _e(platform.node()))
    info.add_row("Nulla osta", f"[bold {theme.OK}]LIVELLO OMEGA[/] [dim]({admin_word()})[/]" if is_root() else
                 f"[#fcc419]LIVELLO 1[/] [dim](utente: copertura ridotta, {'Esegui come amministratore' if IS_WINDOWS else 'usa sudo'})[/]")
    info.add_row("Profilo", f"[bold]{STATE['profile']}[/]")
    info.add_row("Arsenale", tool_chips(runner))
    if console.width >= 110:
        body = Table.grid(padding=(0, 4))
        body.add_column(no_wrap=True, vertical="middle")
        body.add_column(no_wrap=True, vertical="middle")
        body.add_row(theme.pyramid("open", rays=True), logo())
        body = Group(body, Rule(f"[{theme.CYAN}]◄ ◉ ►[/]", style=theme.GOLD_DIM), info)
    else:
        body = Group(theme.pyramid("open", rays=True), Text(""), logo(), Rule(f"[{theme.CYAN}]◄ ◉ ►[/]", style=theme.GOLD_DIM), info)
    console.print(Panel(body, border_style=theme.GOLD, box=box.DOUBLE, padding=(1, 2),
                        title=f"[{theme.GOLD}]▲ ACCESSO RISERVATO ▲[/]",
                        subtitle=f"[{theme.CYAN}]classificazione:[/] [dim]riservatissimo[/]"))
    console.print(f"  [bold {theme.ACCENT}]/scan[/] ricognizione del sistema · [bold {theme.ACCENT}]/web[/] analizza una web app · "
                  f"[bold {theme.ACCENT}]/help[/] i protocolli · [bold {theme.ACCENT}]/update[/] aggiorna l'arsenale\n"
                  f"  [dim]nulla parte da solo: nessun bersaglio viene toccato finché non lo indichi tu[/]\n")


def print_help():
    for title, rows in HELP_GROUPS:
        t = Table(box=box.SIMPLE_HEAD, show_header=False, expand=True, padding=(0, 1))
        t.add_column(style=f"bold {theme.ACCENT}", no_wrap=True, ratio=2)
        t.add_column(ratio=3)
        for cmd, desc in rows:
            t.add_row(_e(cmd), _e(desc))
        console.print(Panel(t, title=f"[bold {theme.GOLD}]▲ {title.upper()}[/]", title_align="left", border_style=theme.BORDER, box=box.ROUNDED))
    console.print("[dim]Esempi: /scan · /scan quick · /scan full --target 192.168.1.10 · /findings high · /findings ssh · /fix FW-001 · /report all --open[/dim]")


def show_findings(findings, title="Risultati"):
    if not findings:
        console.print("[yellow]Nessun risultato per questo filtro. Esegui /scan oppure cambia filtro.[/yellow]")
        return
    table = Table(title=f"[bold]{_e(title)}[/] [dim]— {len(findings)}[/]", box=box.ROUNDED, expand=True, border_style=theme.BORDER,
                  header_style=f"bold {theme.MUTED}")
    for col in ("ID", "Rischio", "P", "I", "P×I", "Esito", "Fonte", "Controllo"):
        table.add_column(col, no_wrap=(col in ("ID", "Rischio", "P", "I", "P×I", "Esito")),
                         justify="right" if col in ("P", "I", "P×I") else "left", overflow="fold")
    for f in findings:
        lvl = f.risk_level
        scored = f.risk_score > 0
        table.add_row(f"[dim]{_e(f.id)}[/]", chip(lvl), str(f.likelihood) if scored else "-", str(f.impact) if f.impact else "-",
                      f"[bold {LEVEL_FG.get(lvl, 'white')}]{f.risk_score}[/]" if scored else "-",
                      STATUS_ICON.get(f.status, _e(f.status)), _e(f.source), _e(f.title))
    console.print(table)


def _sorted(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unverified": 4, "none": 5}
    return sorted(findings, key=lambda f: (order.get(f.risk_level, 9), -f.risk_score, f.id))


def filter_findings(findings, flt: str):
    flt = flt.lower()
    if flt == "all":
        return _sorted(findings)
    if flt == "unverified":
        return _sorted([f for f in findings if f.risk_level == "unverified"])
    if flt in LEVELS:
        return _sorted([f for f in findings if f.risk_level == flt])
    return _sorted([f for f in findings if f.risk_level in LEVELS])


def _bar(value: int, total: int, width: int, color: str) -> str:
    filled = 0 if total <= 0 else max(0, min(width, round(width * value / total)))
    return f"[{color}]{'█' * filled}[/][#2b3245]{'░' * (width - filled)}[/]"


def risk_dashboard(a: Assessment) -> Panel:
    s = a.summary
    g = s.grade
    gcol = GRADE_COLOR.get(g, "white")
    big = Text()
    for line in BIG.get(g, ["", "", ""]):
        big.append(line + "\n", style=f"bold {gcol}")
    big.append(f" voto {g}", style=f"bold {gcol}")
    left = Table.grid(padding=(0, 1))
    left.add_column()
    left.add_row(big)
    left.add_row("")
    left.add_row(f"[#9aa5b8]Postura[/] [bold]{s.posture_score}[/]/100")
    left.add_row(_bar(s.posture_score, 100, 22, gcol))
    left.add_row(f"[#9aa5b8]Rischio complessivo[/] {chip(s.overall_level)}")
    left.add_row(f"[#9aa5b8]Copertura[/] [bold]{s.coverage_pct}%[/] · [#9aa5b8]non verificati[/] {s.unverified} · [#9aa5b8]superati[/] {s.passed}")
    if s.lynis_hardening_index is not None:
        left.add_row(f"[#9aa5b8]Indice Lynis[/] {s.lynis_hardening_index}/100")
    mx = max([s.counts.get(l, 0) for l in LEVELS] + [1])
    counts = Table.grid(padding=(0, 1))
    for _ in range(3):
        counts.add_column()
    for l in LEVELS:
        n = s.counts.get(l, 0)
        counts.add_row(f"[{LEVEL_FG[l]}]{LEVEL_IT[l]:>7}[/]", f"[bold]{n:>3}[/]", _bar(n, mx, 18, LEVEL_FG[l]))
    m = Table(box=box.SIMPLE, show_header=True, header_style="#9aa5b8", padding=(0, 0), pad_edge=False)
    m.add_column("P\\I", justify="right", style="#9aa5b8")
    for i in range(1, 6):
        m.add_column(f" {i} ", justify="center")
    for lik in range(5, 0, -1):
        cells = []
        for imp in range(1, 6):
            n, sc = s.matrix[lik - 1][imp - 1], lik * imp
            lvl = "critical" if sc >= 20 else "high" if sc >= 12 else "medium" if sc >= 8 else "low"
            style = LEVEL_STYLE[lvl] if n else f"{LEVEL_FG[lvl]} dim"
            cells.append(f"[{style}] {n if n else '·':^3}[/]")
        m.add_row(str(lik), *cells)
    right = Group(Text("Rischi per livello", style="bold"), counts, Text(""), Text("Matrice probabilità × impatto", style="bold"), m)
    grid = Table.grid(expand=True, padding=(0, 4))
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(left, right)
    body: list = [grid]
    if s.partial:
        body.append(Rule(style="#fcc419"))
        body.append(Text.from_markup("[bold #fcc419]⚠ Valutazione PARZIALE[/] — " + _e("; ".join(s.partial_reasons))))
    for n in s.grade_notes:
        body.append(Text.from_markup(f"[dim]{_e(n)}[/dim]"))
    host = (a.host or {}).get("hostname", "")
    return Panel(Group(*body), title=f"[bold]Risk assessment · {_e(host)}[/]", border_style=gcol, box=box.ROUNDED, padding=(1, 2))


def show_risk(a: Assessment, top_table: bool = True):
    console.print(risk_dashboard(a))
    if top_table:
        top = [f for f in a.findings if f.id in a.summary.top_risks]
        show_findings(_sorted(top), "Rischi principali")


def export_report(fmt="json", open_after: bool = False):
    a = STATE["assessment"]
    if a is None:
        console.print("[yellow]Nessun audit da esportare. Esegui /scan prima.[/yellow]")
        return
    payload = build_payload(a)
    try:
        for f in (FORMATS if fmt == "all" else (fmt,)):
            path = write_report(payload, f)
            if f == "html":
                STATE["last_html"] = path
            console.print(f"[#51cf66]✔ Rapporto {f.upper()} salvato:[/] {_e(path)} [dim](+ .sha256)[/dim]")
    except ReportError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    if open_after:
        open_html()


def open_html():
    path = STATE.get("last_html")
    if not path:
        console.print("[yellow]Nessun rapporto HTML in questa sessione: usa /report html.[/yellow]")
        return
    if not IS_WINDOWS and is_root():
        console.print(f"[yellow]Non apro il browser come root.[/yellow] Apri il file da utente: {_e(path)}")
        return
    webbrowser.open(Path(path).resolve().as_uri())
    console.print(f"[dim]Aperto nel browser: {_e(path)}[/dim]")


def web_assessment(url: str, out) -> Assessment:
    """Costruisce un Assessment minimo dai risultati di /web, così si può generare il report (HTML grafico, JSON, ...)."""
    from datetime import datetime
    from .risk import assess
    host = (out.info or {}).get("host", "")
    ts = datetime.now().astimezone().isoformat(timespec="seconds")
    opts = ScanOptions(mode="quick", web_targets=[url])
    scope = {"type": "web", "targets": [], "web_targets": [url],
             "authorization": {"required": not host_is_loopback(host), "declared": True,
                               "note": "Analisi esterna non intrusiva (sola lettura) dell'URL indicato."}}
    summary = assess(list(out.findings))
    modules = [ModuleResult(f"web:{host}", "ok" if out.status == "ok" else "failed", out.detail)]
    host_info = {"hostname": host, "os": "", "platform": "windows" if IS_WINDOWS else "linux", "url": url}
    return Assessment(os.urandom(8).hex(), ts, ts, opts, is_root(), list(out.findings), modules, summary, [], scope, host_info)


def offer_web_report(url: str, out) -> None:
    """Propone di aprire il report grafico nel browser (una pagina chiara, adatta anche ai meno esperti)."""
    if not Confirm.ask("Aprire il report grafico nel browser? [dim](una pagina chiara, adatta anche ai meno esperti)[/dim]", default=True):
        console.print(f"[dim]Puoi sempre rigenerarlo: imposta /web … e poi usa questo menu, oppure 'lstk web {_e(url)} --open'.[/dim]")
        return
    try:
        payload = build_payload(web_assessment(url, out))
        path = write_report(payload, "html")
    except ReportError as exc:
        console.print(f"[red]Report non creato:[/red] {_e(exc)}")
        return
    STATE["last_html"] = path
    console.print(f"[{theme.OK}]✔ Report grafico salvato:[/] {_e(path)} [dim](+ .sha256)[/dim]")
    open_html()


# --------------------------------------------------------------------------- installazione strumenti mancanti
def show_install_results(results) -> None:
    for r in results:
        console.print(f"  {'[green]✔[/green]' if r.ok else '[red]✘[/red]'} {_e(r.tool)}: {_e(r.detail)}")
        STATE["installs"].append(r.to_dict())


def wanted_tools(opts: ScanOptions) -> list[str]:
    if IS_WINDOWS:
        return (["nmap"] if opts.use_nmap else []) + (["trivy"] if opts.trivy_enabled() else [])
    return (["iproute2"] + (["nmap"] if opts.use_nmap else []) + (["lynis"] if opts.lynis_enabled() else [])
            + (["trivy"] if opts.trivy_enabled() else []) + (["clamav"] if opts.malware_enabled() else []))


def ensure_tools(runner: Runner, wanted: list[str], context: str = "") -> bool:
    """Se mancano strumenti, mostra i comandi esatti e chiede il permesso di installarli. Ritorna True se ne è stato installato qualcuno."""
    missing = installer.missing_tools(runner, wanted)
    if not missing:
        return False
    try:
        steps = installer.plan_install(runner, missing)
    except installer.InstallError as exc:
        console.print(f"[yellow]Mancano {_e(', '.join(missing))} e non posso proporne l'installazione: {_e(exc)}[/yellow]")
        return False
    lines = [f"Mancano: [bold]{_e(', '.join(missing))}[/bold]" + (f" ({_e(context)})" if context else "")]
    prefix = ("sudo --",) if not is_root() and not IS_WINDOWS else ()
    for st in steps:
        lines.append(f"  • {_e(st.description)}")
        if st.argv:
            lines.append(f"    [dim]{_e(' '.join(prefix + tuple(st.argv)))}[/dim]")
    lines.append("")
    lines.append("[yellow]Questo MODIFICA il sistema[/yellow] (installa software)" +
                 (": Windows potrebbe chiedere conferma con una finestra UAC." if IS_WINDOWS else
                  " e richiede privilegi di amministratore" + ("." if is_root() else " (verrà usato sudo).")))
    console.print(Panel("\n".join(lines), title="Installazione strumenti mancanti", border_style="yellow", box=box.ROUNDED))
    if not Confirm.ask("Installarli ora?", default=False):
        console.print("Installazione annullata: i moduli corrispondenti verranno saltati e la valutazione sarà parziale.")
        return False
    try:
        results = installer.run_install(runner, steps, root=is_root(), log=lambda m: console.print(f"[dim]{_e(m)}[/dim]"), names=missing)
    except KeyboardInterrupt:
        console.print("\n[yellow]Installazione interrotta.[/yellow]")
        return False
    except installer.InstallError as exc:
        console.print(f"[red]Installazione non riuscita:[/red] {_e(exc)}")
        return False
    show_install_results(results)
    return any(r.ok for r in results)


def doctor(runner: Runner) -> None:
    table = Table(title="Strumenti", box=box.ROUNDED, border_style=theme.BORDER, header_style=f"bold {theme.MUTED}")
    for col in ("Strumento", "Stato", "Percorso", "A cosa serve"):
        table.add_column(col)
    for name, t in installer.TOOLS.items():
        path = runner.which(t.binary)
        table.add_row(name, "[#51cf66]✔ installato[/]" if path else "[#fcc419]✘ mancante[/]", _e(path or "-"), _e(t.description))
    extra = ((("powershell", "controlli nativi di Windows"), ("winget", "installazione di nmap/trivy")) if IS_WINDOWS else
             (("dpkg", "integrità file (Debian/Ubuntu/Kali)"), ("rpm", "integrità file (RHEL/Fedora/Rocky)"), ("systemctl", "servizi")))
    for b, why in extra:
        path = runner.which(b)
        table.add_row(b, "[#51cf66]presente[/]" if path else "[dim]assente[/]", _e(path or "-"), why)
    if IS_WINDOWS:
        mp = malware.defender_exe()
        table.add_row("defender", "[#51cf66]presente[/]" if mp else "[dim]assente[/]", _e(mp or "-"), "antivirus (MpCmdRun, scansione senza rimozione)")
    console.print(table)
    if IS_WINDOWS:
        npcap = os.path.isdir(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"))
        console.print(f"[dim]Npcap (scansione SYN/UDP di Nmap): {'presente' if npcap else 'assente: Nmap usa la scansione TCP connect'}[/dim]")
    console.print(f"[dim]Privilegi: {admin_word() if is_root() else 'utente'} · gestore pacchetti: {installer.detect_manager(runner) or 'nessuno supportato'}[/dim]")


GUARDIA_NOTE = ("[#fcc419]Nota:[/] se il bersaglio ha un rilevamento delle scansioni (come la «Guardia» di Tono), "
                "potrebbe bannare l'IP dell'analizzatore. Mettilo tra i consentiti o disattivalo per la durata del test, "
                "e riattivalo dopo.")


def show_web(out, title: str) -> None:
    from .risk import assess, score_finding
    for f in out.findings:
        score_finding(f)
    issues = [f for f in out.findings if f.status in ("fail", "warn")]
    if issues:
        show_findings(_sorted(issues), title)
    else:
        console.print(f"[{theme.OK}]✔ Nessun problema di configurazione esposta rilevato.[/]")
    s = assess(list(out.findings))
    console.print(f"[dim]Postura esterna indicativa:[/] [bold {GRADE_COLOR.get(s.grade, 'white')}]{s.grade}[/] "
                  f"[dim]({s.posture_score}/100) · rischio = impatto × probabilità · /details ID · /fix ID[/dim]")


def do_web(args: list[str]) -> None:
    insecure = "--insecure" in args
    url = next((a for a in args if not a.startswith("--")), "")
    if not url:                      # nessun URL indicato: lo chiediamo (la persona sceglie la sua web app)
        console.print("[dim]Analisi esterna NON intrusiva di una web application (header di sicurezza, TLS, cookie, metodi).[/dim]")
        url = Prompt.ask(f"[bold {theme.ACCENT}]URL della web application da analizzare[/] [dim](es. https://… — vuoto per annullare)[/dim]").strip()
        if not url:
            console.print("Analisi annullata.")
            return
    try:
        full, host, port = normalize_url(url)
    except WebScanError as exc:
        console.print(f"[red]URL non valido:[/red] {_e(exc)} [dim]Deve iniziare con http:// o https://[/dim]")
        return
    console.print(Panel(
        f"Bersaglio: [bold]{_e(full)}[/]  [dim](host {_e(host)}:{port})[/]\n"
        "Verranno fatte poche richieste in [bold]sola lettura[/] (GET e OPTIONS) e, su https, una connessione TLS per leggere il certificato.\n"
        "[bold]Non[/] vengono inviati payload d'attacco, non si forza nulla: è una revisione della configurazione esposta, [bold]non un penetration test[/].\n"
        + GUARDIA_NOTE,
        title="▲ Analisi esterna della web application", border_style=theme.GOLD, box=box.ROUNDED))
    if not host_is_loopback(host):
        console.print(f"[#fcc419]Il bersaglio non è locale ({_e(host)}).[/] Analizza solo sistemi di cui sei il titolare o hai autorizzazione scritta.")
        if Prompt.ask("Digita AUTORIZZO per confermare di essere autorizzato").strip() != "AUTORIZZO":
            console.print("Analisi annullata.")
            return
    if not Confirm.ask("Sei sicuro di voler avviare l'analisi?", default=False):
        console.print("Analisi annullata.")
        return
    try:
        with console.status("[cyan]Analisi esterna in corso…"):
            out = run_webscan(full, insecure=insecure)
    except WebScanError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    if out.status != "ok":
        console.print(f"[red]Analisi non riuscita:[/red] {_e(out.detail)}")
        return
    STATE["web_findings"] = out.findings
    console.print(f"[dim]{_e(out.detail)}[/dim]")
    show_web(out, f"Analisi esterna · {host}")
    offer_web_report(full, out)


def plan_update(runner: Runner) -> list:
    return installer.plan_update(runner, signatures=malware.update_commands(runner))


def show_update_results(results) -> None:
    for r in results:
        console.print(f"  {'[' + theme.OK + ']◉[/]' if r.ok else '[#ff6b6b]✘[/]'} {_e(r.tool)}: {_e(r.detail)}")
        STATE["installs"].append(r.to_dict())


def do_update(runner: Runner) -> None:
    """Aggiorna ciò che è già installato: strumenti di scansione, database di Trivy, firme antivirus, librerie Python."""
    try:
        steps = plan_update(runner)
    except installer.InstallError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    if not steps:
        console.print("[yellow]Niente da aggiornare: nessuno strumento installato.[/yellow] Usa /install per installarli.")
        return
    prefix = ("sudo --",) if not is_root() and not IS_WINDOWS else ()
    lines = []
    for st in steps:
        lines.append(f"  [{theme.GOLD}]◉[/] {_e(st.description)}")
        if st.argv:
            lines.append(f"    [dim]{_e(' '.join((prefix if st.privileged else ()) + tuple(st.argv)))}[/dim]")
    missing = installer.missing_tools(runner)
    if missing:
        lines.append(f"\n[dim]Non installati (quindi non aggiornati): {_e(', '.join(missing))} · /install per aggiungerli[/dim]")
    lines.append("\n[yellow]Questo MODIFICA il sistema[/yellow] (aggiorna software" + (": Windows potrebbe chiedere conferma con UAC)." if IS_WINDOWS else
                 ("" if is_root() else "; verrà usato sudo dove serve") + ")."))
    console.print(Panel("\n".join(lines), title="▲ Aggiornamento dell'arsenale", border_style=theme.GOLD, box=box.ROUNDED))
    if not Confirm.ask("Procedere con l'aggiornamento?", default=False):
        console.print("Aggiornamento annullato.")
        return
    try:
        results = installer.run_update(runner, steps, root=is_root(), log=lambda m: console.print(f"[dim]{_e(m)}[/dim]"))
    except KeyboardInterrupt:
        console.print("\n[yellow]Aggiornamento interrotto.[/yellow]")
        return
    show_update_results(results)
    bad = [r for r in results if not r.ok]
    console.print(f"[bold {theme.OK}]✔ Arsenale aggiornato.[/]" if not bad else
                  f"[#fcc419]{len(bad)} passo/i non riuscito/i: gli altri strumenti sono stati comunque aggiornati.[/]")


# --------------------------------------------------------------------------- /scan
class _ArgError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _ArgError(message)


def parse_scan_args(args: list[str]) -> ScanOptions:
    p = _Parser(prog="/scan", add_help=False)
    p.add_argument("mode", nargs="?", default="full", choices=MODES)
    p.add_argument("--target", "-t", action="append", default=[])
    p.add_argument("--no-nmap", action="store_true")
    p.add_argument("--no-lynis", action="store_true")
    p.add_argument("--no-trivy", action="store_true")
    p.add_argument("--no-integrity", action="store_true")
    p.add_argument("--no-malware", action="store_true")
    p.add_argument("--offline", action="store_true")
    p.add_argument("--web", action="append", default=[])
    p.add_argument("--web-insecure", action="store_true")
    ns = p.parse_args(args)
    return ScanOptions(profile=STATE["profile"], mode=ns.mode, targets=ns.target, use_nmap=not ns.no_nmap,
                       use_lynis=False if ns.no_lynis else None, use_trivy=False if ns.no_trivy else None,
                       use_integrity=False if ns.no_integrity else None, offline=ns.offline,
                       use_malware=False if ns.no_malware else None, web_targets=ns.web, web_insecure=ns.web_insecure)


def describe_plan(opts: ScanOptions, runner: Runner, targets) -> str:
    from .scan import trivy_target
    miss = lambda tool: "" if runner.which(tool) else f" [#fcc419]({tool} non installato: verrà saltato)[/]"  # noqa: E731
    lines = [f"Sistema [bold]{OS_LABEL}[/] · profilo [cyan]{opts.profile}[/cyan] · modalità [cyan]{opts.mode}[/cyan]",
             f"[dim]{_e(MODE_TABLE[opts.mode])}[/dim]",
             f"Privilegi: {admin_word() if is_root() else '[#fcc419]utente non privilegiato (copertura ridotta, valutazione parziale)[/]'}", "",
             "[bold]Verranno eseguiti[/bold] (solo lettura, nessuna modifica al sistema):",
             f"  [{theme.GOLD}]◉[/] controlli nativi {OS_LABEL} {'estesi' if opts.mode != 'quick' else 'base'}"
             + (" [dim](registro e cmdlet PowerShell Get-*)[/dim]" if IS_WINDOWS else "")]
    if opts.integrity_enabled():
        if IS_WINDOWS:
            lines.append(f"  [{theme.GOLD}]◉[/] firme digitali (Authenticode) degli eseguibili dei servizi")
        else:
            ok = runner.which("dpkg") or runner.which("rpm")
            lines.append(f"  [{theme.GOLD}]◉[/] integrità dei file installati (dpkg --verify / rpm -Va)" + ("" if ok else " [#fcc419](dpkg/rpm assenti: verrà saltato)[/]"))
    if opts.use_nmap:
        lines.append(f"  [{theme.GOLD}]◉[/] Nmap su: {_e(', '.join(t.raw for t in targets))}{miss('nmap')} [dim](genera traffico verso i bersagli)[/dim]")
    if opts.trivy_enabled():
        lines.append(f"  [{theme.GOLD}]◉[/] Trivy: vulnerabilità e segreti in {_e(trivy_target())}{miss('trivy')} [dim](può richiedere diversi minuti)[/dim]")
        lines.append("    [dim]" + ("database in cache locale, nessun download" if opts.offline else
                                     "scarica il database pubblico delle vulnerabilità; nessun file viene inviato; il contenuto dei segreti non viene riportato") + "[/dim]")
    if opts.malware_enabled():
        engines = ["Defender" if malware.defender_exe() else "", "ClamAV" if runner.which("clamscan") else "", "motore interno LSTK"]
        lines.append(f"  [{theme.GOLD}]◉[/] Antivirus ({', '.join(e for e in engines if e)}) su: {_e(', '.join(malware.default_targets('quick'))[:300])}")
        lines.append("    [dim]solo rilevamento: nulla viene spostato o cancellato senza conferma (/quarantine)[/dim]")
    if opts.lynis_enabled() and not IS_WINDOWS:
        lines.append(f"  [{theme.GOLD}]◉[/] Lynis: audit system{miss('lynis')} [dim](può richiedere alcuni minuti)[/dim]")
    if opts.web_enabled():
        lines.append(f"  [{theme.GOLD}]◉[/] Analisi esterna web su: {_e(', '.join(opts.web_targets))} "
                     "[dim](non intrusiva: header di sicurezza, TLS, cookie, metodi; nessun attacco)[/dim]")
    return "\n".join(lines)


def _phases(opts: ScanOptions) -> int:
    return (2 + int(opts.integrity_enabled()) + int(opts.use_nmap) + int(opts.trivy_enabled()) + int(opts.malware_enabled())
            + int(opts.lynis_enabled() and not IS_WINDOWS) + len(opts.web_targets))


def print_modules(a: Assessment):
    t = Table.grid(padding=(0, 1))
    t.add_column()
    t.add_column(style="bold", no_wrap=True)
    t.add_column(style="dim")
    for m in a.modules:
        t.add_row(MODULE_ICON.get(m.status, "•"), f"{m.name} [dim]{m.status}[/]", _e(m.detail))
    console.print(Panel(t, title="Moduli impiegati", title_align="left", border_style=theme.BORDER, box=box.ROUNDED))


def do_scan(opts: ScanOptions) -> None:
    runner = Runner()
    try:
        opts.validate()
        targets, _ = resolve_targets(opts.targets, runner)
    except (TargetError, ValueError) as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    external = [t for t in targets if not t.is_self]
    try:
        web_external = [w for w in opts.web_targets if not host_is_loopback(normalize_url(w)[1])]
    except WebScanError as exc:
        console.print(f"[red]URL non valido:[/red] {_e(exc)}")
        return
    ensure_tools(runner, wanted_tools(opts), "necessari per questa scansione")
    console.print(Panel(describe_plan(opts, runner, targets), title="▲ Piano operativo", border_style=theme.GOLD, box=box.ROUNDED))
    if external or web_external:
        console.print(Panel("[bold red]ATTENZIONE: bersagli NON locali.[/bold red]\n"
                            f"{_e(', '.join([t.raw for t in external] + web_external))}\n"
                            "Analizzare sistemi altrui senza autorizzazione scritta può essere illegale. "
                            "L'analisi web è non intrusiva (solo lettura), ma vale lo stesso principio.",
                            border_style="red"))
        if Prompt.ask("Digita AUTORIZZO per confermare di essere autorizzato ad analizzarli").strip() != "AUTORIZZO":
            console.print("Audit annullato.")
            return
        opts.authorized = True
    if not Confirm.ask("Avviare il risk assessment?", default=True):
        console.print("Audit annullato.")
        return
    total = _phases(opts)
    try:
        with Progress(SpinnerColumn("eye", style=theme.GOLD), TextColumn("[bold]{task.description}"), BarColumn(bar_width=28, complete_style=theme.GOLD, finished_style=theme.OK),
                      TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("Avvio…", total=total)
            first = [True]

            def progress(msg):
                if not first[0]:
                    prog.advance(task)
                first[0] = False
                prog.update(task, description=_e(msg))
            a = run_assessment(opts, runner, progress, STATE["installs"])
            prog.update(task, completed=total, description="Completato")
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrotto dall'utente: nessun risultato salvato.[/yellow]")
        return
    except (AuthorizationError, TargetError, ValueError) as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    STATE["assessment"], STATE["last_scan"] = a, a.finished_at
    print_modules(a)
    show_risk(a)
    if history.enabled():
        try:
            prev = history.entries()
            path = history.save(build_payload(a))
            msg = f"[dim]Salvato nello storico: {_e(path.name)}[/dim]"
            if prev:
                delta = a.summary.posture_score - prev[-1].posture
                arrow = f"[#51cf66]▲ +{delta}[/]" if delta > 0 else f"[#ff6b6b]▼ {delta}[/]" if delta < 0 else "= 0"
                msg += f" [dim]· postura rispetto alla scansione precedente:[/dim] {arrow} [dim](/diff per i dettagli)[/dim]"
            console.print(msg)
        except ReportError as exc:
            console.print(f"[dim]Storico non salvato: {_e(exc)}[/dim]")
    console.print("\n[dim]/findings elenco · /details ID dettaglio · /fix ID correzioni · /report html --open esporta e apre[/dim]")


# --------------------------------------------------------------------------- storico e confronto
def show_history():
    try:
        items = history.entries()
    except ReportError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    if not items:
        console.print("[yellow]Storico vuoto: le scansioni completate dalla console vengono salvate automaticamente.[/yellow]")
        return
    t = Table(title=f"Storico scansioni — {len(items)}", box=box.ROUNDED, border_style=theme.BORDER, header_style=f"bold {theme.MUTED}")
    for col in ("#", "Quando", "Run", "Host", "Modalità", "Voto", "Postura", "Δ", "crit", "alto", "medio", "basso", "Integro"):
        t.add_column(col, justify="right" if col in ("#", "Postura", "Δ", "crit", "alto", "medio", "basso") else "left", no_wrap=True)
    prev = None
    for i, e in enumerate(items, 1):
        delta = "" if prev is None else (f"[#51cf66]+{e.posture - prev}[/]" if e.posture > prev else
                                         f"[#ff6b6b]{e.posture - prev}[/]" if e.posture < prev else "0")
        t.add_row(str(i), _e(e.finished_at[:19].replace("T", " ")), _e(e.short), _e(e.hostname), _e(e.mode),
                  f"[bold {GRADE_COLOR.get(e.grade, 'white')}]{_e(e.grade)}[/]", str(e.posture), delta,
                  *(str(e.counts.get(l, 0)) for l in LEVELS), "[#51cf66]✔[/]" if e.intact else "[#ff6b6b]✘[/]")
        prev = e.posture
    console.print(t)
    console.print(f"Trend postura: [bold {theme.GOLD}]{history.sparkline([e.posture for e in items[-40:]])}[/]  "
                  f"[dim](min {min(e.posture for e in items)}, max {max(e.posture for e in items)}) · /diff A B con # o ID di run[/dim]")


def show_diff(args: list[str]):
    if len(args) > 2:
        console.print("Uso: /diff [A] [B]  (numeri di /history, prefissi dell'ID di run o file JSON)")
        return
    try:
        items = history.entries()

        def resolve(ref):
            if ref and Path(ref).is_file():
                return history.load(Path(ref))
            e = history.find(ref, items)
            return history.load(e.path) if e else None
        if not args:
            if len(items) < 2:
                console.print("[yellow]Servono almeno due scansioni nello storico.[/yellow]")
                return
            old, new = history.load(items[-2].path), history.load(items[-1].path)
        elif len(args) == 1:
            old, new = resolve(args[0]), (history.load(items[-1].path) if items else None)
        else:
            old, new = resolve(args[0]), resolve(args[1])
    except ReportError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    if old is None or new is None:
        console.print("[yellow]Scansione non trovata. Usa /history per gli identificativi.[/yellow]")
        return
    d = history.compare(old, new)
    go, gn = d.grade_change
    arrow = f"[#51cf66]▲ +{d.posture_delta}[/]" if d.posture_delta > 0 else f"[#ff6b6b]▼ {d.posture_delta}[/]" if d.posture_delta < 0 else "invariata"
    head = (f"Voto [bold {GRADE_COLOR.get(go, 'white')}]{_e(go)}[/] → [bold {GRADE_COLOR.get(gn, 'white')}]{_e(gn)}[/] · postura "
            f"{old['summary']['posture_score']} → {new['summary']['posture_score']} ({arrow})\n"
            f"[#ff6b6b]+{len(d.added)} nuovi[/] · [#51cf66]-{len(d.resolved)} risolti[/] · [#ff922b]{len(d.worse)} peggiorati[/] · "
            f"[#4dabf7]{len(d.better)} migliorati[/]")
    for n in d.notes:
        head += f"\n[#fcc419]⚠ {_e(n)}[/]"
    console.print(Panel(head, title=f"Confronto {_e(old['run']['id'][:8])} → {_e(new['run']['id'][:8])}", border_style=theme.GOLD, box=box.ROUNDED))

    def table(title, rows, color):
        if not rows:
            return
        t = Table(title=title, box=box.SIMPLE_HEAVY, title_style=f"bold {color}", expand=True)
        for c in ("ID", "Rischio", "P×I", "Controllo"):
            t.add_column(c, no_wrap=c != "Controllo")
        for f in rows:
            if isinstance(f, tuple):
                old_f, new_f = f
                t.add_row(_e(new_f["id"]), f"{chip(old_f['risk_level'])} → {chip(new_f['risk_level'])}",
                          f"{old_f['risk_score']} → {new_f['risk_score']}", _e(new_f["title"]))
            else:
                t.add_row(_e(f["id"]), chip(f["risk_level"]), str(f["risk_score"]), _e(f["title"]))
        console.print(t)
    table("Nuovi rischi", d.added, "#ff6b6b")
    table("Peggiorati", d.worse, "#ff922b")
    table("Risolti", d.resolved, "#51cf66")
    table("Migliorati", d.better, "#4dabf7")
    if not (d.added or d.resolved or d.worse or d.better):
        console.print("[#51cf66]Nessuna differenza tra i rischi delle due scansioni.[/]")


def show_fix(fid: str, a: Optional[Assessment]):
    m = next((f for f in _known_findings(a) if f.id.lower() == fid.lower()), None)
    real = m.id if m else fid.upper()
    sug = suggestions(real, system_name())
    parts: list = []
    if m:
        parts.append(Text.from_markup(f"{chip(m.risk_level)} {STATUS_ICON.get(m.status, '')}  [bold]{_e(m.title)}[/]\n"
                                      f"[bold #51cf66]Raccomandazione:[/] {_e(m.recommendation)}"))
    if sug["commands"]:
        parts.append(Text(""))
        parts.append(Syntax("\n".join(sug["commands"]), "powershell" if IS_WINDOWS else "bash", theme="monokai", word_wrap=True,
                            background_color="default"))
    if sug["note"]:
        parts.append(Text.from_markup(f"\n[#fcc419]Nota:[/] {_e(sug['note'])}"))
    if not sug["commands"] and not sug["note"]:
        parts.append(Text("Nessun comando predefinito per questo controllo: seguire la raccomandazione in /details."))
    parts.append(Text.from_markup("\n[dim]LSTK non esegue correzioni: usa i comandi solo dopo averli capiti, con un backup, "
                                  "meglio se prima su un sistema di prova.[/dim]"))
    console.print(Panel(Group(*parts), title=f"Correzione suggerita · {_e(real)}", border_style="#fcc419", box=box.ROUNDED))


def show_details(m) -> None:
    refs = ("\n\n[bold]Riferimenti[/bold]\n" + "\n".join(_e(r) for r in m.references)) if m.references else ""
    console.print(Panel(
        f"{chip(m.risk_level)} {STATUS_ICON.get(m.status, _e(m.status))}  [bold]{_e(m.title)}[/bold]\n"
        f"[dim]ID {_e(m.id)} · fonte {_e(m.source)} · categoria {_e(m.category)} · gravità {m.severity} · confidenza {m.confidence}[/dim]\n"
        f"Rischio: P{m.likelihood} × I{m.impact} = [bold]{m.risk_score}[/bold]\n\n"
        f"[bold {theme.ACCENT}]Evidenza[/]\n{_e(m.evidence)}\n\n[bold #51cf66]Raccomandazione[/]\n{_e(m.recommendation)}{refs}\n\n"
        f"[dim]/fix {_e(m.id)} per i comandi di correzione suggeriti[/dim]",
        title="Dettaglio controllo", expand=True, border_style=LEVEL_FG.get(m.risk_level, "white"), box=box.ROUNDED))


def _run_single_module(cmd: str, args: list[str]) -> None:
    runner = Runner()
    offline = "--offline" in args
    if cmd == "/vuln" and not runner.which("trivy"):
        ensure_tools(runner, ["trivy"], "necessario per /vuln")
    if cmd == "/vuln" and not runner.which("trivy"):
        console.print("[yellow]Trivy non disponibile: scansione annullata.[/yellow]")
        return
    if cmd == "/integrity" and not IS_WINDOWS and not (runner.which("dpkg") or runner.which("rpm")):
        console.print("[yellow]dpkg/rpm non disponibili: verifica non supportata su questo sistema.[/yellow]")
        return
    what = "la scansione Trivy (può richiedere diversi minuti)" if cmd == "/vuln" else "la verifica di integrità"
    if not Confirm.ask(f"Avviare {what}? Sola lettura.", default=True):
        return
    from .integrity import run_integrity
    from .risk import score_finding
    from .scan import trivy_target
    from .trivy import run_trivy
    try:
        with console.status("[cyan]In corso…"):
            if cmd == "/vuln":
                out = run_trivy(runner, root=is_root(), offline=offline, target=trivy_target())
                fs, label = out.findings, f"trivy: {out.status} — {out.detail}"
            elif IS_WINDOWS:
                from . import winaudit
                ctx = winaudit.WinCtx(STATE["profile"], True, runner, is_root())
                ctx.deep_inv, _ = winaudit.collect_inventory(runner, winaudit.DEEP_PS, "controlli-approfonditi", 600)
                fs, label = winaudit.check_integrity(ctx), "firme Authenticode degli eseguibili dei servizi"
            else:
                out = run_integrity(runner, root=is_root())
                fs, label = out.findings, f"integrità: {out.status} — {out.detail}"
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrotto.[/yellow]")
        return
    for f in fs:
        score_finding(f)
    console.print(_e(label))
    show_findings(_sorted([f for f in fs if f.status in ("fail", "warn", "unknown", "manual")]), "Risultati")


# --------------------------------------------------------------------------- antivirus e quarantena
def _known_findings(a: Optional[Assessment]) -> list:
    """Finding dell'ultimo /scan più quelli dell'ultimo /av e /web (per /details e /fix)."""
    return (list(a.findings) if a else []) + list(STATE["av_findings"]) + list(STATE["web_findings"])


def parse_av_args(args: list[str]) -> argparse.Namespace:
    p = _Parser(prog="/av", add_help=False)
    p.add_argument("items", nargs="*")
    p.add_argument("--native", action="store_true")
    p.add_argument("--hashes", action="append", default=[])
    ns = p.parse_args(args)
    ns.mode = "quick"
    if ns.items and ns.items[0].lower() in malware.MODES:
        ns.mode = ns.items.pop(0).lower()
    return ns


def av_update(runner: Runner, confirm: bool = True, log=None) -> bool:
    """Aggiorna le firme (freshclam / Defender): modifica solo i database degli antivirus."""
    say = log or (lambda m: console.print(f"[dim]{_e(m)}[/dim]"))
    cmds = malware.update_commands(runner)
    if not cmds:
        say("Nessun antivirus da aggiornare: " + ("Defender non trovato." if IS_WINDOWS else "installare ClamAV con /install clamav."))
        return False
    if not IS_WINDOWS:
        try:
            cmds = [installer._privileged(c, is_root(), runner) for c in cmds]
        except installer.InstallError as exc:
            say(str(exc))
            return False
    if confirm:
        console.print(Panel("\n".join(f"[dim]{_e(' '.join(c))}[/dim]" for c in cmds) +
                            "\n\nScarica le firme ufficiali e aggiorna SOLO il database dell'antivirus.",
                            title="Aggiornamento firme", border_style=theme.GOLD, box=box.ROUNDED))
        if not Confirm.ask("Procedere?", default=True):
            return False
    ok = True
    for c in cmds:
        say("→ " + " ".join(c))
        rc = installer._exec(c, to_stderr=log is not None)
        if rc != 0:
            ok = False
            say(f"terminato con codice {rc}" + ("" if IS_WINDOWS else
                " (se il servizio clamav-freshclam è attivo aggiorna già da solo e tiene bloccato il database)"))
    return ok


def _av_engines(native_only: bool) -> tuple[str, ...]:
    return ("lstk",) if native_only else ("clamav", "defender", "lstk")


def show_av(out) -> None:
    t = Table.grid(padding=(0, 1))
    t.add_column()
    t.add_column(style="bold", no_wrap=True)
    t.add_column(style="dim")
    for e in out.engines:
        t.add_row(MODULE_ICON.get(e.status, "•"), f"{e.engine} [dim]{e.status}[/]", _e(e.detail))
    console.print(Panel(t, title="Motori antivirus", title_align="left", border_style=theme.BORDER, box=box.ROUNDED))
    issues = [f for f in out.findings if f.status in ("fail", "warn", "unknown", "manual")]
    if issues:
        show_findings(_sorted(issues), "Antivirus")
    else:
        console.print("[#51cf66]✔ Nessun malware trovato.[/]")


def offer_quarantine(dets) -> None:
    files = malware.quarantinable(dets)
    if not files:
        return
    console.print(Panel("\n".join(f"  • {_e(p)}" for p in files) +
                        "\n\nI file vengono spostati in una cartella privata, resi non eseguibili e restano ripristinabili (/quarantine restore ID).",
                        title=f"{len(files)} file con malware", border_style="red", box=box.ROUNDED))
    if not Confirm.ask("Metterli in quarantena?", default=False):
        console.print("[dim]Nessun file spostato. Puoi farlo dopo con /quarantine add FILE.[/dim]")
        return
    names: dict = {}
    for d in dets:
        names.setdefault(os.path.normcase(os.path.abspath(d.path)), f"{d.engine}: {d.name}")
    for p in files:
        try:
            it = quarantine.add(p, reason=names.get(os.path.normcase(os.path.abspath(p)), ""), engine="lstk")
            console.print(f"[#51cf66]✔[/] {_e(p)} → quarantena [bold]{it.id}[/]")
        except quarantine.QuarantineError as exc:
            console.print(f"[#ff6b6b]✘[/] {_e(p)}: {_e(exc)}")


def do_av(args: list[str]) -> None:
    runner = Runner()
    if args and args[0].lower() == "update":
        console.print(f"[dim]Le firme ora si aggiornano con[/] [bold {theme.ACCENT}]/update[/] [dim](insieme a tutti gli altri strumenti).[/]")
        return
    try:
        av = parse_av_args(args)
    except _ArgError as exc:
        console.print(f"[red]Argomenti non validi:[/red] {_e(exc)}. Uso: /av [quick|full] [PERCORSO…] [--native] [--hashes FILE]")
        return
    if not IS_WINDOWS and not av.native and not runner.which("clamscan"):
        ensure_tools(runner, ["clamav"], "motore antivirus con firme per /av")
    targets = av.items or malware.default_targets(av.mode)
    missing = [t for t in targets if not os.path.exists(t)]
    if missing:
        console.print(f"[red]Percorsi inesistenti:[/red] {_e(', '.join(missing))}")
        return
    engines = [n for n, ok in (("Defender", IS_WINDOWS and malware.defender_exe()), ("ClamAV", runner.which("clamscan")),
                               ("motore interno LSTK", True)) if ok and (not av.native or n.startswith("motore"))]
    note = ("scansione completa del disco: può richiedere molto tempo" if av.mode == "full" and not av.items
            else "solo lettura: nulla viene spostato senza conferma")
    console.print(Panel(f"Motori: [bold]{_e(', '.join(engines))}[/bold]\nPercorsi: {_e(', '.join(targets))}\n[dim]{note}[/dim]",
                        title="Scansione antivirus", border_style=theme.GOLD, box=box.ROUNDED))
    if not Confirm.ask("Avviare la scansione?", default=True):
        return
    from .risk import score_finding
    try:
        with console.status("[cyan]Scansione in corso…") as status:
            out = malware.run_malware(runner, targets, mode=av.mode, engines=_av_engines(av.native), extra_hashes=av.hashes,
                                      progress=lambda m: status.update(f"[cyan]{_e(m)}"))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scansione interrotta.[/yellow]")
        return
    except ValueError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    for f in out.findings:
        score_finding(f)
    STATE["av_findings"] = out.findings
    show_av(out)
    offer_quarantine(out.detections)
    console.print("[dim]/details ID dettaglio · /fix ID cosa fare · /quarantine elenco dei file in quarantena[/dim]")


def show_quarantine() -> None:
    try:
        its, d = quarantine.items(), quarantine.quarantine_dir()
    except quarantine.QuarantineError as exc:
        console.print(f"[red]{_e(exc)}[/red]")
        return
    if not its:
        console.print(f"[dim]Quarantena vuota ({_e(d)}).[/dim]")
        return
    table = Table(title=f"Quarantena — {len(its)}", caption=_e(str(d)), box=box.ROUNDED, border_style=theme.BORDER, header_style=f"bold {theme.MUTED}")
    for col in ("ID", "Data", "File originale", "Motivo", "Byte"):
        table.add_column(col, overflow="fold", no_wrap=col in ("ID", "Byte"))
    for it in its:
        table.add_row(it.id, it.quarantined_at[:19].replace("T", " "), _e(it.original_path), _e(it.reason), str(it.size))
    console.print(table)


def do_quarantine(args: list[str]) -> None:
    action = args[0].lower() if args else "list"
    try:
        if action == "list":
            show_quarantine()
        elif action == "add" and len(args) >= 2:
            path = " ".join(args[1:])
            if Confirm.ask(f"Spostare in quarantena {_e(path)}?", default=False):
                it = quarantine.add(path, reason="aggiunto manualmente")
                console.print(f"[#51cf66]✔ In quarantena con ID {it.id}[/] (SHA-256 {it.sha256})")
        elif action == "restore" and len(args) >= 2:
            it = quarantine.find(args[1])
            dest = args[2] if len(args) > 2 else None
            console.print(f"[yellow]Ripristinare un file rilevato come malware lo rende di nuovo eseguibile.[/yellow] Motivo: {_e(it.reason)}")
            if Confirm.ask(f"Ripristinare {_e(dest or it.original_path)}?", default=False):
                console.print(f"[#51cf66]✔ Ripristinato:[/] {_e(quarantine.restore(it.id, dest))}")
        elif action == "delete" and len(args) >= 2:
            it = quarantine.find(args[1])
            if Confirm.ask(f"Eliminare DEFINITIVAMENTE {_e(it.original_path)} (SHA-256 {it.sha256[:16]}…)?", default=False):
                quarantine.delete(it.id)
                console.print("[#51cf66]✔ Eliminato.[/]")
        else:
            console.print("Uso: /quarantine [list] · /quarantine add FILE · /quarantine restore ID [DESTINAZIONE] · /quarantine delete ID")
    except quarantine.QuarantineError as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")


def command(line: str) -> bool:
    try:
        parts = shlex.split(line.strip(), posix=not IS_WINDOWS)
    except ValueError as exc:
        console.print(f"[red]Sintassi non valida:[/red] {_e(exc)}")
        return True
    if not parts:
        return True
    cmd, args = parts[0].lower(), [p.strip('"') for p in parts[1:]]
    a: Optional[Assessment] = STATE["assessment"]
    if cmd in ("/exit", "/quit", "exit", "quit"):
        return False
    if cmd in ("/help", "help"):
        print_help()
    elif cmd == "/clear":
        console.clear()
        banner()
    elif cmd == "/profile":
        if not args:
            console.print(f"Profilo corrente: [cyan]{STATE['profile']}[/cyan]. Uso: /profile desktop|server")
        elif args[0] in PROFILES:
            STATE["profile"] = args[0]
            console.print(f"[green]Profilo impostato:[/green] {STATE['profile']}")
        else:
            console.print("[red]Profilo non valido. Usa desktop oppure server.[/red]")
    elif cmd == "/scan":
        try:
            do_scan(parse_scan_args(args))
        except _ArgError as exc:
            console.print(f"[red]Argomenti non validi:[/red] {_e(exc)}. Uso: /scan [quick|deep|full] [--target T] [--no-nmap] [--no-trivy]")
    elif cmd == "/risk":
        show_risk(a) if a else console.print("[yellow]Nessun audit disponibile. Esegui /scan.[/yellow]")
    elif cmd == "/findings":
        if not a:
            console.print("[yellow]Nessun risultato disponibile. Esegui prima /scan.[/yellow]")
        else:
            flt = args[0].lower() if args else "issues"
            if len(args) <= 1 and flt in ("issues", "all", "unverified", *LEVELS):
                show_findings(filter_findings(a.findings, flt), f"Controlli ({flt})")
            else:
                q = " ".join(args).lower()
                show_findings(_sorted([f for f in a.findings if q in f.id.lower() or q in f.title.lower() or q in f.evidence.lower()
                                       or q in f.category.lower()]), f"Ricerca «{q}»")
    elif cmd == "/details":
        if not args:
            console.print("Uso: /details ID")
        else:
            m = next((f for f in _known_findings(a) if f.id.lower() == args[0].lower()), None)
            show_details(m) if m else console.print("[yellow]Controllo non trovato. Esegui /scan e verifica l'ID.[/yellow]")
    elif cmd == "/fix":
        if not args:
            console.print("[yellow]Uso: /fix ID[/yellow]: mostra i comandi di correzione suggeriti (LSTK non modifica mai il sistema).")
        else:
            show_fix(args[0], a)
    elif cmd == "/report":
        fmt = args[0].lower() if args and not args[0].startswith("--") else "html"
        if fmt not in (*FORMATS, "all"):
            console.print(f"Uso: /report [{'|'.join(FORMATS)}|all] [--open]")
        else:
            export_report(fmt, open_after="--open" in args)
    elif cmd == "/history":
        show_history()
    elif cmd == "/diff":
        show_diff(args)
    elif cmd == "/verify":
        if not args:
            console.print("Uso: /verify FILE")
        else:
            res = verify_report(args[0])
            for ok, msg in res.checks:
                console.print(f"  {'[green]✔[/green]' if ok else '[yellow]–[/yellow]' if ok is None else '[red]✘[/red]'} {_e(msg)}")
            console.print("[green]Rapporto integro.[/green]" if res.ok else "[red]Verifica NON superata.[/red]")
    elif cmd == "/doctor":
        doctor(Runner())
    elif cmd == "/install":
        runner = Runner()
        wanted = list(installer.ALL) if not args or args[0] == "all" else args
        bad = [w for w in wanted if w not in installer.TOOLS]
        if bad:
            console.print(f"[red]Strumenti sconosciuti:[/red] {_e(', '.join(bad))}. Disponibili: {', '.join(installer.ALL)}, all")
        elif not installer.missing_tools(runner, wanted):
            console.print("[green]Tutto già installato.[/green]")
        else:
            ensure_tools(runner, wanted)
    elif cmd in ("/vuln", "/integrity"):
        _run_single_module(cmd, args)
    elif cmd == "/update":
        do_update(Runner())
    elif cmd == "/web":
        do_web(args)
    elif cmd == "/av":
        do_av(args)
    elif cmd == "/quarantine":
        do_quarantine(args)
    elif cmd == "/lynis":
        if IS_WINDOWS:
            console.print("[yellow]Lynis esiste solo per Linux/Unix.[/yellow] Su Windows i controlli di hardening sono inclusi in /scan.")
            return True
        runner = Runner()
        if not runner.which("lynis"):
            ensure_tools(runner, ["lynis"], "necessario per /lynis")
        if not runner.which("lynis"):
            console.print("[yellow]Lynis non disponibile: audit annullato.[/yellow]")
        elif Confirm.ask("Avviare 'lynis audit system' (sola lettura, può richiedere minuti)?", default=False):
            from .lynis import run_lynis
            with console.status("[cyan]Lynis in corso…"):
                out = run_lynis(runner, root=is_root())
            console.print(f"Lynis: {out.status} — {_e(out.detail)}")
            show_findings(_sorted([f for f in out.findings if f.status in ("fail", "warn")]), "Controlli Lynis")
    else:
        console.print(f"[red]Comando sconosciuto:[/red] {_e(cmd)}. Digita /help.")
    return True


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Avvia la console interattiva LSTK."""
    if ctx.invoked_subcommand is not None:
        return
    banner(animate=True)
    while True:
        try:
            line = Prompt.ask(f"[bold {theme.GOLD}]▲[/] [bold]lstk[/][dim]@{_e(platform.node()[:20])} ›[/dim]")
            if not command(line):
                break
        except (KeyboardInterrupt, EOFError):
            console.print()
            break
    theme.outro(console)
    console.print(f"[{theme.MUTED}]▲ Canale chiuso. L'occhio si riposa.[/]")


@app.command()
def scan(profile: str = typer.Option("desktop", help="Profilo: desktop o server"),
         mode: str = typer.Option("full", "--mode", "-m", help="quick | deep | full"),
         target: Optional[List[str]] = typer.Option(None, "--target", "-t", help="Bersaglio Nmap non locale (ripetibile)"),
         authorized: bool = typer.Option(False, "--authorized", help="Dichiaro di essere autorizzato a scansionare i bersagli non locali"),
         no_nmap: bool = typer.Option(False, "--no-nmap"), no_lynis: bool = typer.Option(False, "--no-lynis"),
         no_trivy: bool = typer.Option(False, "--no-trivy"), no_integrity: bool = typer.Option(False, "--no-integrity"),
         offline: bool = typer.Option(False, "--offline", help="Trivy: usa solo la cache locale del database"),
         no_malware: bool = typer.Option(False, "--no-malware", help="Non eseguire l'antivirus"),
         web: Optional[List[str]] = typer.Option(None, "--web", help="URL di una web app da analizzare dall'esterno (non intrusivo; ripetibile)"),
         web_insecure: bool = typer.Option(False, "--web-insecure", help="Analisi web: accetta un certificato TLS non verificabile (tipico in rete locale)"),
         install_missing: bool = typer.Option(False, "--install-missing", help="Installa gli strumenti mancanti prima della scansione (modifica il sistema; consenso esplicito)"),
         save: bool = typer.Option(False, "--save", help="Salva anche i rapporti JSON+HTML in lstk-reports/"),
         keep_history: bool = typer.Option(False, "--history", help="Salva la scansione nello storico (per history e diff)"),
         fmt: str = typer.Option("json", "--format", "-f", help="Output su stdout: json | table | sarif | csv | md"),
         fail_on: str = typer.Option("none", "--fail-on", help="Exit code 3 se il rischio complessivo è >= none|low|medium|high|critical"),
         deep: bool = typer.Option(False, "--deep", hidden=True)):
    """Risk assessment non interattivo: risultato su stdout, avanzamento su stderr."""
    if deep and mode == "full":
        mode = "deep"
    if profile not in PROFILES:
        raise typer.BadParameter("Usa desktop oppure server")
    if mode not in MODES:
        raise typer.BadParameter("Usa quick, deep o full")
    if fmt not in ("json", "table", "sarif", "csv", "md"):
        raise typer.BadParameter("--format: json | table | sarif | csv | md")
    if fail_on not in ("none", *LEVELS[::-1]):
        raise typer.BadParameter("--fail-on: none|low|medium|high|critical")
    opts = ScanOptions(profile=profile, mode=mode, targets=list(target or []), authorized=authorized,
                       use_nmap=not no_nmap, use_lynis=False if no_lynis else None,
                       use_trivy=False if no_trivy else None, use_integrity=False if no_integrity else None, offline=offline,
                       use_malware=False if no_malware else None, web_targets=list(web or []), web_insecure=web_insecure)
    runner = Runner()
    installs: list = []
    if install_missing:
        miss = installer.missing_tools(runner, wanted_tools(opts))
        if miss:
            try:
                res = installer.run_install(runner, installer.plan_install(runner, miss), root=is_root(),
                                            log=lambda m: typer.echo(f"[lstk] {m}", err=True), to_stderr=True, names=miss)
            except installer.InstallError as exc:
                typer.echo(f"[lstk] installazione non riuscita: {exc}", err=True)
                res = []
            installs = [r.to_dict() for r in res]
            for r in res:
                typer.echo(f"[lstk] {'OK' if r.ok else 'ERR'} {r.tool}: {r.detail}", err=True)
    try:
        a = run_assessment(opts, runner, lambda m: typer.echo(f"[lstk] {m}", err=True), installs)
    except AuthorizationError as exc:
        typer.echo(f"Errore: {exc} Usa --authorized solo se autorizzato.", err=True)
        raise typer.Exit(2)
    except (TargetError, ValueError) as exc:
        raise typer.BadParameter(str(exc))
    payload = build_payload(a)
    if fmt == "table":
        if not console.is_terminal:
            console.width = max(console.width, 170)
        show_risk(a, top_table=False)
        show_findings(filter_findings(a.findings, "issues"), "Registro dei rischi (rischio = probabilità × impatto)")
        unv = filter_findings(a.findings, "unverified")
        if unv:
            show_findings(unv, "Controlli NON verificati (lacune di copertura, non assenza di rischio)")
    else:
        typer.echo(RENDER[fmt](payload))
    if save:
        try:
            for f in ("json", "html"):
                typer.echo(f"[lstk] salvato: {write_report(payload, f)}", err=True)
        except ReportError as exc:
            typer.echo(f"Errore: {exc}", err=True)
            raise typer.Exit(1)
    if keep_history:
        try:
            typer.echo(f"[lstk] storico: {history.save(payload)}", err=True)
        except ReportError as exc:
            typer.echo(f"[lstk] storico non salvato: {exc}", err=True)
    if fail_on != "none":
        order = ["low", "medium", "high", "critical"]
        if a.summary.overall_level in order and order.index(a.summary.overall_level) >= order.index(fail_on):
            raise typer.Exit(3)


@app.command(name="web")
def web_cmd(url: str = typer.Argument(..., help="URL della web application (es. https://tono.local)"),
            insecure: bool = typer.Option(False, "--insecure", help="Accetta un certificato TLS non verificabile (tipico in rete locale)"),
            authorized: bool = typer.Option(False, "--authorized", help="Dichiaro di essere autorizzato ad analizzare questo bersaglio"),
            fmt: str = typer.Option("table", "--format", "-f", help="table | json"),
            open_report: bool = typer.Option(False, "--open", help="Genera e apre il report grafico HTML nel browser (chiaro anche per i meno esperti)"),
            fail_on: str = typer.Option("none", "--fail-on", help="Exit code 3 se il rischio esterno è >= none|low|medium|high|critical")):
    """Analisi ESTERNA non intrusiva di una web app: header di sicurezza, TLS, cookie, metodi. Nessun attacco, nessun penetration test."""
    if fmt not in ("table", "json"):
        raise typer.BadParameter("--format: table | json")
    if fail_on not in ("none", *LEVELS[::-1]):
        raise typer.BadParameter("--fail-on: none|low|medium|high|critical")
    try:
        full, host, _port = normalize_url(url)
    except WebScanError as exc:
        raise typer.BadParameter(str(exc))
    if not host_is_loopback(host) and not authorized:
        typer.echo(f"Errore: {host} non è locale. Usa --authorized solo se sei il titolare o hai autorizzazione scritta.", err=True)
        raise typer.Exit(2)
    try:
        out = run_webscan(full, insecure=insecure)
    except WebScanError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(1)
    from .risk import assess, score_finding
    for f in out.findings:
        score_finding(f)
    summary = assess(list(out.findings))
    if fmt == "json":
        typer.echo(json.dumps({"url": full, "status": out.status, "detail": out.detail,
                               "summary": summary.to_dict(), "findings": [f.to_dict() for f in out.findings]},
                              ensure_ascii=False, indent=2))
    else:
        if not console.is_terminal:
            console.width = max(console.width, 160)
        show_web(out, f"Analisi esterna · {host}")
    if open_report:
        try:
            path = write_report(build_payload(web_assessment(full, out)), "html")
            STATE["last_html"] = path
            typer.echo(f"Report grafico: {path}")
            open_html()
        except ReportError as exc:
            typer.echo(f"Report non creato: {exc}", err=True)
    if fail_on != "none":
        order = ["low", "medium", "high", "critical"]
        if summary.overall_level in order and order.index(summary.overall_level) >= order.index(fail_on):
            raise typer.Exit(3)


@app.command()
def install(tools: Optional[List[str]] = typer.Argument(None, help="nmap, trivy (su Linux anche lynis, iproute2); default: tutti i mancanti"),
            yes: bool = typer.Option(False, "--yes", "-y", help="Non chiedere conferma")):
    """Installa gli strumenti mancanti (Linux: repository della distribuzione e Trivy verificato; Windows: winget)."""
    runner = Runner()
    wanted = list(tools or installer.ALL)
    if "all" in wanted:
        wanted = list(installer.ALL)
    bad = [w for w in wanted if w not in installer.TOOLS]
    if bad:
        typer.echo(f"Errore: strumenti sconosciuti: {', '.join(bad)} (disponibili: {', '.join(installer.ALL)}, all)", err=True)
        raise typer.Exit(2)
    try:
        missing = installer.missing_tools(runner, wanted)
        if not missing:
            typer.echo("Tutto già installato.")
            raise typer.Exit(0)
        steps = installer.plan_install(runner, missing)
    except installer.InstallError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(2)
    typer.echo("Mancano: " + ", ".join(missing))
    for st in steps:
        typer.echo(f"  - {st.description}" + (f"\n      {' '.join(st.argv)}" if st.argv else ""))
    if not yes and not typer.confirm("Questo modifica il sistema (installa software). Procedere?", default=False):
        typer.echo("Annullato.")
        raise typer.Exit(1)
    try:
        results = installer.run_install(runner, steps, root=is_root(), log=typer.echo, names=missing)
    except installer.InstallError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(1)
    for r in results:
        typer.echo(f"{'OK ' if r.ok else 'ERR'} {r.tool}: {r.detail}")
    raise typer.Exit(0 if results and all(r.ok for r in results) else 1)


@app.command(name="update")
def update_cmd(yes: bool = typer.Option(False, "--yes", "-y", help="Non chiedere conferma"),
               no_python: bool = typer.Option(False, "--no-python", help="Non aggiornare le librerie Python (typer, rich)")):
    """Aggiorna gli strumenti già installati (nmap, lynis, clamav, trivy…), il database di Trivy, le firme antivirus e le librerie Python."""
    runner = Runner()
    try:
        steps = installer.plan_update(runner, signatures=malware.update_commands(runner), python=False if no_python else None)
    except installer.InstallError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(2)
    if not steps:
        typer.echo("Niente da aggiornare: nessuno strumento installato (usa 'lstk install').")
        raise typer.Exit(0)
    for st in steps:
        typer.echo(f"  - {st.description}" + (f"\n      {' '.join(st.argv)}" if st.argv else ""))
    if not yes and not typer.confirm("Questo modifica il sistema (aggiorna software). Procedere?", default=False):
        typer.echo("Annullato.")
        raise typer.Exit(1)
    results = installer.run_update(runner, steps, root=is_root(), log=typer.echo)
    for r in results:
        typer.echo(f"{'OK ' if r.ok else 'ERR'} {r.tool}: {r.detail}")
    raise typer.Exit(0 if all(r.ok for r in results) else 1)


@app.command(name="doctor")
def doctor_cmd():
    """Mostra quali strumenti sono installati."""
    doctor(Runner())


@app.command()
def verify(file: Path = typer.Argument(..., help="Rapporto da verificare")):
    """Verifica hash (e firma HMAC se presente) di un rapporto."""
    res = verify_report(file)
    for ok, msg in res.checks:
        typer.echo(f"{'OK ' if ok else '-- ' if ok is None else 'ERR'} {msg}")
    typer.echo("Rapporto integro." if res.ok else "Verifica NON superata.")
    raise typer.Exit(0 if res.ok else 1)


@app.command(name="history")
def history_cmd():
    """Elenca le scansioni salvate nello storico, con il trend della postura."""
    show_history()


@app.command(name="diff")
def diff_cmd(old: Optional[str] = typer.Argument(None, help="Scansione vecchia (# di history, ID di run o file JSON)"),
             new: Optional[str] = typer.Argument(None, help="Scansione nuova (default: l'ultima)")):
    """Confronta due scansioni: nuovi rischi, risolti, peggiorati, migliorati."""
    show_diff([x for x in (old, new) if x])


@app.command()
def export(file: Path = typer.Argument(..., help="Rapporto JSON di LSTK (anche dallo storico)"),
           fmt: str = typer.Option("html", "--format", "-f", help="html | sarif | csv | md | json")):
    """Rigenera un rapporto in un altro formato partendo dal JSON, senza ripetere la scansione."""
    if fmt not in FORMATS:
        raise typer.BadParameter(f"--format: {' | '.join(FORMATS)}")
    try:
        payload = json.loads(Path(file).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or "findings" not in payload or "integrity" not in payload:
            raise ValueError("non è un rapporto LSTK")
    except (OSError, ValueError) as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(2)
    for f in payload["findings"]:
        f.setdefault("fix", {"commands": [], "note": ""})
    body = {k: v for k, v in payload.items() if k != "integrity"}
    from .report import canonical
    import hashlib
    if payload["integrity"].get("payload_sha256") != hashlib.sha256(canonical(body)).hexdigest():
        typer.echo("Attenzione: il contenuto del rapporto di partenza non corrisponde al suo hash interno.", err=True)
    try:
        typer.echo(f"Salvato: {write_report(payload, fmt)}")
    except ReportError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(1)


@app.command()
def av(paths: Optional[List[str]] = typer.Argument(None, help="File o cartelle (default: percorsi a rischio; con --full tutto il disco)"),
       full: bool = typer.Option(False, "--full", help="Scansione completa del disco"),
       native: bool = typer.Option(False, "--native", help="Solo il motore interno (hash ed euristiche)"),
       hashes: Optional[List[str]] = typer.Option(None, "--hashes", help="Elenco di hash SHA-256 di malware (ripetibile)"),
       update: bool = typer.Option(False, "--update", help="Aggiorna prima le firme (freshclam / Defender)"),
       quarantine_found: bool = typer.Option(False, "--quarantine", help="Mette in quarantena i file con malware (modifica il sistema)"),
       fmt: str = typer.Option("table", "--format", "-f", help="table | json"),
       fail_on_detect: bool = typer.Option(False, "--fail-on-detect", help="Exit code 4 se viene trovato malware")):
    """Antivirus: cerca malware con Defender/ClamAV e il motore interno. Senza --quarantine non modifica nulla."""
    if fmt not in ("table", "json"):
        raise typer.BadParameter("--format: table | json")
    runner = Runner()
    log = lambda m: typer.echo(f"[lstk] {m}", err=True)  # noqa: E731
    if update:
        av_update(runner, confirm=False, log=log)
    try:
        out = malware.run_malware(runner, list(paths or []) or None, mode="full" if full else "quick", engines=_av_engines(native),
                                  extra_hashes=list(hashes or []), progress=log)
    except ValueError as exc:
        raise typer.BadParameter(str(exc))
    from .risk import score_finding
    for f in out.findings:
        score_finding(f)
    moved = []
    if quarantine_found:
        for p in malware.quarantinable(out.detections):
            try:
                it = quarantine.add(p, reason="rilevato da lstk av", engine="lstk")
                moved.append({"path": p, "id": it.id, "sha256": it.sha256})
                log(f"quarantena {it.id}: {p}")
            except quarantine.QuarantineError as exc:
                log(f"quarantena NON riuscita per {p}: {exc}")
    if fmt == "json":
        typer.echo(json.dumps({"status": out.status, "detail": out.detail, "engines": [vars(e) for e in out.engines],
                               "findings": [f.to_dict() for f in out.findings], "quarantined": moved}, ensure_ascii=False, indent=2))
    else:
        show_av(out)
    if fail_on_detect and any(f.id.startswith("AV-DET") for f in out.findings):
        raise typer.Exit(4)


@app.command(name="quarantine")
def quarantine_cmd(action: str = typer.Argument("list", help="list | add | restore | delete"),
                   target: Optional[str] = typer.Argument(None, help="FILE (add) o ID (restore, delete)"),
                   dest: Optional[str] = typer.Option(None, "--dest", help="restore: percorso diverso dall'originale"),
                   yes: bool = typer.Option(False, "--yes", "-y", help="Non chiedere conferma")):
    """Gestisce la quarantena: elenco, aggiunta, ripristino, eliminazione definitiva."""
    if action not in ("list", "add", "restore", "delete"):
        raise typer.BadParameter("list | add | restore | delete")
    if action == "list":
        show_quarantine()
        return
    if not target:
        raise typer.BadParameter("serve un FILE (add) o un ID (restore, delete)")
    try:
        if action == "add":
            if not yes and not typer.confirm(f"Spostare in quarantena {target}?", default=False):
                raise typer.Exit(1)
            it = quarantine.add(target, reason="aggiunto manualmente")
            typer.echo(f"In quarantena: {it.id} (SHA-256 {it.sha256})")
        elif action == "restore":
            it = quarantine.find(target)
            if not yes and not typer.confirm(f"Ripristinare {dest or it.original_path}? Era: {it.reason}", default=False):
                raise typer.Exit(1)
            typer.echo(f"Ripristinato: {quarantine.restore(it.id, dest)}")
        else:
            it = quarantine.find(target)
            if not yes and not typer.confirm(f"Eliminare definitivamente {it.original_path}?", default=False):
                raise typer.Exit(1)
            quarantine.delete(it.id)
            typer.echo("Eliminato.")
    except quarantine.QuarantineError as exc:
        typer.echo(f"Errore: {exc}", err=True)
        raise typer.Exit(2)


if __name__ == "__main__":
    app()
