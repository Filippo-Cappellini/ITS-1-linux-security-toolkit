from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import webbrowser
from pathlib import Path
from typing import List, Optional

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

from . import __version__, history, installer
from .fixes import suggestions
from .nmapscan import TargetError
from .osinfo import IS_WINDOWS, admin_word, system_name
from .report import FORMATS, RENDER, ReportError, build_payload, verify_report, write_report
from .risk import LEVELS
from .runner import Runner, is_root
from .scan import MODE_TABLE, MODES, PROFILES, Assessment, AuthorizationError, ScanOptions, resolve_targets, run_assessment

app = typer.Typer(add_completion=False, no_args_is_help=False, help="LSTK Security Toolkit (Linux e Windows)")
console = Console(highlight=False)
STATE: dict = {"profile": "desktop", "assessment": None, "last_scan": None, "installs": [], "last_html": None}

OS_LABEL = "Windows" if IS_WINDOWS else "Linux"
LOGO_LINES = [
    "██╗     ███████╗████████╗██╗  ██╗",
    "██║     ██╔════╝╚══██╔══╝██║ ██╔╝",
    "██║     ███████╗   ██║   █████╔╝ ",
    "██║     ╚════██║   ██║   ██╔═██╗ ",
    "███████╗███████║   ██║   ██║  ██╗",
    "╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝",
]
GRADIENT = ["#4dabf7", "#4c9cf5", "#5c7cfa", "#7048e8", "#9c36b5", "#c2255c"]

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
    ("Scansione", [
        ("/scan [quick|deep|full]", "Risk assessment completo del sistema (default: full)"),
        ("   --target IP|CIDR|host", "Scansiona anche bersagli non locali (serve autorizzazione)"),
        ("   --no-nmap --no-trivy --no-integrity" + ("" if IS_WINDOWS else " --no-lynis"), "Esclude un modulo (valutazione parziale)"),
        ("   --offline", "Trivy usa solo il database in cache"),
        ("/vuln · /integrity" + ("" if IS_WINDOWS else " · /lynis"), "Esegue un singolo modulo"),
        ("/profile desktop|server", "Mostra o cambia profilo"),
    ]),
    ("Risultati", [
        ("/risk", "Cruscotto: voto, postura, matrice 5×5, rischi principali"),
        ("/findings [filtro]", "issues (default) · all · critical|high|medium|low · unverified"),
        ("/details ID · /fix ID", "Dettaglio di un controllo · comandi di correzione suggeriti"),
        ("/search TESTO", "Cerca tra i controlli (titolo, evidenza, ID)"),
    ]),
    ("Rapporti e storico", [
        ("/report [json|html|sarif|csv|md|all]", "Esporta (hash SHA-256, HMAC opzionale); --open apre l'HTML"),
        ("/open", "Apre nel browser l'ultimo rapporto HTML"),
        ("/history", "Scansioni precedenti con trend della postura"),
        ("/diff [A] [B]", "Confronta due scansioni (default: le ultime due)"),
        ("/verify FILE", "Verifica l'integrità di un rapporto"),
    ]),
    ("Strumenti e console", [
        ("/doctor · /install [nome|all]", "Strumenti presenti · installazione guidata"),
        ("/checks · /status", "Controlli implementati · stato del programma"),
        ("/clear · /help · /exit", "Pulisce · guida · esce"),
    ]),
]
HELP = [row for _, rows in HELP_GROUPS for row in rows]


def _e(x) -> str:
    return escape(str(x))


def chip(level: str, text: str | None = None) -> str:
    return f"[{LEVEL_STYLE.get(level, 'white')}] {_e(text or LEVEL_IT.get(level, level))} [/]"


def logo() -> Text:
    t = Text()
    for line, col in zip(LOGO_LINES, GRADIENT):
        t.append(line + "\n", style=f"bold {col}")
    t.append("SECURITY TOOLKIT", style="bold white")
    t.append(f"  v{__version__}\n", style="dim")
    t.append("Linux & Windows · Risk assessment · Nmap · Trivy · Lynis", style="#9aa5b8")
    return t


def tool_chips(runner: Runner) -> str:
    return "  ".join(f"[#51cf66]✔[/] {n}" if runner.which(t.binary) else f"[#ff6b6b]✘[/] [dim]{n}[/]" for n, t in installer.TOOLS.items())


def banner():
    runner = Runner()
    info = Table.grid(padding=(0, 2))
    info.add_column(style="#9aa5b8", justify="right")
    info.add_column()
    info.add_row("Sistema", _e(f"{OS_LABEL} · {platform.platform(terse=True)}"))
    info.add_row("Host", _e(platform.node()))
    info.add_row("Privilegi", f"[#51cf66]{admin_word()}[/]" if is_root() else
                 f"[#fcc419]utente[/] [dim](copertura ridotta: {'Esegui come amministratore' if IS_WINDOWS else 'usa sudo'})[/]")
    info.add_row("Profilo", f"[bold]{STATE['profile']}[/]")
    info.add_row("Strumenti", tool_chips(runner))
    if console.width >= 100:
        body = Table.grid(padding=(0, 6))
        body.add_column(no_wrap=True)
        body.add_column(vertical="middle")
        body.add_row(logo(), info)
    else:
        body = Group(logo(), Text(""), info)
    console.print(Panel(body, border_style="#5c7cfa", box=box.ROUNDED, padding=(1, 2)))
    console.print("  [bold #4dabf7]/scan[/] avvia l'assessment · [bold #4dabf7]/help[/] tutti i comandi · "
                  "[dim]nulla parte da solo e nulla viene modificato sul sistema[/]\n")


def print_help():
    for title, rows in HELP_GROUPS:
        t = Table(box=box.SIMPLE_HEAD, show_header=False, expand=True, padding=(0, 1))
        t.add_column(style="bold #4dabf7", no_wrap=True, ratio=2)
        t.add_column(ratio=3)
        for cmd, desc in rows:
            t.add_row(_e(cmd), _e(desc))
        console.print(Panel(t, title=f"[bold]{title}[/]", title_align="left", border_style="#3b5bdb", box=box.ROUNDED))
    console.print("[dim]Esempi: /scan · /scan quick · /scan full --target 192.168.1.10 · /findings high · /fix FW-001 · /report all · /diff[/dim]")


def show_findings(findings, title="Risultati"):
    if not findings:
        console.print("[yellow]Nessun risultato per questo filtro. Esegui /scan oppure cambia filtro.[/yellow]")
        return
    table = Table(title=f"[bold]{_e(title)}[/] [dim]— {len(findings)}[/]", box=box.ROUNDED, expand=True, border_style="#3b5bdb",
                  header_style="bold #9aa5b8")
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


# --------------------------------------------------------------------------- installazione strumenti mancanti
def show_install_results(results) -> None:
    for r in results:
        console.print(f"  {'[green]✔[/green]' if r.ok else '[red]✘[/red]'} {_e(r.tool)}: {_e(r.detail)}")
        STATE["installs"].append(r.to_dict())


def wanted_tools(opts: ScanOptions) -> list[str]:
    if IS_WINDOWS:
        return (["nmap"] if opts.use_nmap else []) + (["trivy"] if opts.trivy_enabled() else [])
    return (["iproute2"] + (["nmap"] if opts.use_nmap else []) + (["lynis"] if opts.lynis_enabled() else [])
            + (["trivy"] if opts.trivy_enabled() else []))


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
    table = Table(title="Strumenti", box=box.ROUNDED, border_style="#3b5bdb", header_style="bold #9aa5b8")
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
    console.print(table)
    if IS_WINDOWS:
        npcap = os.path.isdir(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"))
        console.print(f"[dim]Npcap (scansione SYN/UDP di Nmap): {'presente' if npcap else 'assente: Nmap usa la scansione TCP connect'}[/dim]")
    console.print(f"[dim]Privilegi: {admin_word() if is_root() else 'utente'} · gestore pacchetti: {installer.detect_manager(runner) or 'nessuno supportato'}[/dim]")


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
    p.add_argument("--offline", action="store_true")
    ns = p.parse_args(args)
    return ScanOptions(profile=STATE["profile"], mode=ns.mode, targets=ns.target, use_nmap=not ns.no_nmap,
                       use_lynis=False if ns.no_lynis else None, use_trivy=False if ns.no_trivy else None,
                       use_integrity=False if ns.no_integrity else None, offline=ns.offline)


def describe_plan(opts: ScanOptions, runner: Runner, targets) -> str:
    from .scan import trivy_target
    miss = lambda tool: "" if runner.which(tool) else f" [#fcc419]({tool} non installato: verrà saltato)[/]"  # noqa: E731
    lines = [f"Sistema [bold]{OS_LABEL}[/] · profilo [cyan]{opts.profile}[/cyan] · modalità [cyan]{opts.mode}[/cyan]",
             f"[dim]{_e(MODE_TABLE[opts.mode])}[/dim]",
             f"Privilegi: {admin_word() if is_root() else '[#fcc419]utente non privilegiato (copertura ridotta, valutazione parziale)[/]'}", "",
             "[bold]Verranno eseguiti[/bold] (solo lettura, nessuna modifica al sistema):",
             f"  [#4dabf7]●[/] controlli nativi {OS_LABEL} {'estesi' if opts.mode != 'quick' else 'base'}"
             + (" [dim](registro e cmdlet PowerShell Get-*)[/dim]" if IS_WINDOWS else "")]
    if opts.integrity_enabled():
        if IS_WINDOWS:
            lines.append("  [#4dabf7]●[/] firme digitali (Authenticode) degli eseguibili dei servizi")
        else:
            ok = runner.which("dpkg") or runner.which("rpm")
            lines.append("  [#4dabf7]●[/] integrità dei file installati (dpkg --verify / rpm -Va)" + ("" if ok else " [#fcc419](dpkg/rpm assenti: verrà saltato)[/]"))
    if opts.use_nmap:
        lines.append(f"  [#4dabf7]●[/] Nmap su: {_e(', '.join(t.raw for t in targets))}{miss('nmap')} [dim](genera traffico verso i bersagli)[/dim]")
    if opts.trivy_enabled():
        lines.append(f"  [#4dabf7]●[/] Trivy: vulnerabilità e segreti in {_e(trivy_target())}{miss('trivy')} [dim](può richiedere diversi minuti)[/dim]")
        lines.append("    [dim]" + ("database in cache locale, nessun download" if opts.offline else
                                     "scarica il database pubblico delle vulnerabilità; nessun file viene inviato; il contenuto dei segreti non viene riportato") + "[/dim]")
    if opts.lynis_enabled() and not IS_WINDOWS:
        lines.append(f"  [#4dabf7]●[/] Lynis: audit system{miss('lynis')} [dim](può richiedere alcuni minuti)[/dim]")
    return "\n".join(lines)


def _phases(opts: ScanOptions) -> int:
    return 2 + int(opts.integrity_enabled()) + int(opts.use_nmap) + int(opts.trivy_enabled()) + int(opts.lynis_enabled() and not IS_WINDOWS)


def print_modules(a: Assessment):
    t = Table.grid(padding=(0, 1))
    t.add_column()
    t.add_column(style="bold", no_wrap=True)
    t.add_column(style="dim")
    for m in a.modules:
        t.add_row(MODULE_ICON.get(m.status, "•"), f"{m.name} [dim]{m.status}[/]", _e(m.detail))
    console.print(Panel(t, title="Moduli", title_align="left", border_style="#3b5bdb", box=box.ROUNDED))


def do_scan(opts: ScanOptions) -> None:
    runner = Runner()
    try:
        opts.validate()
        targets, _ = resolve_targets(opts.targets, runner)
    except (TargetError, ValueError) as exc:
        console.print(f"[red]Errore:[/red] {_e(exc)}")
        return
    external = [t for t in targets if not t.is_self]
    ensure_tools(runner, wanted_tools(opts), "necessari per questa scansione")
    console.print(Panel(describe_plan(opts, runner, targets), title="Piano di assessment", border_style="#4dabf7", box=box.ROUNDED))
    if external:
        console.print(Panel("[bold red]ATTENZIONE: bersagli NON locali.[/bold red]\n"
                            f"{_e(', '.join(t.raw for t in external))}\n"
                            "Scansionare sistemi altrui senza autorizzazione scritta può essere illegale.",
                            border_style="red"))
        if Prompt.ask("Digita AUTORIZZO per confermare di essere autorizzato a scansionarli").strip() != "AUTORIZZO":
            console.print("Audit annullato.")
            return
        opts.authorized = True
    if not Confirm.ask("Avviare il risk assessment?", default=True):
        console.print("Audit annullato.")
        return
    total = _phases(opts)
    try:
        with Progress(SpinnerColumn(style="#4dabf7"), TextColumn("[bold]{task.description}"), BarColumn(bar_width=28, complete_style="#5c7cfa"),
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
    console.print("\n[dim]/findings elenco · /details ID dettaglio · /fix ID correzioni · /report html|sarif|all esporta · /open apre l'HTML[/dim]")


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
    t = Table(title=f"Storico scansioni — {len(items)}", box=box.ROUNDED, border_style="#3b5bdb", header_style="bold #9aa5b8")
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
    console.print(f"Trend postura: [bold #5c7cfa]{history.sparkline([e.posture for e in items[-40:]])}[/]  "
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
    console.print(Panel(head, title=f"Confronto {_e(old['run']['id'][:8])} → {_e(new['run']['id'][:8])}", border_style="#5c7cfa", box=box.ROUNDED))

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
    m = next((f for f in (a.findings if a else []) if f.id.lower() == fid.lower()), None)
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
        f"[bold #4dabf7]Evidenza[/]\n{_e(m.evidence)}\n\n[bold #51cf66]Raccomandazione[/]\n{_e(m.recommendation)}{refs}\n\n"
        f"[dim]/fix {_e(m.id)} per i comandi di correzione suggeriti[/dim]",
        title="Dettaglio controllo", expand=True, border_style=LEVEL_FG.get(m.risk_level, "white"), box=box.ROUNDED))


CHECKS_LINUX = [
    ("sistema", "OS, kernel, contesto/privilegi, container, riavvio richiesto"),
    ("pacchetti", "gestore e aggiornamenti in sospeso (da cache locale, sola lettura)"),
    ("firewall", "servizi attivi e, come root, regole nft/iptables"),
    ("ssh", "configurazione effettiva (sshd -T come root) o file con Include; cifrari deboli"),
    ("account", "UID 0, password vuote, sudo NOPASSWD, scadenza password"),
    ("filesystem", "permessi file critici, mount /tmp, SUID e directory world-writable (deep/full)"),
    ("kernel", "parametri sysctl di hardening"),
    ("hardening", "SELinux/AppArmor, logging, auditd, NTP, cifratura disco"),
    ("servizi", "servizi abilitati e legacy (deep/full)"),
    ("integrità file", "dpkg --verify / rpm -Va; file world-writable e orfani (deep/full)"),
    ("vulnerabilità (Trivy)", "CVE di pacchetti OS e librerie, segreti nei file, OS fuori supporto (full)"),
    ("rete (Nmap)", "porte TCP (UDP top-50 come root in full), servizi/versioni, esposizione loopback vs rete"),
    ("Lynis", "audit completo importato come finding (warning/suggerimenti, hardening index)"),
]
CHECKS_WINDOWS = [
    ("sistema", "versione e ciclo di vita di Windows (fine supporto), riavvio in sospeso, privilegi"),
    ("aggiornamenti", "aggiornamenti in sospeso (dati locali di Windows Update), ultimo hotfix, servizio wuauserv"),
    ("antimalware", "Defender in tempo reale, firme, Tamper Protection, esclusioni rischiose, PUA, regole ASR, antivirus di terze parti"),
    ("firewall", "profili Dominio/Privato/Pubblico e azione predefinita in ingresso"),
    ("account", "UAC, Guest, Administrator integrato, account senza password, membri Administrators, policy password/blocco"),
    ("credenziali", "WDigest, protezione LSA (RunAsPPL), NTLMv1/LM, Credential Guard e VBS"),
    ("cifratura e avvio", "BitLocker/Crittografia dispositivo, Secure Boot"),
    ("rete", "SMBv1, firma SMB, condivisioni, LLMNR, porte TCP in ascolto con processo"),
    ("hardening", "PowerShell 2.0, Script Block Logging, AutoRun, SmartScreen"),
    ("accesso remoto e servizi", "RDP e NLA, WinRM, OpenSSH, Spooler (server), Telnet/FTP/SNMP/Registro remoto/UPnP"),
    ("privilege escalation (deep/full)", "percorsi dei servizi senza virgolette, cartelle del PATH scrivibili, programmi in avvio automatico"),
    ("integrità (deep/full)", "firma Authenticode degli eseguibili dei servizi"),
    ("vulnerabilità (Trivy, full)", "librerie vulnerabili e segreti nei file del profilo utente"),
    ("rete (Nmap)", "porte TCP, servizi/versioni, esposizione loopback vs rete (SYN/UDP con Npcap e amministratore)"),
]


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
    if cmd in ("/help", "help", "/?"):
        print_help()
    elif cmd == "/clear":
        console.clear()
        banner()
    elif cmd == "/status":
        console.print(Panel(f"LSTK {__version__} · {OS_LABEL}\nSistema: {_e(platform.platform())}\nPrivilegi: {admin_word() if is_root() else 'utente'}\n"
                            f"Profilo: {STATE['profile']}\nUltimo audit: {STATE['last_scan'] or 'nessuno'}\n"
                            f"Controlli in memoria: {len(a.findings) if a else 0}\n"
                            f"Storico: {'attivo' if history.enabled() else 'disattivato (LSTK_NO_HISTORY)'}",
                            title="Stato", border_style="#3b5bdb", box=box.ROUNDED))
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
            flt = args[0] if args else "issues"
            if flt not in ("issues", "all", "unverified", *LEVELS):
                console.print("Uso: /findings [issues|all|critical|high|medium|low|unverified]")
            else:
                show_findings(filter_findings(a.findings, flt), f"Controlli ({flt})")
    elif cmd == "/search":
        if not args:
            console.print("Uso: /search TESTO")
        elif not a:
            console.print("[yellow]Nessun risultato disponibile. Esegui prima /scan.[/yellow]")
        else:
            q = " ".join(args).lower()
            show_findings(_sorted([f for f in a.findings if q in f.id.lower() or q in f.title.lower() or q in f.evidence.lower()
                                   or q in f.category.lower()]), f"Ricerca «{q}»")
    elif cmd == "/details":
        if not args:
            console.print("Uso: /details ID")
        else:
            m = next((f for f in (a.findings if a else []) if f.id.lower() == args[0].lower()), None)
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
    elif cmd == "/open":
        open_html()
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
    elif cmd == "/checks":
        table = Table(title=f"Controlli implementati ({OS_LABEL})", box=box.ROUNDED, border_style="#3b5bdb")
        table.add_column("Area", style="cyan")
        table.add_column("Copertura")
        for x, y in (CHECKS_WINDOWS if IS_WINDOWS else CHECKS_LINUX):
            table.add_row(x, y)
        console.print(table)
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
    banner()
    while True:
        try:
            line = Prompt.ask("[bold #5c7cfa]lstk[/] [dim]›[/dim]")
            if not command(line):
                break
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Uscita dalla console.[/dim]")
            break
    console.print("[dim]LSTK terminato.[/dim]")


@app.command()
def scan(profile: str = typer.Option("desktop", help="Profilo: desktop o server"),
         mode: str = typer.Option("full", "--mode", "-m", help="quick | deep | full"),
         target: Optional[List[str]] = typer.Option(None, "--target", "-t", help="Bersaglio Nmap non locale (ripetibile)"),
         authorized: bool = typer.Option(False, "--authorized", help="Dichiaro di essere autorizzato a scansionare i bersagli non locali"),
         no_nmap: bool = typer.Option(False, "--no-nmap"), no_lynis: bool = typer.Option(False, "--no-lynis"),
         no_trivy: bool = typer.Option(False, "--no-trivy"), no_integrity: bool = typer.Option(False, "--no-integrity"),
         offline: bool = typer.Option(False, "--offline", help="Trivy: usa solo la cache locale del database"),
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
                       use_trivy=False if no_trivy else None, use_integrity=False if no_integrity else None, offline=offline)
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


if __name__ == "__main__":
    app()
