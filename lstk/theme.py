"""Grafica "classificata" della console: piramide con l'occhio, timbri e animazione d'avvio.

Solo presentazione: nessuna logica di sicurezza qui. L'animazione parte solo su un terminale vero
e si disattiva con LSTK_NO_ANIM=1 (o premendo Ctrl+C, che la salta).
"""
from __future__ import annotations

import os
import random
import time

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.spinner import SPINNERS
from rich.text import Text

GOLD = "#d4af37"
GOLD_HI = "#ffe08a"
GOLD_DIM = "#8b6914"
BORDER = "#8b6914"
ACCENT = "#e6c35c"
STAMP = "bold white on #9b111e"
MUTED = "#9a8f6e"
OK = "#3ddc84"
CYAN = "#39d0d8"          # accento "scanner" freddo, contrasta con l'oro
DANGER = "#ff4d4d"

# Pulsazione del bagliore dell'occhio (dal cupo al bianco e ritorno)
PULSE = ["#8b6914", "#b8860b", "#d4af37", "#f5d76e", "#ffe08a", "#ffffff", "#ffe08a", "#f5d76e", "#d4af37", "#b8860b"]

LOGO_LINES = [
    "██╗     ███████╗████████╗██╗  ██╗",
    "██║     ██╔════╝╚══██╔══╝██║ ██╔╝",
    "██║     ███████╗   ██║   █████╔╝ ",
    "██║     ╚════██║   ██║   ██╔═██╗ ",
    "███████╗███████║   ██║   ██║  ██╗",
    "╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝",
]
# Gradiente oro "lucido": ripetuto così da poter scorrere (shimmer) sotto il logo
GRADIENT = ["#fff3b0", "#f5d76e", "#e6b422", "#d4a017", "#b8860b", "#8b6508"]
SHIMMER = ["#8b6508", "#b8860b", "#d4a017", "#e6b422", "#f5d76e", "#fff3b0", "#ffffff", "#fff3b0", "#f5d76e", "#e6b422"]
MOTTO = "OCULUS · VIDET · OMNIA"

# Occhio: tre righe (larghezze 7, 9, 11) dentro la piramide
EYES = {
    "closed": ("       ", "  ━━━━━  ", "           "),
    "half":   ("  ___  ", " ( ━◉━ ) ", "           "),
    "open":   ("  .-.  ", " ( (◉) ) ", "    `-´    "),
    "left":   ("  .-.  ", " ((◉)  ) ", "    `-´    "),
    "right":  ("  .-.  ", " (  (◉)) ", "    `-´    "),
    "wide":   ("  .-.  ", " (((◉))) ", "    `-´    "),
}
H = 9            # righe della piramide sotto la punta
EYE_ROW = 4      # prima riga dell'occhio
CAP_ROW = 7      # linea che separa il vertice dai mattoni

# Spinner con l'occhio che si guarda intorno (usato da Progress/status)
SPINNERS.setdefault("eye", {"interval": 130, "frames": ["(◉  )", "( ◉ )", "(  ◉)", "( ◉ )", "( ─ )", "( ◉ )"]})
SPINNERS.setdefault("scan", {"interval": 90, "frames": ["▰▱▱▱▱", "▰▰▱▱▱", "▱▰▰▱▱", "▱▱▰▰▱", "▱▱▱▰▰", "▱▱▱▱▰", "▱▱▱▱▱"]})


def _bricks(width: int, row: int) -> str:
    pattern = "▀▀▀ " if row % 2 else "▀ ▀▀"
    return (pattern * (width // 4 + 2))[row % 3: row % 3 + width]


def pyramid(eye: str = "open", rows: int = H + 2, glow: str = GOLD, sweep: int | None = None,
            rays: bool = False) -> Text:
    """La piramide con l'occhio.

    rows  : costruzione dal basso durante l'animazione (quante righe mostrare).
    glow  : colore dell'occhio e del vertice (per la pulsazione).
    sweep : indice di riga (1..H) illuminato più forte: una banda che scorre (effetto scansione).
    rays  : aggiunge due raggi laterali al vertice (l'occhio "irradia").
    """
    lines: list[tuple[str, str]] = []                 # (testo, stile)
    apex = " " * H + "▲" + " " * H
    if rays:
        apex = " " * (H - 2) + "‹ " + "▲" + " ›" + " " * (H - 2)
    lines.append((apex, f"bold {glow}"))
    e = EYES.get(eye, EYES["open"])
    for i in range(1, H + 1):
        w = 2 * i - 1
        pad = " " * (H - i)
        if EYE_ROW <= i < EYE_ROW + 3:
            inner, style = e[i - EYE_ROW], f"bold {glow}"
        elif i == CAP_ROW:
            inner, style = "─" * w, GOLD_DIM
        elif i > CAP_ROW:
            inner, style = _bricks(w, i), GOLD_DIM
        else:
            inner, style = " " * w, GOLD
        if sweep == i:                                 # banda luminosa di scansione
            inner_style = f"bold {GOLD_HI}"
            lines.append((pad + "╱" + inner + "╲" + pad, f"{GOLD_HI}|{inner_style}"))
            continue
        lines.append((pad + "╱" + inner + "╲" + pad, style if i > CAP_ROW else f"{GOLD}|{style}"))
    lines.append(("▀" * (2 * H + 1), GOLD_DIM))
    t = Text()
    hidden = len(lines) - rows
    for n, (s, style) in enumerate(lines):
        if n < hidden:
            t.append(" " * len(s) + "\n")
            continue
        if "|" in style:                               # bordo e interno con colori diversi
            frame, inner_style = style.split("|")
            t.append(s[: s.index("╱") + 1], style=frame)
            t.append(s[s.index("╱") + 1: s.rindex("╲")], style=inner_style)
            t.append(s[s.rindex("╲"):] + "\n", style=frame)
        else:
            t.append(s + "\n", style=style)
    t.rstrip()
    return t


SCRAMBLE = "░▒▓█#@%&$¥§Ω∆λΞ‡◢◣01"


def _scramble(s: str, reveal: float, rnd: random.Random) -> str:
    return "".join(c if c == " " or rnd.random() < reveal else rnd.choice(SCRAMBLE) for c in s)


def logo(reveal: float = 1.0, version: str = "", seed: int = 0, shift: int = 0) -> Text:
    """Logo LSTK. reveal<1 = effetto "decifratura"; shift = scorrimento del gradiente (shimmer)."""
    rnd = random.Random(seed)
    grad = SHIMMER if shift else GRADIENT
    t = Text()
    for n, line in enumerate(LOGO_LINES):
        col = grad[(n + shift) % len(grad)]
        t.append(_scramble(line, reveal, rnd) + "\n", style=f"bold {col}")
    t.append(_scramble("SECURITY TOOLKIT", reveal, rnd), style="bold white")
    if version:
        t.append(f"  v{version}", style="dim")
    t.append("\n")
    t.append(_scramble(MOTTO, reveal, rnd), style=f"italic {MUTED}")
    t.append("\n\n")
    t.append(" TOP SECRET ", style=STAMP)
    t.append(" ")
    t.append(" EYES ONLY ", style=f"bold black on {GOLD}")
    return t


def stamp(text: str) -> str:
    return f"[{STAMP}] {text} [/]"


def should_animate(console: Console) -> bool:
    return console.is_terminal and not os.environ.get("LSTK_NO_ANIM") and not os.environ.get("CI")


# --------------------------------------------------------------------------- log di avvio "a macchina"
BOOT_LOG = [
    ("stabilizzazione del canale cifrato", OK),
    ("blocco biometrico dell'operatore", OK),
    ("montaggio del dossier riservato", OK),
    ("l'occhio è vigile", GOLD_HI),
]


def _typed(done: list[str], current: str, cursor: bool) -> Text:
    t = Text()
    for line in done:
        t.append("  ✔ ", style=OK)
        t.append(line + "\n", style=MUTED)
    if current is not None:
        t.append("  › ", style=CYAN)
        t.append(current, style=f"bold {CYAN}")
        t.append("█" if cursor else " ", style=CYAN)
    return t


def intro(console: Console, version: str) -> None:
    """Animazione d'avvio (~3 s): la piramide si erge, una scansione la percorre, l'occhio si apre e pulsa,
    un log di accesso si scrive a macchina, il titolo si decifra e lampeggia 'ACCESSO CONCESSO'."""
    if not should_animate(console):
        return

    def frame(eye="closed", rows=H + 2, reveal=0.0, glow=GOLD, sweep=None, rays=False,
              shift=0, seed=0, boot_done=(), boot_cur=None, cursor=True, banner_line=""):
        parts = [Text(""), Align.center(pyramid(eye, rows, glow, sweep, rays)), Text("")]
        parts.append(Align.center(logo(reveal, version, seed, shift)))
        if boot_done or boot_cur is not None:
            parts += [Text(""), Align.center(_typed(list(boot_done), boot_cur, cursor))]
        if banner_line:
            parts += [Text(""), Align.center(Text.from_markup(banner_line))]
        return Group(*parts)

    try:
        with Live(frame(rows=0), console=console, refresh_per_second=60, transient=True) as live:
            # 1) la piramide si erge dal basso, con un fremito di glitch sul vertice
            for r in range(1, H + 3):
                live.update(frame(rows=r, glow=random.choice([GOLD, GOLD_HI, GOLD_DIM]),
                                  banner_line=f"[{CYAN}]▚ costruzione del canale sicuro…[/]"))
                time.sleep(0.045)
            # 2) una banda di scansione percorre la piramide (due passate)
            for _ in range(2):
                for s in range(1, H + 1):
                    live.update(frame(eye="closed", sweep=s, banner_line=f"[{CYAN}]▚ scansione della struttura…[/]"))
                    time.sleep(0.022)
            # 3) l'occhio si apre e pulsa, con i raggi
            for eye, pause in (("closed", 0.18), ("half", 0.12), ("open", 0.22), ("wide", 0.12), ("open", 0.15)):
                live.update(frame(eye, rays=True, banner_line=f"[{GOLD}]◉ identificazione dell'operatore…[/]"))
                time.sleep(pause)
            for g in PULSE + PULSE[:4]:
                live.update(frame("open", glow=g, rays=True, banner_line=f"[{GOLD}]◉ identificazione dell'operatore…[/]"))
                time.sleep(0.04)
            # 4) l'occhio osserva, mentre si scrive il log d'accesso
            done: list[str] = []
            eyes = ["left", "open", "right", "open", "wide", "open"]
            for idx, (msg, _col) in enumerate(BOOT_LOG):
                for j in range(1, len(msg) + 1):
                    live.update(frame(eyes[(idx * 2 + j) % len(eyes)], glow=GOLD_HI, rays=True,
                                      boot_done=done, boot_cur=msg[:j], cursor=(j % 2 == 0)))
                    time.sleep(0.014)
                done.append(msg)
                live.update(frame("open", glow=GOLD_HI, rays=True, boot_done=done, boot_cur=None))
                time.sleep(0.09)
            # 5) il titolo si decifra con lo shimmer del gradiente
            for k in range(1, 15):
                live.update(frame("open", reveal=k / 14, glow=GOLD_HI, rays=True, shift=k, seed=k, boot_done=done, boot_cur=None))
                time.sleep(0.045)
            # 6) lampeggio finale "ACCESSO CONCESSO"
            for on in (True, False, True, False, True):
                live.update(frame("wide" if on else "open", reveal=1, glow="#ffffff" if on else GOLD_HI, rays=True,
                                  shift=6, boot_done=done, boot_cur=None,
                                  banner_line=(f"[bold black on {OK}]  ✔ ACCESSO CONCESSO  [/]" if on else "")))
                time.sleep(0.12)
            live.update(frame("open", reveal=1, glow=GOLD, rays=True, shift=0, boot_done=done, boot_cur=None,
                              banner_line=f"[bold black on {OK}]  ✔ ACCESSO CONCESSO  [/]"))
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass


def outro(console: Console) -> None:
    """L'occhio si chiude all'uscita, con un ultimo bagliore."""
    if not should_animate(console):
        return
    try:
        with Live(pyramid("open"), console=console, refresh_per_second=60, transient=True) as live:
            for g in ("#ffffff", GOLD_HI, GOLD):
                live.update(pyramid("open", glow=g))
                time.sleep(0.08)
            for eye in ("open", "half", "closed"):
                live.update(pyramid(eye, glow=GOLD_DIM))
                time.sleep(0.16)
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
