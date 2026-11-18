"""Grafica "classificata" della console: piramide con l'occhio, timbri e animazione d'avvio.

Solo presentazione: nessuna logica di sicurezza qui. L'animazione parte solo su un terminale vero
e si disattiva con LSTK_NO_ANIM=1 (o premendo Ctrl+C, che la salta).
"""
from __future__ import annotations

import os
import random
import time

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

LOGO_LINES = [
    "██╗     ███████╗████████╗██╗  ██╗",
    "██║     ██╔════╝╚══██╔══╝██║ ██╔╝",
    "██║     ███████╗   ██║   █████╔╝ ",
    "██║     ╚════██║   ██║   ██╔═██╗ ",
    "███████╗███████║   ██║   ██║  ██╗",
    "╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝",
]
GRADIENT = ["#fff3b0", "#f5d76e", "#e6b422", "#d4a017", "#b8860b", "#8b6508"]
MOTTO = "OCULUS · VIDET · OMNIA"

# Occhio: tre righe (larghezze 7, 9, 11) dentro la piramide
EYES = {
    "closed": ("       ", "  ━━━━━  ", "           "),
    "half":   ("  ___  ", " ( ━◉━ ) ", "           "),
    "open":   ("  .-.  ", " ( (◉) ) ", "    `-´    "),
    "left":   ("  .-.  ", " ((◉)  ) ", "    `-´    "),
    "right":  ("  .-.  ", " (  (◉)) ", "    `-´    "),
}
H = 9            # righe della piramide sotto la punta
EYE_ROW = 4      # prima riga dell'occhio
CAP_ROW = 7      # linea che separa il vertice dai mattoni

# Spinner con l'occhio che si guarda intorno (usato da Progress/status)
SPINNERS.setdefault("eye", {"interval": 140, "frames": ["(◉  )", "( ◉ )", "(  ◉)", "( ◉ )", "( ─ )", "( ◉ )"]})


def _bricks(width: int, row: int) -> str:
    pattern = "▀▀▀ " if row % 2 else "▀ ▀▀"
    return (pattern * (width // 4 + 2))[row % 3: row % 3 + width]


def pyramid(eye: str = "open", rows: int = H + 2, glow: str = GOLD) -> Text:
    """La piramide con l'occhio; `rows` permette di costruirla dal basso durante l'animazione."""
    lines: list[tuple[str, str]] = []                 # (testo, stile)
    lines.append((" " * H + "▲" + " " * H, f"bold {glow}"))
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


SCRAMBLE = "░▒▓█#@%&$¥§Ω∆"


def _scramble(s: str, reveal: float, rnd: random.Random) -> str:
    return "".join(c if c == " " or rnd.random() < reveal else rnd.choice(SCRAMBLE) for c in s)


def logo(reveal: float = 1.0, version: str = "", seed: int = 0) -> Text:
    rnd = random.Random(seed)
    t = Text()
    for line, col in zip(LOGO_LINES, GRADIENT):
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


def intro(console: Console, version: str) -> None:
    """Animazione d'avvio (~2,5 s): la piramide si alza, l'occhio si apre e si guarda intorno, il titolo si decifra."""
    if not should_animate(console):
        return

    def frame(eye="closed", rows=H + 2, reveal=0.0, glow=GOLD, status="", seed=0):
        line = Text(status, style=f"{MUTED}") if status else Text("")
        return Group(Text(""), pyramid(eye, rows, glow), Text(""), logo(reveal, version, seed), Text(""), line)

    try:
        with Live(frame(rows=0), console=console, refresh_per_second=30, transient=True) as live:
            for r in range(1, H + 3):
                live.update(frame(rows=r, status="▲ costruzione del canale sicuro…"))
                time.sleep(0.05)
            for eye, pause in (("closed", 0.25), ("half", 0.12), ("open", 0.3)):
                live.update(frame(eye, status="◉ identificazione dell'operatore…"))
                time.sleep(pause)
            for glow in (GOLD_HI, "#ffffff", GOLD_HI, GOLD):
                live.update(frame("open", glow=glow, status="◉ identificazione dell'operatore…"))
                time.sleep(0.07)
            for eye in ("left", "open", "right", "open"):
                live.update(frame(eye, status="◉ l'occhio osserva il sistema…"))
                time.sleep(0.2)
            for k in range(1, 13):
                live.update(frame("open", reveal=k / 12, seed=k, status="▓ decifratura del dossier…"))
                time.sleep(0.05)
            live.update(frame("half", reveal=1, status="✔ accesso concesso"))
            time.sleep(0.1)
            live.update(frame("open", reveal=1, status="✔ accesso concesso"))
            time.sleep(0.35)
    except KeyboardInterrupt:
        pass


def outro(console: Console) -> None:
    """L'occhio si chiude all'uscita."""
    if not should_animate(console):
        return
    try:
        with Live(pyramid("open"), console=console, refresh_per_second=30, transient=True) as live:
            for eye in ("half", "closed"):
                time.sleep(0.15)
                live.update(pyramid(eye))
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
