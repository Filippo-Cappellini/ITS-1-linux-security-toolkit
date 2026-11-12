"""Esecuzione controllata di comandi esterni (Linux e Windows).

- nessuna shell (argv come lista);
- binari risolti solo in directory di sistema (anti PATH-hijacking, importante se eseguito come root/amministratore);
- ambiente minimo e stdin chiuso;
- timeout con terminazione dell'intero gruppo/albero di processi;
- ogni esecuzione è registrata e finisce nel rapporto (trasparenza).
"""
from __future__ import annotations

import base64
import os
import shutil
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime

from .osinfo import IS_WINDOWS, is_admin

POSIX_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT = 2_000_000


def _windows_safe_path() -> str:
    """Directory di sistema e di Program Files (scrivibili solo da amministratori), poi i collegamenti di winget."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    pf = os.environ.get("ProgramFiles") or r"C:\Program Files"
    pf86 = os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)"
    dirs = [os.path.join(root, "System32"), root, os.path.join(root, "System32", "Wbem"),
            os.path.join(root, "System32", "WindowsPowerShell", "v1.0"),
            os.path.join(pf, "Nmap"), os.path.join(pf86, "Nmap"), os.path.join(pf, "Trivy")]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        # winget installa alcuni pacchetti per utente (es. Trivy) e crea qui i collegamenti: cartelle dell'utente, ultime in ordine.
        dirs += [os.path.join(local, "Microsoft", "WinGet", "Links"), os.path.join(local, "Microsoft", "WindowsApps")]
    return os.pathsep.join(dirs)


SAFE_PATH = _windows_safe_path() if IS_WINDOWS else POSIX_SAFE_PATH


def is_root() -> bool:
    """root su Linux, amministratore (token elevato) su Windows."""
    return is_admin()


@dataclass
class CmdResult:
    rc: int
    out: str = ""
    err: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


@dataclass
class Execution:
    argv: list
    started_at: str
    duration_s: float
    returncode: int
    timed_out: bool

    def to_dict(self) -> dict:
        return asdict(self)


_WIN_ENV_KEYS = ("SystemRoot", "windir", "SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432",
                 "CommonProgramFiles", "USERPROFILE", "USERNAME", "USERDOMAIN", "COMPUTERNAME", "LOCALAPPDATA", "APPDATA",
                 "TEMP", "TMP", "PATHEXT", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS", "HOMEDRIVE", "HOMEPATH")

PS_PRELUDE = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
              "[Console]::OutputEncoding=[Text.Encoding]::UTF8;")


def powershell_argv(exe: str, script: str) -> list[str]:
    """Script passato come -EncodedCommand (UTF-16LE base64): nessun problema di quoting né di iniezione di argomenti."""
    encoded = base64.b64encode((PS_PRELUDE + script).encode("utf-16-le")).decode("ascii")
    return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]


class Runner:
    def __init__(self) -> None:
        self.executions: list[Execution] = []

    def which(self, name: str) -> str | None:
        return shutil.which(name, path=SAFE_PATH)

    @staticmethod
    def _env() -> dict[str, str]:
        if IS_WINDOWS:
            env = {k: os.environ[k] for k in _WIN_ENV_KEYS if k in os.environ}
            env["PATH"] = SAFE_PATH
            return env
        env = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C", "TERM": "dumb"}
        for key in ("HOME", "USER", "LOGNAME"):
            if key in os.environ:
                env[key] = os.environ[key]
        return env

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        if IS_WINDOWS:
            taskkill = shutil.which("taskkill", path=SAFE_PATH)
            if taskkill:   # termina l'intero albero di processi
                subprocess.run([taskkill, "/T", "/F", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
            try:
                proc.kill()
            except OSError:
                pass
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass

    def run(self, args: list[str], timeout: int = 10, *, encoding: str | None = None,
            label: list[str] | None = None) -> CmdResult:
        exe = args[0]
        if not os.path.isabs(exe):
            resolved = self.which(exe)
            if resolved is None:
                return CmdResult(127, "", f"comando non trovato: {exe}")
            args = [resolved, *args[1:]]
        started = datetime.now().astimezone().isoformat(timespec="seconds")
        t0 = time.monotonic()
        kwargs: dict = {}
        if IS_WINDOWS:
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kwargs["start_new_session"] = True
        try:
            proc = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding=encoding, errors="replace", env=self._env(), **kwargs,
            )
        except OSError as exc:
            return CmdResult(127, "", str(exc))
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(proc)
            out, err = proc.communicate()
        except BaseException:
            self._kill(proc)
            proc.wait()
            raise
        rc = 124 if timed_out else proc.returncode
        self.executions.append(Execution(list(label or args), started, round(time.monotonic() - t0, 2), rc, timed_out))
        return CmdResult(rc, (out or "").strip()[:MAX_OUTPUT], (err or "").strip()[:MAX_OUTPUT], timed_out)

    def powershell(self, script: str, timeout: int = 30, *, name: str = "") -> CmdResult:
        """Esegue uno script PowerShell di sola lettura. Nel rapporto compare con un'etichetta leggibile, non in base64."""
        exe = self.which("powershell") or self.which("pwsh")
        if not exe:
            return CmdResult(127, "", "PowerShell non trovato")
        label = ["powershell", f"<{name or 'script'}>", " ".join(script.split())[:200]]
        return self.run(powershell_argv(exe, script), timeout, encoding="utf-8", label=label)
