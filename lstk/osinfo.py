"""Rilevamento della piattaforma (Linux / Windows) e dei privilegi, in un solo punto."""
from __future__ import annotations

import os
import platform
import sys

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")


def system_name() -> str:
    """'windows', 'linux' o il nome restituito da platform (es. 'darwin')."""
    if IS_WINDOWS:
        return "windows"
    if IS_LINUX:
        return "linux"
    return platform.system().lower() or "unknown"


def is_admin() -> bool:
    """root su Linux, membro attivo (token elevato) degli Administrators su Windows."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def admin_word() -> str:
    return "amministratore" if IS_WINDOWS else "root"


def current_user() -> str:
    for key in ("USERNAME", "USER", "LOGNAME"):
        if os.environ.get(key):
            return os.environ[key]
    return str(os.getuid()) if hasattr(os, "getuid") else ""
