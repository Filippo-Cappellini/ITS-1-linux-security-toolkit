"""Quarantena dei file rilevati dall'antivirus: spostati, resi non eseguibili e ripristinabili.

Come per l'installer, è una delle poche parti che modificano il sistema, e solo su richiesta esplicita:
- il file viene letto, cifrato con uno XOR fisso (non è protezione crittografica: serve solo a renderlo
  non eseguibile e a non farlo rilevare di nuovo dagli antivirus) e salvato in una cartella privata (0700, file 0600);
- l'originale viene cancellato solo dopo che la copia è stata scritta e riletta con lo stesso SHA-256;
- link simbolici, cartelle e file speciali sono rifiutati;
- il ripristino non sovrascrive mai un file esistente e verifica lo SHA-256;
- ogni operazione resta nei metadati (<id>.json accanto a <id>.bin).

Cartella: LSTK_QUARANTINE_DIR, altrimenti %LOCALAPPDATA%\\lstk\\quarantine (Windows), /var/lib/lstk/quarantine (root)
o ~/.local/share/lstk/quarantine.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .osinfo import IS_WINDOWS, is_admin
from .report import ReportError, _write_exclusive, secure_dir

KEY = bytes.fromhex("6c73746b2d71756172616e74696e6521")   # "lstk-quarantine!"
MAX_SIZE = int(os.environ.get("LSTK_QUARANTINE_MAX", str(1 << 30)))   # 1 GiB


class QuarantineError(RuntimeError):
    pass


@dataclass
class Item:
    id: str
    original_path: str
    sha256: str
    size: int
    mode: int
    reason: str
    engine: str
    quarantined_at: str

    def to_dict(self) -> dict:
        return asdict(self)


def quarantine_dir() -> Path:
    custom = os.environ.get("LSTK_QUARANTINE_DIR")
    if custom:
        base = Path(custom)
    elif IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "lstk" / "quarantine"
    elif is_admin():
        base = Path("/var/lib/lstk/quarantine")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "lstk" / "quarantine"
    try:
        base.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return secure_dir(base)
    except (ReportError, OSError) as exc:
        raise QuarantineError(f"cartella di quarantena non utilizzabile: {exc}") from exc


def _xor(data: bytes) -> bytes:
    k = (KEY * (len(data) // len(KEY) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(k, "little")).to_bytes(len(data), "little")


def _read_regular(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise QuarantineError(f"file non accessibile: {exc}") from exc
    if stat.S_ISLNK(st.st_mode) or getattr(os.path, "isjunction", lambda _p: False)(path):
        raise QuarantineError("è un link simbolico: rifiutato (si metterebbe in quarantena il file sbagliato)")
    if not stat.S_ISREG(st.st_mode):
        raise QuarantineError("non è un file regolare")
    if st.st_size > MAX_SIZE:
        raise QuarantineError(f"file troppo grande ({st.st_size} byte, limite {MAX_SIZE}): usare lo strumento dell'antivirus")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_SIZE + 1)
    except OSError as exc:
        raise QuarantineError(f"lettura non riuscita: {exc}") from exc
    return data, st


def add(path: str | os.PathLike, *, reason: str = "", engine: str = "", directory: Path | None = None) -> Item:
    """Sposta il file in quarantena. Ritorna l'elemento creato; in caso di errore l'originale resta dov'era."""
    src = Path(os.path.abspath(path))
    data, st = _read_regular(src)
    d = directory or quarantine_dir()
    if src.resolve().is_relative_to(d.resolve()):
        raise QuarantineError("il file è già nella cartella di quarantena")
    digest = hashlib.sha256(data).hexdigest()
    item = Item(uuid.uuid4().hex[:12], str(src), digest, len(data), stat.S_IMODE(st.st_mode), reason[:500], engine[:40],
                datetime.now().astimezone().isoformat(timespec="seconds"))
    blob, meta = d / f"{item.id}.bin", d / f"{item.id}.json"
    try:
        _write_exclusive(blob, _xor(data))
        if hashlib.sha256(_xor(blob.read_bytes())).hexdigest() != digest:
            raise QuarantineError("la copia in quarantena non corrisponde all'originale")
        _write_exclusive(meta, json.dumps(item.to_dict(), ensure_ascii=False, indent=2).encode("utf-8"))
    except (OSError, QuarantineError) as exc:
        for p in (blob, meta):
            p.unlink(missing_ok=True)
        raise QuarantineError(f"copia in quarantena non riuscita: {exc}") from exc
    try:
        if IS_WINDOWS and not os.access(src, os.W_OK):
            os.chmod(src, stat.S_IWRITE)      # file in sola lettura: su Windows impedirebbe la cancellazione
        os.remove(src)
    except OSError as exc:
        blob.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
        raise QuarantineError(f"impossibile rimuovere l'originale ({exc}): servono privilegi di {'amministratore' if IS_WINDOWS else 'root'}? "
                              "Nulla è stato spostato.") from exc
    return item


def items(directory: Path | None = None) -> list[Item]:
    d = directory or quarantine_dir()
    out: list[Item] = []
    for meta in sorted(d.glob("*.json")):
        try:
            raw = json.loads(meta.read_text(encoding="utf-8"))
            it = Item(**{k: raw[k] for k in Item.__dataclass_fields__})
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if it.id == meta.stem and (d / f"{it.id}.bin").is_file():
            out.append(it)
    return sorted(out, key=lambda i: i.quarantined_at)


def find(item_id: str, directory: Path | None = None) -> Item:
    matches = [i for i in items(directory) if i.id.startswith(item_id.strip().lower())] if item_id.strip() else []
    if not matches:
        raise QuarantineError(f"nessun elemento in quarantena con ID {item_id!r}")
    if len(matches) > 1:
        raise QuarantineError(f"ID {item_id!r} ambiguo: specificare più caratteri")
    return matches[0]


def restore(item_id: str, dest: str | None = None, directory: Path | None = None) -> Path:
    """Ripristina il file (nel percorso originale o in dest). Non sovrascrive mai."""
    d = directory or quarantine_dir()
    it = find(item_id, d)
    data = _xor((d / f"{it.id}.bin").read_bytes())
    if hashlib.sha256(data).hexdigest() != it.sha256:
        raise QuarantineError("il contenuto in quarantena è alterato (SHA-256 diverso): ripristino rifiutato")
    target = Path(os.path.abspath(dest or it.original_path))
    if target.exists() or target.is_symlink():
        raise QuarantineError(f"{target} esiste già: indicare un'altra destinazione")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_exclusive(target, data)
        if not IS_WINDOWS:
            os.chmod(target, it.mode & 0o777)
    except OSError as exc:
        raise QuarantineError(f"scrittura non riuscita: {exc}") from exc
    _drop(d, it.id)
    return target


def delete(item_id: str, directory: Path | None = None) -> Item:
    d = directory or quarantine_dir()
    it = find(item_id, d)
    _drop(d, it.id)
    return it


def _drop(d: Path, item_id: str) -> None:
    for ext in (".bin", ".json"):
        (d / f"{item_id}{ext}").unlink(missing_ok=True)
