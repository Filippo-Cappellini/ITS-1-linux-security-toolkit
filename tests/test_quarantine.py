import hashlib
import json
import os

import pytest

from lstk import quarantine
from lstk.quarantine import QuarantineError

PAYLOAD = b"MZ contenuto finto di un malware \x00\x01\x02" * 50


@pytest.fixture
def qdir(tmp_path, monkeypatch):
    d = tmp_path / "q"
    monkeypatch.setenv("LSTK_QUARANTINE_DIR", str(d))
    return d


def make(tmp_path, name="bad.exe", data=PAYLOAD):
    f = tmp_path / name
    f.write_bytes(data)
    return f


def test_add_list_restore_roundtrip(tmp_path, qdir):
    f = make(tmp_path)
    it = quarantine.add(f, reason="clamav: Win.Trojan.Test", engine="clamav")
    assert not f.exists()
    blob = (qdir / f"{it.id}.bin").read_bytes()
    assert PAYLOAD not in blob and b"MZ" != blob[:2]                  # non eseguibile e non più rilevabile
    meta = json.loads((qdir / f"{it.id}.json").read_text(encoding="utf-8"))
    assert meta["sha256"] == hashlib.sha256(PAYLOAD).hexdigest() and meta["original_path"] == str(f)
    assert [i.id for i in quarantine.items()] == [it.id]
    assert quarantine.restore(it.id[:6]) == f and f.read_bytes() == PAYLOAD
    assert quarantine.items() == []


def test_restore_never_overwrites(tmp_path, qdir):
    f = make(tmp_path)
    it = quarantine.add(f)
    f.write_bytes(b"nuovo file legittimo")
    with pytest.raises(QuarantineError, match="esiste già"):
        quarantine.restore(it.id)
    assert f.read_bytes() == b"nuovo file legittimo"
    alt = tmp_path / "altro" / "copia.exe"
    assert quarantine.restore(it.id, str(alt)) == alt and alt.read_bytes() == PAYLOAD


def test_tampered_blob_is_refused(tmp_path, qdir):
    it = quarantine.add(make(tmp_path))
    blob = qdir / f"{it.id}.bin"
    data = bytearray(blob.read_bytes())
    data[0] ^= 0xFF
    blob.write_bytes(bytes(data))
    with pytest.raises(QuarantineError, match="alterato"):
        quarantine.restore(it.id)


def test_delete(tmp_path, qdir):
    it = quarantine.add(make(tmp_path))
    quarantine.delete(it.id)
    assert quarantine.items() == [] and not list(qdir.iterdir())


def test_rejects_directories_and_missing(tmp_path, qdir):
    with pytest.raises(QuarantineError):
        quarantine.add(tmp_path)
    with pytest.raises(QuarantineError):
        quarantine.add(tmp_path / "manca.exe")


def test_rejects_symlinks(tmp_path, qdir):
    target = make(tmp_path, "vero.txt", b"file importante")
    link = tmp_path / "link.exe"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("link simbolici non disponibili")
    with pytest.raises(QuarantineError, match="link"):
        quarantine.add(link)
    assert target.read_bytes() == b"file importante"


def test_unknown_and_ambiguous_ids(tmp_path, qdir):
    with pytest.raises(QuarantineError, match="nessun"):
        quarantine.find("abc")
    with pytest.raises(QuarantineError):
        quarantine.find("")


def test_original_kept_when_copy_fails(tmp_path, qdir, monkeypatch):
    f = make(tmp_path)
    monkeypatch.setattr(quarantine, "_write_exclusive", lambda *_a: (_ for _ in ()).throw(OSError("disco pieno")))
    with pytest.raises(QuarantineError, match="disco pieno"):
        quarantine.add(f)
    assert f.read_bytes() == PAYLOAD and not any(qdir.iterdir())
