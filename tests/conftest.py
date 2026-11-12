import os
import pytest
from lstk.runner import CmdResult, Runner


class FakeRunner(Runner):
    """Runner deterministico: nessun comando reale viene eseguito.

    responses: {"nome-binario": CmdResult | callable(args)} e, per PowerShell, {"ps:<nome-script>": CmdResult | callable(script)}.
    """

    def __init__(self, responses=None, binaries=()):
        super().__init__()
        self.responses = responses or {}
        self.binaries = set(binaries)
        self.calls = []

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.binaries else None

    def run(self, args, timeout=10, **kw):
        self.calls.append(list(args))
        h = self.responses.get(os.path.basename(args[0]))
        if h is None:
            return CmdResult(127, "", "non trovato")
        return h(args) if callable(h) else h

    def powershell(self, script, timeout=30, *, name=""):
        self.calls.append(["powershell", name])
        h = self.responses.get(f"ps:{name}")
        if h is None:
            return CmdResult(127, "", "PowerShell non disponibile (test)")
        return h(script) if callable(h) else h


@pytest.fixture
def fake():
    return FakeRunner


@pytest.fixture(autouse=True)
def _isolated_reports(tmp_path, monkeypatch):
    """I test non scrivono mai rapporti o storico nella cartella del progetto."""
    d = tmp_path / "reports"
    d.mkdir(mode=0o700)
    monkeypatch.setenv("LSTK_REPORT_DIR", str(d))
    monkeypatch.delenv("LSTK_HISTORY_DIR", raising=False)
