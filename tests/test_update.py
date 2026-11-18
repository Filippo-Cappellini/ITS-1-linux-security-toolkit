import io
import os
import sys
import pytest
from rich.console import Console
from lstk import cli, installer, theme
from lstk.installer import plan_update, run_update
from lstk.runner import CmdResult


linux_only = pytest.mark.skipif(os.name == "nt", reason="specifico di Linux/POSIX: eseguito nella CI Linux")


class Spy:
    def __init__(self, rc=0):
        self.calls, self.rc = [], rc

    def __call__(self, argv, to_stderr=False):
        assert isinstance(argv, list)
        self.calls.append(list(argv))
        return self.rc


def trivy_says(version):
    return {"trivy": CmdResult(0, f"Version: {version}\n")}


@linux_only
def test_update_only_touches_installed_packages(fake):
    r = fake(binaries=["apt-get", "nmap", "clamscan", "sudo"])
    steps = plan_update(r, python=False)
    assert steps[0].argv == ["/usr/bin/apt-get", "update"] and steps[0].optional
    assert steps[1].argv == ["/usr/bin/apt-get", "install", "--only-upgrade", "-y", "clamav", "nmap"]
    assert not any("lynis" in " ".join(s.argv or []) for s in steps)


@linux_only
def test_update_other_managers(fake):
    assert plan_update(fake(binaries=["dnf", "nmap"]), python=False)[0].argv == ["/usr/bin/dnf", "upgrade", "-y", "nmap"]
    assert plan_update(fake(binaries=["zypper", "lynis"]), python=False)[0].argv == ["/usr/bin/zypper", "--non-interactive", "update", "lynis"]
    assert plan_update(fake(binaries=["pacman", "nmap"]), python=False)[0].argv == ["/usr/bin/pacman", "-Syu", "--noconfirm"]


@linux_only
def test_update_trivy_binary_only_if_older_and_always_db(fake):
    old = plan_update(fake(trivy_says("0.50.1"), binaries=["trivy"]), python=False)
    assert old[0].download and old[0].tool == "trivy"
    assert old[1].argv == ["/usr/bin/trivy", "image", "--download-db-only", "--no-progress"] and not old[1].privileged
    new = plan_update(fake(trivy_says(installer.TRIVY_VERSION), binaries=["trivy"]), python=False)
    assert [s.tool for s in new] == ["trivy-db"]


def test_update_nothing_installed_is_empty(fake):
    assert plan_update(fake(), python=False) == []


def test_update_signatures_and_python(fake):
    steps = plan_update(fake(), signatures=[["/usr/bin/freshclam"]], python=True)
    assert steps[0].argv == ["/usr/bin/freshclam"]
    assert steps[1].argv[:4] == [sys.executable, "-m", "pip", "install"] and not steps[1].privileged


@linux_only
def test_run_update_uses_sudo_only_where_needed_and_continues_after_errors(fake):
    r = fake(binaries=["sudo"])
    steps = [installer.UpdateStep("a", "a", ["/usr/bin/apt-get", "update"], optional=True),
             installer.UpdateStep("b", "b", ["/usr/bin/apt-get", "install"]),
             installer.UpdateStep("c", "c", ["/usr/bin/trivy", "image"], privileged=False)]
    spy = Spy(rc=1)
    res = run_update(r, steps, root=False, log=lambda m: None, exec_fn=spy)
    assert spy.calls[0][:2] == ["/usr/bin/sudo", "--"] and spy.calls[2] == ["/usr/bin/trivy", "image"]
    assert [x.ok for x in res] == [True, False, False] and len(spy.calls) == 3


def test_console_update_and_removed_commands(fake, monkeypatch):
    monkeypatch.setattr(cli, "Runner", lambda: fake())
    monkeypatch.setattr(cli.malware, "update_commands", lambda runner: [])
    monkeypatch.setattr(installer, "in_virtualenv", lambda: False)
    assert cli.command("/update") is True          # niente da aggiornare: nessuna domanda
    for gone in ("/status", "/checks", "/open", "/search x", "/antivirus"):
        assert cli.command(gone) is True           # "comando sconosciuto", nessun errore


def test_theme_pyramid_shape_and_no_animation_off_terminal():
    lines = theme.pyramid("open").plain.splitlines()
    assert len(lines) == theme.H + 2 and len({len(l) for l in lines}) == 1 and "◉" in theme.pyramid("left").plain
    for eye in theme.EYES.values():
        assert [len(x) for x in eye] == [7, 9, 11]
    c = Console(file=io.StringIO())
    assert not theme.should_animate(c)
    theme.intro(c, "x")
    theme.outro(c)
