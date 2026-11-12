import base64
import os

import pytest

from lstk import runner as rmod
from lstk.runner import Runner, powershell_argv

windows_only = pytest.mark.skipif(os.name != "nt", reason="solo Windows")


def test_powershell_script_is_encoded_not_interpolated():
    script = "Write-Output 'a\"; Remove-Item C:\\ -Recurse #'"
    argv = powershell_argv("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", script)
    assert "-EncodedCommand" in argv and "-NonInteractive" in argv and "-NoProfile" in argv
    decoded = base64.b64decode(argv[-1]).decode("utf-16-le")
    assert decoded.endswith(script) and "$ErrorActionPreference='Stop'" in decoded
    assert all(script not in a for a in argv)            # lo script non compare mai in chiaro sulla riga di comando


@windows_only
def test_windows_safe_path_has_system_dirs_first():
    first = rmod.SAFE_PATH.split(os.pathsep)[0].lower()
    assert first.endswith("system32")


@windows_only
def test_windows_runs_without_shell_and_records_execution():
    r = Runner()
    res = r.run(["cmd", "/c", "echo", "lstk-ok"])
    assert res.ok and "lstk-ok" in res.out and r.executions[0].returncode == 0


@windows_only
def test_windows_timeout_kills_process_tree():
    r = Runner()
    res = r.run(["ping", "-n", "8", "127.0.0.1"], timeout=1)
    assert res.timed_out and res.rc == 124


@windows_only
def test_windows_environment_is_minimal(monkeypatch):
    monkeypatch.setenv("LSTK_EVIL", "1")
    env = Runner._env()
    assert "LSTK_EVIL" not in env and env["PATH"] == rmod.SAFE_PATH and "SystemRoot" in env


@windows_only
def test_powershell_label_in_executions():
    r = Runner()
    res = r.powershell("Write-Output ('è' + 'ok')", timeout=60, name="prova")
    assert res.ok and res.out == "èok"
    assert r.executions[-1].argv[:2] == ["powershell", "<prova>"]
