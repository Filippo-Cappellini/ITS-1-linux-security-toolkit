import json

from typer.testing import CliRunner

from lstk import cli
from lstk.sourcescan import parse_semgrep, run_sourcescan


def write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def ids(out):
    return {f.id.rsplit("-", 1)[0] for f in out.findings}


def test_heuristics_flag_secrets_and_dangerous_calls(tmp_path):
    write(tmp_path, "app/config.py", 'API_KEY = "sk-abcdef123456"\npassword = "hunter2xyz"\n')
    write(tmp_path, "app/run.py", "import os\nos.system(user_cmd)\nq = 'SELECT * FROM t WHERE id=' + uid\n")
    write(tmp_path, "web/view.js", "el.innerHTML = userInput\n")
    out = run_sourcescan(str(tmp_path), use_semgrep=False)
    got = ids(out)
    assert "CODE-SECRET-ASSIGN" in got and "CODE-EXEC-SHELL" in got
    assert "CODE-SQL-CONCAT" in got and "CODE-XSS-DOM" in got
    assert out.status == "ok" and all(f.source == "code" for f in out.findings)


def test_skips_generated_dirs_and_binaries(tmp_path):
    write(tmp_path, "node_modules/evil.js", "eval(x)\n")
    write(tmp_path, ".git/config.py", 'secret = "abcdef123456"\n')
    write(tmp_path, "src/ok.py", "x = 1\n")
    out = run_sourcescan(str(tmp_path), use_semgrep=False)
    assert not [f for f in out.findings if f.status in ("fail", "warn")]


def test_private_key_is_critical(tmp_path):
    write(tmp_path, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
    # .pem non è tra le estensioni, ma un file senza estensione .env/Dockerfile sì; usiamo un .sh che le contiene
    write(tmp_path, "deploy.sh", "KEY='-----BEGIN PRIVATE KEY-----'\n")
    out = run_sourcescan(str(tmp_path), use_semgrep=False)
    assert any(f.id.startswith("CODE-SECRET-PRIVKEY") and f.severity == "critical" for f in out.findings)


def test_missing_dir_is_failed():
    out = run_sourcescan("/percorso/che/non/esiste", use_semgrep=False)
    assert out.status == "failed"


def test_parse_semgrep_maps_results():
    data = {"results": [{"check_id": "python.lang.security.dangerous-exec", "path": "app/x.py",
                         "start": {"line": 10}, "extra": {"severity": "ERROR", "message": "uso di exec"}}]}
    fs = parse_semgrep(data, ".")
    assert fs and fs[0].source == "semgrep" and fs[0].severity == "high" and "x.py" in fs[0].evidence


def test_cli_source_json(tmp_path):
    write(tmp_path, "a.py", "os.system(cmd)\n")
    res = CliRunner().invoke(cli.app, ["source", str(tmp_path), "--no-semgrep", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["findings"] and "summary" in data


def test_cli_source_fail_on(tmp_path):
    write(tmp_path, "a.py", "os.system(cmd)\n")   # genera un finding high
    res = CliRunner().invoke(cli.app, ["source", str(tmp_path), "--no-semgrep", "--fail-on", "high"])
    assert res.exit_code == 3
