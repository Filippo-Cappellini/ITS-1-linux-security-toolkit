import json
import os

import pytest
from typer.testing import CliRunner

from lstk import cli
from lstk.dbcheck import run_dbcheck

linux_only = pytest.mark.skipif(os.name == "nt", reason="permessi POSIX: eseguito nella CI Linux")


def conf(tmp_path, pg="", hba=""):
    if pg is not None:
        (tmp_path / "postgresql.conf").write_text(pg, encoding="utf-8")
    if hba:
        (tmp_path / "pg_hba.conf").write_text(hba, encoding="utf-8")
    return str(tmp_path)


def ids(out):
    return {f.id if not f.id[-1].isdigit() else f.id.rsplit("-", 1)[0] for f in out.findings}


def test_risky_postgresql_conf(tmp_path):
    out = run_dbcheck(conf(tmp_path, pg="listen_addresses = '*'\nssl = off\npassword_encryption = md5\n"))
    got = ids(out)
    assert "DB-LISTEN" in got and "DB-SSL" in got and "DB-PWENC" in got
    listen = next(f for f in out.findings if f.id == "DB-LISTEN")
    assert listen.status == "warn" and listen.severity == "high" and all(f.source == "db" for f in out.findings)


def test_safe_postgresql_conf(tmp_path):
    out = run_dbcheck(conf(tmp_path, pg="listen_addresses = 'localhost'\nssl = on\npassword_encryption = scram-sha-256\n"))
    assert next(f for f in out.findings if f.id == "DB-LISTEN").status == "pass"
    assert not any(f.id in ("DB-SSL", "DB-PWENC") for f in out.findings)


def test_pg_hba_trust_and_wide(tmp_path):
    out = run_dbcheck(conf(tmp_path, hba="local all all trust\nhost all all 0.0.0.0/0 md5\nhost all all 127.0.0.1/32 scram-sha-256\n"))
    got = ids(out)
    assert "DB-HBA-TRUST" in got and "DB-HBA-WIDE" in got
    trust = next(f for f in out.findings if f.id.startswith("DB-HBA-TRUST"))
    assert trust.severity == "high" and trust.impact == 5


def test_pg_hba_clean(tmp_path):
    out = run_dbcheck(conf(tmp_path, hba="local all all peer\nhost all all 127.0.0.1/32 scram-sha-256\n"))
    assert any(f.id == "DB-HBA-OK" and f.status == "pass" for f in out.findings)


def test_missing_files_failed(tmp_path):
    out = run_dbcheck(str(tmp_path))
    assert out.status == "failed"


@linux_only
def test_permissions_flagged(tmp_path):
    p = conf(tmp_path, pg="listen_addresses = 'localhost'\n")
    os.chmod(os.path.join(p, "postgresql.conf"), 0o644)   # leggibile da 'altri'
    out = run_dbcheck(p)
    assert any(f.id.startswith("DB-PERM") for f in out.findings)


def test_cli_dbcheck_json(tmp_path):
    conf(tmp_path, pg="listen_addresses = '*'\n")
    res = CliRunner().invoke(cli.app, ["dbcheck", str(tmp_path), "--format", "json"])
    assert res.exit_code == 0
    assert json.loads(res.stdout)["findings"]


def test_cli_dbcheck_fail_on(tmp_path):
    conf(tmp_path, hba="local all all trust\n")
    res = CliRunner().invoke(cli.app, ["dbcheck", str(tmp_path), "--fail-on", "high"])
    assert res.exit_code == 3
