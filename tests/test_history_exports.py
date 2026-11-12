import csv
import io
import json
import os

import pytest
from typer.testing import CliRunner

from lstk import cli, history
from lstk.fixes import suggestions
from lstk.models import Finding
from lstk.report import build_payload, render_csv, render_html, render_markdown, render_sarif, verify_report, write_report
from lstk.risk import assess
from lstk.scan import Assessment, ScanOptions


def assessment(findings, run_id="11111111-aaaa", host="pc1", mode="full"):
    s = assess(findings, [])
    return Assessment(run_id, "2026-11-01T10:00:00", "2026-11-01T10:05:00", ScanOptions(mode=mode), True, findings, [], s, [],
                      {"type": "locale", "targets": ["127.0.0.1"], "authorization": {"note": "n"}},
                      {"hostname": host, "os": "o", "kernel": "k", "arch": "a", "user": "u", "platform": "linux"})


def F(fid, sev="high", status="fail", title="t", evidence="e"):
    return Finding(fid, title, sev, status, "c", evidence, "fai qualcosa", "high")


def test_history_save_list_and_diff(tmp_path):
    d = tmp_path / "h"
    d.mkdir(mode=0o700)
    old = build_payload(assessment([F("A-1"), F("B-1", "medium", "warn"), F("C-1", "low", "warn")], "aaaaaaaa-1"))
    new = build_payload(assessment([F("A-1", "critical"), F("C-1", "low", "pass"), F("D-1", "medium", "warn")], "bbbbbbbb-2"))
    history.save(old, d)
    history.save(new, d)
    items = history.entries(d)
    assert [e.short for e in items] == ["aaaaaaaa", "bbbbbbbb"] and all(e.intact for e in items)
    assert history.find("-1", items).short == "bbbbbbbb" and history.find("1", items).short == "aaaaaaaa"
    assert history.find("bbbb", items).short == "bbbbbbbb" and history.find("99", items) is None
    diff = history.compare(history.load(items[0].path), history.load(items[1].path))
    assert [f["id"] for f in diff.added] == ["D-1"]
    assert {f["id"] for f in diff.resolved} == {"B-1", "C-1"}
    assert [b["id"] for _, b in diff.worse] == ["A-1"] and diff.comparable


def test_history_detects_tampering_and_other_host(tmp_path):
    d = tmp_path / "h"
    d.mkdir(mode=0o700)
    p = history.save(build_payload(assessment([F("A-1")])), d)
    data = json.loads(p.read_text(encoding="utf-8"))
    data["summary"]["grade"] = "A"
    p.write_text(json.dumps(data), encoding="utf-8")
    assert not history.entries(d)[0].intact
    a = build_payload(assessment([F("A-1")], host="pc1"))
    b = build_payload(assessment([F("A-1")], host="pc2"))
    assert not history.compare(a, b).comparable


def test_history_can_be_disabled(monkeypatch):
    monkeypatch.setenv("LSTK_NO_HISTORY", "1")
    assert not history.enabled()
    monkeypatch.delenv("LSTK_NO_HISTORY")
    assert history.enabled()


def test_sparkline():
    assert history.sparkline([]) == "" and len(history.sparkline([10, 50, 90])) == 3
    assert history.sparkline([10, 90])[0] == "▁" and history.sparkline([10, 90])[-1] == "█"


def test_sarif_structure_and_levels():
    p = build_payload(assessment([F("A-1", "critical"), F("B-1", "low", "warn"), F("OK-1", "high", "pass"), F("U-1", "high", "unknown")]))
    doc = json.loads(render_sarif(p))
    assert doc["version"] == "2.1.0"
    res = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert set(res) == {"A-1", "B-1", "U-1"} and res["A-1"]["level"] == "error" and res["B-1"]["level"] == "note"
    rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert float(rules["A-1"]["properties"]["security-severity"]) == 10.0


def test_csv_neutralizes_formula_injection():
    p = build_payload(assessment([F("A-1", title="=HYPERLINK(\"http://evil\")", evidence="+cmd|' /C calc'!A0")]))
    text = render_csv(p).lstrip("﻿")
    rows = list(csv.reader(io.StringIO(text), delimiter=";"))
    header, row = rows[0], rows[1]
    assert row[header.index("title")].startswith("'=") and row[header.index("evidence")].startswith("'+")


def test_markdown_escapes_tables():
    md = render_markdown(build_payload(assessment([F("A-1", title="a | b <script>")])))
    assert "a \\| b &lt;script>" in md and "## Registro dei rischi" in md


def test_html_has_filters_fix_commands_and_no_scripts():
    p = build_payload(assessment([F("FW-001", title="<img src=x onerror=alert(1)>")]))
    html = render_html(p)
    assert "<script" not in html.lower() and "onerror=alert" not in html.replace("onerror=alert(1)&gt;", "")
    assert "&lt;img src=x" in html and 'id="critical"' in html and "ufw" in html and "Content-Security-Policy" in html


def test_every_format_is_written_with_sidecar(tmp_path):
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    p = build_payload(assessment([F("A-1")]))
    for fmt in ("json", "html", "sarif", "csv", "md"):
        path = write_report(p, fmt, d)
        assert path.suffix == "." + fmt and verify_report(path).ok


def test_fix_suggestions():
    assert any("ufw" in c for c in suggestions("FW-001", "linux")["commands"])
    assert any("Set-NetFirewallProfile" in c for c in suggestions("WFW-001", "windows")["commands"])
    assert suggestions("FW-001-dup2", "linux")["commands"]
    nm = suggestions("NMAP-TCP-445", "windows")["commands"]
    assert any("-LocalPort 445" in c for c in nm)
    assert suggestions("NMAP-10.0.0.5-TCP-23", "linux")["commands"][-1] == "sudo ufw deny 23/tcp"
    assert suggestions("TRV-openssl-abc123", "linux")["commands"] and suggestions("TRV-SEC-aws-123", "linux")["note"]
    assert suggestions("NMAP-001", "linux") == {"commands": [], "note": ""}
    assert suggestions("XYZ", "windows") == {"commands": [], "note": ""}


def test_console_new_commands_do_not_crash():
    f = F("FW-001", title="[bold red]x[/]", evidence="[link=http://evil]y[/link]")
    cli.STATE["assessment"] = assessment([f, F("B-2", "low", "warn")])
    for line in ("/fix FW-001", "/fix NOPE", "/search fw", "/search", "/history", "/diff", "/risk", "/help", "/checks", "/status", "/report bogus"):
        assert cli.command(line) is True
    cli.STATE["assessment"] = None


def test_export_command_regenerates_formats(tmp_path):
    d = tmp_path / "r"
    d.mkdir(mode=0o700)
    src = write_report(build_payload(assessment([F("A-1")])), "json", d)
    res = CliRunner().invoke(cli.app, ["export", str(src), "--format", "sarif"])
    assert res.exit_code == 0 and "Salvato" in res.output
    assert CliRunner().invoke(cli.app, ["export", str(src), "--format", "xml"]).exit_code != 0
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    assert CliRunner().invoke(cli.app, ["export", str(bad)]).exit_code == 2


def test_cli_scan_accepts_new_formats():
    assert CliRunner().invoke(cli.app, ["scan", "--format", "xml"]).exit_code == 2
