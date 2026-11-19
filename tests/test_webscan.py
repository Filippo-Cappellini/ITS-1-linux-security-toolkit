import json

import pytest
from typer.testing import CliRunner

from lstk import cli, webscan
from lstk.webscan import Resp, TlsInfo, WebScanError, build_findings, normalize_url, run_webscan


def test_normalize_url_accepts_http_https_and_rejects_others():
    assert normalize_url("https://tono.local/app")[1:] == ("tono.local", 443)
    assert normalize_url("http://127.0.0.1:8080")[1:] == ("127.0.0.1", 8080)
    for bad in ("ftp://x", "javascript:alert(1)", "tono.local", "", "https://"):
        with pytest.raises(WebScanError):
            normalize_url(bad)


def test_loopback_detection():
    assert webscan.host_is_loopback("127.0.0.1") and webscan.host_is_loopback("localhost")
    assert not webscan.host_is_loopback("192.168.1.10") and not webscan.host_is_loopback("example.com")


def make_transport(headers, *, status=200, cookies=(), options_allow=None, tls=None, location=""):
    def http(url, method):
        if method == "OPTIONS":
            if options_allow is None:
                raise WebScanError("OPTIONS non disponibile")
            return Resp(200, {"allow": options_allow}, [], url)
        return Resp(status, {k.lower(): v for k, v in headers.items()}, list(cookies), url, location)
    return http, (lambda h, p: tls)


def ids(findings):
    return {f.id: f for f in findings}


def test_https_missing_headers_and_insecure_cookie_flagged():
    http, tls = make_transport({"content-type": "text/html"}, cookies=["sid=abc; Path=/"],
                               options_allow="GET, POST", tls=TlsInfo("TLSv1.3", "Jan 1 00:00:00 2099 GMT", 400))
    out = run_webscan("https://tono.local", http_request=http, tls_probe=tls)
    by = ids(out.findings)
    assert by["WEB-HDR-CONTENT-SECURITY-POLICY"].status == "warn"
    assert by["WEB-HDR-STRICT-TRANSPORT-SECURITY"].status == "warn"
    cookie = next(f for f in out.findings if f.id.startswith("WEB-COOKIE-"))
    assert cookie.status == "warn" and "Secure" in cookie.title and "HttpOnly" in cookie.title
    assert by["WEB-TLS-PROTO"].status == "pass" and by["WEB-TLS-EXP"].status == "info"
    assert all(f.source == "web" for f in out.findings)


def test_good_config_has_no_issues():
    headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
               "strict-transport-security": "max-age=63072000", "x-content-type-options": "nosniff",
               "referrer-policy": "no-referrer", "permissions-policy": "geolocation=()"}
    http, tls = make_transport(headers, cookies=["sid=x; Secure; HttpOnly; SameSite=Strict"],
                               options_allow="GET, HEAD, POST, OPTIONS", tls=TlsInfo("TLSv1.3", "Jan 1 2099", 400))
    out = run_webscan("https://tono.local", http_request=http, tls_probe=tls)
    assert not [f for f in out.findings if f.status in ("fail", "warn")]
    # X-Frame-Options è coperto da frame-ancestors: non deve comparire come warn
    assert "WEB-HDR-X-FRAME-OPTIONS" not in ids(out.findings)


def test_http_without_redirect_is_high_risk():
    http, tls = make_transport({}, tls=None)
    out = run_webscan("http://tono.local", http_request=http, tls_probe=tls)
    f = ids(out.findings)["WEB-HTTPS"]
    assert f.status == "fail" and f.severity == "high" and f.impact == 4 and f.likelihood == 5


def test_expired_cert_and_weak_tls_and_dangerous_methods():
    http, tls = make_transport({}, options_allow="GET, PUT, DELETE, TRACE",
                               tls=TlsInfo("TLSv1", "Jan 1 00:00:00 2000 GMT", -500))
    out = run_webscan("https://old.local", http_request=http, tls_probe=tls)
    by = ids(out.findings)
    assert by["WEB-TLS-PROTO"].status == "fail" and by["WEB-TLS-EXP"].status == "fail"
    assert by["WEB-METHODS"].status == "warn" and "DELETE" in by["WEB-METHODS"].title


def test_version_disclosure():
    http, tls = make_transport({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"}, tls=None)
    out = run_webscan("http://tono.local", http_request=http, tls_probe=tls)
    by = ids(out.findings)
    assert by["WEB-DISCLOSE-SERVER"].status == "warn" and by["WEB-DISCLOSE-X-POWERED-BY"].status == "warn"


def test_unreachable_returns_failed():
    def http(url, method):
        raise WebScanError("connection refused")
    out = run_webscan("https://down.local", http_request=http, tls_probe=lambda h, p: None)
    assert out.status == "failed" and "connection refused" in out.detail


def test_findings_feed_risk_engine_impact_times_likelihood():
    from lstk.risk import score_finding
    f = build_findings("http://t", "t", "http", Resp(200, {}, [], "http://t"), None, None, None)
    hy = next(x for x in f if x.id == "WEB-HTTPS")
    score_finding(hy)
    assert hy.risk_score == hy.impact * hy.likelihood and hy.risk_level in ("critical", "high", "medium", "low")


def test_cli_web_requires_authorized_for_remote(monkeypatch):
    res = CliRunner().invoke(cli.app, ["web", "https://example.com"])
    assert res.exit_code == 2


def test_cli_web_json_on_loopback(monkeypatch):
    http, tls = make_transport({"content-security-policy": "default-src 'self'"},
                               options_allow="GET", tls=TlsInfo("TLSv1.3", "Jan 1 2099", 400))
    real = webscan.run_webscan
    monkeypatch.setattr(cli, "run_webscan", lambda url, **kw: real(url, http_request=http, tls_probe=tls))
    res = CliRunner().invoke(cli.app, ["web", "https://127.0.0.1", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["url"].startswith("https://127.0.0.1") and "summary" in data and data["findings"]


def test_cli_web_rejects_bad_url():
    assert CliRunner().invoke(cli.app, ["web", "not-a-url"]).exit_code != 0


def test_console_web_prompts_for_url_when_missing(monkeypatch):
    # /web senza URL: la persona lo digita; vuoto = annulla (nessuna analisi)
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: "")
    called = []
    monkeypatch.setattr(cli, "run_webscan", lambda *a, **k: called.append(1))
    assert cli.command("/web") is True and called == []


def test_console_web_uses_prompted_url(monkeypatch):
    http, tls = make_transport({"content-security-policy": "default-src 'self'"},
                               options_allow="GET", tls=TlsInfo("TLSv1.3", "Jan 1 2099", 400))
    real = webscan.run_webscan
    monkeypatch.setattr(cli.Prompt, "ask", lambda *a, **k: "https://127.0.0.1")
    monkeypatch.setattr(cli.Confirm, "ask", lambda *a, **k: True)
    monkeypatch.setattr(cli, "run_webscan", lambda url, **kw: real(url, http_request=http, tls_probe=tls))
    assert cli.command("/web") is True
    assert cli.STATE["web_findings"]
    cli.STATE["web_findings"] = []
