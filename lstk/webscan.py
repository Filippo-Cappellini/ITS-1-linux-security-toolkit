"""Analisi ESTERNA, NON INTRUSIVA, della configurazione di sicurezza di una web application.

Cosa fa (solo lettura, come un browser che apre la pagina):
- una richiesta GET all'URL indicato e una OPTIONS per leggere i metodi dichiarati;
- legge gli header di sicurezza della risposta (CSP, HSTS, X-Frame-Options, ecc.), i flag dei cookie,
  l'eventuale divulgazione di prodotto/versione (Server, X-Powered-By) e il comportamento di redirect http→https;
- per gli URL https apre la connessione TLS e legge protocollo negoziato e validità/scadenza del certificato.

Cosa NON fa, di proposito:
- nessun payload d'attacco, nessuna iniezione (SQLi/XSS/traversal), nessun tentativo di exploit;
- nessun "fuzzing" né forzatura di percorsi/credenziali; non segue redirect verso altri host;
- non dichiara CVE sfruttabili: è una revisione della POSTURA/configurazione esposta, non un penetration test.

Il penetration testing attivo va eseguito e documentato a parte, su un bersaglio autorizzato.
Ogni finding è pensato per il risk engine di LSTK: rischio = impatto × probabilità.
"""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .models import Finding

USER_AGENT = "LSTK-webposture/1.0 (controllo di configurazione, sola lettura)"
MAX_BODY = 1_000_000
DEFAULT_TIMEOUT = 15.0

# Header di sicurezza attesi: nome -> (severità se assente, perché conta, riferimento)
SEC_HEADERS = {
    "content-security-policy": ("medium", "Limita le sorgenti di script/stili e mitiga XSS e injection di contenuti.",
                                "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy"),
    "strict-transport-security": ("medium", "Impone HTTPS al browser ed evita il downgrade a http (solo su https).",
                                  "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    "x-content-type-options": ("low", "Con 'nosniff' impedisce al browser di indovinare il Content-Type (MIME sniffing).",
                               "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    "x-frame-options": ("low", "Protegge dal clickjacking se manca 'frame-ancestors' nella CSP.",
                        "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options"),
    "referrer-policy": ("low", "Controlla quante informazioni sull'origine vengono inviate ai siti di destinazione.",
                        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"),
    "permissions-policy": ("low", "Disabilita funzioni del browser non necessarie (fotocamera, geolocalizzazione, ecc.).",
                           "https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"),
}
DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"}
WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


class WebScanError(ValueError):
    pass


@dataclass
class Resp:
    status: int
    headers: dict               # chiavi in minuscolo, ultimo valore
    cookies: list               # valori grezzi di Set-Cookie
    final_url: str
    location: str = ""          # valore di Location su un redirect (non seguito)


@dataclass
class TlsInfo:
    protocol: str = ""
    not_after: str = ""
    days_left: int | None = None
    verified: bool = True
    error: str = ""
    issuer: str = ""


@dataclass
class WebOutcome:
    status: str                 # ok | partial | failed
    detail: str
    findings: list = field(default_factory=list)
    info: dict = field(default_factory=dict)


def normalize_url(raw: str) -> tuple[str, str, int]:
    """Valida l'URL e ritorna (url, host, porta). Accetta http e https (la web app può essere locale in http)."""
    u = urlsplit((raw or "").strip())
    if u.scheme not in ("http", "https"):
        raise WebScanError("L'URL deve iniziare con http:// o https:// (es. https://tono.local).")
    if not u.hostname:
        raise WebScanError(f"URL senza host: {raw!r}")
    port = u.port or (443 if u.scheme == "https" else 80)
    if not (0 < port < 65536):
        raise WebScanError(f"Porta non valida: {u.port}")
    return u.geturl(), u.hostname, port


def host_is_loopback(host: str) -> bool:
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() in ("localhost", "ip6-localhost")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Non seguire i redirect: vogliamo osservarli, non rincorrerli (ed evitare di uscire dall'host indicato)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_request(url: str, method: str, timeout: float, insecure: bool) -> Resp:
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            if method == "GET":
                resp.read(MAX_BODY)
            return _resp_from(resp.status, resp.headers, resp.geturl())
    except urllib.error.HTTPError as exc:          # 3xx/4xx/5xx: comunque una risposta valida da leggere
        return _resp_from(exc.code, exc.headers, url, location=exc.headers.get("Location", "") if exc.headers else "")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise WebScanError(f"richiesta {method} fallita: {getattr(exc, 'reason', exc)}") from exc


def _resp_from(status, headers, final_url, location="") -> Resp:
    low = {k.lower(): v for k, v in (headers.items() if headers else [])}
    cookies = headers.get_all("Set-Cookie") if headers and hasattr(headers, "get_all") else []
    return Resp(int(status), low, list(cookies or []), final_url, location or low.get("location", ""))


def probe_tls(host: str, port: int, timeout: float) -> TlsInfo:
    """Apre la connessione TLS e legge protocollo e certificato. Se la verifica fallisce, lo registra e riprova senza verifica
    solo per leggere protocollo/scadenza (senza fidarsi del certificato)."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return _tls_from(ss, verified=True)
    except ssl.SSLCertVerificationError as exc:
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    return _tls_from(ss, verified=False, error=str(exc.verify_message or exc))
        except OSError as exc2:
            return TlsInfo(verified=False, error=str(exc2))
    except (ssl.SSLError, OSError) as exc:
        return TlsInfo(verified=False, error=str(exc))


def _tls_from(ss, *, verified: bool, error: str = "") -> TlsInfo:
    proto = ss.version() or ""
    cert = ss.getpeercert() or {}
    not_after, days = "", None
    if cert.get("notAfter"):
        not_after = cert["notAfter"]
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass
    issuer = ", ".join("=".join(x) for part in cert.get("issuer", ()) for x in part) if cert else ""
    return TlsInfo(proto, not_after, days, verified, error, issuer)


# --------------------------------------------------------------------------- costruzione dei finding
def _cookie_flags(raw: str) -> tuple[str, set]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=")[0] if parts else "?"
    flags = {p.lower().split("=")[0] for p in parts[1:]}
    return name, flags


def build_findings(url: str, host: str, scheme: str, resp: Resp, options: Resp | None,
                   redirect: Resp | None, tls: TlsInfo | None) -> list[Finding]:
    F, ref_owasp = [], "https://owasp.org/www-project-secure-headers/"

    def add(fid, title, severity, status, evidence, reco, *, refs=(), impact=0, likelihood=0, conf="high"):
        F.append(Finding(fid, title, severity, status, "web", evidence, reco, confidence=conf,
                         source="web", impact=impact, likelihood=likelihood, references=list(refs)))

    add("WEB-000", f"Web application raggiunta ({scheme}://{host})", "info", "info",
        f"Risposta HTTP {resp.status} da {url}. Analisi esterna non intrusiva (sola lettura).",
        "Nessuna azione: voce informativa sul bersaglio analizzato.")

    # Trasporto: http in chiaro / redirect verso https
    if scheme == "http":
        loc = (redirect or resp).location if (redirect or resp) else ""
        to_https = loc.startswith("https://")
        add("WEB-HTTPS", "Traffico HTTP non cifrato" + ("" if to_https else " e senza redirect a HTTPS"),
            "high", "warn" if to_https else "fail",
            f"L'URL usa http://. Redirect osservato: {loc or 'nessuno'}.",
            "Servire l'app solo su HTTPS e reindirizzare http→https con redirect permanente (301).",
            refs=["https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security"],
            impact=4, likelihood=5 if not to_https else 3)

    # Header di sicurezza mancanti
    has_csp = "content-security-policy" in resp.headers
    for name, (sev, why, ref) in SEC_HEADERS.items():
        if name == "strict-transport-security" and scheme != "https":
            continue                                  # HSTS ha senso solo su https
        if name == "x-frame-options" and has_csp and "frame-ancestors" in resp.headers.get("content-security-policy", "").lower():
            continue                                  # coperto da CSP frame-ancestors
        present = name in resp.headers
        add(f"WEB-HDR-{name.upper()}", f"Header di sicurezza {'presente' if present else 'assente'}: {name}",
            sev, "pass" if present else "warn",
            f"{name}: {resp.headers.get(name) if present else 'assente nella risposta'}", why, refs=[ref, ref_owasp])

    # Cookie senza flag di protezione
    for raw in resp.cookies:
        cname, flags = _cookie_flags(raw)
        missing = [f for f, present in (("Secure", "secure" in flags), ("HttpOnly", "httponly" in flags),
                                        ("SameSite", "samesite" in flags)) if not present]
        if scheme != "https":
            missing = [m for m in missing if m != "Secure"] + (["Secure"] if "secure" not in flags else [])
        if missing:
            add(f"WEB-COOKIE-{cname[:24]}", f"Cookie «{cname}» senza flag {', '.join(missing)}",
                "medium", "warn", f"Set-Cookie: {raw[:200]}",
                "Impostare i cookie di sessione con Secure, HttpOnly e SameSite (Lax o Strict).",
                refs=["https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies"])

    # Divulgazione di prodotto/versione
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        val = resp.headers.get(h)
        if val and any(c.isdigit() for c in val):
            add(f"WEB-DISCLOSE-{h.upper()}", f"Divulgazione di versione nell'header {h}", "low", "warn",
                f"{h}: {val}", "Rimuovere o rendere generico l'header per non rivelare prodotto e versione agli attaccanti.",
                refs=[ref_owasp])
        elif val:
            add(f"WEB-DISCLOSE-{h.upper()}", f"Header {h} presente (senza versione)", "info", "info", f"{h}: {val}",
                "Nessun numero di versione esposto: rischio basso.")

    # Metodi HTTP pericolosi dichiarati da OPTIONS
    if options is not None:
        allow = options.headers.get("allow", "")
        advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(advertised & DANGEROUS_METHODS)
        if risky:
            add("WEB-METHODS", f"Metodi HTTP potenzialmente pericolosi dichiarati: {', '.join(risky)}",
                "medium", "warn", f"OPTIONS → Allow: {allow}",
                "Disabilitare i metodi non necessari (PUT, DELETE, TRACE, CONNECT) sul web server o nell'app.",
                refs=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"])
        elif allow:
            add("WEB-METHODS", "Metodi HTTP dichiarati limitati", "info", "pass", f"Allow: {allow}",
                "Nessun metodo rischioso dichiarato.")

    # TLS: certificato e protocollo
    if tls is not None:
        if tls.error and not tls.protocol:
            add("WEB-TLS", "Connessione TLS non riuscita o certificato non verificabile", "high", "warn",
                f"Errore TLS: {tls.error}", "Verificare certificato, catena e configurazione del server HTTPS.",
                refs=["https://ssl-config.mozilla.org/"], impact=4, likelihood=3)
        else:
            if not tls.verified:
                add("WEB-TLS-CERT", "Certificato TLS non valido per questo host", "high", "warn",
                    f"Verifica fallita: {tls.error or 'certificato non attendibile'} (emittente: {tls.issuer or 'n/d'}).",
                    "Usare un certificato valido e corrispondente al nome host (es. Let's Encrypt). "
                    "Su una rete locale è atteso un certificato interno: documentarlo.",
                    refs=["https://ssl-config.mozilla.org/"], impact=4, likelihood=3)
            if tls.protocol in WEAK_TLS:
                add("WEB-TLS-PROTO", f"Protocollo TLS obsoleto negoziato: {tls.protocol}", "high", "fail",
                    f"Protocollo: {tls.protocol}", "Disabilitare SSLv3/TLS 1.0/1.1 e permettere solo TLS 1.2 e 1.3.",
                    refs=["https://ssl-config.mozilla.org/"], impact=4, likelihood=4)
            elif tls.protocol:
                add("WEB-TLS-PROTO", f"Protocollo TLS: {tls.protocol}", "info", "pass", f"Protocollo: {tls.protocol}",
                    "Protocollo moderno.")
            if tls.days_left is not None:
                if tls.days_left < 0:
                    add("WEB-TLS-EXP", "Certificato TLS scaduto", "high", "fail",
                        f"Scaduto il {tls.not_after} ({-tls.days_left} giorni fa).",
                        "Rinnovare subito il certificato e automatizzarne il rinnovo.", impact=4, likelihood=5)
                elif tls.days_left < 21:
                    add("WEB-TLS-EXP", f"Certificato TLS in scadenza tra {tls.days_left} giorni", "medium", "warn",
                        f"Scadenza: {tls.not_after}.", "Rinnovare il certificato e automatizzare il rinnovo (es. certbot).")
                else:
                    add("WEB-TLS-EXP", f"Certificato TLS valido ancora {tls.days_left} giorni", "info", "info",
                        f"Scadenza: {tls.not_after}.", "Nessuna azione imminente.")
    return F


def run_webscan(url: str, *, timeout: float = DEFAULT_TIMEOUT, insecure: bool = False,
                http_request=None, tls_probe=None) -> WebOutcome:
    """Esegue l'analisi esterna non intrusiva. http_request/tls_probe sono iniettabili per i test."""
    full, host, port = normalize_url(url)
    scheme = urlsplit(full).scheme
    http_request = http_request or (lambda u, m: _http_request(u, m, timeout, insecure))
    tls_probe = tls_probe or (lambda h, p: probe_tls(h, p, timeout))
    notes: list[str] = []
    try:
        resp = http_request(full, "GET")
    except WebScanError as exc:
        return WebOutcome("failed", str(exc), [], {"url": full, "host": host})
    # Se l'app reindirizza http→https, leggiamo gli header dalla destinazione (stesso host) per non valutare a vuoto.
    redirect = None
    if resp.status in (301, 302, 307, 308) and resp.location.startswith(("http://", "https://")):
        try:
            dest_host = urlsplit(resp.location).hostname
            if dest_host == host:
                redirect, resp2 = resp, http_request(resp.location, "GET")
                full, scheme = resp.location, urlsplit(resp.location).scheme
                resp = resp2
        except WebScanError:
            notes.append("redirect non seguito")
    try:
        options = http_request(full, "OPTIONS")
    except WebScanError:
        options = None
        notes.append("OPTIONS non disponibile")
    tls = None
    if scheme == "https":
        tls = tls_probe(host, urlsplit(full).port or 443)
    findings = build_findings(full, host, scheme, resp, options, redirect, tls)
    issues = sum(1 for f in findings if f.status in ("fail", "warn"))
    detail = f"{len(findings)} controlli esterni, {issues} potenziali problemi" + (f"; {'; '.join(notes)}" if notes else "")
    return WebOutcome("ok", detail, findings, {"url": full, "host": host, "scheme": scheme,
                                               "tls": tls.protocol if tls else "", "notes": notes})
