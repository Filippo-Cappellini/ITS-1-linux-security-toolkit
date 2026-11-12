"""Controlli Windows con registro e inventario PowerShell simulati: girano su qualsiasi sistema operativo."""
import json
import re
import os
from datetime import date

import pytest

from lstk import winaudit as w
from lstk.risk import assess
from lstk.runner import CmdResult

TODAY = date(2026, 11, 12)

GOOD_REG = {
    (w.CV, "CurrentBuild"): "26200", (w.CV, "UBR"): 7000, (w.CV, "EditionID"): "Professional",
    (w.CV, "InstallationType"): "Client", (w.CV, "DisplayVersion"): "25H2",
    (w.POL, "EnableLUA"): 1, (w.POL, "ConsentPromptBehaviorAdmin"): 5, (w.POL, "PromptOnSecureDesktop"): 1,
    (w.LSA, "RunAsPPL"): 1,
    (w.TS, "fDenyTSConnections"): 1,
    (r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"): 1,
    (r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"): 4,
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"): 255,
    (r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"): 0,
}

GOOD_INV = {
    "defender": {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "AntivirusSignatureAge": 0,
                 "IsTamperProtected": True, "AMRunningMode": "Normal"},
    "mppref": {"ExclusionPath": [], "ExclusionProcess": [], "ExclusionExtension": [], "PUAProtection": 1, "AsrIds": [], "AsrActions": []},
    "av": [{"displayName": "Windows Defender", "productState": 397568}],
    "firewall": [{"Name": n, "Enabled": True, "DefaultInboundAction": "NotConfigured"} for n in ("Domain", "Private", "Public")],
    "bitlocker": 1,
    "admins": [{"Name": "PC\\admin", "Class": "User", "Source": "Local"}],
    "users": [{"Name": "Guest", "Enabled": False, "PasswordRequired": True, "SID": "S-1-5-21-1-2-3-501"},
              {"Name": "Administrator", "Enabled": False, "PasswordRequired": True, "SID": "S-1-5-21-1-2-3-500"}],
    "netaccounts": "\n".join(f"Voce {i}:   {v}" for i, v in enumerate(["Mai", "0", "42", "14", "24", "5", "15", "15", "WORKSTATION"])),
    "hotfix": [{"HotFixID": "KB1", "InstalledOn": "2026-11-01"}],
    "pending": [],
    "services": [{"Name": "wuauserv", "Status": "Running", "StartType": "Manual"}],
    "listen": [{"LocalAddress": "127.0.0.1", "LocalPort": 5432, "Process": "postgres"}],
    "smb": {"EnableSMB1Protocol": False, "RequireSecuritySignature": True, "EncryptData": False},
    "psv2": "Disabled",
}


def ctx(reg=None, inv=None, deep_inv=None, profile="desktop", root=True, deep=False):
    reg = dict(GOOD_REG if reg is None else reg)
    keys = {k[0] for k in reg}
    return w.WinCtx(profile, deep, None, root, inv=dict(GOOD_INV if inv is None else inv), deep_inv=deep_inv or {},
                    reg_get=lambda p, n: reg.get((p, n)), reg_has=lambda p: p in keys, today=TODAY)


def run_all(c):
    out = []
    for chk in w.CHECKS + ([w.check_privesc] if c.deep else []):
        out += chk(c)
    return {f.id: f for f in out}


def test_hardened_machine_has_no_issues():
    fs = run_all(ctx())
    s = assess(list(fs.values()))
    bad = {i: (f.status, f.evidence) for i, f in fs.items() if f.status in ("fail", "warn")}
    assert not bad, bad
    assert s.counts["critical"] == 0 and fs["WDEF-001"].status == "pass" and fs["WFW-001"].status == "pass"


def test_lifecycle_table():
    assert w.windows_support(26100, "Core", "Client", TODAY)[0] == "eol"            # 24H2 Home: fine supporto 13/10/2026
    assert w.windows_support(26100, "Enterprise", "Client", TODAY)[0] == "supported"
    assert w.windows_support(19045, "Professional", "Client", TODAY)[0] == "eol"    # Windows 10
    assert w.windows_support(26200, "Core", "Client", TODAY)[0] == "supported"
    assert w.windows_support(26300, "Core", "Client", TODAY)[0] == "unknown"        # build nuova/Insider: mai "supportata" a caso
    assert w.windows_support(20348, "ServerStandard", "Server", TODAY)[0] == "unknown"
    assert w.windows_support(None, "", "", TODAY)[0] == "unknown"


def test_eol_windows_is_a_risk():
    reg = {**GOOD_REG, (w.CV, "CurrentBuild"): "19045"}
    f = run_all(ctx(reg=reg))["WSYS-002"]
    assert f.status == "fail" and f.severity == "high"


def test_defender_off_without_other_av_is_critical():
    inv = {**GOOD_INV, "defender": {**GOOD_INV["defender"], "RealTimeProtectionEnabled": False}}
    f = run_all(ctx(inv=inv))["WDEF-001"]
    assert f.status == "fail" and f.severity == "critical"
    assess([f])
    assert f.risk_level == "critical"


def test_third_party_antivirus_accepted():
    inv = {**GOOD_INV, "defender": {**GOOD_INV["defender"], "RealTimeProtectionEnabled": False, "AMRunningMode": "Passive Mode"},
           "av": [{"displayName": "Windows Defender", "productState": 393472}, {"displayName": "ESET Security", "productState": 266240}]}
    f = run_all(ctx(inv=inv))["WDEF-001"]
    assert f.status == "pass" and "ESET" in f.evidence


def test_defender_unreadable_is_unknown_not_pass():
    inv = {**GOOD_INV, "defender": {"error": "Accesso negato"}, "av": []}
    f = run_all(ctx(inv=inv))["WDEF-001"]
    assert f.status == "unknown"


def test_risky_defender_exclusions():
    inv = {**GOOD_INV, "mppref": {**GOOD_INV["mppref"], "ExclusionPath": ["C:\\", "C:\\Users\\me\\Downloads"], "ExclusionExtension": ["exe"]}}
    f = run_all(ctx(inv=inv))["WDEF-004"]
    assert f.status == "warn" and f.severity == "high" and "Downloads" in f.evidence


def test_firewall_public_off_is_high_fail():
    inv = {**GOOD_INV, "firewall": [{"Name": "Domain", "Enabled": True, "DefaultInboundAction": "NotConfigured"},
                                    {"Name": "Public", "Enabled": False, "DefaultInboundAction": "NotConfigured"}]}
    f = run_all(ctx(inv=inv))["WFW-001"]
    assert f.status == "fail" and f.severity == "high"


def test_credentials_weaknesses():
    reg = {**GOOD_REG, (r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"): 1,
           (w.LSA, "LmCompatibilityLevel"): 1, (w.POL, "EnableLUA"): 0}
    fs = run_all(ctx(reg=reg))
    assert fs["WLSA-001"].status == "fail" and fs["WLSA-003"].status == "fail" and fs["WUAC-001"].status == "fail"


def test_rdp_without_nla_and_smb1():
    reg = {**GOOD_REG, (w.TS, "fDenyTSConnections"): 0, (w.TS + r"\WinStations\RDP-Tcp", "UserAuthentication"): 0,
           (r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"): 2}
    inv = {**GOOD_INV, "smb": {"EnableSMB1Protocol": True, "RequireSecuritySignature": False}}
    fs = run_all(ctx(reg=reg, inv=inv))
    assert fs["WRDP-001"].status == "fail" and fs["WSMB-001"].status == "fail" and fs["WSMB-002"].status == "warn"


def test_guest_and_password_policy():
    inv = {**GOOD_INV, "users": [{"Name": "Guest", "Enabled": True, "PasswordRequired": False, "SID": "S-1-5-21-9-501"}],
           "netaccounts": "\n".join(f"x {i}: {v}" for i, v in enumerate(["Never", "0", "42", "0", "None", "Never", "30", "30", "WORKSTATION"]))}
    fs = run_all(ctx(inv=inv))
    assert fs["WACC-001"].status == "fail" and fs["WACC-003"].status == "warn"
    assert fs["WPWD-001"].status == "warn" and "lunghezza minima password 0" in fs["WPWD-001"].evidence


def test_net_accounts_is_parsed_by_position_not_language():
    it = "Lunghezza minima della password:   0"
    text = "\n".join(["Min. tra tempo limite e disconnessione imposta:   Mai", "Durata minima della password (giorni):   0",
                      "Durata massima della password (giorni):   42", it, "Lunghezza cronologia della password:   Nessuno",
                      "Soglia di blocchi:   10", "Durata dei blocchi (minuti):   10", "Finestra di osservazione dei blocchi (minuti):   10",
                      "Ruolo del computer:   WORKSTATION", "Esecuzione comando riuscita."])
    p = w.parse_net_accounts(text)
    assert p == {"min_length": 0, "lockout_threshold": 10, "max_age": 42, "raw_ok": True}


def test_updates_pending_and_old_hotfix():
    inv = {**GOOD_INV, "pending": [{"title": "Aggiornamento cumulativo KB9", "severity": "Critical", "security": True}],
           "hotfix": [{"HotFixID": "KB1", "InstalledOn": "2026-06-01"}]}
    fs = run_all(ctx(inv=inv))
    assert fs["WUPD-001"].status == "warn" and fs["WUPD-001"].severity == "high" and fs["WUPD-002"].status == "warn"


def test_powershell_51_array_wrapping_is_unwrapped():
    data = {"shares": {"value": [], "Count": 0}, "listen": {"value": [{"LocalAddress": "::", "LocalPort": 445, "Process": "System"}], "Count": 1}}
    u = w._unwrap(data)
    assert u["shares"] == [] and u["listen"][0]["LocalPort"] == 445
    f = run_all(ctx(inv={**GOOD_INV, **u}))["WNET-001"]
    assert "[::]:445 (System)" in f.evidence


def test_deep_privesc_checks():
    deep = {"unquoted": [{"Name": "Vuln", "PathName": r"C:\Program Files\Vendor App\svc.exe -k", "StartMode": "Auto"},
                         {"Name": "Sys", "PathName": r"C:\Windows\system32\svchost.exe -k netsvcs", "StartMode": "Auto"}],
            "pathacl": [{"path": r"C:\Tools", "sid": "S-1-5-11", "rights": "Modify"}],
            "startup": [{"key": "HKCU", "name": "upd", "command": r"powershell -enc AAAA"}]}
    fs = run_all(ctx(deep_inv=deep, deep=True))
    assert fs["WPRIV-001"].status == "warn" and "Vuln" in fs["WPRIV-001"].evidence and "Sys:" not in fs["WPRIV-001"].evidence
    assert fs["WPRIV-002"].status == "fail" and "Authenticated Users" in fs["WPRIV-002"].evidence
    assert fs["WPRIV-003"].status == "warn"


def test_deep_data_missing_is_unknown():
    fs = run_all(ctx(deep_inv={"unquoted": {"error": "x"}, "pathacl": {"error": "y"}}, deep=True))
    assert fs["WPRIV-001"].status == "unknown" and fs["WPRIV-002"].status == "unknown"


def test_signature_integrity():
    c = ctx(deep_inv={"unsigned": {"checked": 50, "bad": [{"service": "evil", "path": "C:\\x.exe", "status": "HashMismatch"},
                                                          {"service": "old", "path": "C:\\y.exe", "status": "NotSigned"}]}})
    fs = {f.id: f for f in w.check_integrity(c)}
    assert fs["WINT-001"].status == "fail" and fs["WINT-002"].status == "warn"
    assert w.check_integrity(ctx(deep_inv={}))[0].status == "unknown"


def test_server_profile_raises_spooler_and_rdp():
    inv = {**GOOD_INV, "services": [{"Name": "Spooler", "Status": "Running", "StartType": "Automatic"},
                                    {"Name": "TlntSvr", "Status": "Running", "StartType": "Automatic"}]}
    fs = run_all(ctx(inv=inv, profile="server"))
    assert fs["WSRV-002"].status == "warn" and fs["WSRV-001"].severity == "critical"


def test_collect_uses_powershell_inventory_and_isolates_errors(fake):
    inv = json.dumps({**GOOD_INV, "listen": {"value": [], "Count": 0}})
    r = fake({"ps:inventario": CmdResult(0, inv, "")})
    c = w.WinCtx("desktop", False, r, True, reg_get=lambda p, n: GOOD_REG.get((p, n)), reg_has=lambda p: False, today=TODAY)
    fs = w.collect("desktop", False, r, ctx=c)
    ids = {f.id for f in fs}
    assert "WDEF-001" in ids and "WSYS-000" not in ids and ["powershell", "inventario"] in r.calls


def test_collect_without_powershell_reports_gap(fake):
    r = fake()
    c = w.WinCtx("desktop", False, r, False, reg_get=lambda p, n: None, reg_has=lambda p: False, today=TODAY)
    fs = {f.id: f for f in w.collect("desktop", False, r, ctx=c)}
    assert fs["WSYS-000"].status == "unknown" and fs["WDEF-001"].status == "unknown"
    assert all(f.status != "pass" for f in fs.values() if f.id.startswith(("WDEF", "WFW")))


def test_inventory_scripts_are_read_only():
    for script in (w.INVENTORY_PS, w.DEEP_PS):
        verbs = set(re.findall(r"\b([A-Z][a-z]+)-[A-Z][A-Za-z]+", script))
        assert verbs <= {"Get", "Select", "Where", "Sort", "ForEach", "Test", "New", "ConvertTo"}, verbs
        assert "New-Object" in script or "New-" not in script.replace("New-Object", "")




@pytest.mark.skipif(os.name != "nt", reason="solo Windows: legge davvero il registro")
def test_real_registry_reader_is_read_only_and_works():
    get, has = w._winreg_reader()
    assert get(w.CV, "CurrentBuild") and has(w.CV) and get(w.CV, "NonEsiste") is None
