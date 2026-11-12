"""Controlli di sicurezza nativi per Windows: sola lettura, best-effort, nessuna modifica al sistema.

I dati vengono raccolti con:
- letture del registro (modulo winreg, accesso KEY_READ, vista a 64 bit);
- uno script PowerShell di inventario (cmdlet Get-*, nessun Set-*), più uno script aggiuntivo in modalità deep/full.

Come per Linux, ogni controllo è isolato e un dato non disponibile produce "unknown"/"manual", mai "pass".
"""
from __future__ import annotations

import json
import platform
import re
import socket
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Callable

from .models import Finding
from .runner import Runner, is_root

REF_CIS = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
MS_LIFECYCLE = "https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro"


# --------------------------------------------------------------------------- registro
def _winreg_reader():
    try:
        import winreg  # type: ignore
    except ImportError:          # non Windows
        return (lambda path, name: None), (lambda path: False)
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}

    def _open(path: str):
        hive, _, sub = path.partition("\\")
        return winreg.OpenKey(hives[hive.upper()], sub, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0))

    def get(path: str, name: str):
        try:
            with _open(path) as k:
                return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    def has(path: str) -> bool:
        try:
            with _open(path):
                return True
        except OSError:
            return False
    return get, has


@dataclass
class WinCtx:
    profile: str
    deep: bool
    runner: Runner
    root: bool
    inv: dict = field(default_factory=dict)          # inventario PowerShell
    deep_inv: dict = field(default_factory=dict)
    reg_get: Callable[[str, str], Any] | None = None
    reg_has: Callable[[str], bool] | None = None
    today: date = field(default_factory=date.today)

    def __post_init__(self) -> None:
        if self.reg_get is None or self.reg_has is None:
            g, h = _winreg_reader()
            self.reg_get = self.reg_get or g
            self.reg_has = self.reg_has or h

    @property
    def server(self) -> bool:
        return self.profile == "server"

    def reg(self, path: str, name: str):
        return self.reg_get(path, name)

    def section(self, key: str, deep: bool = False):
        """Valore di una sezione dell'inventario; None se assente o in errore."""
        val = (self.deep_inv if deep else self.inv).get(key)
        if isinstance(val, dict) and set(val) == {"error"}:
            return None
        return val

    def error(self, key: str, deep: bool = False) -> str:
        val = (self.deep_inv if deep else self.inv).get(key)
        if isinstance(val, dict) and "error" in val:
            return str(val["error"])[:300]
        return "dato non disponibile"


def F(fid, title, severity, status, category, evidence, recommendation, confidence="medium", **extra) -> Finding:
    return Finding(fid, title, severity, status, category, evidence, recommendation, confidence, **extra)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- inventario PowerShell
_HELPER = r"""
$r = [ordered]@{}
function T([string]$k, [scriptblock]$b) { try { $r[$k] = & $b } catch { $r[$k] = @{ error = "$($_.Exception.Message)" } } }
"""

INVENTORY_PS = _HELPER + r"""
T 'defender' { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureAge,IsTamperProtected,QuickScanAge,@{n='AMRunningMode';e={"$($_.AMRunningMode)"}} }
T 'mppref' { Get-MpPreference | Select-Object @{n='ExclusionPath';e={@($_.ExclusionPath)}},@{n='ExclusionProcess';e={@($_.ExclusionProcess)}},@{n='ExclusionExtension';e={@($_.ExclusionExtension)}},PUAProtection,EnableNetworkProtection,@{n='AsrIds';e={@($_.AttackSurfaceReductionRules_Ids)}},@{n='AsrActions';e={@($_.AttackSurfaceReductionRules_Actions)}} }
T 'av' { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState) }
T 'firewall' { @(Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={[bool]$_.Enabled}},@{n='DefaultInboundAction';e={"$($_.DefaultInboundAction)"}}) }
T 'bitlocker' { [int](New-Object -ComObject Shell.Application).NameSpace("$env:SystemDrive\").Self.ExtendedProperty('System.Volume.BitLockerProtection') }
T 'admins' { @(Get-LocalGroupMember -SID S-1-5-32-544 | Select-Object Name,@{n='Class';e={"$($_.ObjectClass)"}},@{n='Source';e={"$($_.PrincipalSource)"}}) }
T 'users' { @(Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,@{n='SID';e={$_.SID.Value}}) }
T 'netaccounts' { (& "$env:SystemRoot\System32\net.exe" accounts) -join "`n" }
T 'hotfix' { @(Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}) }
T 'pending' {
  $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $s.Online = $false
  $u = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
  @($u | ForEach-Object { [ordered]@{ title = $_.Title; severity = "$($_.MsrcSeverity)"; security = [bool]($_.Categories | Where-Object { $_.Name -match 'Security|Sicurezza' }) } })
}
T 'services' { @(Get-Service -Name RemoteRegistry,TlntSvr,SNMP,FTPSVC,simptcp,WinRM,Spooler,wuauserv,SSDPSRV,upnphost,sshd,TermService,W3SVC,XblGameSave,Fax -ErrorAction SilentlyContinue | Select-Object Name,@{n='Status';e={"$($_.Status)"}},@{n='StartType';e={"$($_.StartType)"}}) }
T 'listen' {
  $p = @{}; Get-Process | ForEach-Object { $p[$_.Id] = $_.ProcessName }
  @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,@{n='Process';e={$p[[int]$_.OwningProcess]}})
}
T 'deviceguard' { Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard | Select-Object VirtualizationBasedSecurityStatus,@{n='Running';e={@($_.SecurityServicesRunning)}} }
T 'smb' { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature,EncryptData }
T 'psv2' { "$((Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State)" }
T 'shares' { @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | Select-Object Name,Path) }
$r | ConvertTo-Json -Depth 5 -Compress
"""

DEEP_PS = _HELPER + r"""
T 'unquoted' { @(Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' -and ($_.PathName -split '(?i)\.exe',2)[0] -match ' ' } | Select-Object Name,PathName,StartMode) }
T 'pathacl' {
  $weak = @('S-1-1-0','S-1-5-11','S-1-5-32-545'); $out = @()
  foreach ($d in ([Environment]::GetEnvironmentVariable('Path','Machine') -split ';' | Where-Object { $_ } | Select-Object -Unique)) {
    $x = [Environment]::ExpandEnvironmentVariables($d)
    if (-not (Test-Path -LiteralPath $x -PathType Container)) { continue }
    try { $acl = Get-Acl -LiteralPath $x } catch { continue }
    foreach ($a in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($a.AccessControlType -eq 'Allow' -and $weak -contains $a.IdentityReference.Value -and -not ($a.PropagationFlags -band 2) -and (([int]$a.FileSystemRights) -band 0x50000006)) {
        $out += [ordered]@{ path = $x; sid = $a.IdentityReference.Value; rights = "$($a.FileSystemRights)" }
      }
    }
  }
  $out
}
T 'startup' {
  $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  @(foreach ($k in $keys) { if (Test-Path $k) { $i = Get-ItemProperty $k; $i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { [ordered]@{ key = $k; name = $_.Name; command = "$($_.Value)" } } } })
}
T 'unsigned' {
  $seen = @{}; $out = @()
  foreach ($s in (Get-CimInstance Win32_Service | Where-Object { $_.PathName })) {
    $m = [regex]::Match($s.PathName, '^\s*"?([^"]+?\.exe)', 'IgnoreCase'); if (-not $m.Success) { continue }
    $f = [Environment]::ExpandEnvironmentVariables($m.Groups[1].Value)
    if ($seen.ContainsKey($f) -or -not (Test-Path -LiteralPath $f)) { continue }; $seen[$f] = 1
    if ($seen.Count -gt 400) { break }
    $sig = Get-AuthenticodeSignature -LiteralPath $f
    if ("$($sig.Status)" -ne 'Valid') { $out += [ordered]@{ service = $s.Name; path = $f; status = "$($sig.Status)" } }
  }
  [ordered]@{ checked = $seen.Count; bad = $out }
}
$r | ConvertTo-Json -Depth 5 -Compress
"""


def _unwrap(v):
    """PowerShell 5.1 serializza alcuni array come {"value": [...], "Count": n}: li riporta a liste."""
    if isinstance(v, dict):
        if set(v) == {"value", "Count"} and isinstance(v["value"], list):
            return [_unwrap(x) for x in v["value"]]
        return {k: _unwrap(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_unwrap(x) for x in v]
    return v


def collect_inventory(runner: Runner, script: str, name: str, timeout: int) -> tuple[dict, str]:
    r = runner.powershell(script, timeout=timeout, name=name)
    if r.timed_out:
        return {}, f"PowerShell: timeout dopo {timeout}s"
    text = (r.out or "").strip()
    start = text.find("{")
    if start < 0:
        return {}, f"PowerShell non ha prodotto JSON (exit {r.rc}): {(r.err or '')[:300]}"
    try:
        data = json.loads(text[start:])
    except ValueError as exc:
        return {}, f"JSON PowerShell non valido: {exc}"
    data = _unwrap(data)
    return (data if isinstance(data, dict) else {}), ""


# --------------------------------------------------------------------------- supporto del sistema operativo
# Fine supporto per build (Home/Pro; Enterprise/Education hanno circa 12 mesi in più). Fonte: Microsoft Lifecycle.
WIN11_EOS = {22000: ("21H2", date(2023, 10, 10), date(2024, 10, 8)),
             22621: ("22H2", date(2024, 10, 8), date(2025, 10, 14)),
             22631: ("23H2", date(2025, 11, 11), date(2026, 11, 10)),
             26100: ("24H2", date(2026, 10, 13), date(2027, 10, 12)),
             26200: ("25H2", date(2027, 10, 12), date(2028, 10, 10))}
WIN10_EOS = (date(2025, 10, 14), date(2025, 10, 14))     # 22H2, ultima versione; poi solo ESU a pagamento


def windows_support(build: int | None, edition: str, install_type: str, today: date) -> tuple[str, str]:
    """Ritorna (stato, spiegazione) con stato in: supported | eol | unknown."""
    if build is None:
        return "unknown", "build non determinata"
    if "server" in (install_type or "").lower():
        return "unknown", "Windows Server: verificare il ciclo di vita della release sul sito Microsoft"
    ed = (edition or "").lower()
    if "ltsc" in ed or ed.endswith("s") and ed.startswith("enterprise"):
        return "unknown", "edizione LTSC: ciclo di vita dedicato"
    long_life = any(x in ed for x in ("enterprise", "education", "iot"))
    if build < 22000:
        end = WIN10_EOS[1 if long_life else 0]
        if today > end:
            return "eol", f"Windows 10 ha raggiunto la fine del supporto il {end.isoformat()} (aggiornamenti solo con ESU)"
        return "supported", f"Windows 10 supportato fino al {end.isoformat()}"
    known = [b for b in WIN11_EOS if b <= build]
    if not known:
        return "unknown", f"build {build} non riconosciuta"
    base = max(known)
    if base != build and build - base > 99:
        return "unknown", f"build {build} più recente di quelle note (versione nuova o Insider)"
    ver, home_end, ent_end = WIN11_EOS[base]
    end = ent_end if long_life else home_end
    if today > end:
        return "eol", f"Windows 11 {ver} fuori supporto dal {end.isoformat()}"
    return "supported", f"Windows 11 {ver} supportato fino al {end.isoformat()}"


# --------------------------------------------------------------------------- sistema e aggiornamenti
CV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def check_system(ctx: WinCtx) -> list[Finding]:
    build = _int(ctx.reg(CV, "CurrentBuild") or ctx.reg(CV, "CurrentBuildNumber"))
    ubr = ctx.reg(CV, "UBR")
    edition = str(ctx.reg(CV, "EditionID") or "")
    itype = str(ctx.reg(CV, "InstallationType") or "")
    disp = str(ctx.reg(CV, "DisplayVersion") or ctx.reg(CV, "ReleaseId") or "")
    family = "Windows 11" if (build or 0) >= 22000 and "server" not in itype.lower() else str(ctx.reg(CV, "ProductName") or "Windows")
    out = [F("WSYS-001", "Sistema operativo", "info", "info", "system",
             f"{family} {edition} {disp} (build {build}{'.' + str(ubr) if ubr is not None else ''}) | arch={platform.machine()} | host={socket.gethostname()}",
             "Verificare che il sistema sia supportato e riceva aggiornamenti di sicurezza.", "high")]
    state, why = windows_support(build, edition, itype, ctx.today)
    if state == "eol":
        out.append(F("WSYS-002", "Versione di Windows fuori supporto", "high", "fail", "system", why + ".",
                     "Aggiornare alla versione di Windows più recente (Impostazioni › Windows Update) o, per Windows 10, valutare ESU/migrazione.",
                     "high", likelihood=4, references=[MS_LIFECYCLE]))
    elif state == "supported":
        out.append(F("WSYS-002", "Ciclo di vita di Windows", "high", "pass", "system", why + ".",
                     "Pianificare per tempo l'aggiornamento alla versione successiva.", "medium", references=[MS_LIFECYCLE]))
    else:
        out.append(F("WSYS-002", "Ciclo di vita di Windows", "medium", "manual", "system", why + ".",
                     "Verificare la data di fine supporto sul sito Microsoft Lifecycle.", "low", references=[MS_LIFECYCLE]))
    out.append(F("WSYS-003", "Contesto di esecuzione", "info", "info", "system",
                 "Esecuzione come amministratore (copertura completa)." if ctx.root else
                 "Esecuzione senza privilegi elevati: Defender (esclusioni), SMB, BitLocker dettagliato e alcune policy non sono leggibili.",
                 "Per un audit completo avviare il terminale con 'Esegui come amministratore'.", "high"))
    pending = [p for p in (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                           r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") if ctx.reg_has(p)]
    if pending:
        out.append(F("WSYS-004", "Riavvio richiesto", "low", "warn", "system",
                     "Aggiornamenti installati in attesa di riavvio (chiavi RebootRequired/RebootPending presenti).",
                     "Riavviare il sistema per completare l'installazione degli aggiornamenti.", "high", likelihood=2))
    return out


def check_updates(ctx: WinCtx) -> list[Finding]:
    out: list[Finding] = []
    pend = ctx.section("pending")
    if pend is None:
        out.append(F("WUPD-001", "Aggiornamenti di Windows in sospeso", "high", "unknown", "packages",
                     f"Elenco non disponibile: {ctx.error('pending')}", "Verificare in Impostazioni › Windows Update.", "low"))
    else:
        items = _as_list(pend)
        sec = [u for u in items if isinstance(u, dict) and (u.get("security") or u.get("severity") in ("Critical", "Important"))]
        titles = "; ".join(str(u.get("title", ""))[:90] for u in items[:8] if isinstance(u, dict))
        ev = (f"Aggiornamenti disponibili secondo l'ultima ricerca di Windows Update (dati locali, nessuna connessione): {len(items)}, "
              f"di cui di sicurezza/critici: {len(sec)}." + (f" {titles}" if titles else ""))
        if not items:
            out.append(F("WUPD-001", "Aggiornamenti di Windows", "high", "pass", "packages", ev,
                         "Mantenere attivi gli aggiornamenti automatici; il dato dipende dall'ultima ricerca eseguita da Windows Update.", "medium"))
        else:
            out.append(F("WUPD-001", "Aggiornamenti di Windows in sospeso", "high" if sec else "medium", "warn", "packages", ev,
                         "Installare gli aggiornamenti da Impostazioni › Windows Update (priorità a quelli di sicurezza) e riavviare.",
                         "medium", likelihood=4 if sec else 3))
    hot = ctx.section("hotfix")
    if hot is not None:
        items = [h for h in _as_list(hot) if isinstance(h, dict) and h.get("InstalledOn")]
        if items:
            try:
                last = datetime.strptime(str(items[0]["InstalledOn"])[:10], "%Y-%m-%d").date()
                age = (ctx.today - last).days
                out.append(F("WUPD-002", "Ultimo aggiornamento installato", "medium", "warn" if age > 45 else "pass", "packages",
                             f"Ultimo hotfix {items[0].get('HotFixID', '?')} installato il {last.isoformat()} ({age} giorni fa).",
                             "Microsoft rilascia aggiornamenti di sicurezza ogni mese (Patch Tuesday): installarli entro poche settimane.",
                             "medium", likelihood=3))
            except ValueError:
                pass
    au = ctx.reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
    svc = {s.get("Name"): s for s in _as_list(ctx.section("services")) if isinstance(s, dict)}
    wu = svc.get("wuauserv")
    if _int(au) == 1 or (wu and wu.get("StartType") == "Disabled"):
        out.append(F("WUPD-003", "Aggiornamenti automatici disattivati", "high", "fail", "packages",
                     ("Policy NoAutoUpdate=1. " if _int(au) == 1 else "") + (f"Servizio wuauserv: {wu.get('StartType')}." if wu else ""),
                     "Riattivare Windows Update (servizio wuauserv in avvio manuale/automatico, rimuovere la policy NoAutoUpdate).", "high"))
    return out


# --------------------------------------------------------------------------- antimalware
def check_defender(ctx: WinCtx) -> list[Finding]:
    out: list[Finding] = []
    d = ctx.section("defender")
    av = [a for a in _as_list(ctx.section("av")) if isinstance(a, dict)]
    third = [a.get("displayName", "?") for a in av if "defender" not in str(a.get("displayName", "")).lower()]
    # productState: bit 12 (0x1000) = protezione in tempo reale attiva, 0x10 = firme non aggiornate (convenzione WSC)
    third_on = [a.get("displayName", "?") for a in av if "defender" not in str(a.get("displayName", "")).lower()
                and (_int(a.get("productState"), 0) & 0x1000)]
    if isinstance(d, dict) and d.get("AMServiceEnabled") is not None:
        rt = bool(d.get("RealTimeProtectionEnabled")) and bool(d.get("AntivirusEnabled"))
        mode = str(d.get("AMRunningMode") or "")
        if rt:
            out.append(F("WDEF-001", "Protezione antimalware in tempo reale", "critical", "pass", "malware",
                         f"Microsoft Defender attivo (modalità {mode or 'normale'}), protezione in tempo reale abilitata.",
                         "Mantenere attiva la protezione.", "high"))
        elif third_on:
            out.append(F("WDEF-001", "Protezione antimalware in tempo reale", "critical", "pass", "malware",
                         f"Defender non in tempo reale (modalità {mode or '?'}); antivirus di terze parti attivo: {', '.join(third_on)}.",
                         "Verificare che il prodotto di terze parti sia aggiornato e gestito.", "medium"))
        else:
            out.append(F("WDEF-001", "Protezione antimalware in tempo reale disattivata", "critical", "fail", "malware",
                         f"RealTimeProtectionEnabled={d.get('RealTimeProtectionEnabled')}, AntivirusEnabled={d.get('AntivirusEnabled')}; "
                         f"nessun altro antivirus attivo rilevato da Sicurezza di Windows.",
                         "Riattivare la protezione in tempo reale (Sicurezza di Windows › Protezione da virus e minacce).", "high"))
        age = _int(d.get("AntivirusSignatureAge"))
        if age is not None and rt:
            out.append(F("WDEF-002", "Aggiornamento delle firme antimalware", "medium", "warn" if age > 3 else "pass", "malware",
                         f"Età delle firme: {age} giorni.", "Aggiornare le firme (Windows Update o 'Verifica disponibilità aggiornamenti' in Sicurezza di Windows).",
                         "high", likelihood=3))
        tp = d.get("IsTamperProtected")
        if tp is not None and rt:
            out.append(F("WDEF-003", "Protezione da manomissioni (Tamper Protection)", "medium", "pass" if tp else "warn", "malware",
                         f"IsTamperProtected={tp}.", "Attivare la protezione da manomissioni: impedisce a malware di disattivare Defender.",
                         "high", likelihood=2))
    elif third_on:
        out.append(F("WDEF-001", "Protezione antimalware in tempo reale", "critical", "pass", "malware",
                     f"Antivirus registrato e attivo: {', '.join(third_on)} (Defender non interrogabile).",
                     "Verificare che il prodotto sia aggiornato e gestito.", "medium"))
    else:
        out.append(F("WDEF-001", "Protezione antimalware", "critical", "unknown", "malware",
                     f"Stato non determinabile: {ctx.error('defender')}. Prodotti registrati: {', '.join(a.get('displayName', '?') for a in av) or 'nessuno'}.",
                     "Verificare in Sicurezza di Windows che un antivirus sia attivo.", "low"))
    pref = ctx.section("mppref")
    if isinstance(pref, dict):
        excl = [str(x) for k in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension") for x in _as_list(pref.get(k)) if x]
        hidden = any("N/A" in x or "must be an administrator" in x.lower() for x in excl)
        if hidden or not ctx.root and not excl:
            out.append(F("WDEF-004", "Esclusioni di Defender", "medium", "manual", "malware",
                         "Le esclusioni sono visibili solo agli amministratori.", "Rieseguire come amministratore.", "low"))
        else:
            risky = [x for x in excl if re.match(r"^(?i:[a-z]:\\?$|%?(temp|tmp|userprofile|appdata)%?|.*\\(temp|downloads|appdata)\\?$|\.?(exe|dll|ps1|bat|cmd|js|vbs)$)", x.strip())]
            st = "warn" if risky else ("info" if excl else "pass")
            out.append(F("WDEF-004", "Esclusioni di Defender", "high" if risky else "medium", st, "malware",
                         (f"{len(excl)} esclusioni: {', '.join(excl[:12])}." + (f" Rischiose: {', '.join(risky[:6])}." if risky else ""))
                         if excl else "Nessuna esclusione configurata.",
                         "Rimuovere le esclusioni non indispensabili, in particolare intere unità, cartelle temporanee/Download e estensioni eseguibili: "
                         "sono un nascondiglio classico per malware.", "high", likelihood=3))
        pua = _int(pref.get("PUAProtection"), 0)
        out.append(F("WDEF-005", "Blocco app potenzialmente indesiderate (PUA)", "low", "pass" if pua == 1 else "warn", "malware",
                     f"PUAProtection={pua} (1 = blocco).", "Attivare il blocco delle app potenzialmente indesiderate in Sicurezza di Windows.",
                     "high", likelihood=2))
        asr = [a for a, act in zip(_as_list(pref.get("AsrIds")), _as_list(pref.get("AsrActions"))) if _int(act, 0) in (1, 6)]
        out.append(F("WDEF-006", "Regole di riduzione della superficie di attacco (ASR)", "low", "pass" if asr else "info", "malware",
                     f"{len(asr)} regole ASR in blocco/avviso." if asr else "Nessuna regola ASR attiva (richiedono Defender come antivirus principale).",
                     "In ambito aziendale valutare le regole ASR (es. blocco di processi figli di Office, credenziali da LSASS).", "medium"))
    return out


# --------------------------------------------------------------------------- firewall
def check_firewall(ctx: WinCtx) -> list[Finding]:
    profiles = [p for p in _as_list(ctx.section("firewall")) if isinstance(p, dict)]
    sev = "high" if ctx.server else "medium"
    if not profiles:
        return [F("WFW-001", "Windows Firewall", sev, "unknown", "firewall", f"Stato non determinabile: {ctx.error('firewall')}",
                  "Verificare in Sicurezza di Windows › Firewall e protezione rete.", "low")]
    off = [p.get("Name", "?") for p in profiles if not p.get("Enabled")]
    allow = [p.get("Name", "?") for p in profiles if str(p.get("DefaultInboundAction", "")).lower() == "allow"]
    ev = "; ".join(f"{p.get('Name')}: {'attivo' if p.get('Enabled') else 'DISATTIVATO'}, ingresso={p.get('DefaultInboundAction') or 'NotConfigured'}"
                   for p in profiles)
    if off or allow:
        public = "Public" in off or "Public" in allow
        return [F("WFW-001", "Windows Firewall disattivato o permissivo", "high" if public else sev, "fail", "firewall",
                  ev + (f". Profili disattivati: {', '.join(off)}." if off else "") + (f" Ingresso consentito di default: {', '.join(allow)}." if allow else ""),
                  "Attivare il firewall su tutti i profili (Dominio, Privato, Pubblico) con traffico in ingresso bloccato di default.",
                  "high", likelihood=4 if public else 3)]
    return [F("WFW-001", "Windows Firewall", sev, "pass", "firewall", ev + ". (NotConfigured = blocco, valore predefinito di Windows)",
              "Rivedere periodicamente le regole in ingresso consentite.", "high")]


# --------------------------------------------------------------------------- account e credenziali
POL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"


def parse_net_accounts(text: str) -> dict:
    """'net accounts' è localizzato: si legge per POSIZIONE (ordine fisso delle righe), non per etichetta."""
    vals = []
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        v = line.rsplit(":", 1)[1].strip()
        vals.append(v)
    keys = ("force_logoff", "min_age", "max_age", "min_length", "history", "lockout_threshold", "lockout_duration", "lockout_window", "role")
    d = dict(zip(keys, vals))
    num = lambda s: int(s) if s and s.isdigit() else 0  # noqa: E731  "Mai"/"Never"/"Nessuno" = 0
    return {"min_length": num(d.get("min_length")), "lockout_threshold": num(d.get("lockout_threshold")),
            "max_age": num(d.get("max_age")), "raw_ok": len(vals) >= 8}


def check_accounts(ctx: WinCtx) -> list[Finding]:
    out: list[Finding] = []
    uac = ctx.reg(POL, "EnableLUA")
    prompt = _int(ctx.reg(POL, "ConsentPromptBehaviorAdmin"))
    secure = _int(ctx.reg(POL, "PromptOnSecureDesktop"))
    if uac is None:
        out.append(F("WUAC-001", "Controllo account utente (UAC)", "high", "unknown", "accounts", "Chiave di registro non leggibile.",
                     "Verificare UAC dal Pannello di controllo.", "low"))
    elif _int(uac) == 0:
        out.append(F("WUAC-001", "Controllo account utente (UAC) disattivato", "high", "fail", "accounts", "EnableLUA=0: ogni programma gira con i privilegi completi.",
                     "Riattivare UAC (EnableLUA=1) e riavviare.", "high"))
    else:
        weak = prompt == 0 or secure == 0
        out.append(F("WUAC-001", "Controllo account utente (UAC)", "high", "warn" if weak else "pass", "accounts",
                     f"EnableLUA=1, ConsentPromptBehaviorAdmin={prompt}, PromptOnSecureDesktop={secure}."
                     + (" Elevazione senza richiesta o fuori dal desktop sicuro." if weak else ""),
                     "Impostare UAC almeno al livello predefinito (notifica sul desktop sicuro).", "high", likelihood=2))
    users = [u for u in _as_list(ctx.section("users")) if isinstance(u, dict)]
    if users:
        guest = [u["Name"] for u in users if str(u.get("SID", "")).endswith("-501") and u.get("Enabled")]
        builtin = [u["Name"] for u in users if str(u.get("SID", "")).endswith("-500") and u.get("Enabled")]
        nopwd = [u["Name"] for u in users if u.get("Enabled") and u.get("PasswordRequired") is False]
        out.append(F("WACC-001", "Account Guest abilitato" if guest else "Account Guest", "high", "fail" if guest else "pass", "accounts",
                     f"Guest abilitato: {', '.join(guest)}." if guest else "Account Guest disabilitato.",
                     "Disabilitare l'account Guest.", "high"))
        out.append(F("WACC-002", "Account Administrator integrato", "medium", "warn" if builtin else "pass", "accounts",
                     f"Abilitato: {', '.join(builtin)} (bersaglio noto di attacchi a forza bruta)." if builtin else "Administrator integrato disabilitato.",
                     "Disabilitare l'Administrator integrato e usare account amministrativi nominativi.", "high", likelihood=2))
        if nopwd:
            out.append(F("WACC-003", "Account a cui è consentita una password vuota", "medium", "warn", "accounts",
                         f"Account abilitati con flag PASSWD_NOTREQD (PasswordRequired=False): {', '.join(nopwd)}. "
                         "Non significa che la password sia vuota, ma che il sistema la ammetterebbe.",
                         "Richiedere una password per gli account abilitati: net user NOME /passwordreq:yes", "low", likelihood=2))
    else:
        out.append(F("WACC-001", "Account locali", "medium", "unknown", "accounts", f"Elenco non disponibile: {ctx.error('users')}",
                     "Verificare gli account con 'Gestione computer'.", "low"))
    admins = [a for a in _as_list(ctx.section("admins")) if isinstance(a, dict)]
    if admins:
        names = [str(a.get("Name", "?")) for a in admins]
        many = len(names) > (3 if ctx.server else 2)
        out.append(F("WACC-004", "Membri del gruppo Administrators", "medium", "warn" if many else "info", "accounts",
                     f"{len(names)} membri: {', '.join(names[:15])}.",
                     "Usare per l'uso quotidiano un account standard e riservare i privilegi amministrativi a pochi account.", "medium", likelihood=2))
    na = ctx.section("netaccounts")
    if isinstance(na, str) and na:
        pol = parse_net_accounts(na)
        if pol["raw_ok"]:
            issues = []
            if pol["min_length"] < 8:
                issues.append(f"lunghezza minima password {pol['min_length']} (< 8)")
            if pol["lockout_threshold"] == 0:
                issues.append("nessun blocco dopo tentativi falliti")
            elif pol["lockout_threshold"] > 10:
                issues.append(f"blocco dopo {pol['lockout_threshold']} tentativi (> 10)")
            out.append(F("WPWD-001", "Policy password e blocco account (locali)", "medium", "warn" if issues else "pass", "accounts",
                         ("; ".join(issues) if issues else "Lunghezza minima e blocco account adeguati.")
                         + " Account Microsoft/Azure AD seguono le proprie policy.",
                         "Impostare lunghezza minima ≥ 12 (Criteri di sicurezza locali) e blocco dopo 5–10 tentativi.", "medium", likelihood=2))
    wd = _int(ctx.reg(LSA.replace("Lsa", r"SecurityProviders\WDigest"), "UseLogonCredential"))
    out.append(F("WLSA-001", "WDigest (password in chiaro in memoria)", "high", "fail" if wd == 1 else "pass", "credentials",
                 "UseLogonCredential=1: le password restano in chiaro nella memoria di LSASS (Mimikatz)." if wd == 1 else
                 f"UseLogonCredential={wd if wd is not None else 'non impostato (predefinito sicuro)'}.",
                 "Impostare UseLogonCredential=0 o rimuovere il valore.", "high"))
    ppl = _int(ctx.reg(LSA, "RunAsPPL"))
    out.append(F("WLSA-002", "Protezione LSA (RunAsPPL)", "medium", "pass" if ppl in (1, 2) else "warn", "credentials",
                 f"RunAsPPL={ppl if ppl is not None else 'non impostato'}.",
                 "Attivare la protezione LSA (Sicurezza di Windows › Sicurezza dispositivi › Isolamento core) per proteggere le credenziali.",
                 "high", likelihood=2))
    lm = _int(ctx.reg(LSA, "LmCompatibilityLevel"))
    nolm = _int(ctx.reg(LSA, "NoLMHash"))
    bad = []
    if lm is not None and lm < 3:
        bad.append(f"LmCompatibilityLevel={lm} (LM/NTLMv1 ammessi)")
    if nolm == 0:
        bad.append("NoLMHash=0 (hash LM memorizzati)")
    out.append(F("WLSA-003", "Autenticazione NTLM/LM", "high", "fail" if bad else "pass", "credentials",
                 "; ".join(bad) if bad else f"LmCompatibilityLevel={lm if lm is not None else 'predefinito (3)'}; hash LM non memorizzati.",
                 "Impostare LmCompatibilityLevel=5 (solo NTLMv2) e NoLMHash=1.", "high"))
    dg = ctx.section("deviceguard")
    if isinstance(dg, dict):
        running = [int(x) for x in _as_list(dg.get("Running")) if _int(x) is not None]
        vbs = _int(dg.get("VirtualizationBasedSecurityStatus"), 0)
        out.append(F("WVBS-001", "Credential Guard / sicurezza basata su virtualizzazione", "low", "pass" if 1 in running else "info", "credentials",
                     f"VBS={'in esecuzione' if vbs == 2 else 'abilitata ma non in esecuzione' if vbs == 1 else 'disattivata'}; "
                     f"Credential Guard={'attivo' if 1 in running else 'non attivo'}; HVCI={'attivo' if 2 in running else 'non attivo'}.",
                     "Dove l'hardware lo consente attivare Isolamento core / Integrità della memoria e Credential Guard.", "high"))
    return out


# --------------------------------------------------------------------------- cifratura, avvio, hardening
def check_hardening(ctx: WinCtx) -> list[Finding]:
    out: list[Finding] = []
    bl = ctx.section("bitlocker")
    labels = {0: "non cifrabile/sconosciuto", 1: "attivo", 2: "disattivato", 3: "cifratura in corso", 4: "decifratura in corso",
              5: "sospeso", 6: "attivo (bloccato)", 7: "in attesa di attivazione (dati cifrati ma chiave non protetta)"}
    if isinstance(bl, int) or (isinstance(bl, str) and bl.isdigit()):
        v = int(bl)
        st = "pass" if v in (1, 3, 6) else "warn"
        out.append(F("WENC-001", "Cifratura del disco di sistema (BitLocker)", "medium", st, "hardening",
                     f"Stato BitLocker dell'unità di sistema: {labels.get(v, v)}.",
                     "Attivare BitLocker/Crittografia dispositivo e conservare la chiave di ripristino in un luogo sicuro: protegge i dati in caso di furto.",
                     "medium", likelihood=2))
    else:
        out.append(F("WENC-001", "Cifratura del disco di sistema", "medium", "unknown", "hardening",
                     f"Stato non determinabile: {ctx.error('bitlocker')}", "Verificare con 'manage-bde -status' come amministratore.", "low"))
    sb = ctx.reg(r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    if sb is not None:
        out.append(F("WBOOT-001", "Secure Boot", "medium", "pass" if _int(sb) == 1 else "warn", "boot",
                     f"UEFISecureBootEnabled={sb}.", "Attivare Secure Boot nel firmware UEFI: blocca bootkit e loader non firmati.", "high", likelihood=2))
    else:
        out.append(F("WBOOT-001", "Secure Boot", "medium", "manual", "boot", "Firmware legacy (BIOS) o stato non leggibile.",
                     "Verificare con msinfo32 (Stato avvio protetto).", "low"))
    smb1_srv = ctx.reg(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    smb1_cli = ctx.reg(r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    smb = ctx.section("smb")
    enabled = []
    if isinstance(smb, dict) and smb.get("EnableSMB1Protocol"):
        enabled.append("server (EnableSMB1Protocol=True)")
    elif smb is None and smb1_srv is not None and _int(smb1_srv) != 0:
        enabled.append(f"server (SMB1={smb1_srv})")
    if smb1_cli is not None and _int(smb1_cli) != 4:
        enabled.append(f"client (mrxsmb10 Start={smb1_cli})")
    out.append(F("WSMB-001", "Protocollo SMBv1", "high", "fail" if enabled else "pass", "network",
                 ("SMBv1 abilitato: " + ", ".join(enabled) + ". Protocollo obsoleto sfruttato da WannaCry/NotPetya.") if enabled else
                 "SMBv1 non abilitato (driver client assente/disattivato, server non attivo).",
                 "Disattivare SMBv1 (Funzionalità di Windows › Supporto per condivisione file SMB 1.0/CIFS).", "medium" if smb is None else "high"))
    sign = (smb or {}).get("RequireSecuritySignature") if isinstance(smb, dict) else _int(
        ctx.reg(r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature"))
    if sign is not None:
        out.append(F("WSMB-002", "Firma SMB obbligatoria (server)", "medium" if ctx.server else "low", "pass" if sign in (True, 1) else "warn", "network",
                     f"RequireSecuritySignature={sign}.", "Richiedere la firma SMB per prevenire attacchi relay/man-in-the-middle.", "medium", likelihood=2))
    shares = [s for s in _as_list(ctx.section("shares")) if isinstance(s, dict)]
    if shares:
        out.append(F("WSMB-003", "Cartelle condivise in rete", "low", "info", "network",
                     "Condivisioni: " + ", ".join(f"{s.get('Name')} ({s.get('Path')})" for s in shares[:10]) + ".",
                     "Verificare che ogni condivisione sia necessaria e che i permessi non includano 'Everyone'.", "medium"))
    feat = ctx.section("psv2")
    ps2 = ctx.reg(r"HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion")
    why = "PowerShell 2.0 non supporta AMSI né il logging degli script: è usato per aggirare i controlli (downgrade)."
    fix = "Rimuovere la funzionalità 'Windows PowerShell 2.0' (Funzionalità di Windows)."
    perr = ctx.error("psv2").lower()
    if isinstance(feat, str) and feat:
        out.append(F("WPS-001", "Motore PowerShell 2.0" + (" abilitato" if feat == "Enabled" else ""), "medium",
                     "warn" if feat == "Enabled" else "pass", "hardening",
                     f"Funzionalità MicrosoftWindowsPowerShellV2Root: {feat}. " + why, fix, "high", likelihood=2))
    elif "not found" in perr or "non trovat" in perr or "unknown feature" in perr:
        out.append(F("WPS-001", "Motore PowerShell 2.0", "medium", "pass", "hardening",
                     "Funzionalità PowerShell 2.0 non presente in questa versione di Windows.", fix, "high"))
    elif ps2 and str(ps2).startswith("2"):
        out.append(F("WPS-001", "Motore PowerShell 2.0 forse presente", "medium", "manual", "hardening",
                     "Motore 2.0 registrato; lo stato della funzionalità è leggibile solo da amministratore. " + why, fix, "low"))
    sbl = _int(ctx.reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"))
    out.append(F("WPS-002", "Logging degli script PowerShell", "low", "pass" if sbl == 1 else ("warn" if ctx.server else "info"), "logging",
                 f"EnableScriptBlockLogging={sbl if sbl is not None else 'non impostato'}.",
                 "Abilitare lo Script Block Logging via Criteri di gruppo per tracciare l'uso di PowerShell.", "high", likelihood=2))
    autorun = _int(ctx.reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun"))
    noauto = _int(ctx.reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun"))
    ok = autorun == 255 or noauto == 1
    out.append(F("WHRD-001", "AutoRun/AutoPlay su supporti rimovibili", "low", "pass" if ok else "warn", "hardening",
                 f"NoDriveTypeAutoRun={autorun if autorun is not None else 'non impostato'}, NoAutorun={noauto if noauto is not None else 'non impostato'}.",
                 "Disattivare AutoRun per tutte le unità (NoDriveTypeAutoRun=255): evita l'esecuzione automatica da chiavette USB.", "high", likelihood=2))
    llmnr = _int(ctx.reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast"))
    out.append(F("WNET-002", "LLMNR (risoluzione nomi multicast)", "low", "pass" if llmnr == 0 else "warn", "network",
                 f"EnableMulticast={llmnr if llmnr is not None else 'non impostato (LLMNR attivo)'}.",
                 "Disattivare LLMNR via Criteri di gruppo: è sfruttato per il furto di hash NTLM (Responder).", "high", likelihood=2))
    ss = ctx.reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    ss2 = ctx.reg(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    off = _int(ss) == 0 or str(ss2 or "").lower() == "off"
    out.append(F("WHRD-002", "SmartScreen", "low", "warn" if off else "pass", "hardening",
                 f"EnableSmartScreen={ss if ss is not None else 'non impostato'}, SmartScreenEnabled={ss2 or 'non impostato'}.",
                 "Mantenere SmartScreen attivo per bloccare file e siti malevoli noti.", "medium", likelihood=2))
    return out


# --------------------------------------------------------------------------- accesso remoto, rete, servizi
TS = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"


def check_remote(ctx: WinCtx) -> list[Finding]:
    deny = ctx.reg(TS, "fDenyTSConnections")
    nla = _int(ctx.reg(TS + r"\WinStations\RDP-Tcp", "UserAuthentication"))
    if deny is None:
        return [F("WRDP-001", "Desktop remoto (RDP)", "high", "unknown", "remote", "Chiave di registro non leggibile.",
                  "Verificare in Impostazioni › Sistema › Desktop remoto.", "low")]
    if _int(deny) == 1:
        return [F("WRDP-001", "Desktop remoto (RDP)", "high", "pass", "remote", "Connessioni Desktop remoto disattivate.",
                  "Nessuna azione se non serve.", "high")]
    if nla != 1:
        return [F("WRDP-001", "Desktop remoto attivo senza NLA", "high", "fail", "remote",
                  "RDP abilitato e autenticazione a livello di rete (NLA) disattivata: il login è esposto prima dell'autenticazione (es. BlueKeep).",
                  "Attivare NLA, limitare RDP alla VPN/rete di gestione e usare password robuste o MFA.", "high")]
    return [F("WRDP-001", "Desktop remoto attivo", "medium" if ctx.server else "high", "warn" if not ctx.server else "info", "remote",
              "RDP abilitato con NLA.", "Se non serve, disattivarlo; altrimenti limitarlo con il firewall a reti fidate e attivare il blocco account.",
              "high", likelihood=2)]


def _is_loop(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("::1",)


def check_network(ctx: WinCtx) -> list[Finding]:
    rows = [r for r in _as_list(ctx.section("listen")) if isinstance(r, dict)]
    if not rows:
        return [F("WNET-001", "Porte TCP in ascolto", "info", "unknown", "network", f"Elenco non disponibile: {ctx.error('listen')}",
                  "Verificare con 'netstat -ano'.", "low")]
    seen, exposed, local = set(), [], 0
    for r in rows:
        key = (str(r.get("LocalAddress")), r.get("LocalPort"))
        if key in seen:
            continue
        seen.add(key)
        if _is_loop(key[0]):
            local += 1
        else:
            addr = f"[{key[0]}]" if ":" in key[0] else key[0]
            exposed.append(f"{addr}:{key[1]} ({r.get('Process') or '?'})")
    return [F("WNET-001", "Porte TCP in ascolto", "info", "info", "network",
              f"{len(exposed)} socket su interfacce di rete, {local} solo loopback. " + ", ".join(exposed[:40]),
              "Riconoscere ogni porta esposta e chiudere i servizi non necessari. La scansione Nmap valuta il rischio di esposizione.", "high")]


RISKY_SERVICES = {
    "RemoteRegistry": ("Registro remoto", "medium", "consente la lettura/modifica remota del registro"),
    "TlntSvr": ("Server Telnet", "critical", "accesso remoto in chiaro"),
    "SNMP": ("Servizio SNMP", "medium", "community SNMPv1/2c in chiaro"),
    "FTPSVC": ("Server FTP IIS", "high", "credenziali e dati in chiaro"),
    "simptcp": ("Simple TCP/IP Services", "medium", "servizi legacy (echo, chargen) abusabili per amplificazione"),
    "SSDPSRV": ("Rilevamento SSDP", "low", "annuncio UPnP di dispositivi in rete"),
    "upnphost": ("Host dispositivi UPnP", "low", "UPnP esposto in rete locale"),
}


def check_services(ctx: WinCtx) -> list[Finding]:
    svc = {s.get("Name"): s for s in _as_list(ctx.section("services")) if isinstance(s, dict)}
    if not svc:
        return [F("WSRV-001", "Servizi a rischio", "medium", "unknown", "services", f"Elenco non disponibile: {ctx.error('services')}",
                  "Verificare con services.msc.", "low")]
    out = []
    running = [(n, *RISKY_SERVICES[n]) for n, s in svc.items() if n in RISKY_SERVICES and s.get("Status") == "Running"]
    worst = max((x[2] for x in running), key=lambda s: ("low", "medium", "high", "critical").index(s), default="medium")
    out.append(F("WSRV-001", "Servizi legacy/a rischio in esecuzione" if running else "Servizi legacy/a rischio", worst,
                 "warn" if running else "pass", "services",
                 "; ".join(f"{label} ({n}): {why}" for n, label, _, why in running) if running else
                 "Nessuno tra Telnet, FTP, SNMP, Registro remoto, Simple TCP/IP, UPnP in esecuzione.",
                 "Arrestare e disattivare i servizi non necessari (services.msc › Tipo di avvio: Disabilitato).", "high", likelihood=3))
    sp = svc.get("Spooler")
    if sp and sp.get("Status") == "Running" and ctx.server:
        out.append(F("WSRV-002", "Spooler di stampa attivo su server", "high", "warn", "services",
                     "Il servizio Spooler è attivo: superficie di attacco storica (PrintNightmare) inutile su server senza stampa.",
                     "Disattivare lo Spooler sui server che non gestiscono stampanti (soprattutto domain controller).", "high", likelihood=3))
    winrm = svc.get("WinRM")
    if winrm and winrm.get("Status") == "Running":
        out.append(F("WSRV-003", "Gestione remota WinRM attiva", "medium", "info" if ctx.server else "warn", "remote",
                     "Il servizio WinRM (PowerShell Remoting) è in esecuzione.",
                     "Se non serve, disattivarlo; altrimenti limitarlo con il firewall e usare HTTPS.", "medium", likelihood=2))
    sshd = svc.get("sshd")
    if sshd and sshd.get("Status") == "Running":
        out.append(F("WSRV-004", "Server OpenSSH attivo", "info", "info", "remote", "Il servizio sshd è in esecuzione.",
                     "Verificare C:\\ProgramData\\ssh\\sshd_config: niente password, solo chiavi, accesso limitato.", "high"))
    return out


# --------------------------------------------------------------------------- controlli approfonditi (deep/full)
WEAK_SIDS = {"S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-32-545": "Users"}


def check_privesc(ctx: WinCtx) -> list[Finding]:
    out: list[Finding] = []
    uq = ctx.section("unquoted", deep=True)
    if uq is None:
        out.append(F("WPRIV-001", "Percorsi dei servizi senza virgolette", "medium", "unknown", "privilege",
                     f"Dato non disponibile: {ctx.error('unquoted', True)}", "Verificare con 'wmic service get name,pathname'.", "low"))
    else:
        items = [s for s in _as_list(uq) if isinstance(s, dict)
                 and not re.match(r"(?i)^\s*%?(systemroot|windir)%?\\|^\s*[a-z]:\\windows\\", str(s.get("PathName", "")))]
        out.append(F("WPRIV-001", "Servizi con percorso non tra virgolette" if items else "Percorsi dei servizi", "high",
                     "warn" if items else "pass", "privilege",
                     ("; ".join(f"{s.get('Name')}: {s.get('PathName')}" for s in items[:10])) if items else
                     "Nessun servizio con percorso contenente spazi e privo di virgolette (fuori da C:\\Windows).",
                     "Racchiudere il percorso tra virgolette (chiave ImagePath del servizio): altrimenti un utente che può scrivere in una "
                     "cartella intermedia può far eseguire un proprio programma come SYSTEM.", "medium", likelihood=2))
    acl = ctx.section("pathacl", deep=True)
    if acl is None:
        out.append(F("WPRIV-002", "Cartelle del PATH di sistema scrivibili", "high", "unknown", "privilege",
                     f"Dato non disponibile: {ctx.error('pathacl', True)}", "Verificare i permessi delle cartelle del PATH con icacls.", "low"))
    else:
        items = [a for a in _as_list(acl) if isinstance(a, dict)]
        paths = sorted({f"{a.get('path')} ({WEAK_SIDS.get(a.get('sid'), a.get('sid'))}: {a.get('rights')})" for a in items})
        out.append(F("WPRIV-002", "Cartelle del PATH di sistema scrivibili da utenti" if items else "Cartelle del PATH di sistema", "high",
                     "fail" if items else "pass", "privilege",
                     "; ".join(paths[:10]) if paths else "Nessuna cartella del PATH di sistema scrivibile da Everyone/Users/Authenticated Users.",
                     "Rimuovere il permesso di scrittura per gli utenti non amministratori (icacls): consente DLL/PATH hijacking verso SYSTEM.",
                     "high", likelihood=3))
    st = ctx.section("startup", deep=True)
    if st is not None:
        items = [s for s in _as_list(st) if isinstance(s, dict)]
        odd = [s for s in items if re.search(r"(?i)\\(temp|appdata\\local\\temp|downloads|public)\\|powershell.*-enc|mshta|wscript|cscript|rundll32.*javascript",
                                             str(s.get("command", "")))]
        out.append(F("WPRIV-003", "Programmi in avvio automatico sospetti" if odd else "Programmi in avvio automatico", "medium",
                     "warn" if odd else "info", "persistence",
                     (f"{len(items)} voci Run; sospette: " + "; ".join(f"{s.get('name')}: {s.get('command')}"[:160] for s in odd[:6])) if odd else
                     f"{len(items)} voci nelle chiavi Run: " + ", ".join(str(s.get("name")) for s in items[:20]),
                     "Verificare ogni voce in avvio automatico (Gestione attività › App di avvio); comandi da cartelle temporanee o "
                     "PowerShell codificato sono tipici di malware.", "medium", likelihood=3))
    return out


def check_integrity(ctx: WinCtx) -> list[Finding]:
    """Integrità su Windows: firma Authenticode degli eseguibili dei servizi."""
    data = ctx.section("unsigned", deep=True)
    if not isinstance(data, dict):
        return [F("WINT-001", "Firma digitale degli eseguibili dei servizi", "high", "unknown", "integrity",
                  f"Verifica non completata: {ctx.error('unsigned', True)}", "Verificare con Get-AuthenticodeSignature o sigcheck.", "low")]
    bad = [b for b in _as_list(data.get("bad")) if isinstance(b, dict)]
    invalid = [b for b in bad if b.get("status") in ("HashMismatch", "NotTrusted", "NotSupportedFileFormat")]
    unsigned = [b for b in bad if b not in invalid]
    out = [F("WINT-001", "Eseguibili di servizi con firma non valida" if invalid else "Firma degli eseguibili dei servizi", "high",
             "fail" if invalid else "pass", "integrity",
             ("; ".join(f"{b.get('service')}: {b.get('path')} [{b.get('status')}]" for b in invalid[:10])) if invalid else
             f"{data.get('checked', 0)} eseguibili controllati: nessuna firma alterata (HashMismatch) o non attendibile.",
             "Una firma con hash non corrispondente indica un file modificato dopo la firma: trattarlo come possibile compromissione.",
             "high", likelihood=4)]
    if unsigned:
        out.append(F("WINT-002", "Servizi con eseguibile non firmato", "medium", "warn", "integrity",
                     f"{len(unsigned)} eseguibili senza firma: " + "; ".join(f"{b.get('service')}: {b.get('path')}" for b in unsigned[:10]),
                     "Verificare provenienza ed editore dei servizi non firmati (spesso software legittimo ma datato).", "medium", likelihood=2))
    return out


CHECKS = [check_system, check_updates, check_defender, check_firewall, check_accounts, check_hardening, check_remote,
          check_network, check_services]


def collect(profile: str = "desktop", deep: bool = False, runner: Runner | None = None, ctx: WinCtx | None = None) -> list[Finding]:
    runner = runner or Runner()
    if ctx is None:
        ctx = WinCtx(profile, deep, runner, is_root())
    results: list[Finding] = []
    if not ctx.inv:
        ctx.inv, err = collect_inventory(runner, INVENTORY_PS, "inventario", 240)
        if err:
            results.append(F("WSYS-000", "Inventario PowerShell non disponibile", "medium", "unknown", "internal", err,
                             "Verificare che PowerShell sia disponibile; i controlli basati sul registro restano validi.", "low"))
    if deep and not ctx.deep_inv:
        ctx.deep_inv, err = collect_inventory(runner, DEEP_PS, "controlli-approfonditi", 600)
    checks = CHECKS + ([check_privesc] if deep else [])
    for chk in checks:
        try:
            results.extend(chk(ctx))
        except Exception as exc:  # un controllo non deve mai interrompere l'audit
            name = chk.__name__.removeprefix("check_").upper()
            results.append(F(f"ERR-W{name}", f"Errore nel controllo {name.lower()}", "medium", "unknown", "internal",
                             f"{type(exc).__name__}: {exc}", "Segnalare il problema agli sviluppatori allegando la versione dello strumento.", "low"))
    results.append(F("WSYS-005", "Profilo selezionato", "info", "info", "system", f"Profilo: {ctx.profile}; modalità approfondita: {'sì' if deep else 'no'}.",
                     "Il profilo orienta severità e probabilità in alcuni controlli.", "high"))
    return results
