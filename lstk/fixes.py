"""Comandi di correzione SUGGERITI per i singoli finding (Linux e Windows).

LSTK non esegue mai questi comandi: li mostra in /fix ID e nel rapporto, perché l'operatore li capisca,
li adatti al proprio sistema e li provi prima di usarli. I segnaposto sono in MAIUSCOLO tra < >.
"""
from __future__ import annotations

import re

LINUX: dict[str, tuple[list[str], str]] = {
    "FW-001": (["sudo ufw default deny incoming", "sudo ufw allow OpenSSH        # solo se serve l'accesso SSH", "sudo ufw enable",
                "sudo ufw status verbose"], "Su RHEL/Fedora: sudo systemctl enable --now firewalld."),
    "SSH-001": (["sudoedit /etc/ssh/sshd_config.d/99-lstk.conf   # PermitRootLogin no / PasswordAuthentication no / PermitEmptyPasswords no",
                 "sudo sshd -t && sudo systemctl reload ssh", "sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'"],
                "Prima di disattivare le password verificare di poter entrare con una chiave, in una seconda sessione aperta."),
    "SSH-002": (["sudoedit /etc/ssh/sshd_config.d/99-lstk.conf   # X11Forwarding no / MaxAuthTries 4 / PermitUserEnvironment no",
                 "sudo sshd -t && sudo systemctl reload ssh"], ""),
    "ACC-001": (["awk -F: '$3 == 0 {print $1}' /etc/passwd", "sudo usermod -u <NUOVO_UID> <UTENTE>   # o rimuovere l'account se non riconosciuto"],
                "Un UID 0 non atteso può indicare una compromissione: indagare prima di modificare."),
    "ACC-002": (["sudo passwd -l <UTENTE>        # blocca l'account", "sudo passwd <UTENTE>           # oppure imposta una password robusta"], ""),
    "ACC-003": (["sudo visudo -f /etc/sudoers.d/<FILE>   # togliere NOPASSWD o limitarlo a comandi precisi"], ""),
    "ACC-004": (["sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs"], "Vale per i nuovi account; per quelli esistenti: sudo chage -M 365 <UTENTE>."),
    "FS-001": (["sudo chown root:root /etc/passwd /etc/group /etc/ssh/sshd_config", "sudo chmod 644 /etc/passwd /etc/group",
                "sudo chmod 640 /etc/shadow /etc/gshadow && sudo chown root:shadow /etc/shadow /etc/gshadow", "sudo chmod 440 /etc/sudoers"], ""),
    "FS-002": (["echo 'tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=2G 0 0' | sudo tee -a /etc/fstab", "sudo mount -o remount /tmp"],
               "noexec su /tmp può rompere alcuni installer: provarlo prima."),
    "FS-003": (["sudo chmod u-s <FILE>"], "Rimuovere il bit SUID solo da file non necessari o sospetti."),
    "FS-004": (["sudo chmod o-w <DIRECTORY>    # oppure: sudo chmod +t <DIRECTORY>"], ""),
    "FS-005": (["sudo chmod o-w <FILE>"], ""),
    "FS-006": (["sudo chown root:root <FILE>   # o rimuoverlo dopo averne verificato l'origine"], ""),
    "KRN-001": (["sudoedit /etc/sysctl.d/99-lstk.conf   # es. kernel.kptr_restrict = 2, kernel.dmesg_restrict = 1, fs.suid_dumpable = 0",
                 "sudo sysctl --system"], "Docker e i router richiedono net.ipv4.ip_forward = 1: non disattivarlo su quei sistemi."),
    "MAC-001": (["sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor   # Debian/Ubuntu",
                 "sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config   # RHEL/Fedora"], ""),
    "LOG-001": (["sudo systemctl enable --now systemd-journald rsyslog"], ""),
    "AUD-001": (["sudo apt install auditd && sudo systemctl enable --now auditd   # o: sudo dnf install audit"], ""),
    "TIME-001": (["sudo timedatectl set-ntp true", "timedatectl status"], ""),
    "PKG-002": (["sudo apt update && sudo apt upgrade        # Debian/Ubuntu/Kali", "sudo dnf upgrade --refresh                # Fedora/RHEL"],
                "Applicare in una finestra di manutenzione, dopo un backup."),
    "SYS-004": (["sudo systemctl reboot"], "Pianificare il riavvio."),
    "SRV-002": (["systemctl list-unit-files --state=enabled | grep -Ei 'telnet|ftp|rsh|tftp|xinetd'",
                 "sudo systemctl disable --now <SERVIZIO>"], ""),
    "INT-001": (["dpkg -S <FILE>                       # pacchetto proprietario", "sudo apt install --reinstall <PACCHETTO>"],
                "Se la modifica non è attesa trattarla come possibile compromissione: prima isolare l'host e conservare le prove."),
    "ENC-001": ([], "La cifratura LUKS del disco di sistema si imposta in fase di installazione: pianificare una reinstallazione o cifrare i dati con volumi dedicati."),
}

WINDOWS: dict[str, tuple[list[str], str]] = {
    "WSYS-002": (["start ms-settings:windowsupdate"], "Aggiornare alla versione di Windows più recente proposta da Windows Update."),
    "WSYS-004": (["shutdown /r /t 0"], "Salvare il lavoro prima di riavviare."),
    "WUPD-001": (["start ms-settings:windowsupdate", "UsoClient StartInteractiveScan"], ""),
    "WUPD-002": (["start ms-settings:windowsupdate"], ""),
    "WUPD-003": (["Set-Service wuauserv -StartupType Manual   # PowerShell come amministratore", "Start-Service wuauserv"], ""),
    "WDEF-001": (["Set-MpPreference -DisableRealtimeMonitoring $false   # PowerShell come amministratore"], ""),
    "WDEF-002": (["Update-MpSignature"], ""),
    "WDEF-003": (["start windowsdefender://threatsettings"], "La protezione da manomissioni si attiva solo dall'interfaccia di Sicurezza di Windows."),
    "WDEF-004": (["Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension",
                  "Remove-MpPreference -ExclusionPath '<PERCORSO>'"], ""),
    "WDEF-005": (["Set-MpPreference -PUAProtection Enabled   # PowerShell come amministratore"], ""),
    "WFW-001": (["Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block   # PowerShell come amministratore"], ""),
    "WUAC-001": (["reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f",
                  "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f",
                  "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f"],
                 "Richiede il riavvio."),
    "WACC-001": (["Disable-LocalUser -Name Guest"], ""),
    "WACC-002": (["Disable-LocalUser -Name Administrator"], "Prima verificare di avere un altro account amministratore funzionante."),
    "WACC-003": (["net user <UTENTE> /passwordreq:yes"], ""),
    "WACC-004": (["Get-LocalGroupMember -SID S-1-5-32-544", "Remove-LocalGroupMember -SID S-1-5-32-544 -Member '<UTENTE>'"],
                 "Lasciare almeno un account amministratore."),
    "WPWD-001": (["net accounts /minpwlen:12 /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15"], "Vale per gli account locali."),
    "WLSA-001": (["reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f"], ""),
    "WLSA-002": (["reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f"],
                 "Richiede il riavvio; driver o plugin LSA non firmati potrebbero smettere di funzionare."),
    "WLSA-003": (["reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f",
                  "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v NoLMHash /t REG_DWORD /d 1 /f"], ""),
    "WVBS-001": (["start windowsdefender://coreisolation"], ""),
    "WENC-001": (["manage-bde -status", "Enable-BitLocker -MountPoint $env:SystemDrive -RecoveryPasswordProtector   # come amministratore"],
                 "Salvare la chiave di ripristino (account Microsoft, chiavetta o stampa) PRIMA di riavviare. Windows Home: Impostazioni › Privacy e sicurezza › Crittografia dispositivo."),
    "WBOOT-001": ([], "Secure Boot si attiva nel firmware UEFI (menu di avvio del PC); con disco MBR serve prima la conversione GPT (mbr2gpt)."),
    "WSMB-001": (["Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart   # come amministratore"], ""),
    "WSMB-002": (["Set-SmbServerConfiguration -RequireSecuritySignature $true -Force   # come amministratore"], ""),
    "WSMB-003": (["Get-SmbShare", "Get-SmbShareAccess -Name <CONDIVISIONE>", "Remove-SmbShare -Name <CONDIVISIONE>"], ""),
    "WPS-001": (["Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart   # come amministratore"], ""),
    "WPS-002": (["reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"], ""),
    "WHRD-001": (["reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"], ""),
    "WHRD-002": (["start windowsdefender://appbrowser"], ""),
    "WNET-002": (["reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f"], ""),
    "WRDP-001": (["reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f",
                  "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f   # disattiva RDP"], ""),
    "WSRV-001": (["Stop-Service -Name <SERVIZIO>", "Set-Service -Name <SERVIZIO> -StartupType Disabled"], ""),
    "WSRV-002": (["Stop-Service -Name Spooler", "Set-Service -Name Spooler -StartupType Disabled"], "Solo su server che non stampano."),
    "WSRV-003": (["Stop-Service WinRM", "Set-Service WinRM -StartupType Disabled"], ""),
    "WPRIV-001": (["reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\<SERVIZIO> /v ImagePath",
                   "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\<SERVIZIO> /v ImagePath /t REG_EXPAND_SZ /d \"\\\"<PERCORSO.exe>\\\" <ARGOMENTI>\" /f"],
                  "Racchiudere tra virgolette solo il percorso dell'eseguibile, lasciando fuori gli argomenti."),
    "WPRIV-002": (["icacls \"<CARTELLA>\"", "icacls \"<CARTELLA>\" /remove:g *S-1-5-32-545 *S-1-5-11 *S-1-1-0"],
                  "Verificare che nessun programma legittimo debba scrivere in quella cartella."),
    "WPRIV-003": (["start ms-settings:startupapps", "Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location"], ""),
    "WINT-001": (["Get-AuthenticodeSignature '<FILE>' | Format-List *", "sfc /scannow   # come amministratore"],
                 "Una firma non valida su un eseguibile di sistema va trattata come possibile compromissione."),
}

NMAP_PORT = re.compile(r"^NMAP-(?:.+-)?(TCP|UDP)-(\d+)$")


def suggestions(fid: str, platform_name: str) -> dict:
    """Ritorna {"commands": [...], "note": str}; vuoto se non ci sono suggerimenti per questo finding."""
    table = WINDOWS if platform_name == "windows" else LINUX
    key = fid.split("-dup")[0]
    if key in table:
        cmds, note = table[key]
        return {"commands": list(cmds), "note": note}
    m = NMAP_PORT.match(key)
    if m:
        proto, port = m.group(1).lower(), m.group(2)
        if platform_name == "windows":
            return {"commands": [f"Get-NetTCPConnection -LocalPort {port} | Select-Object OwningProcess" if proto == "tcp" else
                                 f"Get-NetUDPEndpoint -LocalPort {port} | Select-Object OwningProcess",
                                 f"New-NetFirewallRule -DisplayName 'LSTK blocca {proto}/{port}' -Direction Inbound -Protocol {proto.upper()} -LocalPort {port} -Action Block"],
                    "note": "Meglio ancora: arrestare il servizio che ascolta su quella porta se non serve."}
        return {"commands": [f"sudo ss -lntup '( sport = :{port} )'", f"sudo ufw deny {port}/{proto}"],
                "note": "Meglio ancora: arrestare il servizio che ascolta su quella porta se non serve."}
    if key.startswith("TRV-") and not key.startswith(("TRV-SEC", "TRV-0", "TRV-EOL", "TRV-TRUNC")):
        if platform_name == "windows":
            return {"commands": ["winget upgrade --all", "npm audit fix   # / pip install -U <PACCHETTO>, a seconda del progetto"],
                    "note": "Su Windows Trivy analizza librerie di progetti e applicazioni nel profilo utente."}
        return {"commands": ["sudo apt install --only-upgrade <PACCHETTO>   # Debian/Ubuntu", "sudo dnf upgrade <PACCHETTO>                # Fedora/RHEL"],
                "note": "Per librerie di applicazioni (npm, pip, Maven…) aggiornare la dipendenza nel progetto."}
    if key.startswith("TRV-SEC"):
        return {"commands": [], "note": "Revocare/ruotare il segreto presso il servizio che lo ha emesso, poi rimuoverlo dal file (e dalla cronologia git se presente)."}
    return {"commands": [], "note": ""}
