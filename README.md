# LSTK · Security Toolkit per Linux e Windows (v0.7.0)

**Assessment di sicurezza automatico, in sola lettura, con risk assessment `rischio = probabilità × impatto`.**
Gira su **Linux** e, da questa versione, anche su **Windows 10/11**: stesso comando, stessa console, stesso rapporto.

| Fonte | Linux | Windows |
|---|---|---|
| Controlli nativi (sola lettura) | account, SSH, firewall, sysctl, permessi, SUID, logging, aggiornamenti… | Defender, firewall, Windows Update e fine supporto, UAC, BitLocker, Secure Boot, SMBv1, RDP/NLA, LSA/WDigest/NTLM, account e password… |
| Integrità | `dpkg --verify` / `rpm -Va` | firma Authenticode degli eseguibili dei servizi |
| Privilege escalation | SUID, world-writable, file orfani | servizi con percorso senza virgolette, cartelle del PATH scrivibili, avvio automatico sospetto |
| [Nmap](https://nmap.org/) | porte e servizi esposti (loopback vs rete) | idem (TCP connect, oppure SYN con Npcap + amministratore) |
| [Trivy](https://trivy.dev) | CVE di pacchetti e librerie, segreti, OS fuori supporto | librerie vulnerabili e segreti nel profilo utente |
| [Lynis](https://cisofy.com/lynis/) | audit di hardening importato | — (non esiste per Windows; coperto dai controlli nativi) |

> **Non è una certificazione** né un sostituto di un penetration test. Un controllo non conclusivo non è mai "sicuro": finisce tra i *non verificati* e rende la valutazione **parziale**. Vedi [Limiti](#limiti).

## Avvio rapido

**Linux**
```bash
git clone https://github.com/Filippo-Cappellini/ITS-1-linux-security-toolkit.git
cd ITS-1-linux-security-toolkit
./run.sh            # al primo avvio esegue install.sh (chiede conferma prima di installare qualsiasi cosa)
```

**Windows** (PowerShell; serve Python ≥ 3.10, es. `winget install Python.Python.3.12`)
```powershell
git clone https://github.com/Filippo-Cappellini/ITS-1-linux-security-toolkit.git
cd ITS-1-linux-security-toolkit
.\run.bat           # oppure doppio clic su run.bat; al primo avvio esegue install.ps1
```
`run.ps1` propone di riaprirsi come amministratore (finestra UAC) per la copertura completa; `.\run.ps1 -NoElevate` resta utente normale.

Nel prompt `lstk ›` scrivi `/scan` e conferma. Senza console interattiva: `./run.sh scan --format table` (Linux) o `.\run.bat scan --format table` (Windows).

## Novità della 0.7.0

- **Windows**: oltre 40 controlli nativi (registro + cmdlet PowerShell `Get-*`), integrità con firme digitali, privilege escalation, Nmap e Trivy, installazione degli strumenti con **winget**.
- **Nuova grafica**: console con logo, cruscotto del rischio (voto grande, barra della postura, barre per livello, matrice colorata), barra di avanzamento per modulo; rapporto HTML ridisegnato (tema chiaro/scuro, anello del voto, ciambella dei rischi, filtri per livello, schede espandibili). Tutto senza JavaScript.
- **Storico e confronto**: ogni scansione dalla console viene salvata; `/history` mostra il trend della postura, `/diff` elenca rischi nuovi, risolti, peggiorati e migliorati.
- **Correzioni suggerite**: `/fix ID` mostra i comandi per risolvere il problema (Linux o Windows). LSTK **non li esegue**.
- **Export**: oltre a JSON e HTML, **SARIF 2.1.0** (GitHub code scanning, Azure DevOps), **CSV** (Excel, protetto dalla formula injection) e **Markdown**. `lstk export` rigenera un rapporto dallo storico senza ripetere la scansione.
- `/search`, `/open` (apre l'ultimo rapporto HTML), ciclo di vita di Windows (fine supporto per versione ed edizione).

## Esempio di output

Scansione reale su Windows 11 (modalità `deep`, utente non amministratore):

```text
╭─ Risk assessment · PC ────────────────────────────────────────────────────╮
│   █▀▀▄                         Rischi per livello                         │
│   █  █                          critico   0 ░░░░░░░░░░░░░░░░░░            │
│   █▄▄▀                             alto   4 ██████████░░░░░░░░            │
│   voto D                          medio   2 █████░░░░░░░░░░░░░            │
│  Postura 55/100                   basso   7 ██████████████████            │
│  ████████████░░░░░░░░░░                                                   │
│  Rischio complessivo  alto      Matrice probabilità × impatto  …          │
╰───────────────────────────────────────────────────────────────────────────╯
 WUPD-001   alto   4 4 16  ▲ warn  native  Aggiornamenti di Windows in sospeso
 WPRIV-002  alto   3 4 12  ✘ fail  native  Cartelle del PATH di sistema scrivibili da utenti
 WPRIV-001  medio  2 4  8  ▲ warn  native  Servizi con percorso non tra virgolette
```

P = probabilità (1–5), I = impatto (1–5). Livelli: critical ≥ 20, high ≥ 12, medium ≥ 8, low ≥ 1. Metodologia: [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Modalità

| Modalità | Controlli nativi | Integrità | Nmap | Trivy | Lynis (Linux) |
|---|---|---|---|---|---|
| `quick` | base | no | top-1000 porte TCP | no | no |
| `deep` | estesi (Linux: SUID, world-writable, servizi · Windows: privilege escalation, avvio automatico) | sì | tutte le porte TCP | no | no |
| **`full`** (default) | estesi | sì | tutte le porte + script `default` + UDP top-50 (se possibile) | sì | sì |

## Comandi della console

```text
Scansione   /scan [quick|deep|full] [--target T] [--no-nmap|--no-trivy|--no-integrity|--no-lynis] [--offline]
            /vuln · /integrity · /lynis (solo Linux) · /profile desktop|server
Risultati   /risk · /findings [issues|all|critical|high|medium|low|unverified] · /details ID · /fix ID · /search TESTO
Rapporti    /report [json|html|sarif|csv|md|all] [--open] · /open · /history · /diff [A] [B] · /verify FILE
Strumenti   /doctor · /install [nmap|trivy|lynis|iproute2|all] · /checks · /status · /help · /exit
```

Modalità non interattiva (risultato su stdout, avanzamento su stderr):

```bash
lstk scan --profile server --mode full --format table           # tabella di rischio
lstk scan --mode full --save --history --fail-on high > out.json # JSON + rapporti + storico; exit 3 se rischio >= high
lstk scan --format sarif > lstk.sarif                            # per GitHub code scanning
lstk history ; lstk diff ; lstk export lstk-reports/history/scan-XXXX.json --format html
lstk install trivy --yes ; lstk doctor ; lstk verify lstk-reports/audit-XXXX.json
```
Exit code: `0` ok · `1` errore · `2` argomenti/autorizzazione non validi · `3` soglia `--fail-on` superata.

## Requisiti

- **Python ≥ 3.10**; dipendenze Python: `typer`, `rich`.
- **Linux**: testato su Ubuntu 22.04/24.04 (Debian, Kali, Fedora, Rocky previsti). Pacchetti installati da `install.sh` su richiesta: `nmap`, `lynis`, `iproute2`, Trivy (release ufficiale con SHA-256 fissato nel codice).
- **Windows**: Windows 10/11 con PowerShell 5.1 (incluso). Nmap e Trivy opzionali, installabili con `winget` da `install.ps1` o `/install`. Per scansioni SYN/UDP serve [Npcap](https://npcap.com/) (incluso nell'installer di Nmap) e l'amministratore.
- **Privilegi**: root (Linux) o amministratore (Windows) per l'audit completo. Senza funziona, ma la valutazione è **parziale** (voto massimo B).
- **Rete**: nessuna connessione propria. Nmap contatta solo i bersagli indicati; Trivy scarica il database pubblico delle vulnerabilità (`--offline` per usare solo la cache); su Windows il controllo degli aggiornamenti usa i dati **locali** di Windows Update.

## Parametri utili

| Cosa | Come | Note |
|---|---|---|
| Profilo | `/profile server` o `--profile server` | influenza severità e probabilità di alcuni controlli |
| Bersaglio esterno | `/scan full --target 192.168.1.10` (anche CIDR ≤ /24) | richiede di digitare `AUTORIZZO`; in CLI `--authorized`. Solo sistemi per cui hai autorizzazione scritta |
| Firma dei rapporti | `LSTK_SIGNING_KEY` (≥ 16 caratteri) | aggiunge HMAC-SHA256 |
| Cartella rapporti | `LSTK_REPORT_DIR` | default `./lstk-reports` (Linux 0700, file 0600) |
| Storico | `LSTK_HISTORY_DIR`, `LSTK_NO_HISTORY=1` | default `lstk-reports/history` |
| Trivy | `LSTK_TRIVY_TARGET`, `LSTK_TRIVY_CACHE_DIR`, `LSTK_TRIVY_TIMEOUT` | su Windows il bersaglio predefinito è il profilo utente |
| Timeout | `LSTK_LYNIS_TIMEOUT`, `LSTK_INTEGRITY_TIMEOUT` | secondi |

## Prova in laboratorio

**Linux** (VM usa-e-getta): `sudo apt install -y vsftpd` (FTP in chiaro → Nmap), un finto token in `/root/demo.env` (→ Trivy), un byte aggiunto a `/usr/bin/ischroot` dopo averne fatto una copia (→ integrità). Poi `/scan`, `/findings high`, `/fix INT-001`, `/report all`, `/diff`.

**Windows** (VM di test, PowerShell come amministratore): `Set-NetFirewallProfile -Profile Public -Enabled False` (→ WFW-001), `Enable-LocalUser Guest` (→ WACC-001), `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f` (→ WLSA-001). Rilancia `/scan`, guarda `/diff`, poi ripristina con i comandi di `/fix`.

## Sicurezza dello strumento

- `/scan` è **in sola lettura** su entrambi i sistemi (su Windows solo letture del registro e cmdlet `Get-*`, verificato dai test). L'unico modulo che modifica il sistema è l'installer, solo dopo conferma esplicita.
- Nessuna shell; binari risolti solo in directory di sistema (anti PATH-hijacking); ambiente minimo; timeout con kill dell'albero di processi. Gli script PowerShell passano come `-EncodedCommand` (nessun problema di quoting o iniezione) e compaiono nel rapporto con un'etichetta leggibile.
- Bersagli non locali solo con autorizzazione dichiarata; input validato.
- Rapporti con SHA-256 + HMAC opzionale (`lstk verify`), elenco dei comandi eseguiti, limiti dichiarati. HTML con CSP `default-src 'none'` e nessuno script; CSV protetto dalla formula injection.

Dettagli in [SECURITY.md](SECURITY.md). I rapporti contengono dati sensibili: trattarli come riservati.

## Test

```bash
pip install -e ".[test]" && pytest -q
```
149 test, nessun comando reale (runner, registro e PowerShell simulati). I controlli Windows sono testati anche su Linux; i test specifici di una piattaforma vengono saltati sull'altra.

## Struttura

```
run.sh / install.sh                avvio e installazione su Linux
run.bat / run.ps1 / install.ps1    avvio e installazione su Windows
lstk/audit.py      controlli nativi Linux        lstk/winaudit.py   controlli nativi Windows
lstk/nmapscan.py   Nmap                          lstk/trivy.py      CVE e segreti
lstk/integrity.py  dpkg/rpm verify               lstk/lynis.py      Lynis (Linux)
lstk/scan.py       orchestratore                 lstk/risk.py       probabilità × impatto, voto
lstk/report.py     JSON/HTML/SARIF/CSV/MD        lstk/history.py    storico e confronto
lstk/fixes.py      comandi di correzione suggeriti
lstk/installer.py  installazione guidata (apt/dnf/zypper/pacman, winget)
lstk/runner.py     esecuzione sicura dei comandi lstk/osinfo.py     piattaforma e privilegi
```

## Limiti

- Valutazione best-effort: dipende da privilegi, sistema e strumenti installati.
- Una CVE presente non implica che sia sfruttabile. Nmap non correla i servizi alle CVE. Solo IPv4.
- Nmap eseguito sulla macchina stessa vede le porte in ascolto anche se il firewall le filtra verso l'esterno: per l'esposizione reale scansionare da un altro host.
- Linux: l'integrità non rileva file *aggiunti* né rootkit. Windows: si verificano le firme degli eseguibili dei servizi, non tutti i file di sistema (`sfc /scannow`); Trivy non analizza i componenti del sistema operativo (coperti da Windows Update).
- Su Windows la policy password letta è quella **locale**; account Microsoft/Entra ID seguono le proprie regole. La data di fine supporto si basa su una tabella nel codice (build note).
- Nessuna baseline CIS/SCAP né verifica di conformità. Le correzioni **non** vengono applicate: `/fix` mostra soltanto i comandi.
- Un host compromesso può falsare i risultati; hash/HMAC provano la non alterazione del rapporto, non la veridicità dei dati.

## Sviluppi futuri

Elenco completo in [ROADMAP.md](ROADMAP.md): assessment remoto agent-less (SSH / WinRM), priorità con EPSS/CISA KEV, baseline CIS, correlazione CVE dei servizi Nmap, IPv6, macOS, esecuzione pianificata.

## Riferimenti

- Metodologia: [NIST SP 800-30 Rev. 1](https://csrc.nist.gov/pubs/sp/800/30/r1/final) · [OWASP Risk Rating](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) · ISO/IEC 27005
- Strumenti: [Nmap](https://nmap.org/book/man.html) · [Lynis](https://cisofy.com/lynis/) · [Trivy](https://trivy.dev) · [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- Hardening: [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) · [Microsoft Security Baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) · [Ciclo di vita di Windows](https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro)
- Librerie: [Typer](https://typer.tiangolo.com/) · [Rich](https://rich.readthedocs.io/)

## Licenza

Da definire dal maintainer prima della pubblicazione.
