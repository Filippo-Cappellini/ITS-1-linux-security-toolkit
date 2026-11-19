# LSTK · Security Toolkit e antivirus per Linux e Windows (v0.10.0)

**Assessment di sicurezza automatico, in sola lettura, con risk assessment `rischio = probabilità × impatto`, e antivirus con quarantena.**
Gira su **Linux** e, da questa versione, anche su **Windows 10/11**: stesso comando, stessa console, stesso rapporto.

| Fonte | Linux | Windows |
|---|---|---|
| Controlli nativi (sola lettura) | account, SSH, firewall, sysctl, permessi, SUID, logging, aggiornamenti… | Defender, firewall, Windows Update e fine supporto, UAC, BitLocker, Secure Boot, SMBv1, RDP/NLA, LSA/WDigest/NTLM, account e password… |
| Integrità | `dpkg --verify` / `rpm -Va` | firma Authenticode degli eseguibili dei servizi |
| Privilege escalation | SUID, world-writable, file orfani | servizi con percorso senza virgolette, cartelle del PATH scrivibili, avvio automatico sospetto |
| [Nmap](https://nmap.org/) | porte e servizi esposti (loopback vs rete) | idem (TCP connect, oppure SYN con Npcap + amministratore) |
| [Trivy](https://trivy.dev) | CVE di pacchetti e librerie, segreti, OS fuori supporto | librerie vulnerabili e segreti nel profilo utente |
| Antivirus | [ClamAV](https://www.clamav.net/) + motore interno (hash, euristiche) | Microsoft Defender + ClamAV se presente + motore interno |
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

## Novità della 0.10.0: analisi esterna di una web application

- **`/web URL`** e **`lstk web URL`**: analisi **esterna e non intrusiva** della configurazione di sicurezza di una web app. In **sola lettura** (poche richieste GET/OPTIONS e, su https, una connessione TLS per leggere il certificato): header di sicurezza (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), flag dei cookie (Secure/HttpOnly/SameSite), protocollo e scadenza del certificato TLS, metodi HTTP dichiarati, divulgazione di prodotto/versione, redirect http→https.
- **Nessun attacco**: niente payload, iniezioni, fuzzing o exploit. È una revisione della postura esposta, **non un penetration test**. Il PT attivo va svolto e documentato a parte, su un bersaglio autorizzato (vedi [docs/CONSEGNA.md](docs/CONSEGNA.md)).
- **Integrazione**: con `lstk scan --web URL` i finding esterni entrano nella **stessa tabella** e nello **stesso report** di quelli interni (controlli nativi, Nmap, Trivy, Lynis, antivirus), tutti con **rischio = impatto × probabilità**. Autorizzazione richiesta (`AUTORIZZO` / `--authorized`) se il bersaglio non è loopback.
- **Nota sui rilevatori di scansioni**: se il bersaglio ha una difesa anti-scanner (come la «Guardia» di Tono), può bannare l'IP dell'analizzatore. Mettilo tra i consentiti o disattivala per la durata del test.

## Novità della 0.9.0: grafica "classificata" e `/update`

- **Nuova grafica**: tema oro su nero in stile dossier segreto, con la piramide e l'occhio. All'avvio la piramide si costruisce, l'occhio si apre, si guarda intorno e il titolo si "decifra"; all'uscita l'occhio si chiude. Durante le scansioni lo spinner è un occhio che si muove. L'animazione dura circa 2 secondi, si salta con Ctrl+C e si disattiva con `LSTK_NO_ANIM=1` (parte solo su un terminale vero, mai in pipe o in CI).
- **`/update`** (e `lstk update [--yes] [--no-python]`): aggiorna in un colpo solo ciò che LSTK usa ed è già installato. Mostra i comandi esatti e chiede conferma.
  - Linux: `nmap`, `lynis`, `clamav`, `iproute2` dal gestore pacchetti (`apt-get install --only-upgrade`, `dnf upgrade`, `yum update`, `zypper update`; con `pacman` l'intero sistema, perché gli aggiornamenti parziali non sono supportati). Trivy viene reinstallato solo se più vecchio della versione fissata, sempre con verifica SHA-256.
  - Windows: `winget upgrade` di Nmap e Trivy.
  - Ovunque: database delle vulnerabilità di Trivy, firme antivirus (freshclam / Defender), librerie Python `typer` e `rich` (solo dentro il virtualenv).
  - Non installa nulla di nuovo (per quello resta `/install`); un passo non riuscito non blocca gli altri.
- **Meno comandi**: tolti `/status` (le stesse informazioni sono nel banner), `/checks` (l'elenco dei controlli è in questo README), `/open` (usa `/report html --open`), `/search` (ora è `/findings TESTO`), `/av update` (incluso in `/update`) e gli alias `/antivirus`, `/?`.

## Novità della 0.8.0: antivirus

LSTK ora cerca anche malware, con tutti i motori disponibili insieme:

- **Microsoft Defender** (Windows) e **ClamAV** (Linux, e Windows se installato): firme ufficiali e aggiornate. Defender gira sempre con `-DisableRemediation`, quindi la scansione non tocca nulla.
- **Motore interno di LSTK**, senza dipendenze: file di test EICAR, elenchi di hash SHA-256 di malware forniti da te (es. gli export di [MalwareBazaar](https://bazaar.abuse.ch/)), euristiche (`fattura.pdf.exe`, nomi con carattere RLO, eseguibili in `/tmp` e `/dev/shm`).
- **Quarantena**: i file con malware vengono spostati, solo dopo conferma, in una cartella privata, resi non eseguibili e restano ripristinabili.

```text
/av                      percorsi a rischio (Download, Desktop, Temp, Esecuzione automatica · /tmp, home, cron, /usr/local/bin)
/av full                 tutto il disco (lungo)
/av C:\Users\me\Downloads  uno o più file o cartelle
/av update               aggiorna le firme (freshclam / Defender)
/quarantine              elenco · add FILE · restore ID [DEST] · delete ID
```
```bash
lstk av ~/Scaricati --format json --fail-on-detect     # exit 4 se trova malware
lstk av --full --update --quarantine                    # aggiorna, scansiona tutto, mette in quarantena
lstk quarantine list ; lstk quarantine restore 3f2a --dest /tmp/copia
```
Per provarlo senza rischi usa il [file di test EICAR](https://www.eicar.org/download-anti-malware-testfile/): è innocuo e viene riconosciuto da tutti gli antivirus.

## Novità della 0.7.0

- **Windows**: oltre 40 controlli nativi (registro + cmdlet PowerShell `Get-*`), integrità con firme digitali, privilege escalation, Nmap e Trivy, installazione degli strumenti con **winget**.
- **Nuova grafica**: console con logo, cruscotto del rischio (voto grande, barra della postura, barre per livello, matrice colorata), barra di avanzamento per modulo; rapporto HTML ridisegnato (tema chiaro/scuro, anello del voto, ciambella dei rischi, filtri per livello, schede espandibili). Tutto senza JavaScript.
- **Storico e confronto**: ogni scansione dalla console viene salvata; `/history` mostra il trend della postura, `/diff` elenca rischi nuovi, risolti, peggiorati e migliorati.
- **Correzioni suggerite**: `/fix ID` mostra i comandi per risolvere il problema (Linux o Windows). LSTK **non li esegue**.
- **Export**: oltre a JSON e HTML, **SARIF 2.1.0** (GitHub code scanning, Azure DevOps), **CSV** (Excel, protetto dalla formula injection) e **Markdown**. `lstk export` rigenera un rapporto dallo storico senza ripetere la scansione.
- Ciclo di vita di Windows (fine supporto per versione ed edizione).

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

| Modalità | Controlli nativi | Integrità | Nmap | Trivy | Antivirus | Lynis (Linux) |
|---|---|---|---|---|---|---|
| `quick` | base | no | top-1000 porte TCP | no | no | no |
| `deep` | estesi (Linux: SUID, world-writable, servizi · Windows: privilege escalation, avvio automatico) | sì | tutte le porte TCP | no | no | no |
| **`full`** (default) | estesi | sì | tutte le porte + script `default` + UDP top-50 (se possibile) | sì | percorsi a rischio | sì |

## Comandi della console

```text
Ricognizione  /scan [quick|deep|full] [--target T] [--no-nmap|--no-trivy|--no-malware|--no-integrity|--no-lynis] [--offline]
              /vuln · /integrity · /lynis (solo Linux) · /web URL · /scan --web URL · /profile desktop|server
Antivirus     /av [quick|full|PERCORSO…] [--native] [--hashes FILE] · /quarantine [add|restore|delete]
Dossier       /risk · /findings [issues|all|critical|high|medium|low|unverified|TESTO] · /details ID · /fix ID
Archivio      /report [json|html|sarif|csv|md|all] [--open] · /history · /diff [A] [B] · /verify FILE
Arsenale      /doctor · /install [nmap|trivy|lynis|clamav|iproute2|all] · /update · /clear · /help · /exit
```

Modalità non interattiva (risultato su stdout, avanzamento su stderr):

```bash
lstk scan --profile server --mode full --format table           # tabella di rischio
lstk scan --mode full --save --history --fail-on high > out.json # JSON + rapporti + storico; exit 3 se rischio >= high
lstk scan --format sarif > lstk.sarif                            # per GitHub code scanning
lstk scan --mode full --web https://tono.local --authorized      # interno + esterno nello stesso report
lstk web https://tono.local --format json > web.json             # solo analisi esterna non intrusiva
lstk history ; lstk diff ; lstk export lstk-reports/history/scan-XXXX.json --format html
lstk install trivy --yes ; lstk update --yes ; lstk doctor ; lstk verify lstk-reports/audit-XXXX.json
```
Exit code: `0` ok · `1` errore · `2` argomenti/autorizzazione non validi · `3` soglia `--fail-on` superata · `4` malware trovato (`lstk av --fail-on-detect`).

## Requisiti

- **Python ≥ 3.10**; dipendenze Python: `typer`, `rich`.
- **Linux**: testato su Ubuntu 22.04/24.04 (Debian, Kali, Fedora, Rocky previsti). Pacchetti installati da `install.sh` o `/install` su richiesta: `nmap`, `lynis`, `iproute2`, `clamav`, Trivy (release ufficiale con SHA-256 fissato nel codice).
- **Windows**: Windows 10/11 con PowerShell 5.1 (incluso). Nmap e Trivy opzionali, installabili con `winget` da `install.ps1` o `/install`. Per scansioni SYN/UDP serve [Npcap](https://npcap.com/) (incluso nell'installer di Nmap) e l'amministratore.
- **Privilegi**: root (Linux) o amministratore (Windows) per l'audit completo. Senza funziona, ma la valutazione è **parziale** (voto massimo B).
- **Analisi web (`/web`, `--web`)**: solo `http`/`https`; richieste in sola lettura verso l'URL indicato, nessuna dipendenza esterna (usa la libreria standard di Python). Su rete locale con certificato interno usa `--web-insecure` per leggerlo comunque, documentandolo.
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
| Antivirus | `LSTK_MALWARE_HASHES` (file separati da `:` o `;`), `LSTK_SIGNATURES_DIR`, `LSTK_AV_MAX_FILES`, `LSTK_AV_MAX_SIZE`, `LSTK_AV_TIMEOUT` | elenchi di hash: una riga per SHA-256, nome facoltativo; cartella firme predefinita `~/.local/share/lstk/signatures` o `%LOCALAPPDATA%\lstk\signatures` |
| Quarantena | `LSTK_QUARANTINE_DIR`, `LSTK_QUARANTINE_MAX` | predefinita `~/.local/share/lstk/quarantine` (root: `/var/lib/lstk/quarantine`) o `%LOCALAPPDATA%\lstk\quarantine` |
| Timeout | `LSTK_LYNIS_TIMEOUT`, `LSTK_INTEGRITY_TIMEOUT` | secondi |

## Prova in laboratorio

**Linux** (VM usa-e-getta): `sudo apt install -y vsftpd` (FTP in chiaro → Nmap), un finto token in `/root/demo.env` (→ Trivy), un byte aggiunto a `/usr/bin/ischroot` dopo averne fatto una copia (→ integrità). Poi `/scan`, `/findings high`, `/fix INT-001`, `/report all`, `/diff`.

**Windows** (VM di test, PowerShell come amministratore): `Set-NetFirewallProfile -Profile Public -Enabled False` (→ WFW-001), `Enable-LocalUser Guest` (→ WACC-001), `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f` (→ WLSA-001). Rilancia `/scan`, guarda `/diff`, poi ripristina con i comandi di `/fix`.

## Sicurezza dello strumento

- `/scan` è **in sola lettura** su entrambi i sistemi (su Windows solo letture del registro e cmdlet `Get-*`, verificato dai test). Modificano il sistema solo l'installer, l'aggiornamento (`/update`) e la quarantena, sempre dopo conferma esplicita. La quarantena rifiuta i link simbolici, cancella l'originale solo dopo aver verificato la copia e il ripristino non sovrascrive mai.
- Nessuna shell; binari risolti solo in directory di sistema (anti PATH-hijacking); ambiente minimo; timeout con kill dell'albero di processi. Gli script PowerShell passano come `-EncodedCommand` (nessun problema di quoting o iniezione) e compaiono nel rapporto con un'etichetta leggibile.
- Bersagli non locali solo con autorizzazione dichiarata; input validato.
- Rapporti con SHA-256 + HMAC opzionale (`lstk verify`), elenco dei comandi eseguiti, limiti dichiarati. HTML con CSP `default-src 'none'` e nessuno script; CSV protetto dalla formula injection.

Dettagli in [SECURITY.md](SECURITY.md). I rapporti contengono dati sensibili: trattarli come riservati.

## Test

```bash
pip install -e ".[test]" && pytest -q
```
178 test, nessun comando reale (runner, registro e PowerShell simulati). I controlli Windows sono testati anche su Linux; i test specifici di una piattaforma vengono saltati sull'altra.

## Struttura

```
run.sh / install.sh                avvio e installazione su Linux
run.bat / run.ps1 / install.ps1    avvio e installazione su Windows
lstk/audit.py      controlli nativi Linux        lstk/winaudit.py   controlli nativi Windows
lstk/nmapscan.py   Nmap                          lstk/trivy.py      CVE e segreti
lstk/integrity.py  dpkg/rpm verify               lstk/lynis.py      Lynis (Linux)
lstk/scan.py       orchestratore                 lstk/risk.py       probabilità × impatto, voto
lstk/report.py     JSON/HTML/SARIF/CSV/MD        lstk/history.py    storico e confronto
lstk/malware.py    antivirus (Defender, ClamAV, motore interno) lstk/quarantine.py quarantena
lstk/fixes.py      comandi di correzione suggeriti
lstk/installer.py  installazione guidata (apt/dnf/zypper/pacman, winget)
lstk/runner.py     esecuzione sicura dei comandi lstk/osinfo.py     piattaforma e privilegi
```

## Limiti

- Valutazione best-effort: dipende da privilegi, sistema e strumenti installati.
- Una CVE presente non implica che sia sfruttabile. Nmap non correla i servizi alle CVE. Solo IPv4.
- Nmap eseguito sulla macchina stessa vede le porte in ascolto anche se il firewall le filtra verso l'esterno: per l'esposizione reale scansionare da un altro host.
- Linux: l'integrità non rileva file *aggiunti* né rootkit. Windows: si verificano le firme degli eseguibili dei servizi, non tutti i file di sistema (`sfc /scannow`); Trivy non analizza i componenti del sistema operativo (coperti da Windows Update).
- Antivirus: senza Defender o ClamAV il motore interno riconosce solo EICAR, gli hash che gli fornisci e poche euristiche: **non** sostituisce un antivirus con firme. Nessuna protezione in tempo reale: LSTK scansiona quando glielo chiedi.
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
