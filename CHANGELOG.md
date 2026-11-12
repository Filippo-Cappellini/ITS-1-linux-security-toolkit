# Changelog

## 0.7.0
### Nuovo
- **Supporto Windows 10/11** (`lstk/winaudit.py`): oltre 40 controlli nativi in sola lettura (registro e cmdlet PowerShell `Get-*`): Windows Update e aggiornamenti in sospeso, fine supporto per build/edizione, Defender (tempo reale, firme, Tamper Protection, esclusioni rischiose, PUA, ASR) e antivirus di terze parti, firewall per profilo, UAC, Guest/Administrator, account senza password, membri Administrators, policy password e blocco, WDigest, protezione LSA, NTLMv1/LM, Credential Guard/VBS, BitLocker, Secure Boot, SMBv1 e firma SMB, condivisioni, RDP/NLA, WinRM, OpenSSH, servizi legacy, LLMNR, AutoRun, SmartScreen, PowerShell 2.0 e Script Block Logging, porte in ascolto con processo.
- Windows, modalità deep/full: servizi con percorso senza virgolette, cartelle del PATH di sistema scrivibili, avvio automatico sospetto, **firma Authenticode** degli eseguibili dei servizi (modulo integrità).
- Nmap su Windows (TCP connect, SYN/UDP con Npcap e amministratore), regole per servizi tipici di Windows (RPC dinamico, WinRM, WSDAPI…); Trivy su Windows (`trivy fs` sul profilo utente); installazione di Nmap/Trivy con **winget**; avvio con `run.bat`/`run.ps1`/`install.ps1`.
- **Nuova grafica**: console con logo a gradiente, cruscotto del rischio, avanzamento per modulo, tabelle con badge colorati; rapporto HTML ridisegnato (tema chiaro/scuro, anello del voto, ciambella, matrice, "da fare per primo", filtri per livello senza JavaScript).
- **Storico e confronto**: `/history` (trend della postura), `/diff` (nuovi, risolti, peggiorati, migliorati); `lstk history`, `lstk diff`, `scan --history`.
- **Correzioni suggerite** per controllo (`/fix ID`, anche nel rapporto HTML), mai eseguite.
- **Export SARIF 2.1.0, CSV, Markdown**; `lstk export` rigenera un rapporto dal JSON; `scan --format sarif|csv|md`.
- `/search`, `/open`, `/report --open`.
### Modifiche
- Il codice è ora nella cartella principale del repository (prima in `linux-security-toolkit-v0.6.0/`).
- Schema del rapporto 1.1: campi `host.platform` e `findings[].fix`; modulo con stato `n/a` (non applicabile, non rende parziale la valutazione).
- Runner multipiattaforma: PATH di sistema per Windows, ambiente minimo, kill dell'albero di processi con `taskkill`, PowerShell via `-EncodedCommand`.

## 0.6.0
### Nuovo
- **Avvio con un solo comando dopo `git clone`**: `./run.sh` (esegue `install.sh` al primo avvio: pacchetti di sistema, `.venv`, dipendenze Python, Trivy; chiede conferma prima di installare).
- **Installazione guidata degli strumenti mancanti** (nmap, lynis, trivy, iproute2): `/scan`, `/vuln`, `/lynis` propongono l'installazione mostrando i comandi esatti; nuovi `/install`, `/doctor`, `lstk install`, `lstk doctor`, `lstk scan --install-missing`. Trivy: release a versione fissata con **SHA-256 fissato nel codice** (x86_64 e ARM64), estrazione del solo membro `trivy`, solo HTTPS.
- Tabella di rischio con colonne **P, I, P×I** esplicite; `lstk scan --format table`; colonne P/I anche nel rapporto HTML.
- Le installazioni eseguite compaiono nel rapporto (sezione "installs").
- README completo: prerequisiti, servizi, rete, dati per la prova completa, sviluppi futuri, riferimenti.
### Correzioni
- `lstk install <nome sconosciuto>` ignorava il nome e rispondeva "tutto già installato": ora errore (exit 2).

## 0.5.0
### Nuovo
- **Trivy** (`trivy rootfs /`): CVE dei pacchetti OS e delle librerie raggruppate per pacchetto, **segreti nei file** (contenuto mai riportato), OS fuori supporto. Flag privacy `--offline-scan`/`--skip-version-check`; `--offline` per usare solo la cache. Senza database: ripiego sui soli segreti e vulnerabilità dichiarate **non valutate** (valutazione parziale).
- **Integrità dei file installati** (`dpkg --verify` / `rpm -Va`): rileva binari e librerie diversi dal pacchetto e file critici mancanti; annota i link simbolici (falsi positivi tipici).
- Nuovi controlli deep: file world-writable (FS-005) e file senza proprietario (FS-006).
- Comandi `/vuln` e `/integrity`; flag `--no-trivy`, `--no-integrity`, `--offline` (anche in `lstk scan`).
- Modalità aggiornate: `deep` include l'integrità, `full` include anche Trivy.

## 0.4.0
### Nuovo
- `/scan` ora esegue un **risk assessment completo**: controlli nativi + **Nmap** + **Lynis**, con modalità `quick`, `deep`, `full` (default).
- **Risk engine**: probabilità × impatto, matrice 5×5, punteggio di postura, voto A–F, copertura e lacune "non verificato"; voto limitato se la valutazione è parziale.
- **Importazione del report Lynis** nel modello findings (warning, suggerimenti, pacchetti vulnerabili, hardening index).
- **Nmap**: validazione bersagli, autorizzazione esplicita per bersagli non locali, distinzione loopback/rete, regole di rischio per servizi noti.
- Nuovi controlli: password vuote, sudo NOPASSWD, sshd effettivo (`sshd -T`) e cifrari deboli, permessi file critici, SUID/world-writable, sysctl, MAC, logging/auditd, NTP, cifratura disco, aggiornamenti in sospeso (sola lettura), servizi legacy.
- Rapporti con **integrità** (SHA-256, HMAC opzionale), permessi 0600, `lstk verify`, elenco dei comandi eseguiti, limiti dichiarati.
- CLI non interattiva con `--fail-on` (exit code 3) per pipeline CI e `--save`.
- Comandi `/risk`, `/verify`; `/findings` con filtri.
### Sicurezza
- Runner con PATH sicuro, ambiente minimo, nessuna shell, timeout con kill del gruppo.
- Sanificazione di caratteri di controllo e markup in tutti i testi esterni; HTML con CSP.
- `remediation`: gestione symlink, proprietà preservata, fsync della directory.
### Modifiche di comportamento
- `PermitRootLogin prohibit-password|without-password` non è più segnalato come warning (consente solo chiavi).
- Il parser sshd_config usa "prima occorrenza vince", espande `Include` e ferma al primo `Match`.
- `NET-001`/`SRV-001` sono `info` (prima `pass`).
- Rimosso lo stato globale `STATE["findings"]` a favore di `STATE["assessment"]`.

## 0.3.0
Console interattiva, profili, esportazione JSON/HTML, primitive di remediation.
