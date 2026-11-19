# Changelog

## 0.11.0
### Nuovo
- **Analisi statica del codice sorgente** (`lstk/sourcescan.py`): comando `lstk source` / `/source` / `scan --source`. Due fonti: euristiche interne (segreti nel codice, eval/exec, comandi shell, SQL concatenato, XSS nel DOM, TLS verify off) e Semgrep se installato. Sola lettura, il codice non viene eseguito; salta node_modules/.git/venv/dist.
- **Configurazione e permessi del database** (`lstk/dbcheck.py`): comando `lstk dbcheck` / `/dbcheck` / `scan --db-config`. Legge postgresql.conf e pg_hba.conf (listen_addresses, trust/password/regole 0.0.0.0/0, ssl off, password_encryption md5, permessi dei file). Nessuna connessione né credenziali.
- Entrambi integrati nello stesso Assessment/report degli altri moduli, con rischio = impatto x probabilita'.
- **docs/PENTEST.md**: report della fase di penetration testing (manuale). **docs/screenshot-report.svg**: screenshot del report.
### Correzioni
- f-string con backslash incompatibile con Python 3.10 (Raspberry/CI): corretta.


## 0.10.0
### Nuovo
- **Analisi esterna non intrusiva di una web application** (`lstk/webscan.py`): comando `/web URL` e `lstk web URL`, oppure `lstk scan --web URL` per includerla nello stesso assessment.
  - Solo lettura (GET/OPTIONS + lettura del certificato TLS su https): header di sicurezza (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), flag dei cookie (Secure/HttpOnly/SameSite), protocollo e scadenza del certificato, metodi HTTP dichiarati, divulgazione di versione (Server/X-Powered-By), redirect http->https.
  - Finding con `source="web"` e id `WEB-*`, valutati dal risk engine esistente (rischio = impatto x probabilita') e uniti nella stessa tabella/report dei finding interni.
  - Nessun payload d'attacco, nessuna iniezione/fuzzing/exploit: e' una revisione della postura esposta, non un penetration test. Autorizzazione richiesta (`AUTORIZZO`/`--authorized`) per bersagli non loopback; `--web-insecure` per certificati interni di rete locale.
- **Report grafico anche per `/web`**: al termine di `/web` LSTK propone di aprire il report HTML nel browser; `lstk web URL --open` lo genera e apre in modo non interattivo (`cli.web_assessment` costruisce un Assessment minimo dai finding web).
- **docs/CONSEGNA.md**: guida per la consegna (prerequisiti, URL, accessi a macchina e database, permessi, comandi) e template per documentare la fase di penetration testing, svolta a parte.
### Note
- La fase di penetration testing attiva non e' automatizzata per scelta: LSTK resta uno strumento difensivo in sola lettura.


## 0.9.0
### Nuovo
- **Grafica "classificata"** (`lstk/theme.py`): tema oro su nero, piramide con l'occhio nel banner, timbri TOP SECRET / EYES ONLY, gruppi della guida rinominati (Ricognizione, Controspionaggio, Dossier, Archivio, Arsenale), prompt `▲ lstk@host ›`.
- **Animazioni**: all'avvio la piramide si costruisce dal basso, l'occhio si apre, brilla, si guarda intorno e il titolo si decifra; all'uscita l'occhio si chiude; spinner a forma di occhio durante le scansioni. Solo su terminale, saltabile con Ctrl+C, disattivabile con `LSTK_NO_ANIM=1`.
- **`/update`** e `lstk update [--yes] [--no-python]`: aggiorna gli strumenti già installati (gestore pacchetti o winget), Trivy alla versione fissata con verifica SHA-256 se più vecchio, il database di Trivy, le firme antivirus e le librerie Python nel virtualenv. Non installa nulla di nuovo; ogni passo è indipendente.
### Rimossi
- `/status`, `/checks`, `/open` (usare `/report html --open`), `/search` (ora `/findings TESTO`), `/av update` (incluso in `/update`), alias `/antivirus` e `/?`.

## 0.8.0
### Nuovo
- **Antivirus** (`lstk/malware.py`): ricerca di malware con più motori, risultati uniti per file come finding del risk assessment.
  - **Microsoft Defender** (`MpCmdRun.exe`, sempre con `-DisableRemediation`: la scansione non sposta né cancella nulla) e **ClamAV** (`clamscan`, senza seguire i link simbolici; avviso se le firme hanno più di 7 giorni).
  - **Motore interno** sempre disponibile: file di test EICAR, elenchi di hash SHA-256 dell'utente (`--hashes`, `LSTK_MALWARE_HASHES` o la cartella delle firme; compatibili con gli export di MalwareBazaar), euristiche a bassa confidenza (doppia estensione, carattere RLO nel nome, eseguibili ELF in `/tmp`, `/var/tmp`, `/dev/shm`).
  - Finding: `AV-DET` (malware, critico), `AV-TEST` (EICAR), `AV-HEU` (sospetto), `AV-000` (nessun motore con firme), `AV-CLAM-DB` (firme vecchie o assenti).
- **Quarantena** (`lstk/quarantine.py`): il file viene spostato in una cartella privata, offuscato (non eseguibile e non più rilevato), con metadati e SHA-256; ripristino senza mai sovrascrivere, eliminazione definitiva. Solo su conferma esplicita.
- Console: `/av [quick|full|PERCORSO…] [--native] [--hashes FILE]`, `/av update`, `/quarantine [add|restore|delete]`. CLI: `lstk av` (`--full`, `--update`, `--quarantine`, `--format json`, `--fail-on-detect` → exit 4) e `lstk quarantine`.
- `/scan full` include l'antivirus sui percorsi a rischio (`--no-malware` per escluderlo); `/install clamav` su Linux; Defender in `/doctor`; `/fix` per i finding antivirus.

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
