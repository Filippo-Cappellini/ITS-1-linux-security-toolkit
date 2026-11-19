# Consegna — Vulnerability assessment di una web application

Questo documento spiega come usare LSTK per analizzare una web application **dall'esterno** e **dall'interno** e
produrre un unico report con il rischio calcolato come **rischio = impatto × probabilità**, e come documentare
la fase di **penetration testing**, che va svolta a parte.

> L'esempio usa la web app **Tono** (self-hosted su un Raspberry Pi, in Docker). Sostituisci URL, host e credenziali con i tuoi.

## Che cosa copre LSTK e che cosa fai a mano

| Richiesta della consegna | Come si ottiene |
|---|---|
| Analisi **esterna** dell'URL (configurazione di sicurezza) | `lstk web URL` oppure `lstk scan --web URL` — **non intrusivo, sola lettura** |
| Analisi **interna** della macchina (processi, servizi, configurazione, permessi) | `lstk scan` eseguito **sulla macchina** (localmente o via SSH) |
| Configurazione e **permessi del database** | controlli nativi + ispezione manuale (sezione sotto) |
| **Integrazione di ≥ 2 fonti in un'unica tabella** | `lstk scan --web URL`: controlli nativi + Nmap + Trivy + Lynis + analisi web nello stesso report |
| **Rischio = impatto × probabilità** per ogni problema, con evidenze | nativo nel risk engine (matrice 5×5, voto A–F) |
| **Penetration testing** con verifiche, esiti ed evidenze | **manuale**, su bersaglio autorizzato → compila il template in fondo |

LSTK è uno strumento **difensivo in sola lettura**: non invia payload d'attacco e non esegue exploit. La fase di PT
attiva non è automatizzata di proposito.

## Prerequisiti (per un collega tecnico)

- **Python ≥ 3.10**. Dipendenze Python: `typer`, `rich` (installate da `install.sh` / `install.ps1`).
- L'**analisi esterna** (`/web`) non richiede strumenti di terze parti (usa la libreria standard).
- L'**analisi interna** completa usa, se presenti, strumenti di terze parti installabili con `lstk install` o `install.sh`:
  `nmap` (porte/servizi), `trivy` (CVE di pacchetti e librerie, segreti), `lynis` (hardening, solo Linux), `clamav` (antivirus).
  Così si soddisfa il requisito di **integrare due o più fonti**.
- **Servizi attivi**: la web app e il suo database devono essere in esecuzione e raggiungibili dall'host che esegue LSTK.
- **Permessi**: l'analisi interna va eseguita come **root/amministratore** per una copertura completa (senza, la valutazione è parziale, voto massimo B).

## 1. Analisi esterna (dall'URL)

```bash
# Solo analisi esterna, output a schermo
lstk web https://tono.local

# Bersaglio non locale: serve dichiarare l'autorizzazione
lstk web https://tono.esempio.it --authorized --format json > web.json

# Certificato interno (CA privata di rete locale): leggilo comunque e documentalo
lstk web https://tono.local --web-insecure

# Report grafico HTML aperto nel browser (chiaro anche per i non tecnici)
lstk web https://tono.local --open
```

Controlli svolti (sola lettura): header di sicurezza, flag dei cookie, protocollo e scadenza del certificato TLS,
metodi HTTP dichiarati, divulgazione di prodotto/versione, redirect http→https.

> **Attenzione alla difesa anti-scanner.** Tono ha la «Guardia» che banna gli IP che sembrano scanner. Prima del test
> metti l'IP dell'analizzatore tra i consentiti (`GUARDIA_CONSENTITI`) o disattivala (`GUARDIA=spenta` o dal
> `/gestionale/guardia`), e **riattivala dopo**. Il fatto che la Guardia blocchi le scansioni è di per sé un'evidenza da riportare.

## 2. Analisi interna + esterna in un unico report

Esegui questo **sulla macchina** della web app (localmente, oppure dopo esserti collegato in SSH con credenziali autorizzate):

```bash
# Linux (Raspberry): sulla macchina, con sudo
ssh utente@tono.local                 # accesso con credenziali autorizzate
sudo lstk scan --mode full \
     --web https://127.0.0.1 --web-insecure --authorized \
     --save --history --format table

# Report completo (tabella unica + file)
sudo lstk scan --mode full --web https://127.0.0.1 --web-insecure --authorized --save
#   -> genera lstk-reports/audit-*.json e audit-*.html (con hash SHA-256)
```

Il report unisce in **una sola tabella** i finding interni (`source` native/nmap/trivy/lynis) e quelli esterni
(`source` web), ciascuno con ID, elemento interessato, evidenza, impatto, probabilità e rischio.

## 3. Configurazione e permessi del database (manuale)

I controlli nativi segnalano servizi/porte di database esposti; per la parte specifica di configurazione e permessi,
documenta a mano (esempio PostgreSQL di Tono):

```bash
# Ruolo dell'app: deve essere a privilegi minimi (solo DML), non proprietario, non superuser
psql -U tonecraft -c "\du"
psql -U tonecraft -c "SELECT rolname, rolsuper, rolcreatedb, rolcanlogin FROM pg_roles;"
# Permessi sulle tabelle sensibili (solo scores accetta insert pubblici)
psql -U tonecraft -c "\dp"
# Porta legata solo a localhost (non esposta sulla rete)
ss -ltnp | grep 5432
```

## 4. Penetration testing (manuale) — template da compilare

Da svolgere **solo** su un bersaglio di cui sei titolare o per cui hai autorizzazione scritta, idealmente su una copia
di Tono in laboratorio. Per ogni verifica compila:

| Elemento | Verifica svolta | Esito | Evidenza | Impatto (1-5) | Probabilità (1-5) | Rischio |
|---|---|---|---|---|---|---|
| es. form di login | tentativo di SQL injection sui parametri | nessuna injection: query parametrizzate | risposta/err., screenshot | | | |
| es. header CSP | tentativo di XSS riflesso | bloccato dalla CSP | payload e risposta | | | |
| es. «Guardia» | scansione ripetuta | IP bannato dopo N richieste | voce in `audit_log`, ban | | | |

Riporta la stessa formula **rischio = impatto × probabilità** usata da LSTK, così la tabella del PT è coerente con il report automatico.

## 5. Riproducibilità

Dopo `git clone`, segui il [README](../README.md) (`./run.sh` o `install.ps1`), poi i comandi qui sopra. Tutti i file di
report sono in `lstk-reports/` con hash SHA-256 (e HMAC se imposti `LSTK_SIGNING_KEY`); `lstk verify FILE` ne controlla l'integrità.

## Riferimenti

- OWASP Secure Headers Project — <https://owasp.org/www-project-secure-headers/>
- Mozilla SSL Configuration Generator — <https://ssl-config.mozilla.org/>
- OWASP Web Security Testing Guide — <https://owasp.org/www-project-web-security-testing-guide/>
- MDN HTTP Headers — <https://developer.mozilla.org/docs/Web/HTTP/Headers>
