<#
  Prepara LSTK su Windows dopo un "git clone": ambiente virtuale .venv, dipendenze Python e, su richiesta, Nmap e Trivy con winget.
  Uso: .\install.ps1 [-Yes] [-SkipTools]
#>
param([switch]$Yes, [switch]$SkipTools)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
function Say($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }

# 1) Python >= 3.10 (launcher "py" o python.exe)
$py = $null
foreach ($c in @(@('py', '-3'), @('python'))) {
  try {
    & $c[0] $c[1..9] -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $py = $c; break }
  } catch { }
}
if (-not $py) {
  Warn "Serve Python 3.10 o superiore. Installalo con:  winget install --id Python.Python.3.12 -e   (poi riapri il terminale)"
  exit 1
}
Say "Python trovato: $(& $py[0] $py[1..9] -V)"

# 2) Ambiente virtuale e pacchetto
if (-not (Test-Path '.venv\Scripts\python.exe')) { Say "Creo l'ambiente virtuale .venv"; & $py[0] $py[1..9] -m venv .venv }
Say "Installo LSTK e le dipendenze Python (typer, rich)"
& .venv\Scripts\python.exe -m pip install --quiet --upgrade pip
& .venv\Scripts\python.exe -m pip install --quiet -e .
if ($LASTEXITCODE -ne 0) { Warn "Installazione delle dipendenze non riuscita"; exit 1 }

# 3) Strumenti opzionali (Nmap, Trivy) con winget
if (-not $SkipTools) {
  $env:PYTHONIOENCODING = 'utf-8'
  if ($Yes) { & .venv\Scripts\lstk.exe install --yes } else {
    $r = Read-Host "Installare ora Nmap e Trivy con winget, se mancano (modifica il sistema)? [s/N]"
    if ($r -match '^[sSyY]$') { & .venv\Scripts\lstk.exe install --yes } else { Warn "Saltato: potrai farlo da LSTK con /install" }
  }
}
Say "Verifica finale"
& .venv\Scripts\lstk.exe doctor
Say "Pronto. Avvia con:  .\run.bat   (oppure .\run.ps1)"
