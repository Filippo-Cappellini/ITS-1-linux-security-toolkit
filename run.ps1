<#
  Avvia LSTK su Windows. Se manca l'ambiente esegue prima install.ps1.
  Senza privilegi di amministratore propone di riaprirsi elevato (finestra UAC) per l'audit completo.
  Uso:  .\run.ps1            console interattiva
        .\run.ps1 scan --mode quick --format table
        .\run.ps1 -NoElevate  (resta utente normale: copertura ridotta)
#>
param([switch]$NoElevate, [Parameter(ValueFromRemainingArguments = $true)] [string[]]$LstkArgs)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$lstk = Join-Path $PSScriptRoot '.venv\Scripts\lstk.exe'
if (-not (Test-Path -LiteralPath $lstk)) { & (Join-Path $PSScriptRoot 'install.ps1') }
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $NoElevate) {
  Write-Host "LSTK funziona anche senza privilegi, ma alcuni controlli (esclusioni Defender, SMB, BitLocker) richiedono l'amministratore." -ForegroundColor Yellow
  $r = Read-Host "Riaprire come amministratore? [s/N]"
  if ($r -match '^[sSyY]$') {
    $argList = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-NoElevate') + ($LstkArgs | ForEach-Object { "`"$_`"" })
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -WorkingDirectory $PSScriptRoot
    exit 0
  }
}
& $lstk @LstkArgs
exit $LASTEXITCODE
