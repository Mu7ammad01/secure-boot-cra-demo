# Lancement de la démo sous Windows (PowerShell). Usage : .\run_demo.ps1 [-Pause]
param([switch]$Pause)
$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Write-Host "Python introuvable. Installer Python 3.9+ depuis python.org" -ForegroundColor Red; exit 1 }
& $py.Source -c "import cryptography" 2>$null
if ($LASTEXITCODE -ne 0) { & $py.Source -m pip install --user cryptography }
$args2 = @("$PSScriptRoot\demo_chain.py")
if ($Pause) { $args2 += "--pause" }
& $py.Source @args2
