# PowerShell equivalent of init.sh
# Usage: powershell -ExecutionPolicy Bypass -File scripts\setup\init.ps1

Set-Location -Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)))
Write-Host "=== Project setup ==="

# 1. Root .env
if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "  created .env (edit it before deploying)"
}

# 2. Per-module .env files
foreach ($f in @("pi/.env", "dashboard/.env", "attacker/.env")) {
  if (-not (Test-Path $f)) {
    Copy-Item "$f.example" $f
    Write-Host "  created $f"
  }
}

# 3. Python venv for model-lab + tests
if (-not (Test-Path .venv)) {
  python -m venv .venv
  Write-Host "  created .venv"
}
& .\.venv\Scripts\Activate.ps1
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r dashboard/api/requirements.txt
python -m pip install --quiet pytest
Write-Host "  python deps installed"

# Setup does not generate or select research data. Use an identified external
# dataset or independently recorded controlled-campaign labels.

Write-Host ""
Write-Host "=== Setup complete ==="
Write-Host "Next:"
Write-Host "  - Edit .env files (root, pi/, dashboard/, attacker/)"
Write-Host "  - No dataset was generated; synthetic fixtures are development-only."
Write-Host "  - PC1: cd dashboard; docker compose up -d"
Write-Host "  - Pi:  ssh to Pi, cd pi/ && ./scripts/configure.sh && ./scripts/start.sh"
Write-Host "  - PC2: cd attacker && ./run-scenario.sh --target <PI_IP> --scenario ssh-bruteforce"
