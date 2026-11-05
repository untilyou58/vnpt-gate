# Go VNPTNAN_GATE khoi may dev. Chay bang quyen admin. Khong dong vao cau hinh cua VNPTNAN_HARNESS.
# Keep this file ASCII-only (Windows PowerShell 5.1).
param([string]$InstallRoot = (Join-Path $env:ProgramData 'VNPTNAN_GATE'))
$ErrorActionPreference = 'Continue'
$git = (Get-Command git -ErrorAction SilentlyContinue).Source
if ($git) {
  foreach ($n in 'vnptnan-gate-commit', 'vnptnan-gate-push', 'vnptnan-gate-msg') {
    & $git config --system --remove-section "hook.$n" 2>$null
  }
}
$cli = Join-Path $InstallRoot 'current\cli'
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::SetEnvironmentVariable('Path', (($path -split ';' | Where-Object { $_ -and $_ -ne $cli }) -join ';'), 'Machine')
if (Test-Path (Join-Path $InstallRoot 'current')) { Remove-Item -Recurse -Force (Join-Path $InstallRoot 'current') }
Write-Host 'Da go VNPTNAN_GATE. Log cu van con trong %LOCALAPPDATA%\VNPTNAN_GATE de doi chieu.'
