# Cai VNPTNAN_GATE len may dev Windows. Chay bang quyen admin (installer tu xin UAC).
#   powershell -NoProfile -ExecutionPolicy Bypass -File installer\install.ps1 [-WhatIf]
# Viec lam: copy bo cong cu vao %ProgramData%\VNPTNAN_GATE\current (chi admin ghi duoc), dang ky hook pre-commit,
# pre-push, commit-msg o git config cap he thong bang co che hook.<ten>.event/command (Git for Windows >= 2.54, cung
# co che VNPTNAN_HARNESS dang dung cho hook.vnptnan-guard, nhung TEN KHAC nen hai ben khong de len nhau),
# them cli vao PATH may, tao thu muc log. Khong dong vao bat ky cau hinh nao cua VNPTNAN_HARNESS.
# Keep this file ASCII-only (Windows PowerShell 5.1).
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$InstallRoot = (Join-Path $env:ProgramData 'VNPTNAN_GATE'),
  [string]$Mode = 'enforce'   # enforce | audit (thi diem 2 tuan dau: audit)
)
$ErrorActionPreference = 'Stop'
$source = Split-Path -Parent $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $WhatIfPreference) {
  $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InstallRoot', $InstallRoot, '-Mode', $Mode)
  Start-Process powershell -Verb RunAs -ArgumentList $args -Wait
  exit $LASTEXITCODE
}

function Find-Git {
  foreach ($c in @((Join-Path $env:ProgramFiles 'Git\cmd\git.exe'), (Join-Path $env:LOCALAPPDATA 'Programs\Git\cmd\git.exe'))) {
    if (Test-Path $c) { return $c }
  }
  $g = Get-Command git -ErrorAction SilentlyContinue
  if ($g) { return $g.Source }
  throw 'Can Git for Windows (>= 2.54).'
}
$git = Find-Git
$ver = (& $git --version) -replace '[^0-9.]', '' -split '\.'
if ([int]$ver[0] -lt 2 -or ([int]$ver[0] -eq 2 -and [int]$ver[1] -lt 54)) {
  Write-Warning "Git $($ver -join '.') chua ho tro hook theo config (can >= 2.54). Se chi copy bo cong cu; moi repo chay: vnptnan-gate install-hooks"
  $configHooks = $false
} else { $configHooks = $true }

$current = Join-Path $InstallRoot 'current'
if ($PSCmdlet.ShouldProcess($current, 'Copy bo cong cu')) {
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
  if (Test-Path $current) { Remove-Item -Recurse -Force $current }
  Copy-Item -Recurse -Force $source $current
  Remove-Item -Recurse -Force (Join-Path $current '.git') -ErrorAction SilentlyContinue
  # Admin va SYSTEM ghi, nguoi dung chi doc va chay: AI khong sua duoc rule tren may dev.
  $acl = Get-Acl $InstallRoot
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($id in 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM') {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Users', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  Set-Acl $InstallRoot $acl
  # Che do: ghi vao gate.conf cua ban cai (dang ky thi diem audit)
  $conf = Join-Path $current 'gate.conf'
  (Get-Content $conf) -replace '^MODE=.*', "MODE=$Mode" | Set-Content -Encoding ascii $conf
}

$bashPath = ($current -replace '\\', '/')
if ($configHooks) {
  foreach ($h in @(@{ Name = 'vnptnan-gate-commit'; Event = 'pre-commit'; File = 'pre-commit' },
                   @{ Name = 'vnptnan-gate-push'; Event = 'pre-push'; File = 'pre-push' },
                   @{ Name = 'vnptnan-gate-msg'; Event = 'commit-msg'; File = 'commit-msg' })) {
    if ($PSCmdlet.ShouldProcess("git config --system hook.$($h.Name)", 'Dang ky hook')) {
      & $git config --system --replace-all "hook.$($h.Name).event" $h.Event
      & $git config --system --replace-all "hook.$($h.Name).command" "sh '$bashPath/hooks/$($h.File)'"
    }
  }
}

if ($PSCmdlet.ShouldProcess('PATH (Machine)', 'Them cli')) {
  $cli = Join-Path $current 'cli'
  $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if ($path -notlike "*$cli*") { [Environment]::SetEnvironmentVariable('Path', "$path;$cli", 'Machine') }
}

if ($PSCmdlet.ShouldProcess((Join-Path $env:ProgramData 'VNPTNAN_GATE\logs'), 'Tao thu muc log dung chung')) {
  New-Item -ItemType Directory -Force -Path (Join-Path $InstallRoot 'logs') | Out-Null
}

Write-Host "Da cai VNPTNAN_GATE $(Get-Content (Join-Path $current 'VERSION')) tai $current (MODE=$Mode)."
Write-Host 'Mo terminal moi va chay: vnptnan-gate doctor'
