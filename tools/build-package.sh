#!/usr/bin/env bash
# Đóng gói VNPTNAN_GATE thành MỘT file cài đặt cho máy dev Windows, không cần giải nén, không cần mạng.
#   bash tools/build-package.sh            -> dist/VNPTNAN_GATE-<ver>-setup.cmd       (chế độ chặn)
#                                             dist/VNPTNAN_GATE-<ver>-setup-audit.cmd (chế độ ghi nhận, cho thí điểm)
#                                             dist/VNPTNAN_GATE-<ver>.zip             (cho máy chủ GitLab / cài tay)
#                                             dist/SHA256SUMS.txt
# File .cmd = vài dòng batch + gói zip mã hoá base64 nối ở cuối. Nhấp đúp: xin quyền admin (UAC), tự giải nén
# vào thư mục tạm, chạy installer\install.ps1, xoá thư mục tạm. Chế độ lấy theo tên file (có "audit" thì audit)
# hoặc tham số: setup.cmd /audit | /enforce | /whatif
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VER=$(tr -d '\r\n' < "$ROOT/VERSION")
DIST="$ROOT/dist"; mkdir -p "$DIST"
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
PKG="$STAGE/VNPTNAN_GATE"; mkdir -p "$PKG/tools"

# Chỉ những gì cần để chạy (không kèm docs, slide, video, tests)
cp -r "$ROOT"/{engine,rules,hooks,cli,installer,server,ci} "$PKG/"
cp "$ROOT"/{gate.conf,VERSION,README.md} "$PKG/"
cp "$ROOT/tools/lint-rules.sh" "$PKG/tools/"
# Kiểm tra trước khi đóng gói: rule phải lint sạch
bash "$PKG/tools/lint-rules.sh" >/dev/null || { echo "lint-rules lỗi, không đóng gói" >&2; exit 1; }

ZIP="$DIST/VNPTNAN_GATE-$VER.zip"
rm -f "$ZIP"; (cd "$STAGE" && zip -qr -X "$ZIP" VNPTNAN_GATE)

make_cmd() { # $1 file đích, $2 chế độ mặc định
  {
    printf '%s\r\n' \
'@echo off' \
'rem VNPTNAN_GATE '"$VER"' - bo cai dat mot file cho may dev Windows (Du an 2, Phong Giai phap 2).' \
'rem Nhap dup de cai. Tham so: /audit  /enforce  /whatif' \
'setlocal' \
'set "PSModulePath="' \
'set "VG_SELF=%~f0"' \
'set "VG_MODE='"$2"'"' \
'echo %~n0 | find /i "audit" >nul && set "VG_MODE=audit"' \
'set "VG_WHATIF="' \
'for %%A in (%*) do (' \
'  if /i "%%~A"=="/audit" set "VG_MODE=audit"' \
'  if /i "%%~A"=="/enforce" set "VG_MODE=enforce"' \
'  if /i "%%~A"=="/whatif" set "VG_WHATIF=1"' \
')' \
'if defined VG_WHATIF goto run' \
'net session >nul 2>&1 && goto run' \
'echo Dang xin quyen quan tri (UAC)...' \
'powershell -NoProfile -Command "Start-Process -FilePath $env:ComSpec -ArgumentList ('"'"'/c \"\"'"'"' + $env:VG_SELF + '"'"'\" /'"'"' + $env:VG_MODE + '"'"'\"'"'"') -Verb RunAs -Wait"' \
'exit /b' \
':run' \
'powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='"'"'Stop'"'"'; $l=[IO.File]::ReadAllLines($env:VG_SELF); $i=[Array]::IndexOf($l,'"'"'::VNPTNAN_GATE_PAYLOAD::'"'"'); $b=[Convert]::FromBase64String(($l[($i+1)..($l.Length-1)] -join '"'"''"'"')); $t=Join-Path $env:TEMP ('"'"'vnptnan-gate-'"'"'+[guid]::NewGuid()); New-Item -ItemType Directory $t | Out-Null; try { [IO.File]::WriteAllBytes((Join-Path $t '"'"'p.zip'"'"'),$b); Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $t '"'"'p.zip'"'"'),$t); $a=@{Mode=$env:VG_MODE}; if($env:VG_WHATIF){$a.WhatIf=$true}; & (Join-Path $t '"'"'VNPTNAN_GATE\installer\install.ps1'"'"') @a } finally { Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue }"' \
'set "VG_RC=%ERRORLEVEL%"' \
'echo.' \
'if "%VG_RC%"=="0" (echo Xong. Mo terminal moi va chay: vnptnan-gate doctor) else (echo Cai dat LOI, ma %VG_RC%. Chup man hinh gui Phong Giai phap 2.)' \
'if not defined CI pause' \
'exit /b %VG_RC%' \
'::VNPTNAN_GATE_PAYLOAD::'
    base64 -w 76 "$ZIP" | sed 's/$/\r/'
  } > "$1"
}
make_cmd "$DIST/VNPTNAN_GATE-$VER-setup.cmd" enforce
make_cmd "$DIST/VNPTNAN_GATE-$VER-setup-audit.cmd" audit
(cd "$DIST" && sha256sum "VNPTNAN_GATE-$VER.zip" "VNPTNAN_GATE-$VER-setup.cmd" "VNPTNAN_GATE-$VER-setup-audit.cmd" > SHA256SUMS.txt)
ls -la "$DIST"
