# Tạo file .env chứa khoá quản trị ngẫu nhiên cho LiteLLM (bắt buộc từ các bản sau sự cố 2026).
# Khoá sinh bằng bộ sinh số ngẫu nhiên mật mã của Windows; chỉ lưu trong .env trên máy này.
$ErrorActionPreference = 'Stop'
$envFile = Join-Path $PSScriptRoot '.env'
if (Test-Path $envFile) { Write-Host ".env đã có, giữ nguyên: $envFile"; exit 0 }
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$key = 'sk-' + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
[IO.File]::WriteAllText($envFile, "LITELLM_MASTER_KEY=$key`n", (New-Object Text.UTF8Encoding $false))
Write-Host "Đã tạo $envFile (khoá quản trị LiteLLM). Không gửi file này cho ai, kể cả Claude."
