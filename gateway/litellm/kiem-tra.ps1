# Kiểm tra gateway VNPTNAN_GATE mà KHÔNG tốn token: gửi yêu cầu không kèm đăng nhập Claude.
#  - Yêu cầu sạch      -> chuyển tới Anthropic, Anthropic trả 401 (chưa đăng nhập)          => chuyển tiếp chạy
#  - Yêu cầu có secret -> chế độ mask: vẫn tới Anthropic (401) NHƯNG log gateway ghi "gate-masker: MASKED <rule>"
#                         chế độ block: gateway trả 400 ngay
# Chạy lại sau mỗi lần nâng phiên bản LiteLLM hoặc đổi rule. Secret mẫu ghép lúc chạy (file này không chứa secret).
$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:4000'
$url = "$base/claude/v1/messages"
$key = (Get-Content (Join-Path $PSScriptRoot '.env') | Where-Object { $_ -match '^LITELLM_MASTER_KEY=' }) -replace '^LITELLM_MASTER_KEY=', ''
if (-not $key) { Write-Host 'Chưa có khoá: chạy tao-khoa.ps1 trước.' -ForegroundColor Yellow; exit 1 }
$hc = & curl.exe -s -o NUL -w '%{http_code}' --max-time 5 "$base/health/liveliness"
if ($hc -ne '200') { Write-Host "Không kết nối được gateway ($base, HTTP $hc). Xem: docker compose ps; docker compose logs --tail 60" -ForegroundColor Yellow; exit 1 }
$fail = 0
function Gui([string]$ten, [string]$noiDung, [string]$ruleMongDoi) {
  $body = @{ model = 'claude-sonnet-4-5'; max_tokens = 16; messages = @(@{ role = 'user'; content = $noiDung }) } | ConvertTo-Json -Depth 5 -Compress
  $f = New-TemporaryFile; [IO.File]::WriteAllText($f, $body, (New-Object Text.UTF8Encoding $false))
  $out = New-TemporaryFile
  $t0 = (Get-Date).ToUniversalTime().AddSeconds(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
  $code = & curl.exe -s -o $out -w '%{http_code}' -X POST $url -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -H "x-litellm-api-key: Bearer $key" --data-binary "@$f"
  $resp = [string](Get-Content $out -Raw -Encoding UTF8); Remove-Item $f, $out
  Start-Sleep -Milliseconds 300
  $log = (docker compose logs --since $t0 2>&1 | Out-String)
  $kq = if ($resp -match 'VNPTNAN_GATE') { 'CHẶN tại gateway' }
        elseif ($resp -match '"type":"authentication_error"|x-api-key header is required') { if ($log -match "gate-masker: MASKED[^\r\n]*$ruleMongDoi") { 'ĐÃ CHE rồi chuyển tiếp' } else { 'chuyển tiếp, KHÔNG che' } }
        elseif ($resp -match 'auth_error') { 'LiteLLM từ chối khoá' } else { '?' }
  $dat = if ($ruleMongDoi) { $kq -in @('CHẶN tại gateway', 'ĐÃ CHE rồi chuyển tiếp') } else { $kq -eq 'chuyển tiếp, KHÔNG che' }
  if (-not $dat) { $script:fail++ }
  '{0,-28} HTTP {1}  {2,-26} {3}' -f $ten, $code, $kq, $(if ($dat) { 'đạt' } else { 'LỖI' })
}
Write-Host "== Gateway: $url"
Gui 'Yêu cầu sạch'               'Viết hàm cộng hai số bằng C#'                                        ''
Gui 'Khoá AWS mẫu'               ('AWS_KEY=' + 'AKIA' + 'IOSFODNN7EXAMPLE')                           'g-secret-aws'
Gui 'Chuỗi kết nối PostgreSQL'   ('Host=pg-host;Port=5432;Username=app;' + 'Pass' + 'word=S3cret!x') 'g-secret-connstring'
Gui 'Mật khẩu gán cứng'          ('pass' + 'word = "Vnpt@NgheAn2026"')                                'g-secret-password'
Gui 'Số CCCD'                    ('Khách hàng có CCCD: 0402' + '03001234')                            'g-pii-cccd'
Write-Host ''
if ($fail -eq 0) { Write-Host 'Tất cả đạt.' -ForegroundColor Green } else { Write-Host "$fail phép thử LỖI: không triển khai bản này." -ForegroundColor Red; exit 1 }
