# Lớp gateway AI (LiteLLM + gate_masker)

Lớp thứ năm của VNPTNAN_GATE. Gateway đứng giữa coding agent và nhà cung cấp AI, và **che hoặc chặn secret trong mọi dữ liệu gửi đi**. Dữ liệu gửi đi gồm cả nội dung file mà agent tự đọc, thứ mà hook kiểm tra prompt không thấy. Bộ lọc dùng chung `rules/` với cổng commit, push và prompt: 18 rule `g-` mức chặn và 215 rule Gitleaks áp lên nội dung.

```
Claude Code ──► gateway nội bộ (LiteLLM + gate_masker) ──► api.anthropic.com
 (đăng nhập thuê bao      che: Password=[DA_CHE:g-secret-connstring]
  + khoá LiteLLM)         chặn: khoá riêng tư, hoặc mọi secret nếu ACTION=block
```

## Đã kiểm chứng trên máy thật (06/11/2026, LiteLLM v1.106.7, Claude Code dùng tài khoản thuê bao)

| Phép thử | Kết quả |
|---|---|
| Claude Code dùng tài khoản thuê bao, đi qua gateway | Đạt: trả lời bình thường, vẫn tính vào gói thuê bao |
| Chặn secret dev gõ thẳng vào (khoá AWS, chuỗi kết nối, mật khẩu, CCCD) | Đạt (400) |
| Chặn secret trong file agent tự đọc | Đạt |
| Che bằng `litellm_content_filter` (có sẵn) trên route chuyển tiếp | **Không đạt**: log ghi `Masked…` nhưng bản gốc vẫn được gửi đi |
| Che bằng `gate_masker.py` | Đạt: Claude chỉ thấy `[DA_CHE:…]`, phiên làm việc chạy tiếp |
| PDF có secret (bản 1.2.2) | Đạt trong kiểm thử tự động; chưa thử trên máy thật, chạy `kiem-tra.ps1` để xác nhận |

Nguyên nhân của dòng không đạt: trên route chuyển tiếp, LiteLLM chỉ **kiểm tra**. Nó bỏ bản đã che và gửi bản gốc, xem `litellm/llms/pass_through/guardrail_translation/handler.py`. `gate_masker.py` không đi qua lớp đó: LiteLLM gửi đi đúng dữ liệu bộ lọc này trả về.

## Chạy

```powershell
cd gateway\litellm
powershell -ExecutionPolicy Bypass -File .\tao-khoa.ps1   # lần đầu: .env chứa LITELLM_MASTER_KEY
docker compose up -d --build                              # build image LiteLLM + pypdf (Dockerfile)
powershell -ExecutionPolicy Bypass -File .\kiem-tra.ps1   # 7 phép thử, không tốn token
```

Trên máy dev, Claude Code đi qua gateway như sau. Đây là bản thử; bản thật đẩy hai biến này qua managed settings.

```powershell
$env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:4000/claude'
$env:ANTHROPIC_CUSTOM_HEADERS = 'x-litellm-api-key: Bearer <khoá LiteLLM>'
claude
```

Không đặt `ANTHROPIC_AUTH_TOKEN`. Claude Code vẫn dùng đăng nhập thuê bao; khoá LiteLLM đi trong header riêng.

## Loại dữ liệu được quét

| Claude Code gửi lên | Cách xử lý |
|---|---|
| Chữ: prompt, code, `.md`, `.json`, kết quả lệnh | Che giá trị secret, cho đi tiếp |
| `.docx`, `.xlsx` | Agent phải chạy lệnh (pandoc, python…) để lấy chữ, nên đi lên dưới dạng chữ và được che như trên |
| Khối `document` dạng chữ | Che như trên |
| PDF (khối `document`, base64) | `pypdf` lấy chữ ra để quét. **Có secret thì chặn cả yêu cầu** (không sửa được PDF). Kết quả nhớ theo mã băm, nên các lượt sau không quét lại |
| PDF không lấy được chữ (bản scan ảnh, có mật khẩu, hỏng) | Mặc định cho qua và ghi log `PDF-UNSCANNED`. Đặt `GATE_GATEWAY_PDF_UNSCANNABLE=block` để chặn |
| Ảnh, ảnh chụp màn hình | **Không quét** (cần OCR, chậm và hay sót). Dựa vào Bộ quy tắc: không chụp màn hình có secret |

Một PDF có secret nằm lại trong lịch sử hội thoại, nên mọi lượt sau đều bị chặn tới khi dev gõ `/clear`.



| Biến | Ý nghĩa |
|---|---|
| `GATE_GATEWAY_ACTION` | `mask` (mặc định): che giá trị secret rồi cho đi tiếp. `block`: chặn cả yêu cầu, dev phải gõ `/clear` |
| `GATE_GATEWAY_BLOCK_IDS` | Các rule luôn chặn dù đang ở chế độ `mask` (mặc định: `g-secret-private-key`) |
| `GATE_RULES_DIR` | Thư mục rule (gắn từ `../../rules`). Không nạp được rule nào thì gateway dừng, không chạy “rỗng” |
| `GATE_GATEWAY_PDF` | `scan` (mặc định) hoặc `off` |
| `GATE_GATEWAY_PDF_UNSCANNABLE` | `allow` (mặc định, ghi log) hoặc `block` |
| `GATE_GATEWAY_PDF_MAX_PAGES` | Số trang tối đa lấy chữ (mặc định 200) |

## Điều kiện trước khi dùng thật

1. **Máy chủ nội bộ** có HTTPS (reverse proxy). Chặn mọi kết nối ra ngoài, trừ `api.anthropic.com`.
2. **Khoá LiteLLM riêng cho từng dev** (khoá ảo, cần PostgreSQL); không phát khoá quản trị.
3. **Managed settings trên máy dev**, đẩy qua Harness:
   - `ANTHROPIC_BASE_URL` và `ANTHROPIC_CUSTOM_HEADERS`;
   - `allowedProviders: ["customEndpoint"]` (Claude Code từ 2.1.285 trở lên), để Claude Code không đi vòng qua gateway.
4. **Chuỗi cung ứng** (LiteLLM bị cài mã độc ngày 24/03/2026 và 21/10/2026):
   - chốt image theo digest và kiểm chữ ký bằng cosign; `Dockerfile` chốt cả `python:3.12-slim` và `pypdf==6.17.0` (thêm `--hash` khi build trên máy có mạng);
   - nâng phiên bản chỉ khi ATTT duyệt;
   - **chạy lại `kiem-tra.ps1` sau mỗi lần nâng phiên bản**. Log `Masked…` của LiteLLM từng sai, nên không được tin log.
5. **Log:** không ghi nội dung prompt (`turn_off_message_logging`). Log chỉ có tên rule và số lần che. Cần quy định thời hạn lưu và người được xem.
6. **Phạm vi:**
   - Claude Code (CLI, VS Code): đi qua gateway được.
   - Codex: cần khoá API riêng.
   - Antigravity và chatbot web: không đi qua gateway được, vẫn dựa vào Bộ quy tắc và đào tạo.

## Kiểm thử

`tests/gateway/test_gate_masker.py` chạy trong `tests/run-tests.sh` (cần Python 3.10 trở lên):
- chuỗi kết nối chỉ bị che phần giá trị;
- không sửa khối `thinking`, định nghĩa công cụ hay câu không có secret;
- không che giá trị mẫu (`changeme`);
- che được 215/215 mẫu Gitleaks;
- khối `document` dạng chữ được che;
- PDF có secret bị chặn (cả ở lượt gửi lại); PDF sạch đi qua nguyên vẹn; PDF trống hoặc hỏng xử lý theo `PDF_UNSCANNABLE`;
- gateway không khởi động khi không nạp được rule.

CI cài `pypdf` để chạy phần PDF. Chạy trên máy không có `pypdf` thì phần này được bỏ qua và có ghi rõ.
