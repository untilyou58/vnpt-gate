# VNPTNAN_GATE: Cổng kiểm soát ATBMTT khi dùng AI trong phát triển phần mềm

Chặn secret, dữ liệu cá nhân khách hàng, file cấm và package đáng ngờ **trước khi chúng rời máy dev**. Cổng chạy ở năm điểm:

| Điểm | Cơ chế |
|---|---|
| 0 · Gửi prompt | Hook `UserPromptSubmit` của Claude Code, Codex (`engine/prompt-check.sh`) |
| 1 · Commit | `pre-commit`: quét các dòng được thêm |
| 2 · Push | `pre-push`: quét mọi commit sắp rời máy, kể cả commit tạo bằng lệnh plumbing |
| 3 · Máy chủ GitLab | `pre-receive`: chặn cả máy chưa cài gì, có ở GitLab bản Free, không cần CI |
| 4 · CI | Mẫu `ci/.gitlab-ci.yml`: quét toàn cây, dependency |

Cổng không dùng AI để quyết định. Có 43 rule regex tiếng Việt (`rules/gate.rules`, id `g-`), một engine bash dùng chung cho mọi điểm, log luôn che giá trị secret. Bộ này bổ sung cho VNPTNAN_HARNESS (hook trong phiên AI): hai bên dùng tên hook, thư mục, lệnh và id rule khác nhau.

## Cài trên máy dev Windows

Cần Git for Windows và Node.js 16.7 trở lên.

```powershell
npx -y @vnptnan/gate          # xin quyền admin, cài, tự cập nhật hằng ngày
vnptnan-gate doctor           # mở terminal mới rồi kiểm tra
```

| Lệnh | Việc |
|---|---|
| `npx @vnptnan/gate status` | Bản đang cài, bản mới nhất, chế độ, lịch cập nhật |
| `npx @vnptnan/gate update` | Cập nhật ngay |
| `npx @vnptnan/gate --audit` | Cố định chế độ chỉ ghi log trên máy này (mặc định theo `policy.json` của bản phát hành) |
| `npx @vnptnan/gate uninstall` | Gỡ |

Máy không có Node: tải `VNPTNAN_GATE-<ver>-setup.cmd` ở trang Releases, nhấp đúp.

Máy chủ GitLab: tải `VNPTNAN_GATE-<ver>.zip` ở trang Releases, giải nén, rồi chạy `sudo bash installer/install-server.sh -mode audit`.

## Dùng hằng ngày

`vnptnan-gate scan` · `scan tree` · `scan range A B` · `deps` · `test "<dòng>"` · `report [ngày]` · `doctor` · `tools` · `install-hooks`

Bị chặn nhầm thì khai ngoại lệ, không dùng `--no-verify`:
- trên dòng: `gate-allow:<id> <lý do>`;
- theo đường dẫn: `.vnptnan-gate/allow.rules`, qua merge request có người duyệt.

## Phát triển và phát hành

```bash
bash tests/run-tests.sh      # 94 ca: rule, hook, pre-receive, prompt
bash tools/lint-rules.sh
```

Mỗi push chạy GitHub Actions (`ci.yml`): kiểm thử trên Linux, rồi cài thật trên Windows và kiểm tra hook chặn secret. Phát hành bằng cách tăng `VERSION` rồi đẩy tag `vX.Y.Z`: `release.yml` chạy lại toàn bộ kiểm thử, `npm publish --provenance` và tạo GitHub Release. Chi tiết trong `npm/README.md`.

Giấy phép MIT.
