# VNPTNAN_GATE: Cổng kiểm soát ATBMTT khi dùng AI trong phát triển phần mềm

Chặn secret, dữ liệu cá nhân khách hàng, file cấm và package đáng ngờ **trước khi chúng rời máy dev**. Cổng chạy ở sáu điểm:

| Điểm | Cơ chế |
|---|---|
| 0 · Gửi prompt | Hook `UserPromptSubmit` của Claude Code, Codex (`engine/prompt-check.sh`) |
| 1 · Commit | `pre-commit`: quét các dòng được thêm |
| 2 · Push | `pre-push`: quét mọi commit sắp rời máy, kể cả commit tạo bằng lệnh plumbing |
| 3 · Máy chủ GitLab | `pre-receive`: chặn cả máy chưa cài gì, có ở GitLab bản Free, không cần CI |
| 4 · CI | Mẫu `ci/.gitlab-ci.yml`: quét toàn cây, dependency |
| 5 · Gateway AI (thử nghiệm) | `gateway/litellm/`: LiteLLM và bộ lọc `gate_masker.py` che secret trong mọi dữ liệu gửi lên nhà cung cấp AI, kể cả file agent tự đọc. Dùng chung `rules/`. Xem `gateway/README.md` |

Cổng không dùng AI để quyết định. Có hai bộ rule, áp trong cùng một lần đọc file:
- **43 rule riêng** (`rules/gate.rules`, id `g-`): secret, CCCD, dump số điện thoại/email, chuỗi kết nối Oracle, file cấm, cảnh báo mã do AI sinh.
- **219 rule nhập từ [Gitleaks](https://github.com/gitleaks/gitleaks)** (`rules/gitleaks.jsonl`, id `gl-`, giấy phép MIT, xem `rules/gitleaks.LICENSE`): token của từng dịch vụ (Stripe, Azure, Databricks, Hugging Face, npm, PyPI…), giữ nguyên cách Gitleaks lọc theo từ khoá, entropy và ngoại lệ. Cập nhật bằng `tools/import-gitleaks.py`.

Lõi quét là một tiến trình Perl (`engine/scan-core.pl`, có sẵn trong Git for Windows); máy không có Perl thì dùng bản bash (chỉ rule `g-`). Log luôn che giá trị secret. Bộ này bổ sung cho VNPTNAN_HARNESS (hook trong phiên AI): hai bên dùng tên hook, thư mục, lệnh và id rule khác nhau.

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

## Cài trên Linux / WSL

Cần `git`, `bash`, Node.js 16.7 trở lên **cài trong Linux**. Trong WSL, `which node` phải ra `/usr/bin/...` hoặc `~/.nvm/...`, không phải `/mnt/c/...`: dùng Node của Windows thì bộ cài Windows chạy. `perl` có sẵn trên Ubuntu/Debian.

```bash
npx -y @vnptnan/gate              # không cần sudo; cài vào ~/.local/share/vnptnan-gate, lệnh ~/.local/bin/vnptnan-gate
npx -y @vnptnan/gate --hooks-path # như trên, và áp hook cho mọi repo qua core.hooksPath (Git < 2.54)
vnptnan-gate doctor
```

- **Hook:** Git 2.54 trở lên đăng ký hook theo config ở cấp người dùng, giống bản Windows. Git cũ hơn (Ubuntu 24.04 có 2.43) có hai cách:
  - từng repo chạy `vnptnan-gate install-hooks`;
  - cài với `--hooks-path`: hook riêng của repo trong `.git/hooks` vẫn chạy trước. Repo tự đặt `core.hooksPath` (như husky) thì `doctor` sẽ báo cần thêm một dòng vào hook của repo đó.
- **Tự cập nhật:** dùng `systemd --user` nếu có, rồi tới `cron`. Không có cả hai thì cổng kiểm tra mỗi ngày một lần khi gọi `vnptnan-gate`.
- **WSL:** không cài hook cho repo nằm trên ổ Windows (`/mnt/c`, `/mnt/e`…) mà Git của Windows cũng dùng. Hook ghi đường dẫn Linux, nên Git của Windows sẽ lỗi.
- `npx @vnptnan/gate status | update | uninstall` dùng như trên Windows.

Máy chủ GitLab: tải `VNPTNAN_GATE-<ver>.zip` ở trang Releases, giải nén, rồi chạy `sudo bash installer/install-server.sh -mode audit`.

## Dùng hằng ngày

`vnptnan-gate scan` · `scan tree` · `scan range A B` · `deps` · `test "<dòng>"` · `report [ngày]` · `doctor` · `tools` · `install-hooks`

Bị chặn nhầm thì khai ngoại lệ, không dùng `--no-verify`:
- trên dòng: `gate-allow:<id> <lý do>`;
- theo đường dẫn: `.vnptnan-gate/allow.rules`, qua merge request có người duyệt.

**Bỏ qua thư mục không cần quét** (dữ liệu mẫu, mã sinh tự động, thư viện chép vào repo): tạo `.vnptnan-gate/gate.conf` ở gốc repo và commit qua merge request.

```
# regex đường dẫn (so với gốc repo), nhiều mục nối bằng |
SKIP_PATHS_EXTRA=(^|/)legacy-dump/|(^|/)src/Generated/|\.designer\.cs$
```

Mặc định đã bỏ qua `node_modules`, `bin`, `obj`, `dist`, `build`, `out`, `packages`, `vendor`, `coverage`, `TestResults`, file `.min.js`/`.map`/lockfile, và file lớn hơn 5 MB. Thư mục bỏ qua thì không bị quét ở mọi điểm: commit, push, máy chủ GitLab, `scan tree`. Vì vậy chỉ bỏ qua thứ thật sự không chứa secret.

**Báo cáo sau khi quét cả cây:** mỗi lần `scan tree` ghi một thư mục `.vnptnan-gate/reports/quet-<ngày-giờ>/` ở gốc repo, gồm:
- `bao-cao.html`: mở bằng trình duyệt. Có tổng số, bảng theo rule kèm hướng xử lý, chi tiết từng phát hiện, ô lọc.
- `phat-hien.csv`: mở bằng Excel, có sẵn cột "Người xử lý" và "Trạng thái" để giao việc.

`.vnptnan-gate/reports/moi-nhat.html` luôn là bản gần nhất. Báo cáo chỉ chứa đoạn đã che. Thư mục này tự được thêm vào `.git/info/exclude` nên không bị commit, và không bị quét lại. Đặt `GATE_REPORT=0` để tắt, `GATE_REPORT_DIR=<thư mục>` để ghi chỗ khác.

`scan tree` hiện tiến độ (`Đang quét 2209/3500 file (63%)`), chạy song song theo số nhân CPU (tối đa 4; đặt `GATE_JOBS=N` để đổi), báo file nào quét lâu, và khi xong thì báo số file đã bỏ qua theo `SKIP_PATHS`. Đặt `GATE_PROGRESS=0` để tắt dòng tiến độ, `GATE_PROGRESS=1` để bật khi không chạy trong terminal.

## Phát triển và phát hành

```bash
bash tests/run-tests.sh      # rule, hook, pre-receive, prompt, 215 mẫu Gitleaks
bash tools/lint-rules.sh
```

Mỗi push chạy GitHub Actions (`ci.yml`): kiểm thử trên Linux, rồi cài thật trên Windows và kiểm tra hook chặn secret. Phát hành bằng cách tăng `VERSION` rồi đẩy tag `vX.Y.Z`: `release.yml` chạy lại toàn bộ kiểm thử, `npm publish --provenance` và tạo GitHub Release. Chi tiết trong `npm/README.md`.

Giấy phép MIT. Rule trong `rules/gitleaks.*` thuộc dự án Gitleaks (MIT, Copyright (c) 2019 Zachary Rice).
