# Phát hành `@vnptnan/gate` qua GitHub và npmjs.com

Mã nguồn nằm trên GitHub. GitHub Actions kiểm thử và build. Gói phát hành công khai trên npmjs.com. Máy dev cài bằng `npx -y @vnptnan/gate`, sau đó tự cập nhật hằng ngày.

## Cách hoạt động trên máy dev

1. `npx` tải gói (khoảng 30 KB) và chạy `bin/cli.js`. Gói không phụ thuộc thư viện nào khác.
2. `cli.js` xin quyền admin, chép bộ công cụ vào `%ProgramData%\VNPTNAN_GATE\current` (người dùng và AI chỉ đọc được), rồi đăng ký hook git.
3. Tạo hai lịch Windows chạy bằng tài khoản SYSTEM: 10:17 hằng ngày và 10 phút sau khi khởi động máy. Cả hai chạy `cli.js update --quiet`.
4. Khi cập nhật, `cli.js` đọc bản `latest` trên npm. Có bản mới thì tải về, kiểm tra sha512 do npm công bố (sai thì không cài), giải nén có chặn đường dẫn ra ngoài thư mục, rồi cài đè. Log ghi ở `%ProgramData%\VNPTNAN_GATE\logs\update.log`.
5. Chế độ lấy theo `npm/policy.json` của bản phát hành, trừ máy được cố định bằng `--audit` hoặc `--enforce`.

## Chuẩn bị một lần

1. **GitHub:** tạo repo, ví dụ `vnptnan/gate`, đẩy mã lên. `.gitignore` đã loại `docs/`, `slide/`, `video/` (tài liệu nội bộ) và `dist/`.
   - Bật branch protection cho `main`.
   - Settings → Environments → tạo environment `npm`, đặt Required reviewers (1–2 người).
2. **npmjs.com:** tạo tài khoản và bật 2FA, rồi tạo organization `vnptnan` (bản miễn phí đủ cho gói công khai). Scope `@vnptnan` phải trùng tên org; đặt tên khác thì sửa `name` trong `npm/package.template.json`.
3. **Lần phát hành đầu tiên:** gói chưa tồn tại nên chưa khai Trusted Publisher được.
   - Tạo granular access token có quyền publish cho org.
   - Lưu token vào secret `NPM_TOKEN` của environment `npm`.
4. **Sau lần đầu:** vào npmjs.com → gói `@vnptnan/gate` → Settings → Trusted Publisher → GitHub Actions. Khai repo, workflow `release.yml` và environment `npm`, rồi **xoá secret `NPM_TOKEN`**. Từ đó GitHub xác thực với npm bằng OIDC, không còn token nào để lộ.

## Phát hành bản mới

```bash
# sửa rule/engine, chạy: bash tests/run-tests.sh
echo 1.0.1 > VERSION
git commit -am "rule: ..." && git tag v1.0.1 && git push && git push --tags
```

Workflow `release.yml` chạy theo thứ tự:
1. Kiểm thử Linux.
2. Cài thật trên Windows: setup.cmd, hook chặn secret, npx setup/status/uninstall.
3. Chờ người duyệt (environment `npm`).
4. `npm publish --provenance`, rồi tạo GitHub Release kèm `setup.cmd`, `zip` và `SHA256SUMS`.

Mọi máy nhận bản mới trong vòng 24 giờ.

**Chuyển cả đơn vị sang chặn thật:** sửa `npm/policy.json` thành `"mode": "enforce"`, tăng VERSION, rồi đẩy tag.

**Quay lui:** phát hành lại nội dung bản cũ với số VERSION mới hơn. Máy chỉ cập nhật lên, không bao giờ hạ phiên bản.

## An toàn chuỗi cung ứng

Ai phát hành được gói này thì chạy được lệnh với quyền SYSTEM trên mọi máy dev, nên các lớp bảo vệ sau là bắt buộc:
- 2FA cho mọi thành viên npm org.
- Trusted Publishing, không giữ token lâu dài.
- Provenance: npmjs.com hiển thị gói được build từ commit nào trên GitHub.
- Environment `npm` có người duyệt; branch protection trên `main`.

## Dùng kho nội bộ thay npmjs.com (tuỳ chọn)

`cli.js` đọc kho từ `npm config get @vnptnan:registry` hoặc tham số `--registry`. Kho dùng chứng chỉ tự ký thì truyền thêm `--ca <file>`; cần đăng nhập thì truyền `--token`.
