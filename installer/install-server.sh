#!/usr/bin/env bash
# Cài VNPTNAN_GATE làm server hook toàn cục trên máy chủ GitLab tự host (Linux package / Omnibus, mọi bậc kể cả Free).
# Chạy bằng root trên máy chủ GitLab:
#   sudo bash installer/install-server.sh [-mode enforce|audit]
# Việc làm: copy bộ công cụ vào /opt/vnptnan-gate (root sở hữu, git chỉ đọc), tạo thư mục custom_hooks/pre-receive.d,
# đặt symlink 10-vnptnan-gate, tạo /var/log/vnptnan-gate cho tài khoản git ghi. Không cần khởi động lại GitLab.
# Tài liệu GitLab: Administration > Git server hooks (thư mục custom_hooks toàn cục: gitaly['configuration'][:hooks][:custom_hooks_dir],
# mặc định /var/opt/gitlab/gitaly/custom_hooks).
set -eu
MODE=enforce
[ "${1:-}" = "-mode" ] && MODE=${2:-enforce}
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DEST=/opt/vnptnan-gate
HOOKS_DIR=${GITLAB_CUSTOM_HOOKS_DIR:-/var/opt/gitlab/gitaly/custom_hooks}
GIT_USER=${GITLAB_GIT_USER:-git}

[ "$(id -u)" = 0 ] || { echo "Chạy bằng root."; exit 2; }
id "$GIT_USER" >/dev/null 2>&1 || { echo "Không có tài khoản $GIT_USER. Đặt GITLAB_GIT_USER."; exit 2; }

rm -rf "$DEST"; mkdir -p "$DEST"
cp -r "$SRC"/. "$DEST"/; rm -rf "$DEST/.git"
sed -i "s/^MODE=.*/MODE=$MODE/" "$DEST/gate.conf"
chown -R root:root "$DEST"; chmod -R a+rX "$DEST"; chmod +x "$DEST"/server/pre-receive "$DEST"/engine/*.sh

mkdir -p "$HOOKS_DIR/pre-receive.d"
ln -sfn "$DEST/server/pre-receive" "$HOOKS_DIR/pre-receive.d/10-vnptnan-gate"
chown -R "$GIT_USER":"$GIT_USER" "$HOOKS_DIR"

mkdir -p /var/log/vnptnan-gate; chown "$GIT_USER":"$GIT_USER" /var/log/vnptnan-gate; chmod 750 /var/log/vnptnan-gate

echo "Đã cài VNPTNAN_GATE $(cat "$DEST/VERSION") làm server hook toàn cục (MODE=$MODE)."
echo "Kiểm tra: đẩy một commit chứa 'AKIAIOSFODNN7EXAMPLE' lên nhánh thử; GitLab phải từ chối với dòng GL-HOOK-ERR."
echo "Log: /var/log/vnptnan-gate/gate.log. Để quét định kỳ: xem ci/.gitlab-ci.yml khi bật CI."
