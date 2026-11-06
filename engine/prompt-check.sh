#!/usr/bin/env bash
# Kiểm tra prompt TRƯỚC KHI gửi tới mô hình — hook UserPromptSubmit của Claude Code và Codex.
# Dùng chung rule với cổng commit (rules/gate.rules): rule kind=line và kind=count áp lên nội dung prompt.
#
#   stdin : JSON của sự kiện UserPromptSubmit (có trường "prompt")
#   stdout: {"decision":"block","reason":"..."} khi phải chặn (Claude Code và Codex cùng hiểu); rỗng khi cho qua
#   Mã thoát luôn 0: hook lỗi thì cho qua (cùng cách Codex xử lý), lần lỗi được ghi log.
#
#   bash prompt-check.sh --agent claude|codex
#
# Khác với cổng commit, ở đây KHÔNG áp dụng ngoại lệ: không đọc .vnptnan-gate/allow.rules và không nhận
# "gate-allow:" trong prompt, vì prompt không qua merge request nên không có ai duyệt ngoại lệ.
# Antigravity không có sự kiện trước khi gửi prompt có quyền chặn, nên không dùng được script này.

# Không tin biến môi trường: chỉ đọc gate.conf ở thư mục cài (chỉ admin ghi được)
unset VNPTNAN_GATE_HOME GATE_ROOT GATE_MODE GATE_DEPS GATE_DEPS_AUDIT GATE_SKIP_PATHS GATE_SKIP_EXTRA \
      GATE_MAX_COMMITS GATE_MAX_FILE GATE_QUIET GATE_SERVER GATE_ENGINE GATE_GITLEAKS GATE_CORE_ARGS
set -u
ENGINE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AGENT=claude
[ "${1:-}" = "--agent" ] && AGENT=${2:-claude}

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t gateprompt)
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/in.json"

# Lấy trường "prompt" và giải mã chuỗi JSON (\n, \", \\, \uXXXX kể cả cặp surrogate) bằng perl có sẵn trong Git for Windows,
# không cần module ngoài. Không có trường prompt thì cho qua.
perl -e '
  local $/; my $j = <STDIN>;
  exit 3 unless $j =~ /"prompt"\s*:\s*"((?:[^"\\]|\\.)*)"/s;
  my $s = $1; my $out = "";
  while ($s =~ /\G(?:([^\\]+)|\\u([0-9a-fA-F]{4})(?:\\u([0-9a-fA-F]{4}))?|\\(.))/gcs) {
    if (defined $1) { $out .= $1; next }
    if (defined $2) {
      my $c = hex $2;
      if ($c >= 0xD800 && $c <= 0xDBFF && defined $3) { $c = 0x10000 + (($c - 0xD800) << 10) + (hex($3) - 0xDC00) }
      elsif (defined $3) { $out .= chr_utf8($c); $c = hex $3 }
      $out .= chr_utf8($c); next
    }
    my %m = (n => "\n", t => "\t", r => "", b => "", f => "", "/" => "/", "\\" => "\\", "\"" => "\"");
    $out .= exists $m{$4} ? $m{$4} : $4;
  }
  sub chr_utf8 { my $c = shift; my $x = chr($c); utf8::encode($x); return $x }
  print $out;
' < "$TMP/in.json" > "$TMP/prompt.txt" 2>/dev/null
rc=$?
[ "$rc" -eq 3 ] && exit 0
if [ "$rc" -ne 0 ]; then
  echo "[VNPTNAN_GATE] prompt-check: không đọc được JSON đầu vào, cho qua" >&2
  exit 0
fi
[ -s "$TMP/prompt.txt" ] || exit 0

# shellcheck source=gate-lib.sh
. "$ENGINE_DIR/gate-lib.sh"
gate_load_conf ""
gate_load_rules >/dev/null 2>&1 || { echo "[VNPTNAN_GATE] prompt-check: không nạp được rule, cho qua" >&2; exit 0; }
GATE_STAGE="prompt-$AGENT"
GATE_REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")
GATE_QUIET=1
GATE_NO_INLINE_ALLOW=1   # gate-lib: bỏ qua "gate-allow:" trên dòng
GATE_SKIP_PATHS='^$'     # không bỏ qua gì: đường dẫn giả "<prompt>" phải được quét

# Quét; thu các dòng thông báo để làm lý do chặn
gate_scan_file "<prompt>" "$TMP/prompt.txt" "$TMP/prompt.txt" "$(wc -c < "$TMP/prompt.txt" | tr -d ' ')" 2> "$TMP/findings.txt"

if [ "$GATE_N_BLOCK" -gt 0 ]; then
  {
    echo "Cổng kiểm soát ATBMTT đã chặn prompt này trước khi gửi tới AI (Bộ quy tắc sử dụng AI, Điều 5: dữ liệu mức C3 không được đưa vào AI)."
    sed -n 's/^\[VNPTNAN_GATE\] CHAN \([a-z0-9-]*\)  <prompt>\(:[0-9]*\)\{0,1\}  /- \1: /p' "$TMP/findings.txt" | head -n 8
    echo "Gỡ mật khẩu, khoá, dữ liệu khách hàng khỏi prompt (thay bằng biến môi trường, dữ liệu giả hoặc mô tả bằng lời) rồi gửi lại."
  } > "$TMP/reason.txt"
  perl -e 'local $/; my $r = <STDIN>; $r =~ s/\\/\\\\/g; $r =~ s/"/\\"/g; $r =~ s/\r//g; $r =~ s/\n/\\n/g; $r =~ s/\t/\\t/g;
           print "{\"decision\":\"block\",\"reason\":\"$r\"}\n"' < "$TMP/reason.txt"
fi
exit 0
