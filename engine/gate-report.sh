# shellcheck shell=bash
# Báo cáo sau khi quét cả cây (vnptnan-gate scan tree): một thư mục cho mỗi lần quét
#   <repo>/.vnptnan-gate/reports/quet-YYYYMMDD-HHMMSS/bao-cao.html   mở bằng trình duyệt
#                                                    /phat-hien.csv  mở bằng Excel (UTF-8 có BOM)
#   <repo>/.vnptnan-gate/reports/moi-nhat.html                       bản sao của báo cáo gần nhất
# Thư mục reports được thêm vào .git/info/exclude (không commit) và nằm trong SKIP_PATHS mặc định (không quét lại).
# Báo cáo chỉ chứa đoạn đã che, không chứa secret gốc.
# Biến: GATE_REPORT=0 tắt; GATE_REPORT_DIR=<thư mục> ghi chỗ khác.
# Dữ liệu: gate_report_finding ghi từng phát hiện vào $GATE_FINDINGS_TSV:
#   quyết định  mức  id  đường-dẫn  dòng  đoạn-đã-che  mô-tả

gate_report_begin() {
  [ "${GATE_REPORT:-1}" = 0 ] && return 0
  GATE_FINDINGS_TSV="$TMP/findings.tsv"; : > "$GATE_FINDINGS_TSV"
  GATE_REPORT_T0=$SECONDS
  GATE_REPORT_STARTED=$(date '+%d/%m/%Y %H:%M:%S')
}

gate_report_winpath() {
  # Git Bash: in đường dẫn dạng Windows để người dùng mở được
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi
}

gate_report_write() {
  # $1 thư mục đã quét. In đường dẫn báo cáo ra stderr.
  [ "${GATE_REPORT:-1}" = 0 ] && return 0
  [ -n "${GATE_FINDINGS_TSV:-}" ] && [ -f "$GATE_FINDINGS_TSV" ] || return 0
  local dir=$1 base stamp out name gitdir dur
  stamp=$(date '+%Y%m%d-%H%M%S')
  base=${GATE_REPORT_DIR:-$dir/.vnptnan-gate/reports}
  out="$base/quet-$stamp"
  local i=2; while [ -e "$out" ]; do out="$base/quet-$stamp-$i"; i=$((i + 1)); done   # hai lần quét trong cùng một giây
  if ! mkdir -p "$out" 2>/dev/null; then
    # Thư mục repo không ghi được (chỉ đọc, ổ mạng): ghi vào thư mục của người dùng
    base="$HOME/.vnptnan-gate/reports/$(basename "$dir")"; out="$base/quet-$stamp"
    mkdir -p "$out" 2>/dev/null || { gate_say "Không tạo được thư mục báo cáo."; return 0; }
  fi
  # Không để báo cáo lọt vào commit
  if [ -z "${GATE_REPORT_DIR:-}" ] && gitdir=$(git -C "$dir" rev-parse --git-dir 2>/dev/null); then
    case "$gitdir" in /*|[A-Za-z]:*) ;; *) gitdir="$dir/$gitdir" ;; esac
    mkdir -p "$gitdir/info" 2>/dev/null
    grep -qxF '.vnptnan-gate/reports/' "$gitdir/info/exclude" 2>/dev/null || printf '.vnptnan-gate/reports/\n' >> "$gitdir/info/exclude" 2>/dev/null
  fi
  name=$(basename "$dir")
  dur=$((SECONDS - ${GATE_REPORT_T0:-$SECONDS}))

  # CSV cho Excel: BOM UTF-8, phân cách dấu phẩy, mọi ô trong ngoặc kép
  {
    printf '\xEF\xBB\xBF'
    printf '"Quyết định","Mức rule","Rule","File","Dòng","Đoạn (đã che)","Mô tả","Hướng xử lý","Người xử lý","Trạng thái"\r\n'
    awk -F'\t' -v OFS=',' '
      function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }
      function dec(d) { return d == "block" ? "CHẶN" : d == "audit" ? "AUDIT (sẽ chặn)" : d == "allowed" ? "Ngoại lệ đã khai" : "Cảnh báo" }
      { print q(dec($1)), q($2), q($3), q($4), q($5), q($6), q($7), q(hint($3)), q(""), q("") }
      '"$(gate_report_awk_hint)"'
    ' "$GATE_FINDINGS_TSV" | sed 's/$/\r/'
  } > "$out/phat-hien.csv"

  awk -F'\t' \
    -v repo="$name" -v path="$(gate_report_winpath "$dir")" -v started="${GATE_REPORT_STARTED:-}" -v dur="$dur" \
    -v ver="$GATE_VERSION" -v mode="$GATE_MODE" -v nscan="${GATE_N_SCANNED:-0}" -v nskip="${GATE_N_SKIPPED:-0}" \
    -v nblock="$GATE_N_BLOCK" -v nwarn="$GATE_N_WARN" -v nallow="$GATE_N_ALLOWED" '
    function h(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); gsub(/"/, "\\&quot;", s); return s }
    function dec(d) { return d == "block" ? "CHẶN" : d == "audit" ? "AUDIT" : d == "allowed" ? "Ngoại lệ" : "Cảnh báo" }
    function cls(d) { return d == "block" ? "b" : d == "audit" ? "a" : d == "allowed" ? "o" : "w" }
    '"$(gate_report_awk_hint)"'
    {
      n++; D[n] = $1; L[n] = $2; I[n] = $3; P[n] = $4; N[n] = $5; M[n] = $6; T[n] = $7
      cnt[$3]++; lvl[$3] = $1; msg[$3] = $7; if (!($3 in first)) { first[$3] = n; order[++nr] = $3 }
      if ($1 == "block" || $1 == "audit") hi[$3] = 1
      fc[$4]++
    }
    END {
      print "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      print "<title>Báo cáo quét " h(repo) "</title><style>"
      print ":root{--bg:#fff;--fg:#1d2433;--mut:#5b6474;--line:#dfe3ea;--card:#f6f8fb;--b:#b42318;--a:#b54708;--w:#8a6d00;--o:#3f6f3f}"
      print "@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2a2f38;--card:#1b1f26;--b:#f97066;--a:#fdb022;--w:#e4c74a;--o:#86c286}}"
      print "body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 \"Segoe UI\",system-ui,sans-serif}main{max-width:1100px;margin:0 auto;padding:24px 16px}"
      print "h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}.mut{color:var(--mut)}"
      print ".tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}"
      print ".tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:24px}"
      print "table{border-collapse:collapse;width:100%;font-size:14px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}"
      print "th{color:var(--mut);font-weight:600}code{font:13px Consolas,monospace;word-break:break-all}td:nth-child(1) code,td:nth-child(2) code{white-space:nowrap;word-break:normal}.wrap{overflow-x:auto}"
      print ".tag{font-weight:700;white-space:nowrap}.b{color:var(--b)}.a{color:var(--a)}.w{color:var(--w)}.o{color:var(--o)}"
      print "input{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);width:min(420px,100%)}"
      print "</style></head><body><main>"
      print "<h1>Báo cáo quét VNPTNAN_GATE: " h(repo) "</h1>"
      print "<div class=\"mut\">" h(path) " · bắt đầu " h(started) " · " dur " giây · Gate " h(ver) " · chế độ " h(mode) "</div>"
      print "<div class=\"tiles\">"
      print "<div class=\"tile\"><b>" nscan "</b>file đã quét</div>"
      print "<div class=\"tile\"><b>" nskip "</b>file bỏ qua (SKIP_PATHS)</div>"
      nb = 0; na = 0; nw = 0; no = 0
      for (i = 1; i <= n; i++) { if (D[i] == "block") nb++; else if (D[i] == "audit") na++; else if (D[i] == "allowed") no++; else nw++ }
      print "<div class=\"tile\"><b class=\"b\">" nb + na "</b>vi phạm mức chặn" (na ? " (audit: chưa chặn)" : "") "</div>"
      print "<div class=\"tile\"><b class=\"w\">" nw "</b>cảnh báo</div>"
      print "<div class=\"tile\"><b class=\"o\">" no "</b>ngoại lệ đã khai</div>"
      print "</div>"
      if (n == 0) { print "<p><b class=\"o\">Không phát hiện vi phạm.</b></p></main></body></html>"; exit }
      print "<h2>Theo rule</h2><div class=\"wrap\"><table><tr><th>Rule</th><th>Mức</th><th>Số lần</th><th>Mô tả</th><th>Hướng xử lý</th></tr>"
      # mức chặn trước, rồi số lần giảm dần
      for (k = 1; k <= nr; k++) key[k] = (hi[order[k]] ? 0 : 1) sprintf("%08d", 99999999 - cnt[order[k]]) order[k]
      for (k = 1; k <= nr; k++) for (j = k + 1; j <= nr; j++) if (key[j] < key[k]) { t = key[k]; key[k] = key[j]; key[j] = t; t = order[k]; order[k] = order[j]; order[j] = t }
      for (k = 1; k <= nr; k++) { r = order[k]
        print "<tr><td><code>" h(r) "</code></td><td class=\"tag " cls(lvl[r]) "\">" dec(lvl[r]) "</td><td>" cnt[r] "</td><td>" h(msg[r]) "</td><td>" h(hint(r)) "</td></tr>" }
      print "</table></div>"
      print "<h2>Chi tiết</h2><p><input id=\"q\" placeholder=\"Lọc theo file, rule…\" oninput=\"f(this.value)\"></p>"
      print "<div class=\"wrap\"><table id=\"t\"><tr><th>Mức</th><th>Rule</th><th>File:dòng</th><th>Đoạn (đã che)</th></tr>"
      for (i = 1; i <= n; i++)
        print "<tr><td class=\"tag " cls(D[i]) "\">" dec(D[i]) "</td><td><code>" h(I[i]) "</code></td><td><code>" h(P[i]) (N[i] != "" && N[i] != "0" ? ":" N[i] : "") "</code></td><td><code>" h(M[i]) "</code></td></tr>"
      print "</table></div>"
      print "<p class=\"mut\">Đoạn trích đã được che, báo cáo không chứa secret gốc. Danh sách đầy đủ để giao việc: phat-hien.csv (mở bằng Excel).</p>"
      print "<script>function f(v){v=v.toLowerCase();for(const r of document.querySelectorAll(\"#t tr\")){if(r.querySelector(\"th\"))continue;r.style.display=r.textContent.toLowerCase().includes(v)?\"\":\"none\"}}</script>"
      print "</main></body></html>"
    }' "$GATE_FINDINGS_TSV" > "$out/bao-cao.html"
  cp -f "$out/bao-cao.html" "$base/moi-nhat.html" 2>/dev/null
  GATE_REPORT_OUT=$out
}

gate_report_say() {
  [ -n "${GATE_REPORT_OUT:-}" ] || return 0
  gate_say "Báo cáo: $(gate_report_winpath "$GATE_REPORT_OUT")/bao-cao.html (Excel: phat-hien.csv)"
}

gate_report_awk_hint() {
  # Hàm awk hint(id): hướng xử lý ngắn theo nhóm rule
  cat <<'AWK'
function hint(id) {
  if (id ~ /^g-secret-connstring|^g-secret-url-cred|^g-secret-oracle/) return "Đổi mật khẩu database ngay; đưa chuỗi kết nối ra biến môi trường/user-secrets; secret vẫn còn trong lịch sử git."
  if (id ~ /^g-secret-private-key/) return "Thu hồi và tạo khoá mới; gỡ khỏi repo và lịch sử git."
  if (id ~ /^g-secret-|^gl-/) return "Thu hồi/đổi secret; đọc từ biến môi trường hoặc kho secret; không để trong mã."
  if (id ~ /^g-pii-/) return "Thay bằng dữ liệu giả; không đưa dữ liệu cá nhân thật vào mã hay prompt."
  if (id ~ /^g-path-env|^g-path-appsettings|^g-path-/) return "Gỡ file khỏi repo (git rm --cached), thêm vào .gitignore, chỉ commit file mẫu (.example)."
  if (id ~ /^g-internal-ip/) return "Đưa địa chỉ vào cấu hình môi trường; nếu là tài liệu nội bộ được chấp nhận thì khai ngoại lệ."
  if (id ~ /^g-dep-unresolved/) return "Restore/cài package trên máy này rồi quét lại; kiểm tra tên package có thật."
  if (id ~ /^g-dep-/) return "Xem giấy phép/lỗ hổng của package; thay package hoặc xin ATTT duyệt."
  if (id ~ /^g-sast-/) return "Xem lại đoạn mã; sửa theo khuyến nghị bảo mật hoặc ghi lý do chấp nhận."
  if (id ~ /^g-ai-/) return "Hoàn thiện đoạn mã do AI sinh còn dở, rà lại trước khi merge."
  return "Xem lại và xử lý theo Bộ quy tắc."
}
AWK
}
