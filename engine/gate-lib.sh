#!/usr/bin/env bash
# Thư viện dùng chung của Cổng kiểm soát ATBMTT (VNPTNAN_GATE).
# Chạy được trên Git Bash (Windows), Linux (máy chủ GitLab) và macOS. Chỉ cần: bash >= 4, git, grep -E, awk, sed, wc, stat.
# Không có đầu vào/đầu ra riêng: gate-scan.sh và các hook gọi các hàm ở đây.

# ---------- Vị trí và cấu hình ----------
gate_root() {
  local here
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  echo "${GATE_ROOT:-$(dirname "$here")}"
}

GATE_ROOT=$(gate_root)
GATE_VERSION=$(cat "$GATE_ROOT/VERSION" 2>/dev/null || echo "0.0.0")
GATE_PREFIX="[VNPTNAN_GATE]"

# Giá trị mặc định; ghi đè bằng gate.conf ở gốc bộ công cụ, rồi .vnptnan-gate/gate.conf của dự án, rồi biến môi trường GATE_*.
GATE_MODE=${GATE_MODE:-}            # enforce | audit
GATE_DEPS=${GATE_DEPS:-}            # block | warn | off
GATE_DEPS_AUDIT=${GATE_DEPS_AUDIT:-} # 1 = chạy npm audit / dotnet list --vulnerable (cần mạng, chậm)
GATE_MAX_COMMITS=${GATE_MAX_COMMITS:-}
GATE_MAX_FILE=${GATE_MAX_FILE:-}    # bytes; file lớn hơn không quét theo dòng
GATE_SKIP_PATHS=${GATE_SKIP_PATHS:-}
GATE_SKIP_EXTRA=${GATE_SKIP_EXTRA:-}   # regex thêm vào SKIP_PATHS mặc định (khoá SKIP_PATHS_EXTRA trong gate.conf)
GATE_SERVER=${GATE_SERVER:-0}       # 1 khi chạy trong pre-receive của GitLab
GATE_LOG=${GATE_LOG:-}
GATE_QUIET=${GATE_QUIET:-0}

gate_load_conf_file() {
  local f=$1 key val
  [ -f "$f" ] || return 0
  while IFS='=' read -r key val || [ -n "$key" ]; do
    key=$(printf '%s' "$key" | tr -d ' \r')
    val=$(printf '%s' "$val" | sed 's/[[:space:]]*$//; s/\r$//')
    case "$key" in
      ''|'#'*) continue ;;
      MODE)        [ -z "$GATE_MODE" ] && GATE_MODE=$val ;;
      DEPS)        [ -z "$GATE_DEPS" ] && GATE_DEPS=$val ;;
      DEPS_AUDIT)  [ -z "$GATE_DEPS_AUDIT" ] && GATE_DEPS_AUDIT=$val ;;
      MAX_COMMITS) [ -z "$GATE_MAX_COMMITS" ] && GATE_MAX_COMMITS=$val ;;
      MAX_FILE)    [ -z "$GATE_MAX_FILE" ] && GATE_MAX_FILE=$val ;;
      SKIP_PATHS)  [ -z "$GATE_SKIP_PATHS" ] && GATE_SKIP_PATHS=$val ;;
      SKIP_PATHS_EXTRA) [ -z "$GATE_SKIP_EXTRA" ] && GATE_SKIP_EXTRA=$val ;;
      LOG)         [ -z "$GATE_LOG" ] && GATE_LOG=$val ;;
    esac
  done < "$f"
}

# Thứ tự ưu tiên: biến môi trường > .vnptnan-gate/gate.conf của dự án > gate.conf của bộ công cụ > mặc định.
gate_load_conf() {
  local project_root=${1:-}
  [ -n "$project_root" ] && gate_load_conf_file "$project_root/.vnptnan-gate/gate.conf"
  gate_load_conf_file "$GATE_ROOT/gate.conf"
  : "${GATE_MODE:=enforce}"
  : "${GATE_DEPS:=warn}"
  : "${GATE_DEPS_AUDIT:=0}"
  : "${GATE_MAX_COMMITS:=500}"
  : "${GATE_MAX_FILE:=5242880}"
  : "${GATE_SKIP_PATHS:=(^|/)(node_modules|bin|obj|dist|build|out|packages|\.git|vendor|coverage|TestResults)/|\.(min\.js|min\.css|map|lock|snap)$|(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|packages\.lock\.json)$|(^|/)\.vnptnan-gate/}"
  [ -n "$GATE_SKIP_EXTRA" ] && GATE_SKIP_PATHS="$GATE_SKIP_PATHS|$GATE_SKIP_EXTRA"
  if [ -z "$GATE_LOG" ]; then
    if [ "$GATE_SERVER" = "1" ]; then GATE_LOG=/var/log/vnptnan-gate/gate.log
    elif [ -n "${LOCALAPPDATA:-}" ]; then GATE_LOG="$LOCALAPPDATA/VNPTNAN_GATE/gate.log"
    else GATE_LOG="$HOME/.vnptnan-gate/gate.log"; fi
  fi
}

# ---------- Thông báo ----------
gate_say() {
  # Mọi dòng ra stderr. Trong pre-receive, GitLab chỉ hiện dòng có tiền tố GL-HOOK-ERR:.
  local line
  for line in "$@"; do
    if [ "$GATE_SERVER" = "1" ]; then printf 'GL-HOOK-ERR: %s %s\n' "$GATE_PREFIX" "$line" >&2
    else printf '%s %s\n' "$GATE_PREFIX" "$line" >&2; fi
  done
}

# ---------- Nạp rule ----------
# Mảng song song, chỉ số i: RULE_ID RULE_LEVEL RULE_KIND RULE_RE RULE_MSG
RULE_ID=(); RULE_LEVEL=(); RULE_KIND=(); RULE_RE=(); RULE_MSG=()
TEXT_BLOCK=''; TEXT_WARN=''; TEXT_AUDIT=''
# Ngoại lệ của dự án: ALLOW_ID ALLOW_PATHRE (từ .vnptnan-gate/allow.rules)
ALLOW_ID=(); ALLOW_PATHRE=()

gate_load_rules() {
  local file=${1:-$GATE_ROOT/rules/gate.rules} line id level kind re msg
  [ -f "$file" ] || { gate_say "Không tìm thấy file rule: $file"; return 2; }
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [ -z "$line" ] && continue
    case "$line" in
      '#'*) continue ;;
      '@block-suffix'*) TEXT_BLOCK=${line#*$'\t'} ; continue ;;
      '@warn-suffix'*)  TEXT_WARN=${line#*$'\t'} ; continue ;;
      '@audit-suffix'*) TEXT_AUDIT=${line#*$'\t'} ; continue ;;
      '@'*) continue ;;
    esac
    IFS=$'\t' read -r id level kind re msg <<< "$line"
    if [ -z "$id" ] || [ -z "$level" ] || [ -z "$kind" ] || [ -z "$re" ]; then
      gate_say "Dòng rule hỏng (cần 5 cột ngăn bằng TAB): $line"; return 2
    fi
    case "$level" in block|warn) ;; *) gate_say "Mức không hợp lệ '$level' ở rule $id"; return 2 ;; esac
    case "$kind" in line|path|count|size|allow|exempt|skip) ;; *) gate_say "Loại không hợp lệ '$kind' ở rule $id"; return 2 ;; esac
    RULE_ID+=("$id"); RULE_LEVEL+=("$level"); RULE_KIND+=("$kind"); RULE_RE+=("$re"); RULE_MSG+=("${msg:-}")
  done < "$file"
}

gate_load_allow() {
  # .vnptnan-gate/allow.rules trong repo: rule-id  regex-đường-dẫn  người-duyệt  lý-do
  local file=$1 line id pathre
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [ -z "$line" ] && continue
    case "$line" in '#'*) continue ;; esac
    IFS=$'\t' read -r id pathre _ <<< "$line"
    [ -n "$id" ] && [ -n "$pathre" ] || continue
    ALLOW_ID+=("$id"); ALLOW_PATHRE+=("$pathre")
  done < "$file"
}

gate_is_allowed() {
  # $1 rule id, $2 path. Đúng khi dự án đã khai ngoại lệ cho rule đó trên đường dẫn đó.
  local i
  for i in "${!ALLOW_ID[@]}"; do
    if [ "${ALLOW_ID[$i]}" = "$1" ] && printf '%s' "$2" | grep -qiE -- "${ALLOW_PATHRE[$i]}"; then return 0; fi
  done
  return 1
}

gate_path_skipped() { printf '%s' "$1" | grep -qiE -- "$GATE_SKIP_PATHS"; }

gate_path_exempt() {
  local i
  for i in "${!RULE_ID[@]}"; do
    [ "${RULE_KIND[$i]}" = exempt ] || continue
    printf '%s' "$1" | grep -qiE -- "${RULE_RE[$i]}" && return 0
  done
  return 1
}

gate_line_allowed() {
  # $1 nội dung dòng, $2 id rule đang xét. Đúng khi dòng là giá trị mẫu hoặc có gate-allow:<id>.
  local i
  # Ngoại lệ tại dòng chỉ dành cho mã nguồn (có review qua MR); prompt-check.sh tắt bằng GATE_NO_INLINE_ALLOW=1
  if [ "${GATE_NO_INLINE_ALLOW:-0}" != 1 ]; then
    printf '%s' "$1" | grep -qiE -- "gate-allow:$2([^a-z0-9-]|$)" && return 0
  fi
  for i in "${!RULE_ID[@]}"; do
    [ "${RULE_KIND[$i]}" = allow ] || continue
    printf '%s' "$1" | grep -qiE -- "${RULE_RE[$i]}" && return 0
  done
  return 1
}

# ---------- Che giá trị nhạy cảm khi in và ghi log ----------
gate_mask() {
  # In tối đa 72 ký tự của dòng, phần khớp regex được thay bằng 6 ký tự đầu + ***.
  local text=$1 re=$2 m masked
  m=$(printf '%s' "$text" | grep -oiE -- "$re" | head -n1)
  if [ -n "$m" ] && [ ${#m} -gt 8 ]; then
    masked=${text//"$m"/${m:0:6}***}
  else
    masked=$text
  fi
  masked=$(printf '%s' "$masked" | sed 's/^[[:space:]]*//')
  [ ${#masked} -gt 72 ] && masked="${masked:0:72}..."
  printf '%s' "$masked"
}

# ---------- Ghi log ----------
gate_log() {
  # stage level id decision path lineno masked
  local dir
  dir=$(dirname "$GATE_LOG")
  mkdir -p "$dir" 2>/dev/null || return 0
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GATE_VERSION" "$GATE_MODE" "$1" "$2" "$3" "$4" "${GATE_REPO_NAME:-?}" "$5" "$6" "$7" >> "$GATE_LOG" 2>/dev/null || true
}

# ---------- Kết quả ----------
GATE_N_BLOCK=0; GATE_N_WARN=0; GATE_N_ALLOWED=0
GATE_STAGE=${GATE_STAGE:-scan}
GATE_REPO_NAME=${GATE_REPO_NAME:-}

gate_report_finding() {
  # $1 level, $2 id, $3 path, $4 lineno, $5 masked text, $6 message
  local level=$1 id=$2 path=$3 ln=$4 masked=$5 msg=$6 decision tag
  if gate_is_allowed "$id" "$path"; then
    GATE_N_ALLOWED=$((GATE_N_ALLOWED + 1))
    gate_log "$GATE_STAGE" "$level" "$id" allowed "${GATE_PATH_PREFIX:-}$path" "$ln" "$masked"
    return 0
  fi
  if [ "$level" = block ] && [ "$GATE_MODE" != audit ]; then
    GATE_N_BLOCK=$((GATE_N_BLOCK + 1)); decision=block; tag=CHAN
  elif [ "$level" = block ]; then
    GATE_N_WARN=$((GATE_N_WARN + 1)); decision=audit; tag=AUDIT
  else
    GATE_N_WARN=$((GATE_N_WARN + 1)); decision=warn; tag=CANH-BAO
  fi
  gate_log "$GATE_STAGE" "$level" "$id" "$decision" "${GATE_PATH_PREFIX:-}$path" "$ln" "$masked"
  if [ -n "$ln" ]; then gate_say "$tag $id  ${GATE_PATH_PREFIX:-}$path:$ln  $msg"
  else gate_say "$tag $id  ${GATE_PATH_PREFIX:-}$path  $msg"; fi
  [ -n "$masked" ] && [ "$GATE_QUIET" != 1 ] && gate_say "    > $masked"
  return 0
}

# ---------- Quét một file ----------
# gate_scan_file <path> <file-chứa-các-dòng-cần-quét> [file-đầy-đủ] [kích-thước-bytes]
#   file-chứa-các-dòng: các dòng được thêm (diff) hoặc toàn bộ nội dung (quét cả cây); đã bỏ dấu + ở đầu.
#   file-đầy-đủ: nội dung đầy đủ để kiểm rule count/size; bỏ trống thì dùng file-chứa-các-dòng.
# Lõi Perl (engine/scan-core.pl): một tiến trình áp mọi rule của Gate và rule Gitleaks. Không có perl thì dùng bash.
gate_use_perl() {
  [ "${GATE_ENGINE:-}" = bash ] && return 1
  command -v perl >/dev/null 2>&1 && [ -f "$GATE_ROOT/engine/scan-core.pl" ]
}
gate_core_args() {
  GATE_CORE_ARGS=(--rules "$GATE_ROOT/rules/gate.rules" --skip "$GATE_SKIP_PATHS" --max-file "$GATE_MAX_FILE")
  [ -f "$GATE_ROOT/rules/gitleaks.jsonl" ] && [ "${GATE_GITLEAKS:-on}" != off ] && GATE_CORE_ARGS+=(--gitleaks "$GATE_ROOT/rules/gitleaks.jsonl")
  [ "${GATE_NO_INLINE_ALLOW:-0}" = 1 ] && GATE_CORE_ARGS+=(--no-inline-allow)
  return 0
}
gate_core_rows() {
  # Đọc kết quả của scan-core.pl từ stdin: level id path ln allowed masked msg
  local level id path ln allowed masked msg
  while IFS=$'\t' read -r level id path ln allowed masked msg; do
    [ -n "$id" ] || continue
    if [ "$allowed" = 1 ]; then
      GATE_N_ALLOWED=$((GATE_N_ALLOWED + 1))
      gate_log "$GATE_STAGE" "$level" "$id" allowed-inline "${GATE_PATH_PREFIX:-}$path" "$ln" "$masked"
    else
      gate_report_finding "$level" "$id" "$path" "$ln" "$masked" "$msg"
    fi
  done
}

gate_scan_file() {
  if gate_use_perl; then
    gate_core_args
    gate_core_rows < <(perl "$GATE_ROOT/engine/scan-core.pl" "${GATE_CORE_ARGS[@]}" --one "$1" "$2" "${3:-$2}" "${4:-}")
    return 0
  fi
  gate_scan_file_bash "$@"
}

# Bản bash (dự phòng khi máy không có perl; không có rule Gitleaks).
gate_scan_file_bash() {
  local path=$1 lines=$2 full=${3:-$2} size=${4:-} i id level kind re msg hit ln text masked n thr
  gate_path_skipped "$path" && return 0

  # Rule đường dẫn
  if ! gate_path_exempt "$path"; then
    for i in "${!RULE_ID[@]}"; do
      [ "${RULE_KIND[$i]}" = path ] || continue
      if printf '%s' "$path" | grep -qiE -- "${RULE_RE[$i]}"; then
        gate_report_finding "${RULE_LEVEL[$i]}" "${RULE_ID[$i]}" "$path" "" "" "${RULE_MSG[$i]}"
      fi
    done
  fi

  [ -s "$lines" ] || return 0
  # File nhị phân: không quét theo dòng.
  if grep -qI . "$lines" 2>/dev/null; then :; else return 0; fi
  if [ -z "$size" ]; then size=$(wc -c < "$full" | tr -d ' '); fi

  # Rule kích thước
  for i in "${!RULE_ID[@]}"; do
    [ "${RULE_KIND[$i]}" = size ] || continue
    thr=${RULE_RE[$i]%%|*}; re=${RULE_RE[$i]#*|}
    if [ "$size" -gt "$thr" ] && printf '%s' "$path" | grep -qiE -- "$re"; then
      gate_report_finding "${RULE_LEVEL[$i]}" "${RULE_ID[$i]}" "$path" "" "$size bytes" "${RULE_MSG[$i]}"
    fi
  done

  [ "$size" -gt "$GATE_MAX_FILE" ] && return 0

  # Rule đếm (trên nội dung đầy đủ)
  for i in "${!RULE_ID[@]}"; do
    [ "${RULE_KIND[$i]}" = count ] || continue
    thr=${RULE_RE[$i]%%|*}; re=${RULE_RE[$i]#*|}
    n=$(grep -ciE -- "$re" "$full" 2>/dev/null || true); n=${n:-0}
    if [ "$n" -ge "$thr" ]; then
      gate_report_finding "${RULE_LEVEL[$i]}" "${RULE_ID[$i]}" "$path" "" "$n dòng khớp (ngưỡng $thr)" "${RULE_MSG[$i]}"
    fi
  done

  # Rule theo dòng (trên các dòng được thêm)
  local skipids="" j
  for j in "${!RULE_ID[@]}"; do   # rule kind=skip: "id-regex|path-regex"
    [ "${RULE_KIND[$j]}" = skip ] || continue
    printf '%s' "$path" | grep -qiE -- "${RULE_RE[$j]#*|}" && skipids="$skipids|${RULE_RE[$j]%%|*}"
  done
  skipids=${skipids#|}
  for i in "${!RULE_ID[@]}"; do
    [ "${RULE_KIND[$i]}" = line ] || continue
    id=${RULE_ID[$i]}; level=${RULE_LEVEL[$i]}; re=${RULE_RE[$i]}; msg=${RULE_MSG[$i]}
    if [ -n "$skipids" ] && printf '%s' "$id" | grep -qiE -- "$skipids"; then continue; fi
    while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      ln=${hit%%:*}; text=${hit#*:}
      if gate_line_allowed "$text" "$id"; then
        GATE_N_ALLOWED=$((GATE_N_ALLOWED + 1))
        gate_log "$GATE_STAGE" "$level" "$id" allowed-inline "$path" "$ln" "$(gate_mask "$text" "$re")"
        continue
      fi
      masked=$(gate_mask "$text" "$re")
      gate_report_finding "$level" "$id" "$path" "$ln" "$masked" "$msg"
    done < <(grep -niE -- "$re" "$lines" 2>/dev/null | head -n 20)
  done
}

gate_summary() {
  # Trả về mã thoát: 1 nếu phải chặn, 0 nếu không.
  local what=${1:-thay đổi}
  if [ "$GATE_N_BLOCK" -gt 0 ]; then
    gate_say "Từ chối $what: $GATE_N_BLOCK vi phạm mức CHẶN, $GATE_N_WARN cảnh báo, $GATE_N_ALLOWED ngoại lệ đã khai."
    gate_say "$TEXT_BLOCK"
    return 1
  fi
  if [ "$GATE_N_WARN" -gt 0 ]; then
    if [ "$GATE_MODE" = audit ]; then gate_say "Chế độ audit: $GATE_N_WARN phát hiện, đã ghi log, cho qua. $TEXT_AUDIT"
    else gate_say "Cho qua với $GATE_N_WARN cảnh báo, $GATE_N_ALLOWED ngoại lệ đã khai. $TEXT_WARN"; fi
    return 0
  fi
  [ "$GATE_QUIET" = 1 ] || gate_say "Đạt: không phát hiện vi phạm ($GATE_N_ALLOWED ngoại lệ đã khai)."
  return 0
}
