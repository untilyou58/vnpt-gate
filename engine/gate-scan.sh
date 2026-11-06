#!/usr/bin/env bash
# Điểm vào của Cổng kiểm soát ATBMTT (VNPTNAN_GATE).
#
#   gate-scan.sh staged                 # quét thay đổi đã stage (pre-commit)
#   gate-scan.sh range <old> <new>      # quét các commit trong khoảng (pre-push); <old> có thể là 0000... (nhánh mới)
#   gate-scan.sh receive                # đọc "old new ref" từ stdin (pre-push và pre-receive của GitLab)
#   gate-scan.sh commit <sha>           # quét một commit
#   gate-scan.sh tree [thư-mục]         # quét toàn bộ cây làm việc (đánh giá repo cũ, CI)
#   gate-scan.sh deps [thư-mục]         # kiểm dependency và giấy phép
#
# Mã thoát: 0 cho qua, 1 từ chối, 2 lỗi cấu hình.
set -u
ENGINE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=gate-lib.sh
. "$ENGINE_DIR/gate-lib.sh"

mode=${1:-}
shift || true

ZERO='^0+$'
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t gate)
trap 'rm -rf "$TMP"' EXIT

repo_root() { git rev-parse --show-toplevel 2>/dev/null || pwd; }

init() {
  local root
  root=$(repo_root)
  GATE_REPO_NAME=${GL_PROJECT_PATH:-$(basename "$root")}
  gate_load_conf "$root"
  gate_load_rules || exit 2
  gate_load_allow "$root/.vnptnan-gate/allow.rules"
  # Trên server, file ngoại lệ nằm trong commit mới, đọc từ nhánh được đẩy nếu có.
  if [ "$GATE_SERVER" = 1 ] && [ -n "${GATE_ALLOW_REV:-}" ]; then
    if git cat-file -e "$GATE_ALLOW_REV:.vnptnan-gate/allow.rules" 2>/dev/null; then
      git show "$GATE_ALLOW_REV:.vnptnan-gate/allow.rules" > "$TMP/allow.rules" && gate_load_allow "$TMP/allow.rules"
    fi
  fi
}

# Các dòng được thêm của một diff, bỏ dấu +, bỏ \r. $1 ... là đối số cho git diff.
added_lines() {
  git diff --no-color --no-ext-diff -U0 --diff-filter=ACMR "$@" 2>/dev/null \
    | grep -E '^\+' | grep -vE '^\+\+\+ ' | sed 's/^+//; s/\r$//'
}

scan_staged() {
  GATE_STAGE=pre-commit
  local path blob
  while IFS= read -r -d '' path; do
    [ -n "$path" ] || continue
    added_lines --cached -- "$path" > "$TMP/lines"
    git show ":$path" > "$TMP/full" 2>/dev/null || : > "$TMP/full"
    gate_scan_file "$path" "$TMP/lines" "$TMP/full"
  done < <(git diff --cached --name-only --diff-filter=ACMR -z)
}

scan_commit() {
  # $1 sha. Commit merge chỉ quét những dòng merge tự thêm (so với cha đầu tiên).
  local sha=$1 path short
  short=$(git rev-parse --short "$sha" 2>/dev/null || echo "$sha")
  while IFS= read -r -d '' path; do
    [ -n "$path" ] || continue
    printf '%s' "$path" | grep -qiE '(^|/)(package\.json|[^/]+\.csproj|Directory\.Packages\.props|packages\.config)$' && DEPS_TOUCHED=1
    git diff --no-color --no-ext-diff -U0 --diff-filter=ACMR "$sha^" "$sha" -- "$path" 2>/dev/null \
      | grep -E '^\+' | grep -vE '^\+\+\+ ' | sed 's/^+//; s/\r$//' > "$TMP/lines"
    if ! git rev-parse -q --verify "$sha^" >/dev/null 2>&1; then
      # Commit gốc: mọi dòng đều là dòng thêm.
      git show "$sha:$path" 2>/dev/null | sed 's/\r$//' > "$TMP/lines"
    fi
    git show "$sha:$path" > "$TMP/full" 2>/dev/null || : > "$TMP/full"
    GATE_PATH_PREFIX="$short:" gate_scan_file "$path" "$TMP/lines" "$TMP/full"
  done < <(git diff-tree -r -z --no-commit-id --name-only --diff-filter=ACMR --root "$sha" 2>/dev/null)
}

scan_range() {
  # $1 old, $2 new, $3 ref (tuỳ chọn)
  local old=$1 new=$2 ref=${3:-} list n=0
  if printf '%s' "$new" | grep -qE "$ZERO"; then return 0; fi   # xoá nhánh: không có gì để quét
  if printf '%s' "$old" | grep -qE "$ZERO"; then
    # Nhánh mới: chỉ các commit chưa có ở bất kỳ ref nào khác.
    if [ "$GATE_SERVER" = 1 ]; then list=$(git rev-list "$new" --not --all 2>/dev/null)
    else list=$(git rev-list "$new" --not --remotes 2>/dev/null); fi
  else
    list=$(git rev-list "$old..$new" 2>/dev/null)
  fi
  [ -n "$list" ] || return 0
  n=$(printf '%s\n' "$list" | wc -l | tr -d ' ')
  if [ "$n" -gt "$GATE_MAX_COMMITS" ]; then
    gate_say "Khoảng đẩy có $n commit, chỉ quét $GATE_MAX_COMMITS commit mới nhất (MAX_COMMITS). Phần còn lại cần quét bằng: vnptnan-gate scan tree"
    list=$(printf '%s\n' "$list" | head -n "$GATE_MAX_COMMITS")
  fi
  [ -n "$ref" ] && [ "$GATE_QUIET" != 1 ] && gate_say "Quét $n commit lên $ref"
  GATE_ALLOW_REV=$new
  while IFS= read -r sha; do [ -n "$sha" ] && scan_commit "$sha"; done <<< "$list"
  # Dependency: chỉ trên máy dev (server không có node_modules/NuGet cache) và chỉ khi khoảng đẩy có đổi file khai báo package.
  if [ "$GATE_DEPS" != off ] && [ "$GATE_SERVER" != 1 ] && [ "${DEPS_TOUCHED:-0}" = 1 ]; then
    deps_check "$(repo_root)"
  fi
}

scan_receive() {
  local old new ref
  GATE_STAGE=${GATE_STAGE_NAME:-pre-push}
  [ "$GATE_SERVER" = 1 ] && GATE_STAGE=pre-receive
  local a b c d
  while read -r a b c d; do
    [ -n "$c" ] || continue
    if [ -n "$d" ]; then
      # pre-push của git: local_ref local_sha remote_ref remote_sha
      scan_range "$d" "$b" "$c"
    else
      # pre-receive của GitLab: old new ref
      scan_range "$a" "$b" "$c"
    fi
  done
}

scan_tree() {
  local dir=${1:-.} f rel size
  GATE_STAGE=tree
  dir=$(cd "$dir" && pwd)
  if git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    # File git theo dõi + file chưa theo dõi nhưng không bị ignore.
    git -C "$dir" ls-files -z --cached --others --exclude-standard
  else
    find "$dir" -type f -print0
  fi > "$TMP/files"
  if gate_use_perl; then
    # Cả cây trong một tiến trình perl: đọc thẳng file trên đĩa, không chép tạm
    gate_core_args
    while IFS= read -r -d '' f; do
      [ -n "$f" ] || continue
      rel=${f#"$dir"/}
      case "$rel" in *$'\t'*|*$'\n'*) continue ;; esac
      printf '\t%s\t%s\t%s\n' "$dir/$rel" "$dir/$rel" "$rel"
    done < "$TMP/files" > "$TMP/list"
    # Tiến độ: mặc định chỉ hiện khi chạy trong terminal; GATE_PROGRESS=1 bật, =0 tắt
    if [ "${GATE_PROGRESS:-auto}" = 1 ] || { [ "${GATE_PROGRESS:-auto}" = auto ] && [ -t 2 ] && [ "${GATE_QUIET:-0}" != 1 ]; }; then
      GATE_CORE_ARGS+=(--progress "$(wc -l < "$TMP/list" | tr -d ' ')")
    fi
    gate_core_rows < <(perl "$GATE_ROOT/engine/scan-core.pl" "${GATE_CORE_ARGS[@]}" --list < "$TMP/list")
  else
    while IFS= read -r -d '' f; do
      [ -n "$f" ] || continue
      rel=${f#"$dir"/}
      [ -f "$dir/$rel" ] || continue
      size=$(wc -c < "$dir/$rel" | tr -d ' ')
      sed 's/\r$//' "$dir/$rel" > "$TMP/lines" 2>/dev/null || continue
      gate_scan_file "$rel" "$TMP/lines" "$TMP/lines" "$size"
    done < "$TMP/files"
  fi
  [ "$GATE_DEPS" != off ] && deps_check "$dir"
}

deps_check() {
  # shellcheck source=gate-deps.sh
  . "$ENGINE_DIR/gate-deps.sh"
  gate_deps_scan "$1"
}

case "$mode" in
  staged)  init; scan_staged; gate_summary "commit" ;;
  range)   init; GATE_STAGE=pre-push; scan_range "${1:?old}" "${2:?new}" "${3:-}"; gate_summary "push" ;;
  receive) init; scan_receive; gate_summary "push" ;;
  commit)  init; GATE_STAGE=commit; scan_commit "${1:?sha}"; gate_summary "commit" ;;
  tree)    init; scan_tree "${1:-.}"; gate_summary "cây làm việc" ;;
  deps)    init; GATE_STAGE=deps; deps_check "${1:-$(repo_root)}"; gate_summary "dependency" ;;
  version) echo "VNPTNAN_GATE $GATE_VERSION" ;;
  *) echo "Cách dùng: gate-scan.sh staged | range <old> <new> | receive | commit <sha> | tree [dir] | deps [dir]" >&2; exit 2 ;;
esac
