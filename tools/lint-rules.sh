#!/usr/bin/env bash
# Kiểm tra cú pháp các file rule: đúng số cột, mức và loại hợp lệ, regex biên dịch được bằng grep -E, id không trùng và đều bắt đầu bằng g-.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
err=0
check_regex() { printf 'x' | grep -qiE -- "$1" 2>/dev/null; [ $? -le 1 ]; }

ids=()
while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}
  [ -z "$line" ] && continue
  case "$line" in '#'*|'@'*) continue ;; esac
  IFS=$'\t' read -r id level kind re msg <<< "$line"
  [ "$(printf '%s' "$line" | awk -F'\t' '{print NF}')" = 5 ] || { echo "gate.rules: sai số cột: $line"; err=1; }
  case "$id" in g-*) ;; *) echo "gate.rules: id phải bắt đầu bằng g- (tránh trùng VNPTNAN_HARNESS): $id"; err=1 ;; esac
  for x in "${ids[@]:-}"; do [ "$x" = "$id" ] && { echo "gate.rules: id trùng: $id"; err=1; }; done
  ids+=("$id")
  case "$level" in block|warn) ;; *) echo "gate.rules: mức sai ở $id: $level"; err=1 ;; esac
  case "$kind" in
    line|path|allow|exempt) check_regex "$re" || { echo "gate.rules: regex không hợp lệ ở $id"; err=1; } ;;
    count|size) case "$re" in [0-9]*'|'*) check_regex "${re#*|}" || { echo "gate.rules: regex không hợp lệ ở $id"; err=1; } ;; *) echo "gate.rules: $kind cần dạng N|regex ở $id"; err=1 ;; esac ;;
    *) echo "gate.rules: loại sai ở $id: $kind"; err=1 ;;
  esac
  printf '%s' "$re" | grep -qE '\\[dwsb]|\(\?' && { echo "gate.rules: $id dùng \\d \\w \\s \\b hoặc (?...) không có trong POSIX ERE"; err=1; }
done < "$ROOT/rules/gate.rules"

while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}
  [ -z "$line" ] && continue
  case "$line" in '#'*) continue ;; esac
  IFS=$'\t' read -r t l re msg <<< "$line"
  case "$t" in deny-license|deny-package|allow-registry) ;; *) echo "packages.rules: loại sai: $t"; err=1 ;; esac
  case "$l" in block|warn) ;; *) echo "packages.rules: mức sai: $l"; err=1 ;; esac
  check_regex "$re" || { echo "packages.rules: regex không hợp lệ: $re"; err=1; }
done < "$ROOT/rules/packages.rules"

[ "$err" = 0 ] && echo "rules ok: ${#ids[@]} rule" || exit 1
