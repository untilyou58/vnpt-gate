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

# Rule nhập từ Gitleaks: mọi regex biên dịch được bằng Perl, .pldata khớp .jsonl, id bắt đầu bằng gl- và không trùng
nglr=0
if [ -f "$ROOT/rules/gitleaks.jsonl" ]; then
  if command -v perl >/dev/null 2>&1; then
    nglr=$(perl -e '
      use strict; use warnings; use File::Spec; my ($j, $p) = @ARGV; my $err = 0; my %seen;
      my $d = do File::Spec->rel2abs($p) or die "gitleaks.pldata không nạp được: $@\n";
      my @ids;
      for my $o (@$d) {
        next if $o->{_meta};
        for my $a ($o->{_global} ? ($o->{_global}) : @{ $o->{allow} || [] }) {
          for my $x (@{ $a->{regexes} || [] }, @{ $a->{paths} || [] }) { eval { qr/$x/ } or do { print STDERR "gitleaks: ngoại lệ hỏng: $x\n"; $err = 1 } }
        }
        next unless $o->{id};
        push @ids, $o->{id};
        $o->{id} =~ /^gl-/ or do { print STDERR "gitleaks: id phải bắt đầu bằng gl-: $o->{id}\n"; $err = 1 };
        $seen{ $o->{id} }++ and do { print STDERR "gitleaks: id trùng: $o->{id}\n"; $err = 1 };
        $o->{level} =~ /^(block|warn)$/ or do { print STDERR "gitleaks: mức sai ở $o->{id}\n"; $err = 1 };
        for my $x (grep { defined } $o->{re}, $o->{path}) { eval { qr/$x/ } or do { print STDERR "gitleaks: regex hỏng ở $o->{id}: $@"; $err = 1 } }
      }
      open my $f, "<", $j or die; my $n = grep { /"id": "gl-/ } <$f>;
      $n == @ids or do { print STDERR "gitleaks.pldata ($#ids+1) không khớp gitleaks.jsonl ($n): chạy lại tools/import-gitleaks.py\n"; $err = 1 };
      print scalar @ids; exit $err;
    ' "$ROOT/rules/gitleaks.jsonl" "$ROOT/rules/gitleaks.pldata") || err=1
  else
    echo "  (bỏ qua kiểm tra gitleaks.jsonl: máy không có perl)"
  fi
fi

[ "$err" = 0 ] && echo "rules ok: ${#ids[@]} rule${nglr:+ + $nglr rule Gitleaks}" || exit 1
