#!/usr/bin/env bash
# Chạy toàn bộ kiểm thử của VNPTNAN_GATE: (1) ca rule trong cases.tsv, (2) tích hợp hook trên repo tạm.
# Cách chạy: bash tests/run-tests.sh   (Git Bash trên Windows, hoặc Linux)
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $*"; }

echo "== 1. Ca rule (tests/cases.tsv)"
run_case() {
  # $1 kind, $2 input. In ra danh sách "id level" phát hiện được.
  ( GATE_LOG=/dev/null GATE_QUIET=1 GATE_MODE=enforce
    . "$ROOT/engine/gate-lib.sh"; gate_load_conf ""; gate_load_rules >/dev/null || exit 2
    GATE_SKIP_PATHS='(^|/)node_modules/'
    tmp=$(mktemp)
    if [ "$1" = path ]; then gate_scan_file "$2" /dev/null /dev/null 0
    elif [ "${1#file:}" != "$1" ]; then printf '%s\n' "$2" > "$tmp"; gate_scan_file "${1#file:}" "$tmp" "$tmp" ${#2}
    else printf '%s\n' "$2" > "$tmp"; gate_scan_file test.cs "$tmp" "$tmp" ${#2}; fi
    rm -f "$tmp"
  ) 2>&1 | sed -nE 's/^\[VNPTNAN_GATE\] (CHAN|CANH-BAO) ([a-z0-9-]+) .*/\2 \1/p'
}
n=0
while IFS=$'\t' read -r kind input want level; do
  [ -n "$kind" ] || continue
  case "$kind" in '#'*) continue ;; esac
  n=$((n + 1))
  got=$(run_case "$kind" "$input")
  wantlvl=$([ "$level" = block ] && echo CHAN || echo CANH-BAO)
  [ "$want" = "-" ] || [ -n "$got" ] || [ "${GATE_ENGINE:-}" = bash ] || true
  if [ "$want" = "-" ]; then
    if [ -z "$got" ]; then ok; else fail "[$kind] '$input' phải không khớp, lại ra: $(echo "$got" | tr '\n' ' ')"; fi
  else
    if printf '%s\n' "$got" | grep -qx "$want $wantlvl"; then ok; else fail "[$kind] '$input' mong $want $wantlvl, ra: ${got:-(không gì)}"; fi
  fi
done < "$ROOT/tests/cases.tsv"
echo "  $n ca, đạt $PASS, lỗi $FAIL"

echo "== 2. Tích hợp hook trên repo tạm"
T=$(mktemp -d); export HOME_SAVED=$HOME
export GATE_LOG="$T/gate.log"
# Bản sao riêng của bộ công cụ: hook bỏ qua biến GATE_*, nên chế độ đổi qua gate.conf của bản sao.
TOOL="$T/tool"; cp -r "$ROOT" "$TOOL"; rm -rf "$TOOL/.git"
sed -i 's/^MODE=.*/MODE=enforce/; s/^DEPS=.*/DEPS=off/' "$TOOL/gate.conf"
git init -q --bare -b main "$T/remote.git"
git clone -q "$T/remote.git" "$T/work" 2>/dev/null
cd "$T/work" || exit 1
git config user.name tester; git config user.email tester@example.invalid; git config commit.gpgsign false
VNPTNAN_GATE_HOME=$TOOL bash "$TOOL/cli/vnptnan-gate" install-hooks >/dev/null

echo "# demo" > README.md; git add README.md
if git commit -q -m "init" 2>/dev/null; then ok; else fail "commit sạch bị chặn"; fi

printf 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n' > config.txt; git add config.txt
if git commit -q -m "leak" 2>"$T/err"; then fail "pre-commit không chặn secret"; else ok; grep -q g-secret-aws "$T/err" && ok || fail "thiếu mã rule trong thông báo"; fi
git reset -q config.txt; rm config.txt

cp /dev/null .env 2>/dev/null; echo "X=1" > .env; git add -f .env
if git commit -q -m "env" 2>/dev/null; then fail "pre-commit không chặn .env"; else ok; fi
git reset -q .env; rm .env

# Chế độ audit: cho qua nhưng ghi log
printf 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n' > audit.txt; git add audit.txt
sed -i "s/^MODE=.*/MODE=audit/" "$TOOL/gate.conf"
if git commit -q -m "audit" 2>/dev/null; then ok; else fail "audit mode vẫn chặn"; fi
( cd "$T/work" && VNPTNAN_GATE_HOME=$TOOL bash "$TOOL/cli/vnptnan-gate" doctor 2>&1 ) | grep -q '\[ok\] engine' && ok || fail "doctor ở chế độ audit báo nhầm engine lỗi"
sed -i "s/^MODE=.*/MODE=enforce/" "$TOOL/gate.conf"
grep -q $'\taudit\t' "$GATE_LOG" && ok || fail "audit không ghi log"
# Hạ cổng bằng biến môi trường khi không ở chế độ test: phải KHÔNG có tác dụng
printf 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n' > env.txt; git add env.txt
if GATE_MODE=audit GATE_SKIP_EXTRA=. git commit -q -m "env-bypass" 2>/dev/null; then fail "GATE_MODE=audit vượt được cổng"; git reset -q --hard HEAD~1; else ok; git reset -q env.txt; rm -f env.txt; fi
# Rule nhập từ Gitleaks: token Stripe (Gate không có rule riêng) phải bị chặn; GATE_GITLEAKS=off không được tắt
if command -v perl >/dev/null 2>&1; then
  stripe=$(awk -F'\t' '$1=="gl-stripe-access-token"{print $2}' "$ROOT/tests/gitleaks-cases.tsv" | perl -MMIME::Base64 -ne 'print scalar reverse decode_base64($_)')
  printf 'const k = "%s";\n' "$stripe" > pay.js; git add pay.js
  if GATE_GITLEAKS=off GATE_ENGINE=bash git commit -q -m "stripe" 2>"$T/err"; then fail "token Stripe (rule Gitleaks) lọt qua, hoặc GATE_GITLEAKS=off tắt được"; git reset -q --hard HEAD~1
  else ok; grep -q gl-stripe-access-token "$T/err" && ok || fail "thiếu mã gl-stripe-access-token trong thông báo"; git reset -q pay.js; rm -f pay.js; fi
fi
git reset -q --hard HEAD~1   # bỏ commit audit khỏi lịch sử, vì pre-push ở chế độ enforce sẽ bắt lại (đúng thiết kế)

# Ngoại lệ dự án
mkdir -p .vnptnan-gate; printf 'g-secret-aws\t^fixtures/\ttester\tdữ liệu giả cho test\n' > .vnptnan-gate/allow.rules
mkdir -p fixtures; printf 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\n' > fixtures/aws.txt; git add .vnptnan-gate fixtures
if git commit -q -m "fixture" 2>/dev/null; then ok; else fail "allow.rules không có hiệu lực"; fi

# Trailer AI-Assisted
echo a >> README.md; git add README.md
git commit -q -m "feat: x" -m "Co-Authored-By: Claude <noreply@anthropic.com>" 2>/dev/null
git log -1 --format=%B | grep -q '^AI-Assisted: Claude' && ok || fail "commit-msg không thêm trailer AI-Assisted"

# Commit bằng plumbing (như Harness ghi tri thức) bỏ qua pre-commit, pre-push phải bắt
printf 'glpat-abcdefghijklmnopqrstuvwx\n' > brain.md
blob=$(git hash-object -w brain.md); git update-index --add --cacheinfo 100644 "$blob" brain.md
tree=$(git write-tree); c=$(git commit-tree "$tree" -p HEAD -m "plumbing"); git update-ref HEAD "$c"
if git push -q origin main 2>"$T/err"; then fail "pre-push không chặn commit plumbing"; else ok; grep -q g-secret-gitlab "$T/err" && ok || fail "pre-push thiếu mã rule"; fi
git reset -q --hard HEAD~1
if git push -q origin main 2>/dev/null; then ok; else fail "push sạch bị chặn"; fi

# pre-receive trên server (mô phỏng GitLab: hook trong repo bare)
mkdir -p "$T/remote.git/hooks"
printf '#!/bin/sh\nVNPTNAN_GATE_HOME=%s GATE_LOG=%s exec bash %s/server/pre-receive\n' "$TOOL" "$T/server.log" "$TOOL" > "$T/remote.git/hooks/pre-receive"
chmod +x "$T/remote.git/hooks/pre-receive"
rm -f .git/hooks/pre-push .git/hooks/pre-commit   # giả lập máy dev không cài gate
printf 'xoxb-123456789012-abcdefghijkl\n' > slack.txt; git add slack.txt; git commit -q -m "slack" 2>/dev/null
if git push -q origin main 2>"$T/err"; then fail "pre-receive không chặn"; else ok; grep -q 'GL-HOOK-ERR: .*g-secret-slack' "$T/err" && ok || fail "pre-receive thiếu tiền tố GL-HOOK-ERR"; fi
git reset -q --hard HEAD~1
git checkout -q -b feature/new; echo b > b.txt; git add b.txt; git commit -q -m "b"
if git push -q origin feature/new 2>/dev/null; then ok; else fail "pre-receive chặn nhầm nhánh mới sạch"; fi

# Tiện ích
VNPTNAN_GATE_HOME=$ROOT bash "$ROOT/cli/vnptnan-gate" test 'password = "Vnpt@NgheAn2026"' 2>&1 | grep -q g-secret-password && ok || fail "vnptnan-gate test"
VNPTNAN_GATE_HOME=$ROOT bash "$ROOT/cli/vnptnan-gate" report 1 >/dev/null 2>&1 && ok || fail "vnptnan-gate report"
bash "$ROOT/tools/lint-rules.sh" >/dev/null 2>&1 && ok || fail "lint-rules"

cd / && rm -rf "$T"
echo "== 3. Kiểm tra prompt (tests/prompt-cases.tsv)"
PL=$(mktemp)
while IFS=$'\t' read -r want text; do
  [ -n "$want" ] || continue; case "$want" in '#'*) continue ;; esac
  text=${text//\\n/$'\n'}
  out=$(python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"UserPromptSubmit","prompt":sys.argv[1]}, ensure_ascii=True))' "$text" \
        | GATE_LOG=$PL bash "$ROOT/engine/prompt-check.sh" --agent claude 2>/dev/null)
  if [ "$want" = allow ]; then [ -z "$out" ] && ok || fail "prompt bị chặn nhầm: $text"
  else printf '%s' "$out" | grep -q '"decision":"block"' && printf '%s' "$out" | grep -q -- "$want" && ok || fail "prompt không chặn $want: $text"; fi
done < "$ROOT/tests/prompt-cases.tsv"
out=$(echo '{bad json' | GATE_LOG=$PL bash "$ROOT/engine/prompt-check.sh" --agent codex 2>/dev/null; echo "rc=$?")
[ "$out" = "rc=0" ] && ok || fail "JSON hỏng phải cho qua với mã 0"
rm -f "$PL"

echo "== 4. Rule nhập từ Gitleaks (tests/gitleaks-cases.tsv: một mẫu sinh tự động cho mỗi rule)"
if command -v perl >/dev/null 2>&1; then
  GD=$(mktemp -d); : > "$GD/list"; declare -A WANT=(); k=0
  while IFS=$'\t' read -r id enc; do
    [ -n "$id" ] || continue; case "$id" in '#'*) continue ;; esac
    k=$((k + 1)); printf '%s\n' "$enc" | perl -MMIME::Base64 -ne 'print scalar(reverse decode_base64($_)), "\n"' > "$GD/s$k.txt"
    WANT[s$k.txt]=$id; printf '\t%s\t%s\t%s\n' "$GD/s$k.txt" "$GD/s$k.txt" "s$k.txt" >> "$GD/list"
  done < "$ROOT/tests/gitleaks-cases.tsv"
  perl "$ROOT/engine/scan-core.pl" --gitleaks "$ROOT/rules/gitleaks.jsonl" --list < "$GD/list" | grep -v "^@stat" | cut -f2,3 | sort -u > "$GD/got"
  miss=0
  for f in "${!WANT[@]}"; do grep -qxF "${WANT[$f]}"$'\t'"$f" "$GD/got" || { miss=$((miss + 1)); [ $miss -le 5 ] && echo "  FAIL: ${WANT[$f]} không bắt được mẫu của chính nó"; }; done
  [ $miss = 0 ] && ok || { FAIL=$((FAIL + 1)); echo "  $miss/$k mẫu không bắt được"; }
  # Chống báo nhầm: mã nguồn của chính bộ công cụ không được khớp rule Gitleaks nào
  ( cd "$ROOT" && git ls-files 2>/dev/null | grep -vE '^(tests/|rules/)' || find . -type f ! -path './.git/*' ! -path './tests/*' ! -path './rules/*' | sed 's|^\./||' ) \
    | while IFS= read -r p; do printf '\t%s\t%s\t%s\n' "$ROOT/$p" "$ROOT/$p" "$p"; done > "$GD/self"
  fp=$(perl "$ROOT/engine/scan-core.pl" --gitleaks "$ROOT/rules/gitleaks.jsonl" --list < "$GD/self" | grep -v "^@stat" | grep -v $'\t1\t' | cut -f2,3 | head -n 5)
  [ -z "$fp" ] && ok || fail "rule Gitleaks báo nhầm trên mã của bộ công cụ: $fp"
  echo "  $k mẫu"
  rm -rf "$GD"
else
  echo "  bỏ qua: máy không có perl"
fi

echo "== 6. Kiểm tra package NuGet (cache, giấy phép, báo trùng)"
D=$(mktemp -d); mkdir -p "$D/r/p/obj" "$D/c/okpkg/1.0.0" "$D/c/msft.lib/2.0.0" "$D/c/gplpkg/1.0.0"
printf '<Project><ItemGroup>\n<PackageReference Include="OkPkg" Version="1.0.0" />\n<PackageReference Include="Msft.Lib" Version="2.0.0" />\n<PackageReference Include="GplPkg" Version="1.0.0" />\n<PackageReference Include="Bia.Ten" Version="9.9.9" />\n</ItemGroup></Project>\n' > "$D/r/p/p.csproj"
printf '<package><metadata><license type="expression">MIT</license></metadata></package>' > "$D/c/okpkg/1.0.0/okpkg.nuspec"
printf '<package><metadata><licenseUrl>https://go.microsoft.com/fwlink/?LinkId=329770</licenseUrl></metadata></package>' > "$D/c/msft.lib/2.0.0/msft.lib.nuspec"
printf '<package><metadata><license type="expression">GPL-3.0-only</license></metadata></package>' > "$D/c/gplpkg/1.0.0/gplpkg.nuspec"
printf '{\r\n  "packageFolders": {\r\n    "/khong/co/": {},\r\n    "%s/": {}\r\n  },\r\n  "project": {}\r\n}\r\n' "$D/c" > "$D/r/p/obj/project.assets.json"
out=$(cd "$D/r" && HOME="$D/none" USERPROFILE= NUGET_PACKAGES= VNPTNAN_GATE_HOME="$ROOT" GATE_LOG=/dev/null GATE_DEPS=warn bash "$ROOT/cli/vnptnan-gate" deps . 2>&1)
if [ "$(printf '%s\n' "$out" | grep -c 'g-dep-')" = 2 ] && printf '%s' "$out" | grep -q 'GplPkg@1.0.0 license=GPL' && printf '%s' "$out" | grep -q 'g-dep-unresolved.*' && printf '%s' "$out" | grep -q 'Bia.Ten@9.9.9 không có'; then ok; else FAIL=$((FAIL + 1)); echo "  LỖI deps NuGet:"; printf '%s\n' "$out"; fi
# Restore ở môi trường khác (WSL/container): project.assets.json có tên package nhưng cache không đọc được -> một dòng
mkdir -p "$D/r2/q/obj"
printf '<Project><ItemGroup>\n<PackageReference Include="Xunit" Version="2.5.3" />\n<PackageReference Include="Npgsql" Version="10.0.0" />\n</ItemGroup></Project>\n' > "$D/r2/q/q.csproj"
printf '{\n  "version": 3,\n  "targets": {},\n  "libraries": {\n    "xunit/2.5.3": {\n      "type": "package"\n    },\n    "Npgsql/10.0.0": {\n      "type": "package"\n    }\n  },\n  "projectFileDependencyGroups": {},\n  "packageFolders": {\n    "/home/dev/.nuget/packages/": {}\n  }\n}\n' > "$D/r2/q/obj/project.assets.json"
out=$(cd "$D/r2" && HOME="$D/none" USERPROFILE= NUGET_PACKAGES= VNPTNAN_GATE_HOME="$ROOT" GATE_LOG=/dev/null GATE_DEPS=warn bash "$ROOT/cli/vnptnan-gate" deps . 2>&1)
if [ "$(printf '%s\n' "$out" | grep -c 'g-dep-')" = 1 ] && printf '%s' "$out" | grep -q '2 package đã restore ở môi trường khác (/home/dev/.nuget/packages/)'; then ok; else FAIL=$((FAIL + 1)); echo "  LỖI deps NuGet (restore nơi khác):"; printf '%s\n' "$out"; fi
rm -rf "$D"

echo "== 5. Bộ lọc gateway (gateway/litellm/gate_masker.py)"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
  if out=$(PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tests/gateway/test_gate_masker.py" 2>&1); then ok; echo "  $out"; else FAIL=$((FAIL + 1)); echo "$out"; fi
else
  echo "  bỏ qua: cần Python 3.10 trở lên"
fi

echo
echo "Tổng: đạt $PASS, lỗi $FAIL"
[ "$FAIL" = 0 ]
