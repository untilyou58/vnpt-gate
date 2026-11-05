#!/usr/bin/env bash
# Đóng gói VNPTNAN_GATE thành gói npm @vnptnan/gate (npmjs.com công khai; GitHub Actions gọi script này khi gắn tag).
#   bash tools/build-npm.sh                -> dist/npm/ (thư mục gói) và dist/vnptnan-gate-<ver>.tgz
#   GITHUB_REPO=owner/repo bash tools/build-npm.sh  (trong Actions tự lấy từ GITHUB_REPOSITORY)
# Phát hành: không chạy tay; đẩy tag vX.Y.Z lên GitHub, workflow release.yml build và npm publish --provenance.
# Phiên bản lấy từ file VERSION; mỗi lần phát hành phải tăng VERSION (kho không cho đè bản cũ).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VER=$(tr -d '\r\n' < "$ROOT/VERSION")
OUT="$ROOT/dist/npm"; rm -rf "$OUT"; mkdir -p "$OUT/tools"
bash "$ROOT/tools/lint-rules.sh" >/dev/null || { echo "lint-rules lỗi, không đóng gói" >&2; exit 1; }
cp -r "$ROOT"/{engine,rules,hooks,cli,installer,server,ci} "$OUT/"
cp -r "$ROOT/npm/bin" "$OUT/"
cp "$ROOT"/{gate.conf,VERSION,README.md,LICENSE} "$ROOT/npm/policy.json" "$OUT/"
cp "$ROOT/tools/lint-rules.sh" "$OUT/tools/"
python3 - "$ROOT/npm/package.template.json" "$OUT/package.json" "$VER" "${GITHUB_REPO:-${GITHUB_REPOSITORY:-OWNER/REPO}}" <<'PY'
import json, sys
p = json.load(open(sys.argv[1], encoding='utf-8')); p['version'] = sys.argv[3]
for k in ('homepage',): p[k] = p[k].replace('GITHUB_REPO', sys.argv[4])
p['repository']['url'] = p['repository']['url'].replace('GITHUB_REPO', sys.argv[4])
json.dump(p, open(sys.argv[2], 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
PY
chmod +x "$OUT/bin/cli.js"
(cd "$ROOT/dist" && npm pack ./npm --silent >/dev/null && ls -la "$ROOT/dist"/vnptnan-gate-*.tgz)
