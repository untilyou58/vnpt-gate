#!/usr/bin/env bash
# Kiểm tra thành phần bên thứ ba (dependency) và giấy phép, chạy offline trên máy dev.
# Nguồn: package.json + node_modules (npm), *.csproj + cache NuGet (~/.nuget/packages). Rule: rules/packages.rules.
# Được gate-scan.sh nạp (source), dùng các hàm của gate-lib.sh.

PKG_TYPE=(); PKG_LEVEL=(); PKG_RE=(); PKG_MSG=()

deps_load_rules() {
  local file=$GATE_ROOT/rules/packages.rules line t l re msg
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [ -z "$line" ] && continue
    case "$line" in '#'*) continue ;; esac
    IFS=$'\t' read -r t l re msg <<< "$line"
    [ -n "$t" ] && [ -n "$l" ] && [ -n "$re" ] || continue
    PKG_TYPE+=("$t"); PKG_LEVEL+=("$l"); PKG_RE+=("$re"); PKG_MSG+=("${msg:-}")
  done < "$file"
}

deps_level() {
  # Mức của rule, hạ xuống warn nếu GATE_DEPS=warn.
  if [ "$GATE_DEPS" = warn ]; then echo warn; else echo "$1"; fi
}

deps_check_one() {
  # $1 hệ (npm|nuget), $2 tên, $3 phiên bản, $4 giấy phép ("" nếu không rõ), $5 đường dẫn file khai báo
  # $6=nolic: package chưa restore, không biết giấy phép -> chỉ kiểm tên (g-dep-unresolved đã báo riêng)
  local eco=$1 name=$2 ver=$3 lic=$4 src=$5 nolic=${6:-} i
  for i in "${!PKG_TYPE[@]}"; do
    case "${PKG_TYPE[$i]}" in
      deny-package)
        if printf '%s@%s' "$name" "$ver" | grep -qiE -- "${PKG_RE[$i]}" || printf '%s' "$name" | grep -qiE -- "${PKG_RE[$i]}"; then
          gate_report_finding "$(deps_level "${PKG_LEVEL[$i]}")" "g-dep-package" "$src" "" "$eco $name@$ver" "${PKG_MSG[$i]}"
        fi ;;
      deny-license)
        # DEPS_LICENSE: off = không kiểm giấy phép; known = chỉ báo giấy phép ĐỌC ĐƯỢC và nằm trong danh sách
        # (GPL, AGPL...); all = báo cả package không rõ giấy phép (nhiều package cũ chỉ khai licenseUrl/file)
        [ "$GATE_DEPS_LICENSE" = off ] && continue
        [ "$nolic" = nolic ] && continue
        if [ "$GATE_DEPS_LICENSE" != all ] && printf '%s\n' "$lic" | grep -qiE '^(UNLICENSED|UNKNOWN|SEE LICENSE|NONE)?$'; then continue; fi
        if printf '%s\n' "$lic" | grep -qiE -- "${PKG_RE[$i]}"; then
          gate_report_finding "$(deps_level "${PKG_LEVEL[$i]}")" "g-dep-license" "$src" "" "$eco $name@$ver license=${lic:-?}" "${PKG_MSG[$i]}"
        fi ;;
    esac
  done
}

deps_json_field() {
  # Lấy giá trị chuỗi của khoá cấp 1 trong file JSON nhỏ (đủ cho package.json). $1 file, $2 khoá.
  tr -d '\n\r' < "$1" | sed 's/[{},]/&\n/g' | sed -n 's/^[[:space:]]*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
}

deps_npm() {
  local dir=$1 pj name ver lic nm block
  while IFS= read -r pj; do
    [ -n "$pj" ] || continue
    nm=$(dirname "$pj")/node_modules
    # Lấy tên các dependency trực tiếp (dependencies + devDependencies): dòng dạng "ten": "ver" nằm giữa hai khối.
    # Chuẩn hoá JSON về mỗi phần tử một dòng (package.json có thể nằm trên một dòng) rồi lấy khối dependencies.
    if command -v node >/dev/null 2>&1; then
      # Có node: đọc JSON chuẩn (khối lồng nhau như overrides, ký tự đặc biệt không làm sai)
      block=$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));for(const k of ["dependencies","devDependencies","optionalDependencies"])for(const [n,v] of Object.entries(p[k]||{}))console.log(JSON.stringify(n)+": "+JSON.stringify(String(v)))' "$pj" 2>/dev/null)
    else
      block=$(tr -d '\n\r' < "$pj" | sed 's/[{},]/&\n/g' | awk '/"(dependencies|devDependencies|optionalDependencies)"[[:space:]]*:/{f=1;next} f{print; if (/[}]/) f=0}')
    fi
    # Không có node_modules nào (từ thư mục của package.json lên tới gốc): chưa npm install -> một cảnh báo cho cả file
    nm=$(dirname "$pj"); while [ ! -d "$nm/node_modules" ] && [ "$nm" != "$dir" ] && [ "$nm" != "${nm%/*}" ]; do nm=${nm%/*}; done
    if [ ! -d "$nm/node_modules" ]; then
      local cnt
      cnt=$(printf '%s\n' "$block" | grep -c '^[[:space:]]*"[^"]*"[[:space:]]*:' || true)
      if [ "${cnt:-0}" -gt 0 ]; then
        while IFS= read -r line; do
          name=$(printf '%s' "$line" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p'); [ -n "$name" ] || continue
          deps_check_one npm "$name" "?" "" "${pj#"$dir"/}" nolic
        done <<< "$block"
        gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${pj#"$dir"/}" "" "chưa npm install: $cnt package chưa kiểm được tên và giấy phép" "Chạy npm install (hoặc npm ci) trên máy này rồi quét lại (cổng đọc giấy phép từ node_modules; AI hay bịa tên package)."
      fi
      continue
    fi
    while IFS= read -r line; do
      name=$(printf '%s' "$line" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p')
      [ -n "$name" ] || continue
      # workspaces/monorepo: package có thể được cài ở node_modules của thư mục cha (tới gốc repo)
      nm=$(dirname "$pj"); while [ ! -f "$nm/node_modules/$name/package.json" ] && [ "$nm" != "$dir" ] && [ "$nm" != "${nm%/*}" ]; do nm=${nm%/*}; done
      nm=$nm/node_modules
      if [ -f "$nm/$name/package.json" ]; then
        ver=$(deps_json_field "$nm/$name/package.json" version)
        lic=$(deps_json_field "$nm/$name/package.json" license)
        [ -z "$lic" ] && lic=$(tr -d '\n\r' < "$nm/$name/package.json" | sed -n 's/.*"license"[[:space:]]*:[[:space:]]*{[^}]*"type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        deps_check_one npm "$name" "${ver:-?}" "$lic" "${pj#"$dir"/}"
      else
        ver=$(printf '%s' "$line" | sed -n 's/^[^:]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        deps_check_one npm "$name" "${ver:-?}" "" "${pj#"$dir"/}" nolic
        gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${pj#"$dir"/}" "" "npm $name@${ver:-?} chưa có trong node_modules" "Package chưa được cài: kiểm tra tên có thật trên registry (AI hay bịa tên package) rồi npm install trước khi push."
      fi
    done <<< "$block"
    if [ "$GATE_DEPS_AUDIT" = 1 ] && command -v npm >/dev/null 2>&1 && [ -d "$nm" ]; then
      if ! (cd "$(dirname "$pj")" && npm audit --audit-level=high >/dev/null 2>&1); then
        gate_report_finding "$(deps_level block)" "g-dep-vulnerable" "${pj#"$dir"/}" "" "npm audit --audit-level=high" "Có lỗ hổng mức high/critical trong dependency npm."
      fi
    fi
  done < <(find "$dir" -name package.json -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
}

deps_winpath() {
  # Đường dẫn Windows (C:\...) -> dạng bash hiểu được (Git Bash: /c/...). Trên Linux giữ nguyên.
  local p=$1
  case "$p" in
    [A-Za-z]:[\\/]*) if command -v cygpath >/dev/null 2>&1; then cygpath -u "$p"; else printf '%s\n' "$p" | tr '\\' '/'; fi ;;
    *) printf '%s\n' "$p" ;;
  esac
}

deps_nuget_dirs() {
  # Các thư mục package NuGet có thể có, theo thứ tự tin cậy. $1 thư mục chứa .csproj
  local pdir=$1 d
  # (1) project.assets.json do dotnet restore ghi: chính xác nhất (kể cả globalPackagesFolder trong NuGet.Config)
  if [ -f "$pdir/obj/project.assets.json" ]; then
    tr -d '\r' < "$pdir/obj/project.assets.json" | sed -n '/"packageFolders"/,/^[[:space:]]*},*[[:space:]]*$/p' | sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]*:.*/\1/p' | grep -v packageFolders |
      sed 's/\\\\/\\/g' | while IFS= read -r d; do deps_winpath "$d"; done
  fi
  [ -n "${NUGET_PACKAGES:-}" ] && deps_winpath "$NUGET_PACKAGES"
  # (2) dotnet nuget locals: đọc cả NuGet.Config (đã tính sẵn một lần)
  [ -n "$DEPS_NUGET_GLOBAL" ] && printf '%s\n' "$DEPS_NUGET_GLOBAL"
  [ -n "${USERPROFILE:-}" ] && deps_winpath "$USERPROFILE/.nuget/packages"
  printf '%s\n' "$HOME/.nuget/packages"
}

deps_nuget_license() {
  # Giấy phép từ .nuspec: expression (MIT, Apache-2.0...), hoặc suy từ licenseUrl quen thuộc, hoặc SEE LICENSE
  local nuspec=$1 lic url
  lic=$(tr -d '\r' < "$nuspec" | sed -n 's/.*<license[^>]*type="expression"[^>]*>\([^<]*\)<.*/\1/p' | head -n1)
  if [ -z "$lic" ]; then
    url=$(tr -d '\r' < "$nuspec" | sed -n 's/.*<licenseUrl>\([^<]*\)<.*/\1/p' | head -n1)
    case "$url" in
      *licenses/MIT*|*/MIT|*mit-license*) lic=MIT ;;
      *LICENSE-2.0*|*licenses/Apache-2*) lic=Apache-2.0 ;;
      *licenses/BSD-3*) lic=BSD-3-Clause ;;
      *licenses/BSD-2*) lic=BSD-2-Clause ;;
      *go.microsoft.com/fwlink/?LinkId=329770*|*go.microsoft.com/fwlink/?LinkId=529443*|*dotnet.microsoft.com/*/license*) lic=MS-NET-Library ;;
      "") grep -q '<license[^>]*type="file"' "$nuspec" && lic="SEE LICENSE" ;;
      *) lic="SEE LICENSE" ;;
    esac
  fi
  printf '%s\n' "$lic"
}

deps_nuget() {
  local dir=$1 proj pdir name ver lic lower nuspec d
  DEPS_NUGET_GLOBAL=""
  if command -v dotnet >/dev/null 2>&1; then
    d=$(dotnet nuget locals global-packages --list 2>/dev/null | tr -d '\r' | sed -n 's/^[^:]*global-packages:[[:space:]]*//p' | head -n1)
    [ -n "$d" ] && DEPS_NUGET_GLOBAL=$(deps_winpath "${d%[\\/]}")
  fi
  while IFS= read -r proj; do
    [ -n "$proj" ] || continue
    pdir=$(dirname "$proj")
    mapfile -t DEPS_DIRS < <(deps_nuget_dirs "$pdir" | sed 's#/*$##' | awk 'NF && !seen[$0]++')
    local -a pk_name=() pk_ver=() pk_spec=()
    while IFS='|' read -r name ver; do
      [ -n "$name" ] || continue
      lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
      ver=${ver#[}; ver=${ver%]}           # [1.2.3] -> 1.2.3
      nuspec=""
      for d in "${DEPS_DIRS[@]}"; do
        [ -f "$d/$lower/$ver/$lower.nuspec" ] && { nuspec="$d/$lower/$ver/$lower.nuspec"; break; }
      done
      pk_name+=("$name"); pk_ver+=("$ver"); pk_spec+=("$nuspec")
    done < <(tr -d '\r' < "$proj" | sed -n 's/.*<PackageReference[^>]*Include="\([^"]*\)"[^>]*Version="\([^"]*\)".*/\1|\2/p')
    local found=0 k assets="$pdir/obj/project.assets.json" libs="" elsewhere=0 elsewhere_dir=""
    for k in "${!pk_spec[@]}"; do [ -n "${pk_spec[$k]}" ] && found=$((found + 1)); done
    # project.assets.json liệt kê package NuGet đã giải được ("Ten/phien-ban"): có tên ở đây là package có thật
    if [ -f "$assets" ]; then
      libs=$(tr -d '\r' < "$assets" | sed -n '/"libraries"[[:space:]]*:/,/"projectFileDependencyGroups"/p' | sed -n 's/^[[:space:]]*"\([^"/]*\)\/[^"]*"[[:space:]]*:[[:space:]]*{.*/\1/p' | tr '[:upper:]' '[:lower:]')
      elsewhere_dir=$(tr -d '\r' < "$assets" | sed -n '/"packageFolders"/,/^[[:space:]]*},*[[:space:]]*$/p' | sed -n 's/^[[:space:]]*"\([^"]*\)"[[:space:]]*:.*/\1/p' | grep -v packageFolders | head -n1 | sed 's/\\\\/\\/g')
    fi
    if [ "${#pk_name[@]}" -gt 0 ] && [ "$found" -eq 0 ] && [ ! -f "$assets" ]; then
      # Cả project chưa restore trên máy này (vd. build trong Docker/CI): một cảnh báo cho cả project, không báo từng package
      for k in "${!pk_name[@]}"; do deps_check_one nuget "${pk_name[$k]}" "${pk_ver[$k]}" "" "${proj#"$dir"/}" nolic; done
      gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${proj#"$dir"/}" "" "project chưa restore: ${#pk_name[@]} package chưa kiểm được tên và giấy phép" "Chạy dotnet restore trên máy này rồi quét lại (cổng đọc giấy phép từ cache NuGet; AI hay bịa tên package)."
    else
      for k in "${!pk_name[@]}"; do
        name=${pk_name[$k]}; ver=${pk_ver[$k]}; nuspec=${pk_spec[$k]}
        lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
        if [ -n "$nuspec" ]; then
          deps_check_one nuget "$name" "$ver" "$(deps_nuget_license "$nuspec")" "${proj#"$dir"/}"
        elif [ -n "$libs" ] && printf '%s\n' "$libs" | grep -qxF -- "$lower"; then
          # NuGet đã giải được (tên có thật) nhưng cache nằm ở môi trường khác (WSL, container): chỉ thiếu giấy phép
          deps_check_one nuget "$name" "$ver" "" "${proj#"$dir"/}" nolic
          elsewhere=$((elsewhere + 1))
        else
          # Project đã restore mà package này không có: dấu hiệu tên sai/bịa hoặc chưa restore lại sau khi thêm
          deps_check_one nuget "$name" "$ver" "" "${proj#"$dir"/}" nolic
          gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${proj#"$dir"/}" "" "nuget $name@$ver không có trong obj/project.assets.json lẫn cache NuGet (${DEPS_DIRS[*]})" "Package chưa được restore: kiểm tra tên có thật trên nuget.org (AI hay bịa tên package) rồi dotnet restore trước khi push."
        fi
      done
      if [ "$elsewhere" -gt 0 ]; then
        gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${proj#"$dir"/}" "" "$elsewhere package đã restore ở môi trường khác (${elsewhere_dir:-?}): tên hợp lệ, chưa đọc được giấy phép" "Cache NuGet không đọc được từ máy này (thường do restore trong WSL/container). Chạy dotnet restore trên chính máy này để cổng kiểm giấy phép."
      fi
    fi
    if [ "$GATE_DEPS_AUDIT" = 1 ] && command -v dotnet >/dev/null 2>&1; then
      if dotnet list "$proj" package --vulnerable --include-transitive 2>/dev/null | grep -qiE 'high|critical'; then
        gate_report_finding "$(deps_level block)" "g-dep-vulnerable" "${proj#"$dir"/}" "" "dotnet list package --vulnerable" "Có lỗ hổng mức high/critical trong package NuGet."
      fi
    fi
  done < <(find "$dir" -name '*.csproj' -not -path '*/.git/*' -not -path '*/node_modules/*' 2>/dev/null)
}

gate_deps_scan() {
  local dir=${1:-.}
  deps_load_rules
  deps_npm "$dir"
  deps_nuget "$dir"
}
