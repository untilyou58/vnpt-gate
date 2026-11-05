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
  local eco=$1 name=$2 ver=$3 lic=$4 src=$5 i
  for i in "${!PKG_TYPE[@]}"; do
    case "${PKG_TYPE[$i]}" in
      deny-package)
        if printf '%s@%s' "$name" "$ver" | grep -qiE -- "${PKG_RE[$i]}" || printf '%s' "$name" | grep -qiE -- "${PKG_RE[$i]}"; then
          gate_report_finding "$(deps_level "${PKG_LEVEL[$i]}")" "g-dep-package" "$src" "" "$eco $name@$ver" "${PKG_MSG[$i]}"
        fi ;;
      deny-license)
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
    block=$(tr -d '\n\r' < "$pj" | sed 's/[{},]/&\n/g' | awk '/"(dependencies|devDependencies|optionalDependencies)"[[:space:]]*:/{f=1;next} f&&/^[[:space:]]*}/{f=0} f')
    while IFS= read -r line; do
      name=$(printf '%s' "$line" | sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p')
      [ -n "$name" ] || continue
      if [ -f "$nm/$name/package.json" ]; then
        ver=$(deps_json_field "$nm/$name/package.json" version)
        lic=$(deps_json_field "$nm/$name/package.json" license)
        [ -z "$lic" ] && lic=$(tr -d '\n\r' < "$nm/$name/package.json" | sed -n 's/.*"license"[[:space:]]*:[[:space:]]*{[^}]*"type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
        deps_check_one npm "$name" "${ver:-?}" "$lic" "${pj#"$dir"/}"
      else
        ver=$(printf '%s' "$line" | sed -n 's/^[^:]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        deps_check_one npm "$name" "${ver:-?}" "" "${pj#"$dir"/}"
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

deps_nuget() {
  local dir=$1 proj name ver lic cache lower nuspec
  cache=${NUGET_PACKAGES:-${USERPROFILE:-$HOME}/.nuget/packages}
  while IFS= read -r proj; do
    [ -n "$proj" ] || continue
    while IFS='|' read -r name ver; do
      [ -n "$name" ] || continue
      lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
      lic=""
      nuspec=$(ls "$cache/$lower/$ver/$lower.nuspec" 2>/dev/null | head -n1)
      if [ -n "$nuspec" ]; then
        lic=$(sed -n 's/.*<license[^>]*type="expression"[^>]*>\([^<]*\)<.*/\1/p' "$nuspec" | head -n1)
        [ -z "$lic" ] && grep -q '<licenseUrl>' "$nuspec" && lic="SEE LICENSE"
        deps_check_one nuget "$name" "$ver" "$lic" "${proj#"$dir"/}"
      else
        deps_check_one nuget "$name" "$ver" "" "${proj#"$dir"/}"
        gate_report_finding "$(deps_level warn)" "g-dep-unresolved" "${proj#"$dir"/}" "" "nuget $name@$ver chưa có trong cache NuGet" "Package chưa được restore: kiểm tra tên có thật trên nuget.org (AI hay bịa tên package) rồi dotnet restore trước khi push."
      fi
    done < <(sed -n 's/.*<PackageReference[^>]*Include="\([^"]*\)"[^>]*Version="\([^"]*\)".*/\1|\2/p' "$proj")
    if [ "$GATE_DEPS_AUDIT" = 1 ] && command -v dotnet >/dev/null 2>&1; then
      if dotnet list "$proj" package --vulnerable --include-transitive 2>/dev/null | grep -qiE 'high|critical'; then
        gate_report_finding "$(deps_level block)" "g-dep-vulnerable" "${proj#"$dir"/}" "" "dotnet list package --vulnerable" "Có lỗ hổng mức high/critical trong package NuGet."
      fi
    fi
  done < <(find "$dir" -name '*.csproj' -not -path '*/.git/*' 2>/dev/null)
}

gate_deps_scan() {
  local dir=${1:-.}
  deps_load_rules
  deps_npm "$dir"
  deps_nuget "$dir"
}
