#!/usr/bin/env python3
"""Chuyển bộ rule mặc định của Gitleaks (config/gitleaks.toml, giấy phép MIT) sang rules/gitleaks.jsonl của VNPTNAN_GATE.

  python3 tools/import-gitleaks.py <đường dẫn gitleaks.toml> [commit/phiên bản nguồn]

Mỗi dòng của gitleaks.jsonl là một đối tượng JSON:
  {"_meta": ...}    nguồn, phiên bản, giấy phép
  {"_global": ...}  ngoại lệ chung: paths, regexes (áp lên secret), stopwords
  {"id": "gl-<id gốc>", "desc", "re", "kw", "ent", "grp", "path", "allow": [...], "level"}
engine/scan-core.pl đọc file này (qua bản .pldata cùng nội dung). Cập nhật khi Gitleaks ra bản mới: chạy lại script, chạy tests/run-tests.sh.
"""
import json
import re
import sys
import tomllib

# Không nhập: rule quá rộng (Gate đã có g-secret-generic-key, g-secret-password với ngoại lệ tiếng Việt),
# hoặc cần nhiều dòng liền nhau (Gate quét theo từng dòng; khoá PEM đã có g-secret-private-key).
SKIP = {
    "generic-api-key": "quá rộng; đã có g-secret-generic-key",
    "private-key": "nhiều dòng; đã có g-secret-private-key",
    "kubernetes-secret-yaml": "cần nhiều dòng",
}
# Rule dễ báo nhầm trong mã nghiệp vụ: chỉ cảnh báo
WARN = {"curl-auth-header", "curl-auth-user", "jwt", "jwt-base64", "hashicorp-tf-password", "sourcegraph-access-token"}

QUANT = re.compile(r"\{\d+(?:,\d*)?\}")


def perlish(rx: str) -> str:
    """Go RE2 -> Perl: '{' '}' không thuộc lượng từ {n}, {n,}, {n,m} thì thoát (Perl >= 5.30 báo lỗi '{' trần)."""
    out, i, cls = [], 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            out.append(rx[i:i + 2]); i += 2; continue
        if cls:
            if c == "]":
                cls = False
            out.append(c); i += 1; continue
        if c == "[":
            cls = True
            # ']' ngay sau '[' hoặc '[^' là ký tự thường
            out.append(c); i += 1
            if i < len(rx) and rx[i] == "^":
                out.append("^"); i += 1
            if i < len(rx) and rx[i] == "]":
                out.append("]"); i += 1
            continue
        if c == "{":
            m = QUANT.match(rx, i)
            if m and out:
                out.append(m.group(0)); i = m.end(); continue
            out.append("\\{"); i += 1; continue
        if c == "}":
            out.append("\\}"); i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def allow_obj(a):
    o = {}
    if a.get("regexes"):
        o["regexes"] = [perlish(x) for x in a["regexes"]]
    if a.get("stopwords"):
        o["stopwords"] = [s.lower() for s in a["stopwords"]]
    if a.get("paths"):
        o["paths"] = [perlish(x) for x in a["paths"]]
    if a.get("regexTarget"):
        o["target"] = a["regexTarget"]
    if a.get("condition", "").upper() == "AND":
        o["and"] = True
    return o


def perl_lit(v):
    if isinstance(v, dict):
        return "{" + ",".join(perl_lit(k) + "=>" + perl_lit(x) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ",".join(perl_lit(x) for x in v) + "]"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


def main():
    src = sys.argv[1]
    ver = sys.argv[2] if len(sys.argv) > 2 else ""
    cfg = tomllib.load(open(src, "rb"))
    out = [{"_meta": {
        "source": "https://github.com/gitleaks/gitleaks config/gitleaks.toml",
        "version": ver, "license": "MIT, Copyright (c) 2019 Zachary Rice (xem rules/gitleaks.LICENSE)",
        "note": "Tạo bằng tools/import-gitleaks.py; không sửa tay, sửa SKIP/WARN trong script rồi chạy lại.",
        "skipped": SKIP}}]
    g = cfg.get("allowlist") or {}
    out.append({"_global": allow_obj(g)})
    n = 0
    for r in cfg["rules"]:
        rid = r["id"]
        if rid in SKIP:
            continue
        o = {"id": "gl-" + rid, "desc": r.get("description", rid),
             "level": "warn" if rid in WARN else "block"}
        if "regex" in r:
            o["re"] = perlish(r["regex"])
        if r.get("keywords"):
            o["kw"] = sorted({k.lower() for k in r["keywords"]})
        if r.get("entropy"):
            o["ent"] = r["entropy"]
        if r.get("secretGroup"):
            o["grp"] = r["secretGroup"]
        if r.get("path"):
            o["path"] = perlish(r["path"])
        if r.get("allowlists"):
            o["allow"] = [allow_obj(a) for a in r["allowlists"]]
        out.append(o); n += 1
    dst = sys.argv[3] if len(sys.argv) > 3 else "rules/gitleaks.jsonl"
    with open(dst, "w", encoding="utf-8") as f:
        for o in out:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    # Bản dữ liệu Perl cùng nội dung: engine/scan-core.pl nạp nhanh hơn JSON::PP khoảng 30 ms mỗi file
    with open(dst[:-len(".jsonl")] + ".pldata", "w", encoding="utf-8") as f:
        f.write("# Tạo tự động từ gitleaks.jsonl bằng tools/import-gitleaks.py. Không sửa tay.\n[\n")
        for o in out:
            f.write(perl_lit(o) + ",\n")
        f.write("];\n")
    print(f"Đã nhập {n} rule, bỏ {len(SKIP)}: {', '.join(SKIP)}")


if __name__ == "__main__":
    main()
