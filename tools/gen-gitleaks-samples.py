#!/usr/bin/env python3
"""Sinh mẫu kiểm thử cho rules/gitleaks.jsonl: mỗi rule một chuỗi ngẫu nhiên khớp regex của nó.

  python3 tools/gen-gitleaks-samples.py rules/gitleaks.jsonl tests/gitleaks-cases.tsv

Mỗi rule thử tối đa 60 chuỗi (hạt giống cố định); giữ chuỗi đầu tiên mà engine/scan-core.pl bắt đúng mã rule.
Mẫu được lưu dạng đảo ngược + base64 để chính repo này không chứa chuỗi trông như token thật
(tránh bị GitHub push protection và các công cụ quét secret khác chặn nhầm).
"""
import base64
import json
import random
import re
import subprocess
import sys
import tempfile
import os
import re._parser as sre_parse
import re._constants as C

RNG = random.Random(20261106)
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
CATS = {
    C.CATEGORY_DIGIT: "0123456789",
    C.CATEGORY_NOT_DIGIT: "abcdefXYZ_-",
    C.CATEGORY_SPACE: " ",
    C.CATEGORY_NOT_SPACE: ALNUM,
    C.CATEGORY_WORD: ALNUM + "_",
    C.CATEGORY_NOT_WORD: " =:",
}


def to_python(rx: str) -> str:
    rx = rx.replace("(?i)", "").replace("(?-i:", "(?:").replace("(?i:", "(?:").replace("(?s:", "(?:")
    rx = rx.replace("\\z", "\\Z")
    rx = rx.replace("[:alnum:]", "a-zA-Z0-9").replace("[:alpha:]", "a-zA-Z").replace("[:digit:]", "0-9")
    rx = rx.replace("[:word:]", "a-zA-Z0-9_").replace("[:xdigit:]", "0-9a-fA-F").replace("[:upper:]", "A-Z").replace("[:lower:]", "a-z")
    rx = re.sub(r"\\x\{([0-9a-fA-F]+)\}", lambda m: "\\x%02x" % int(m.group(1), 16), rx)
    return rx


def charset(items):
    neg, chars = False, []
    for op, av in items:
        if op == C.NEGATE:
            neg = True
        elif op == C.LITERAL:
            chars.append(chr(av))
        elif op == C.RANGE:
            lo, hi = av
            chars.extend(chr(c) for c in range(lo, min(hi, lo + 300) + 1))
        elif op == C.CATEGORY:
            chars.extend(CATS.get(av, ALNUM))
    if neg:
        pool = [c for c in ALNUM + "_-" if c not in chars]
        return pool or ["x"]
    return [c for c in chars if c not in "\n\r"] or chars


def gen(tree, groups):
    out = []
    for op, av in tree:
        if op == C.LITERAL:
            out.append(chr(av))
        elif op == C.NOT_LITERAL:
            out.append(RNG.choice([c for c in ALNUM if ord(c) != av]))
        elif op == C.ANY:
            out.append(".")          # '.' trong regex Gitleaks hầu hết là dấu chấm của tên miền chưa thoát
        elif op == C.IN:
            out.append(RNG.choice(charset(av)))
        elif op == C.BRANCH:
            out.append(gen(RNG.choice(av[1]), groups))
        elif op == C.SUBPATTERN:
            gid, _, _, sub = av
            s = gen(sub, groups)
            if gid:
                groups[gid] = s
            out.append(s)
        elif op in (C.MAX_REPEAT, C.MIN_REPEAT, getattr(C, "POSSESSIVE_REPEAT", None)):
            lo, hi, sub = av
            hi = lo + 12 if hi == C.MAXREPEAT else hi
            n = RNG.randint(lo, max(lo, min(hi, lo + 12)))
            out.append("".join(gen(sub, groups) for _ in range(n)))
        elif op == C.GROUPREF:
            out.append(groups.get(av, ""))
        elif op in (C.AT, C.ASSERT, C.ASSERT_NOT):
            continue
        elif op == C.CATEGORY:
            out.append(RNG.choice(CATS.get(av, ALNUM)))
    return "".join(out)


def scan(perl_scanner, rules_file, lines):
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as f:
        f.write("\n".join(lines) + "\n")
        name = f.name
    try:
        res = subprocess.run(["perl", perl_scanner, "--gitleaks", rules_file, "--one", "sample.txt", name, name, ""], capture_output=True, text=True)
    finally:
        os.unlink(name)
    hits = {}
    for row in res.stdout.split("\n"):
        parts = row.split("\t")   # level id path dòng allowed masked msg
        if len(parts) >= 4 and parts[3]:
            hits.setdefault(int(parts[3]), set()).add(parts[1])
    return hits


def main():
    rules_file, out_file = sys.argv[1], sys.argv[2]
    here = os.path.dirname(os.path.abspath(__file__))
    scanner = os.path.join(here, "..", "engine", "scan-core.pl")
    rules = [json.loads(l) for l in open(rules_file, encoding="utf-8") if l.strip()]
    rules = [r for r in rules if r.get("id") and r.get("re") and not r.get("path")]
    cands = {}
    for r in rules:
        try:
            tree = sre_parse.parse(to_python(r["re"]))
        except Exception as e:  # noqa: BLE001
            cands[r["id"]] = []
            print(f"  không phân tích được {r['id']}: {e}", file=sys.stderr)
            continue
        cs = [gen(tree, {}) for _ in range(60)]
        kw = r.get("kw") or []
        # Rule cần từ khoá ở ngữ cảnh (vd. "airtable") mà regex không sinh ra: thêm "<từ khoá>_token = " phía trước
        cands[r["id"]] = [c if not kw or any(k in c.lower() for k in kw) else f"{kw[0]}_token = {c}" for c in cs]
    # Quét từng rule một (bộ quét giới hạn 20 lần báo mỗi rule trong một file)
    keep, missing = {}, []
    for rid, cs in cands.items():
        cs = [c for c in cs if "\n" not in c]
        hits = scan(scanner, rules_file, cs)
        for i, c in enumerate(cs, 1):
            if rid in hits.get(i, set()):
                keep[rid] = c
                break
        else:
            missing.append(rid)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("# Mẫu kiểm thử rule gitleaks: id <TAB> chuỗi đảo ngược rồi mã hoá base64. Tạo bằng tools/gen-gitleaks-samples.py\n")
        for rid in sorted(keep):
            f.write(f"{rid}\t{base64.b64encode(keep[rid][::-1].encode()).decode()}\n")
    print(f"{len(keep)}/{len(cands)} rule có mẫu bắt được; chưa có mẫu: {' '.join(missing) or '(không)'}")


if __name__ == "__main__":
    main()
