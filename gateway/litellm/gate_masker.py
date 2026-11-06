"""VNPTNAN_GATE cho LiteLLM: che (hoặc chặn) secret trong yêu cầu gửi tới nhà cung cấp AI, kể cả trên route
chuyển tiếp (pass-through) giữ tài khoản thuê bao của dev.

Dùng CHUNG bộ rule với cổng commit/push/prompt:
  - rules/gate.rules     : rule kind=line, mức block (g-secret-*, g-pii-cccd)
  - rules/gitleaks.jsonl : 219 rule nhập từ Gitleaks (từ khoá, entropy, nhóm bắt secret, ngoại lệ như Gitleaks)

Vì sao tự viết: bộ lọc có sẵn litellm_content_filter đi qua lớp "unified guardrail"; trên route chuyển tiếp lớp
này chỉ KIỂM TRA (chặn được) nhưng bỏ kết quả đã che và gửi bản gốc (LiteLLM v1.106.7,
litellm/llms/pass_through/guardrail_translation/handler.py: "pass-through doesn't modify the text, just checks it").
Lớp này KHÔNG định nghĩa apply_guardrail nên LiteLLM gọi thẳng async_pre_call_hook, và route chuyển tiếp gửi đi đúng
dữ liệu hàm này trả về. Đã thử trên máy thật ngày 06/11/2026.

Chỉ sửa chữ trong "system" và "messages" (lời dev, lời mô hình, kết quả và đối số công cụ). Không đụng định nghĩa
công cụ, id, chữ ký, ảnh, khối thinking/redacted_thinking (sửa thì chữ ký thinking hỏng).

Tài liệu (khối "document"):
  - dạng chữ (source.type text/content): che như chữ thường;
  - PDF (source.type base64, application/pdf): lấy chữ ra bằng pypdf để quét. PDF không sửa được nên có secret thì
    CHẶN cả yêu cầu. PDF không lấy được chữ (bản scan ảnh, có mật khẩu, hỏng, thiếu pypdf) xử lý theo
    GATE_GATEWAY_PDF_UNSCANNABLE. Kết quả mỗi PDF được nhớ theo mã băm, vì PDF bị gửi lại ở mọi lượt sau.
  - Ảnh: không quét (cần OCR); dựa vào Bộ quy tắc.

Biến môi trường:
  GATE_RULES_DIR          thư mục rules (mặc định /app/rules)
  GATE_GATEWAY_ACTION     mask (mặc định) | block
  GATE_GATEWAY_BLOCK_IDS  danh sách id luôn CHẶN dù ACTION=mask, ngăn bằng dấu phẩy (vd. g-secret-private-key)
  GATE_GATEWAY_PDF        scan (mặc định) | off
  GATE_GATEWAY_PDF_UNSCANNABLE  allow (mặc định: cho qua, ghi log PDF-UNSCANNED) | block
  GATE_GATEWAY_PDF_MAX_PAGES    số trang tối đa lấy chữ (mặc định 200)
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import re
import sys
from collections import OrderedDict
from typing import Any

RULES_DIR = os.environ.get("GATE_RULES_DIR", "/app/rules")
ACTION = os.environ.get("GATE_GATEWAY_ACTION", "mask").strip().lower()
BLOCK_IDS = {x.strip() for x in os.environ.get("GATE_GATEWAY_BLOCK_IDS", "").split(",") if x.strip()}
PDF_MODE = os.environ.get("GATE_GATEWAY_PDF", "scan").strip().lower()
PDF_UNSCANNABLE = os.environ.get("GATE_GATEWAY_PDF_UNSCANNABLE", "allow").strip().lower()
PDF_MAX_PAGES = int(os.environ.get("GATE_GATEWAY_PDF_MAX_PAGES", "200"))

# pypdf: cài vào /opt/gate-vendor khi build image (Dockerfile), không đụng site-packages của LiteLLM
if os.path.isdir("/opt/gate-vendor") and "/opt/gate-vendor" not in sys.path:
    sys.path.append("/opt/gate-vendor")
try:
    from pypdf import PdfReader
    import logging as _logging
    _logging.getLogger("pypdf").setLevel(_logging.ERROR)   # PDF lỗi nhẹ: không làm rác log gateway
except ImportError:
    PdfReader = None

# Với rule g- khớp cả ngữ cảnh (vd. 'password = "..."'), chỉ che phần GIÁ TRỊ để mô hình vẫn hiểu đoạn mã.
# Mỗi mẫu có nhóm tên 's' là phần bị che; áp trong phạm vi chuỗi rule đã khớp. Không có mẫu: che cả chuỗi khớp.
VALUE_PATTERNS = {
    "g-secret-connstring": r"(?i)(?:password|pwd)\s*=\s*(?P<s>[^;\"'\s]+)",
    "g-secret-password": r"(?i)[:=]\s*[\"'](?P<s>[^\"']+)[\"']",
    "g-secret-url-cred": r"://[^/:@\s\"']+:(?P<s>[^@/\s\"']+)@",
    "g-secret-oracle-ezconnect": r"/(?P<s>[^@/\s\"']+)@",
    "g-secret-generic-key": r"[:=]\s*[\"']?(?P<s>[^\"'\s,;]{8,})",
    "g-secret-basic-auth": r"(?i)basic\s+(?P<s>[A-Za-z0-9+/=]{8,})",
    "g-secret-bearer": r"(?i)bearer\s+(?P<s>[A-Za-z0-9._~+/=-]{12,})",
    "g-pii-cccd": r"(?P<s>0[0-9]{11})",
}
SKIP_KEYS = {"type", "id", "tool_use_id", "name", "signature", "cache_control", "source", "media_type", "citations"}
SKIP_BLOCK_TYPES = {"thinking", "redacted_thinking", "image"}


# ---------------------------------------------------------------- nạp rule
def _go_to_python(rx: str) -> tuple[str, int]:
    """Regex Go/Perl -> Python: bỏ cờ (?i) giữa mẫu (Python chỉ cho ở đầu) và bật IGNORECASE cho cả mẫu."""
    flags = 0
    if "(?i)" in rx or "(?i:" in rx:
        flags |= re.IGNORECASE
        rx = rx.replace("(?i)", "").replace("(?i:", "(?:")
    rx = rx.replace("(?-i:", "(?:").replace("(?s:", "(?:").replace("\\z", "\\Z")
    for posix, cls in (("[:alnum:]", "a-zA-Z0-9"), ("[:alpha:]", "a-zA-Z"), ("[:digit:]", "0-9"),
                       ("[:word:]", "a-zA-Z0-9_"), ("[:xdigit:]", "0-9a-fA-F"), ("[:upper:]", "A-Z"),
                       ("[:lower:]", "a-z"), ("[:space:]", "\\s")):
        rx = rx.replace(posix, cls)
    return rx, flags


def load_gate_rules(path: str) -> list[tuple[str, re.Pattern]]:
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\r\n")
        if not line or line[0] in "#@":
            continue
        p = line.split("\t", 4)
        if len(p) < 5 or p[2] != "line" or p[1] != "block":
            continue
        out.append((p[0], re.compile(p[3], re.IGNORECASE | re.MULTILINE)))
    return out


def load_allow_regexes(path: str) -> list[re.Pattern]:
    """Rule kind=allow của Gate (vd. giá trị mẫu changeme, <YOUR_KEY>): dòng khớp thì không che."""
    out = []
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        p = line.rstrip("\r\n").split("\t", 4)
        if len(p) >= 5 and p[2] == "allow":
            out.append(re.compile(p[3], re.IGNORECASE))
    return out


def _compile_allow(a: dict) -> dict:
    a = dict(a)
    a["qre"] = []
    for x in a.get("regexes", []):
        rx, fl = _go_to_python(x)
        try:
            a["qre"].append(re.compile(rx, fl))
        except re.error:
            pass
    return a


def load_gitleaks(path: str) -> tuple[list[dict], dict | None]:
    rules, glob = [], None
    if not os.path.exists(path):
        return rules, glob
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        o = json.loads(line)
        if "_global" in o:
            glob = _compile_allow(o["_global"])
            continue
        if not o.get("id") or not o.get("re") or o.get("path"):
            continue                       # rule chỉ theo đường dẫn file không áp được lên nội dung yêu cầu
        rx, fl = _go_to_python(o["re"])
        try:
            o["q"] = re.compile(rx, fl | re.MULTILINE)
        except re.error:
            continue
        o["allow_c"] = [_compile_allow(a) for a in o.get("allow", [])]
        rules.append(o)
    return rules, glob


GATE_RULES = load_gate_rules(os.path.join(RULES_DIR, "gate.rules"))
ALLOW_RES = load_allow_regexes(os.path.join(RULES_DIR, "gate.rules"))
GL_RULES, GL_GLOBAL = load_gitleaks(os.path.join(RULES_DIR, "gitleaks.jsonl"))
VALUE_RES = {k: re.compile(v) for k, v in VALUE_PATTERNS.items()}


# ---------------------------------------------------------------- dò và che
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _gl_allowed(a: dict, secret: str, match: str, line: str) -> bool:
    target = {"match": match, "line": line}.get(a.get("target", ""), secret)
    re_ok = any(q.search(target) for q in a.get("qre", []))
    ls = secret.lower()
    sw_ok = any(w in ls for w in a.get("stopwords", []))
    if not a.get("and"):
        return re_ok or sw_ok
    checks = []
    if a.get("qre"):
        checks.append(re_ok)
    if a.get("stopwords"):
        checks.append(sw_ok)
    return bool(checks) and all(checks)       # điều kiện đường dẫn không áp dụng cho nội dung yêu cầu


def _line_at(text: str, pos: int) -> str:
    a = text.rfind("\n", 0, pos) + 1
    b = text.find("\n", pos)
    return text[a:] if b < 0 else text[a:b]


def find_secrets(text: str) -> list[tuple[int, int, str]]:
    """Danh sách (đầu, cuối, id) các đoạn cần che trong text, đã gộp đoạn chồng nhau."""
    spans: list[tuple[int, int, str]] = []
    for rid, q in GATE_RULES:
        for m in q.finditer(text):
            if any(a.search(_line_at(text, m.start())) for a in ALLOW_RES):
                continue
            vq = VALUE_RES.get(rid)
            if vq:
                vm = vq.search(m.group(0))
                if vm and vm.group("s"):
                    spans.append((m.start() + vm.start("s"), m.start() + vm.end("s"), rid))
                    continue
            spans.append((m.start(), m.end(), rid))
    low = text.lower()
    for r in GL_RULES:
        kw = r.get("kw")
        if kw and not any(k in low for k in kw):
            continue
        for m in r["q"].finditer(text):
            match = m.group(0)
            gi = 0
            if r.get("grp") and r["grp"] <= (m.re.groups or 0):
                gi = r["grp"]
            elif m.re.groups:
                gi = next((i for i in range(1, m.re.groups + 1) if m.group(i)), 0)
            secret = m.group(gi) if gi else match
            if not secret:
                continue
            if r.get("ent") is not None and _entropy(secret) <= r["ent"]:
                continue
            line = _line_at(text, m.start())
            if GL_GLOBAL and _gl_allowed(GL_GLOBAL, secret, match, line):
                continue
            if any(_gl_allowed(a, secret, match, line) for a in r["allow_c"]):
                continue
            s0, s1 = (m.start(gi), m.end(gi)) if gi else (m.start(), m.end())
            spans.append((s0, s1, r["id"]))
    spans.sort()
    merged: list[tuple[int, int, str]] = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            p = merged[-1]
            merged[-1] = (p[0], max(p[1], s[1]), p[2])
        else:
            merged.append(s)
    return merged


# Mỗi yêu cầu của coding agent lặp lại toàn bộ lịch sử phiên: nhớ kết quả theo mã băm để chỉ quét phần mới.
# Chỉ lưu mã băm và bản ĐÃ CHE (không lưu secret gốc). Giới hạn số mục.
_CACHE: "OrderedDict[bytes, tuple[str, dict]]" = OrderedDict()
_CACHE_MAX = int(os.environ.get("GATE_GATEWAY_CACHE", "4096"))
_CACHE_MIN_LEN = 512


def mask_text(text: str, hits: dict) -> str:
    if len(text) >= _CACHE_MIN_LEN:
        key = hashlib.blake2b(text.encode("utf-8", "surrogatepass"), digest_size=20).digest()
        got = _CACHE.get(key)
        if got is not None:
            _CACHE.move_to_end(key)
            for rid, n in got[1].items():
                hits[rid] = hits.get(rid, 0) + n
            return got[0]
        local: dict = {}
        res = _mask_text_uncached(text, local)
        _CACHE[key] = (res, local)
        if len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)
        for rid, n in local.items():
            hits[rid] = hits.get(rid, 0) + n
        return res
    return _mask_text_uncached(text, hits)


def _mask_text_uncached(text: str, hits: dict) -> str:
    spans = find_secrets(text)
    if not spans:
        return text
    out, last = [], 0
    for a, b, rid in spans:
        hits[rid] = hits.get(rid, 0) + 1
        out.append(text[last:a])
        out.append(f"[DA_CHE:{rid}]")
        last = b
    out.append(text[last:])
    return "".join(out)


class ScanResult:
    """Kết quả quét một yêu cầu."""
    def __init__(self):
        self.hits: dict = {}        # id rule -> số lần che (chữ)
        self.pdf_hits: dict = {}    # id rule -> số PDF chứa secret (phải chặn)
        self.pdf_unscanned: list = []   # lý do từng PDF không quét được


_PDF_CACHE: "OrderedDict[str, tuple]" = OrderedDict()   # sha256(base64) -> (hits, lý do không quét được)


def scan_pdf(b64: str, log=None) -> tuple:
    """Lấy chữ từ PDF (base64) và tìm secret. Trả về ({id rule: số lần}, lý do không quét được hoặc "")."""
    key = hashlib.sha256(b64.encode("ascii", "ignore")).hexdigest()
    got = _PDF_CACHE.get(key)
    if got is not None:
        _PDF_CACHE.move_to_end(key)
        return got
    hits: dict = {}
    reason = ""
    if PdfReader is None:
        reason = "thiếu thư viện pypdf"
    else:
        try:
            reader = PdfReader(io.BytesIO(base64.b64decode(b64)))
            if reader.is_encrypted and not reader.decrypt(""):
                reason = "PDF có mật khẩu"
            else:
                parts = []
                for i, page in enumerate(reader.pages):
                    if i >= PDF_MAX_PAGES:
                        reason = f"PDF quá {PDF_MAX_PAGES} trang, chỉ quét {PDF_MAX_PAGES} trang đầu"
                        break
                    parts.append(page.extract_text() or "")
                text = "\n".join(parts)
                if not text.strip():
                    reason = "PDF không có lớp chữ (bản scan ảnh)"
                for _a, _b, rid in find_secrets(text):
                    hits[rid] = hits.get(rid, 0) + 1
        except Exception as e:  # PDF hỏng hoặc pypdf lỗi: không được làm sập gateway
            reason = f"không đọc được PDF ({type(e).__name__})"
    if log:   # chỉ ghi khi gặp PDF mới (không ghi lại ở mỗi lượt)
        if hits:
            log.warning("gate-masker: PDF-SECRET %s", ", ".join(f"{k} x{n}" for k, n in sorted(hits.items())))
        if reason:
            log.warning("gate-masker: PDF-UNSCANNED %s", reason.encode("ascii", "replace").decode())
    _PDF_CACHE[key] = (hits, reason)
    if len(_PDF_CACHE) > 256:
        _PDF_CACHE.popitem(last=False)
    return hits, reason


def _document(v: dict, res: ScanResult, log=None) -> dict:
    src = v.get("source") if isinstance(v.get("source"), dict) else {}
    out = {k: (x if k in SKIP_KEYS else _walk(x, res, log)) for k, x in v.items()}   # title, context
    st = src.get("type")
    if st == "text" and isinstance(src.get("data"), str):
        out["source"] = {**src, "data": mask_text(src["data"], res.hits)}
    elif st == "content" and isinstance(src.get("content"), (list, str)):
        out["source"] = {**src, "content": _walk(src["content"], res, log)}
    elif st == "base64" and src.get("media_type") == "application/pdf" and PDF_MODE != "off":
        hits, reason = scan_pdf(src.get("data") or "", log)
        for rid, n in hits.items():
            res.pdf_hits[rid] = res.pdf_hits.get(rid, 0) + n
        if reason:
            res.pdf_unscanned.append(reason)
    return out


def _walk(v: Any, res: ScanResult, log=None) -> Any:
    if isinstance(v, str):
        return mask_text(v, res.hits)
    if isinstance(v, list):
        return [_walk(x, res, log) for x in v]
    if isinstance(v, dict):
        t = v.get("type")
        if t in SKIP_BLOCK_TYPES:
            return v
        if t == "document":
            return _document(v, res, log)
        return {k: (x if k in SKIP_KEYS else _walk(x, res, log)) for k, x in v.items()}
    return v


def scan_request(data: dict, log=None) -> ScanResult:
    """Che secret trong data (sửa tại chỗ) và quét PDF đính kèm."""
    res = ScanResult()
    for key in ("system", "messages"):
        if key in data:
            data[key] = _walk(data[key], res, log)
    return res


def mask_request(data: dict) -> dict:
    """Che secret trong data (sửa tại chỗ). Trả về {id rule: số lần che}."""
    return scan_request(data).hits


# ---------------------------------------------------------------- tích hợp LiteLLM
try:
    from fastapi import HTTPException
    from litellm._logging import verbose_proxy_logger
    from litellm.integrations.custom_guardrail import CustomGuardrail
except ImportError:  # chạy kiểm thử ngoài LiteLLM
    CustomGuardrail = object  # type: ignore[assignment,misc]
    verbose_proxy_logger = None
    HTTPException = None  # type: ignore[assignment]


class GateBlocked(Exception):
    """Dùng khi chạy ngoài LiteLLM (kiểm thử); trong LiteLLM là HTTPException 400."""
    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


def _block(detail: dict):
    if HTTPException is not None:
        raise HTTPException(status_code=400, detail=detail)
    raise GateBlocked(detail)


class GateMasker(CustomGuardrail):  # type: ignore[misc,valid-type]
    def __init__(self, **kwargs):
        if CustomGuardrail is not object:
            super().__init__(**kwargs)
        if not GATE_RULES:
            # Không nạp được rule mà vẫn chạy thì gateway cho mọi secret đi qua: dừng hẳn để người vận hành thấy
            raise RuntimeError(f"gate-masker: no Gate rules loaded from {RULES_DIR} (check the ../../rules mount)")
        if verbose_proxy_logger:
            verbose_proxy_logger.warning(
                "gate-masker: loaded %d Gate rules + %d Gitleaks rules from %s; action=%s; always block: %s; "
                "pdf=%s (pypdf %s, unscannable=%s)",
                len(GATE_RULES), len(GL_RULES), RULES_DIR, ACTION, ",".join(sorted(BLOCK_IDS)) or "-",
                PDF_MODE, "ok" if PdfReader is not None else "MISSING", PDF_UNSCANNABLE)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        res = scan_request(data, verbose_proxy_logger)
        log = verbose_proxy_logger

        # PDF không sửa được: có secret thì chặn cả yêu cầu
        if res.pdf_hits:
            if log:
                log.warning("gate-masker: BLOCKED-PDF %s", ", ".join(f"{k} x{n}" for k, n in sorted(res.pdf_hits.items())))
            _block({"error": "VNPTNAN_GATE: file PDF đính kèm chứa thông tin bí mật, không gửi tới nhà cung cấp AI. "
                             "Gỡ secret khỏi PDF (hoặc không đưa PDF này cho AI), gõ /clear rồi thử lại.",
                    "rules": sorted(res.pdf_hits)})
        if res.pdf_unscanned and PDF_UNSCANNABLE == "block":
            if log:
                log.warning("gate-masker: BLOCKED-PDF-UNSCANNED %d", len(res.pdf_unscanned))
            _block({"error": "VNPTNAN_GATE: không kiểm tra được file PDF đính kèm (" + "; ".join(sorted(set(res.pdf_unscanned))) + "). "
                             "Chuyển PDF sang chữ hoặc bỏ mật khẩu, gõ /clear rồi thử lại."})

        hits = res.hits
        if not hits:
            return data
        summary = ", ".join(f"{k} x{n}" for k, n in sorted(hits.items()))
        blocking = ACTION == "block" or bool(BLOCK_IDS.intersection(hits))
        if log:
            log.warning("gate-masker: %s %s", "BLOCKED" if blocking else "MASKED", summary)   # ASCII: script kiểm tra đọc log
        if blocking:
            _block({"error": "VNPTNAN_GATE: yêu cầu chứa thông tin bí mật, không gửi tới nhà cung cấp AI. "
                             "Gỡ secret khỏi file/prompt (dùng biến môi trường), gõ /clear rồi thử lại.",
                    "rules": sorted(hits)})
        return data
