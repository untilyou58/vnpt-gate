"""Kiểm thử gateway/litellm/gate_masker.py ngoài LiteLLM: python3 tests/gateway/test_gate_masker.py
Secret mẫu được ghép lúc chạy hoặc giải mã từ tests/gitleaks-cases.tsv, để chính file này không chứa chuỗi giống secret thật."""
import asyncio
import base64
import copy
import importlib.util
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
os.environ["GATE_RULES_DIR"] = os.path.join(ROOT, "rules")
spec = importlib.util.spec_from_file_location("gm", os.path.join(ROOT, "gateway", "litellm", "gate_masker.py"))
gm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gm)
fails = []
def check(cond, msg):
    if not cond:
        fails.append(msg)

check(len(gm.GATE_RULES) >= 15, f"chỉ nạp {len(gm.GATE_RULES)} rule Gate")
check(len(gm.GL_RULES) >= 200, f"chỉ nạp {len(gm.GL_RULES)} rule Gitleaks")

pw = "S3cret" + "!x"
aws = "AKIA" + "IOSFODNN7EXAMPLE"
req = {
    "model": "claude",
    "tools": [{"name": "Read", "description": "pass" + "word = \"example12\" trong tài liệu"}],
    "system": [{"type": "text", "text": "Bạn là trợ lý lập trình"}],
    "messages": [
        {"role": "user", "content": "đọc file thu.txt"},
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "Pass" + "word=abcdef12", "signature": "sig"},
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "thu.txt"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "text", "text": "Host=pg-host;Port=5432;Username=app;Pass" + "word=" + pw}]}]},
        {"role": "user", "content": "pass" + "word = \"Vnpt@NgheAn2026\"; DATABASE_URL=postgresql://app:" + pw + "w@pg-host/db; CCCD: 0402" + "03001234; key " + aws},
        {"role": "user", "content": "Viết hàm cộng hai số; password đọc từ biến môi trường"},
    ]}
orig = copy.deepcopy(req)
hits = gm.mask_request(req)
blob = json.dumps(req["messages"], ensure_ascii=False)
for s in (pw, "Vnpt@NgheAn2026", "0402" + "03001234", aws):
    check(s not in blob.replace(json.dumps(orig["messages"][1], ensure_ascii=False), ""), f"chưa che: {s[:4]}...")
check("Host=pg-host;Port=5432;Username=app;Pass" + "word=[DA_CHE:g-secret-connstring]" in blob, "chuỗi kết nối phải giữ ngữ cảnh, chỉ che giá trị")
check(req["messages"][4] == orig["messages"][4], "câu không có secret bị sửa")
check(req["messages"][1] == orig["messages"][1], "khối thinking/tool_use bị sửa (hỏng chữ ký)")
check(req["tools"] == orig["tools"], "định nghĩa công cụ bị sửa")
for rid in ("g-secret-connstring", "g-secret-password", "g-secret-url-cred", "g-pii-cccd", "g-secret-aws"):
    check(rid in hits, f"không có lượt che của {rid}")
check(gm.mask_text("api_key = \"changeme\"", {}) == "api_key = \"changeme\"", "giá trị mẫu (changeme) không được che")

# Mỗi mẫu Gitleaks phải bị che (bởi chính rule đó hoặc một rule secret khác)
miss, n = [], 0
for line in open(os.path.join(ROOT, "tests", "gitleaks-cases.tsv"), encoding="utf-8"):
    if not line.strip() or line.startswith("#"):
        continue
    rid, enc = line.rstrip("\n").split("\t")
    sample = base64.b64decode(enc).decode()[::-1]
    n += 1
    h = {}
    if gm.mask_text(sample, h) == sample:
        miss.append(rid)
check(len(miss) <= n // 50, f"{len(miss)}/{n} mẫu Gitleaks không bị che: {' '.join(miss[:8])}")

# Chạy qua hook như LiteLLM gọi
r = asyncio.run(gm.GateMasker().async_pre_call_hook(None, None, {"messages": [{"role": "user", "content": "key " + aws}]}, "pass_through_endpoint"))
check("[DA_CHE:" in r["messages"][0]["content"], "hook không che")

# ---------------------------------------------------------------- tài liệu: chữ và PDF
def make_pdf(lines):
    """PDF tối thiểu, mỗi phần tử một dòng chữ (Helvetica). Không cần thư viện."""
    esc = lambda t: t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = "BT /F1 11 Tf 50 750 Td 14 TL " + " ".join(f"({esc(t)}) Tj T*" for t in lines) + " ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = "%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n" + "".join(f"{o:010d} 00000 n \n" for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n"
    return base64.b64encode(out.encode("latin-1")).decode()


def pdf_req(b64):
    return {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": b64}}]},
        {"type": "text", "text": "Tóm tắt tài liệu này"}]}]}


hook = gm.GateMasker().async_pre_call_hook

# Tài liệu dạng chữ: phải che (trước đây bị bỏ qua)
doc = {"messages": [{"role": "user", "content": [{"type": "document", "title": "cấu hình",
        "source": {"type": "text", "media_type": "text/plain", "data": "Host=pg-host;Pass" + "word=Sup3rS3cr3tX9;"}}]}]}
h = gm.mask_request(doc)
check("g-secret-connstring" in h and "Sup3rS3cr3tX9" not in json.dumps(doc), "tài liệu dạng chữ không bị che")

if gm.PdfReader is None:
    check(not os.environ.get("CI"), "CI phải cài pypdf để kiểm thử PDF")
    pdf_note = "bỏ qua phần PDF: chưa cài pypdf"
else:
    sec = make_pdf(["Huong dan ket noi CSDL", "Server=db01;Database=app;User Id=sa;Pass" + "word=Sup3rS3cr3tX9;"])
    clean = make_pdf(["Bao cao tuan 45", "Tien do: 80 phan tram"])
    blank = base64.b64encode(base64.b64decode(make_pdf([])))  .decode()
    # PDF có secret: chặn, và chặn lại ở lượt sau (PDF gửi lại cùng lịch sử)
    for lan in (1, 2):
        try:
            asyncio.run(hook(None, None, pdf_req(sec), "pass_through_endpoint"))
            check(False, f"PDF có secret không bị chặn (lượt {lan})")
        except gm.GateBlocked as e:
            check("g-secret-connstring" in e.detail.get("rules", []), "lý do chặn PDF sai")
    # PDF sạch: cho qua, không sửa dữ liệu PDF
    r = pdf_req(clean); orig = copy.deepcopy(r)
    out = asyncio.run(hook(None, None, r, "pass_through_endpoint"))
    check(out["messages"][0]["content"][0] == orig["messages"][0]["content"][0], "PDF sạch bị sửa")
    # PDF không có chữ / hỏng: mặc định cho qua, chế độ block thì chặn
    hits, why = gm.scan_pdf(blank)
    check(not hits and "chữ" in why, f"PDF trống phải báo không quét được: {why!r}")
    hits, why = gm.scan_pdf(base64.b64encode(b"khong phai pdf").decode())
    check(not hits and why, "PDF hỏng phải báo không quét được")
    asyncio.run(hook(None, None, pdf_req(blank), "pass_through_endpoint"))
    gm.PDF_UNSCANNABLE = "block"
    try:
        asyncio.run(hook(None, None, pdf_req(blank), "pass_through_endpoint"))
        check(False, "PDF_UNSCANNABLE=block không chặn PDF trống")
    except gm.GateBlocked:
        pass
    gm.PDF_UNSCANNABLE = "allow"
    pdf_note = "PDF: chặn có secret, cho qua PDF sạch"

if fails:
    print("\n".join("  FAIL: " + f for f in fails))
    sys.exit(1)
print(f"gate_masker: đạt ({len(gm.GATE_RULES)} rule Gate, {len(gm.GL_RULES)} rule Gitleaks, {n - len(miss)}/{n} mẫu Gitleaks bị che; {pdf_note})")
