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

if fails:
    print("\n".join("  FAIL: " + f for f in fails))
    sys.exit(1)
print(f"gate_masker: đạt ({len(gm.GATE_RULES)} rule Gate, {len(gm.GL_RULES)} rule Gitleaks, {n - len(miss)}/{n} mẫu Gitleaks bị che)")
