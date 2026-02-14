import unittest
import time
import base64
from typing import Optional, List, Dict

# -----------------------------------------------------------------------------
# Copy of the formatting logic from demo-client/enclave/app.py for isolated test
# -----------------------------------------------------------------------------

def _truncate(text: Optional[str], max_len: int) -> str:
    s = "" if text is None else str(text)
    if max_len <= 0:
        return ""
    if len(s) <= max_len:
        return s
    if max_len <= 1:
        return s[:max_len]
    return s[: max_len - 1] + "…"


def _b64_to_hex(b64_text: Optional[str]) -> Optional[str]:
    if not b64_text:
        return None
    try:
        raw = base64.b64decode(b64_text)
        return raw.hex()
    except Exception:
        return None


def _render_table(headers: List[str], rows: List[List[str]]) -> str:
    # Compute column widths (with hard caps to keep logs readable)
    caps = {
        "Wallet": 42,
        "URL": 48,
        "Readback": 22,
        "Error": 32,
    }

    def cap_for(h: str) -> int:
        return caps.get(h, 24)

    widths: List[int] = []
    for col_idx, h in enumerate(headers):
        w = min(len(h), cap_for(h))
        for r in rows:
            if col_idx < len(r):
                w = max(w, min(len(r[col_idx]), cap_for(h)))
        widths.append(w)

    def fmt_row(cols: List[str]) -> str:
        padded: List[str] = []
        for i, h in enumerate(headers):
            cell = cols[i] if i < len(cols) else ""
            cell = _truncate(cell, widths[i])
            padded.append(cell.ljust(widths[i]))
        return "| " + " | ".join(padded) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    out = [sep, fmt_row(headers), sep]
    for r in rows:
        out.append(fmt_row(r))
    out.append(sep)
    return "\n".join(out)


def _format_scan_summary(entry: dict) -> str:
    ts_ms = entry.get("timestamp_ms")
    status = entry.get("status")
    err = entry.get("error")
    details = entry.get("details") or {}

    # Human timestamp
    try:
        ts_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((ts_ms or 0) / 1000))
    except Exception:
        ts_s = str(ts_ms)

    node_count = details.get("node_count")
    reachable_count = details.get("reachable_count")
    fixed_path = details.get("fixed_derive_path")

    results = details.get("results") or []

    # 1) Node list table
    node_rows: List[List[str]] = []
    for idx, r in enumerate(results, start=1):
        inst = r.get("instance") or {}
        conn = r.get("connection") or {}
        wallet = inst.get("tee_wallet") or r.get("operator") or ""
        url = inst.get("instance_url") or ""
        status_info = inst.get("status") or {}
        status_name = status_info.get("name") or ""
        zk_verified = inst.get("zk_verified")
        connected = "yes" if conn.get("connected") else "no"
        version_id = inst.get("version_id")
        node_rows.append([
            str(idx),
            str(wallet),
            str(url),
            str(status_name),
            str(zk_verified) if zk_verified is not None else "",
            connected,
            str(version_id) if version_id is not None else "",
        ])
    nodes_table = _render_table(["#", "Wallet", "URL", "Status", "ZK", "Conn", "VersionId"], node_rows)

    # 3) Write section
    write = details.get("write") or {}
    if not write.get("performed"):
        write_block = "3. KV Write:\n  (not performed)"
    else:
        write_block = (
            "3. KV Write:\n"
            f"  node: {write.get('node_url')}\n"
            f"  key : {write.get('key')}\n"
            f"  value: {write.get('timestamp')}\n"
            + (f"  http : {write.get('http_status')}\n" if write.get("http_status") is not None else "")
            + (f"  error: {write.get('error')}\n" if write.get("error") else "")
        ).rstrip("\n")

    # 4) Combined derive + data readback
    combined_rows: List[List[str]] = []
    for idx, r in enumerate(results, start=1):
        inst = r.get("instance") or {}
        conn = r.get("connection") or {}
        derive = r.get("derive") or {}
        data = r.get("data") or {}

        wallet = inst.get("tee_wallet") or r.get("operator") or ""
        derive_b64 = derive.get("key") if isinstance(derive, dict) else None
        # derive_hex = _b64_to_hex(derive_b64) # REMOVED in app.py
        derive_ok = derive.get("matches_cluster") if isinstance(derive, dict) else None
        derive_http = derive.get("http_status") if isinstance(derive, dict) else None

        data_val = data.get("value") if isinstance(data, dict) else None
        data_ok = data.get("matches_written") if isinstance(data, dict) else None
        data_http = data.get("http_status") if isinstance(data, dict) else None

        derive_err = derive.get("error") if isinstance(derive, dict) else None
        data_err = data.get("error") if isinstance(data, dict) else None
        row_err = derive_err or data_err or ""

        combined_rows.append([
            str(idx),
            str(wallet),
            str(derive_http) if derive_http is not None else "",
            str(derive_ok) if derive_ok is not None else "",
            str(data_val or ""),
            str(data_http) if data_http is not None else "",
            str(data_ok) if data_ok is not None else "",
            str(row_err),
        ])
    combined_table = _render_table(
        ["#", "Wallet", "DeriveHTTP", "DeriveOK", "Readback", "ReadbackHTTP", "ReadbackOK", "Error"],
        combined_rows,
    )

    lines: List[str] = []
    lines.append(f"Run @ {ts_s} | status={status} | nodes={node_count} reachable={reachable_count}")
    if err:
        lines.append(f"Error: {err}")
    lines.append("")
    lines.append("1. Nodes:")
    lines.append(nodes_table)
    lines.append("")
    lines.append("2. Derive + data readback:")
    if fixed_path:
        lines.append(f"   Derive path: {fixed_path}")
    lines.append(combined_table)
    lines.append("")
    lines.append(write_block)
    return "\n".join(lines)


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

class TestLogs(unittest.TestCase):

    def test_format_scan_summary(self):
        entry = {
            "timestamp_ms": 1600000000000,
            "status": "Success",
            "details": {
                "node_count": 2,
                "reachable_count": 2,
                "fixed_derive_path": "test/path",
                "results": [
                    {
                        "instance": {
                            "tee_wallet": "0x111",
                            "instance_url": "http://1.1.1.1",
                            "status": {"name": "ACTIVE"},
                            "zk_verified": True,
                            "version_id": 1
                        },
                        "connection": {"connected": True},
                        "derive": {"http_status": 200, "matches_cluster": True},
                        "data": {"value": "val1", "http_status": 200, "matches_written": True}
                    }
                ],
                "write": {
                    "performed": True,
                    "node_url": "http://1.1.1.1",
                    "key": "test/key",
                    "timestamp": "12345",
                    "http_status": 200
                }
            }
        }
        
        text = _format_scan_summary(entry)
        
        # Verify major sections and new formatting
        self.assertIn("1. Nodes:", text)
        self.assertIn("2. Derive + data readback:", text)
        self.assertIn("3. KV Write:", text)
        self.assertIn("VersionId", text)
        self.assertIn("DeriveHTTP", text)
        self.assertIn("ReadbackOK", text)
        self.assertIn("Derive path: test/path", text)
        self.assertIn("0x111", text)
        self.assertIn("12345", text)
        
        # Verify DeriveHex is GONE
        self.assertNotIn("DeriveHex", text)

if __name__ == "__main__":
    unittest.main()
