"""
Nova KMS Client - Example Application
"""
import asyncio
import base64
import logging
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

import httpx
import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel

import config
from odyn import Odyn
from nova_registry import NovaRegistry
from kms_identity import verify_instance_identity, verify_response_signature

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("nova-kms-client")

_ETH_WALLET_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")


def _canonical_eth_wallet(wallet: str) -> str:
    """Canonical Ethereum wallet string: '0x' + 40 lowercase hex."""
    w = (wallet or "").strip()
    if not w or not _ETH_WALLET_RE.match(w):
        return w
    w = w.lower()
    if not w.startswith("0x"):
        w = "0x" + w
    return w

# In-memory log storage (keep last N runs)
MAX_LOGS = 10
request_logs = deque(maxlen=MAX_LOGS)


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
        "DeriveHex": 24,
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

    # 2) Write section
    write = details.get("write") or {}
    if not write.get("performed"):
        write_block = "2. KV Write:\n  (not performed)"
    else:
        write_block = (
            "2. KV Write:\n"
            f"  node: {write.get('node_url')}\n"
            f"  key : {write.get('key')}\n"
            f"  value: {write.get('timestamp')}\n"
            + (f"  http : {write.get('http_status')}\n" if write.get("http_status") is not None else "")
            + (f"  error: {write.get('error')}\n" if write.get("error") else "")
        ).rstrip("\n")

    # 3) Combined derive + data readback
    combined_rows: List[List[str]] = []
    for idx, r in enumerate(results, start=1):
        inst = r.get("instance") or {}
        conn = r.get("connection") or {}
        derive = r.get("derive") or {}
        data = r.get("data") or {}

        wallet = inst.get("tee_wallet") or r.get("operator") or ""
        derive_b64 = derive.get("key") if isinstance(derive, dict) else None
        derive_hex = _b64_to_hex(derive_b64)
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
            str(derive_hex or ""),
            str(derive_http) if derive_http is not None else "",
            str(derive_ok) if derive_ok is not None else "",
            str(data_val or ""),
            str(data_http) if data_http is not None else "",
            str(data_ok) if data_ok is not None else "",
            str(row_err),
        ])
    combined_table = _render_table(
        ["#", "Wallet", "DeriveHex", "DeriveHTTP", "DeriveOK", "Readback", "ReadbackHTTP", "ReadbackOK", "Error"],
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
    lines.append(write_block)
    lines.append("")
    lines.append("3. Derive + data readback:")
    if fixed_path:
        lines.append(f"   Derive path: {fixed_path}")
    lines.append(combined_table)
    return "\n".join(lines)

# =============================================================================
# E2E Encryption Helpers
# =============================================================================

def encrypt_json_envelope(odyn: "Odyn", plaintext_dict: dict, receiver_tee_pubkey_hex: str) -> dict:
    """
    Encrypt a JSON payload for end-to-end encryption.
    
    Returns envelope: {
        "sender_tee_pubkey": "<hex>",
        "nonce": "<hex>",
        "encrypted_data": "<hex>"
    }
    """
    import json
    plaintext_json = json.dumps(plaintext_dict)
    
    # Get our own teePubkey
    sender_pubkey_hex = odyn.get_encryption_public_key().get("public_key_der", "")
    if sender_pubkey_hex.startswith("0x"):
        sender_pubkey_hex = sender_pubkey_hex[2:]
    
    # Encrypt using Odyn (ECDH + AES-256-GCM)
    enc_result = odyn.encrypt(plaintext_json, receiver_tee_pubkey_hex)
    
    nonce_hex = enc_result.get("nonce", "")
    if nonce_hex.startswith("0x"):
        nonce_hex = nonce_hex[2:]
    
    encrypted_data_hex = enc_result.get("encrypted_data", "")
    if encrypted_data_hex.startswith("0x"):
        encrypted_data_hex = encrypted_data_hex[2:]
    
    return {
        "sender_tee_pubkey": sender_pubkey_hex,
        "nonce": nonce_hex,
        "encrypted_data": encrypted_data_hex,
    }


def decrypt_json_envelope(odyn: "Odyn", envelope: dict) -> dict:
    """
    Decrypt an E2E encrypted JSON envelope.
    
    Expected envelope format: {
        "sender_tee_pubkey": "<hex>",
        "nonce": "<hex>",
        "encrypted_data": "<hex>"
    }
    """
    import json
    sender_pubkey_hex = envelope["sender_tee_pubkey"]
    nonce_hex = envelope["nonce"]
    encrypted_data_hex = envelope["encrypted_data"]
    
    plaintext = odyn.decrypt(nonce_hex, sender_pubkey_hex, encrypted_data_hex)
    return json.loads(plaintext)


class LogEntry(BaseModel):
    timestamp_ms: int
    kms_node_url: str
    action: str
    status: str
    details: Optional[Dict] = None
    error: Optional[str] = None
    text: Optional[str] = None

class KMSClient:
    def __init__(self):
        self.odyn = Odyn()
        self.nova_registry: Optional[NovaRegistry] = None
        self._kms_wallet_cache: Dict[str, str] = {}  # base_url -> kms_wallet

        def _is_zero_address(addr: Optional[str]) -> bool:
            if not addr:
                return True
            a = addr.strip().lower()
            return a == "0x" + "0" * 40

        if _is_zero_address(getattr(config, "NOVA_APP_REGISTRY_ADDRESS", "")):
            raise RuntimeError(
                "NOVA_APP_REGISTRY_ADDRESS must be configured in enclave/config.py (registry-only client)."
            )

        kms_app_id = int(getattr(config, "KMS_APP_ID", 0) or 0)
        if kms_app_id <= 0:
            raise RuntimeError("KMS_APP_ID must be configured in enclave/config.py")
        
        # Initialize on-chain registry clients
        try:
            self.nova_registry = NovaRegistry(address=config.NOVA_APP_REGISTRY_ADDRESS)
                
        except Exception as e:
             logger.error(f"Failed to initialize registries: {e}")
             raise

    async def get_kms_nodes(self) -> List[dict]:
        """Discover KMS nodes via NovaAppRegistry.

        Algorithm:
          1) app = getApp(KMS_APP_ID)
          2) for version_id in 1..app.latest_version_id:
                if getVersion(...).status == ENROLLED:
                    instances = getInstancesForVersion(app_id, version_id)
                    for each instance_id:
                        inst = getInstance(instance_id)
                        if inst.status == ACTIVE: include
          3) merge all ACTIVE instances across ENROLLED versions (dedupe by tee wallet)
        """
        from nova_registry import InstanceStatus, VersionStatus

        if not self.nova_registry:
            return []

        kms_app_id = int(getattr(config, "KMS_APP_ID", 0) or 0)

        app = await asyncio.to_thread(self.nova_registry.get_app, kms_app_id)
        latest_version_id = int(getattr(app, "latest_version_id", 0) or 0)
        if latest_version_id <= 0:
            return []

        nodes_by_wallet: Dict[str, dict] = {}

        for version_id in range(1, latest_version_id + 1):
            try:
                ver = await asyncio.to_thread(self.nova_registry.get_version, kms_app_id, version_id)
            except Exception:
                continue

            if getattr(ver, "status", None) != VersionStatus.ENROLLED:
                continue

            try:
                instance_ids = await asyncio.to_thread(
                    self.nova_registry.get_instances_for_version, kms_app_id, version_id
                )
            except Exception:
                continue

            for instance_id in instance_ids or []:
                try:
                    inst = await asyncio.to_thread(self.nova_registry.get_instance, int(instance_id))
                except Exception:
                    continue

                if getattr(inst, "status", None) != InstanceStatus.ACTIVE:
                    continue

                tee_wallet = (getattr(inst, "tee_wallet_address", "") or "").lower()
                if not tee_wallet:
                    continue

                # H1 fix: verify teePubkey ↔ tee_wallet consistency on-chain
                if not verify_instance_identity(inst):
                    logger.warning(
                        f"Skipping instance {instance_id}: "
                        f"teePubkey/wallet inconsistency"
                    )
                    continue

                inst_url = self._ensure_http(getattr(inst, "instance_url", ""))
                nodes_by_wallet[tee_wallet] = {
                    "instance": inst,
                    "instance_url": inst_url,
                    "version_id": getattr(inst, "version_id", None),
                    "instance_id": getattr(inst, "instance_id", None),
                }

        return list(nodes_by_wallet.values())

    @staticmethod
    def _ensure_http(url: str) -> str:
        if not url:
            return url
        u = url.strip()
        if u.startswith("http://") or u.startswith("https://"):
            return u
        return f"http://{u}"

    async def _probe_health(self, client: httpx.AsyncClient, base_url: str) -> dict:
        start = time.time()
        try:
            r = await client.get(f"{base_url.rstrip('/')}/health")
            return {
                "connected": r.status_code == 200,
                "http_status": r.status_code,
                "probe_ms": int((time.time() - start) * 1000),
            }
        except Exception as exc:
            return {
                "connected": False,
                "http_status": None,
                "probe_ms": int((time.time() - start) * 1000),
                "error": str(exc),
            }

    async def _signed_request(self, client: httpx.AsyncClient, method: str, url: str, json: Optional[dict] = None) -> httpx.Response:
        """
        Perform a request with full PoP authentication flow and E2E encryption:
        1. GET /nonce from KMS node
        2. Sign (nonce + wallet + timestamp) using Odyn
        3. Encrypt request body with KMS node's teePubkey (E2E)
        4. Send request with X-App-* headers
        5. Verify X-KMS-Response-Signature (H1 fix)
        6. Decrypt response body (E2E)
        """
        # 1. Get Nonce
        base_url = "/".join(url.split("/")[:3]) # http://host:port
        nonce_resp = await client.get(f"{base_url}/nonce")
        nonce_resp.raise_for_status()
        nonce_b64 = nonce_resp.json()["nonce"]
        
        # 2. Prepare PoP
        ts = str(int(time.time()))
        wallet = _canonical_eth_wallet(self.odyn.eth_address())
        
        # Fetch KMS status (cached per node) - includes wallet and teePubkey
        status_data = self._kms_wallet_cache.get(base_url)
        if not status_data or not isinstance(status_data, dict):
            status_resp = await client.get(f"{base_url}/status")
            status_resp.raise_for_status()
            status_json = status_resp.json()["node"]
            status_data = {
                "wallet": _canonical_eth_wallet(status_json["tee_wallet"]),
                "tee_pubkey": status_json.get("tee_pubkey", ""),
            }
            self._kms_wallet_cache[base_url] = status_data
        
        kms_wallet = _canonical_eth_wallet(status_data["wallet"])
        kms_tee_pubkey = status_data.get("tee_pubkey", "")

        # Message format: NovaKMS:AppAuth:<Nonce>:<KMS_Wallet>:<Timestamp>
        message = f"NovaKMS:AppAuth:{nonce_b64}:{kms_wallet}:{ts}"
        
        # Sign with Odyn (auto-selects local vs enclave signing)
        sig_res = self.odyn.sign_message(message)
        signature = sig_res["signature"]

        headers = {
            "X-App-Signature": signature,
            "X-App-Nonce": nonce_b64,
            "X-App-Timestamp": ts,
            "X-App-Wallet": wallet,
            "Content-Type": "application/json"
        }
        
        # 3. E2E Encrypt request body if present
        request_body = json
        if json is not None and kms_tee_pubkey:
            try:
                request_body = encrypt_json_envelope(self.odyn, json, kms_tee_pubkey)
            except Exception as exc:
                logger.warning(f"Failed to encrypt request body: {exc}, sending plaintext")
        
        # 4. Execute Request
        if method == "POST":
            resp = await client.post(url, json=request_body, headers=headers)
        elif method == "PUT":
            resp = await client.put(url, json=request_body, headers=headers)
        elif method == "GET":
            resp = await client.get(url, headers=headers)
        elif method == "DELETE":
            resp = await client.request("DELETE", url, json=request_body, headers=headers)
        else:
            raise ValueError(f"Unsupported method {method}")

        # 5. Verify KMS response signature (H1 fix)
        resp_sig = resp.headers.get("X-KMS-Response-Signature")
        if resp_sig:
            if not verify_response_signature(resp_sig, signature, kms_wallet):
                logger.warning(
                    f"KMS response signature verification FAILED for {base_url}"
                )
                raise httpx.HTTPStatusError(
                    "KMS response signature verification failed",
                    request=resp.request,
                    response=resp,
                )
        else:
            # Log but don't fail — server may be in dev/sim mode
            logger.debug(f"No X-KMS-Response-Signature header from {base_url}")

        # 6. Decrypt E2E encrypted response
        try:
            resp_data = resp.json()
            # Check if response is an encrypted envelope
            if all(k in resp_data for k in ("sender_tee_pubkey", "nonce", "encrypted_data")):
                decrypted_data = decrypt_json_envelope(self.odyn, resp_data)
                # Attach decrypted data to response for callers
                resp._decrypted_json = decrypted_data
            else:
                resp._decrypted_json = resp_data
        except Exception as exc:
            logger.debug(f"Response decryption skipped: {exc}")
            resp._decrypted_json = None

        return resp

    def _get_response_json(self, resp: httpx.Response) -> dict:
        """Get JSON from response, preferring decrypted data if available."""
        if hasattr(resp, "_decrypted_json") and resp._decrypted_json is not None:
            return resp._decrypted_json
        return resp.json()


    async def run_test_cycle(self):
        """Scan all KMS nodes and verify consistency + sync.

        Cycle:
                    1) Discover KMS nodes via NovaAppRegistry
          3) For ACTIVE instances, probe /health
          4) For reachable instances, request a fixed /kms/derive and compare results
          5) Randomly choose one reachable instance, write /kms/data with timestamp
          6) Read that key from all reachable instances and report consistency
        """
        from nova_registry import InstanceStatus

        fixed_path = "nova-kms-client/fixed-derive"
        data_key = "nova-kms-client/timestamp"
        ts_value = str(int(time.time()))
        ts_b64 = base64.b64encode(ts_value.encode("utf-8")).decode("utf-8")

        try:
            nodes = await self.get_kms_nodes()
            if not nodes:
                self._log("Scan", "Failed", error="No KMS nodes found in NovaAppRegistry")
                return

            results: List[dict] = []
            reachable: List[dict] = []
            expected_key: Optional[str] = None

            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1) Resolve instances
                for node in nodes:
                    inst = node.get("instance")
                    op = getattr(inst, "tee_wallet_address", None) if inst else None
                    row: dict = {
                        "operator": op,
                        "instance": None,
                        "connection": {"connected": False},
                        "derive": None,
                        "data": None,
                    }
                    try:
                        if inst is None:
                            row["instance"] = {"error": "instance lookup unavailable"}
                            results.append(row)
                            continue

                        inst_url = self._ensure_http(getattr(inst, "instance_url", ""))
                        inst_status = getattr(inst, "status", None)
                        row["instance"] = {
                            "instance_id": getattr(inst, "instance_id", None),
                            "app_id": getattr(inst, "app_id", None),
                            "version_id": getattr(inst, "version_id", None),
                            "operator": getattr(inst, "operator", None),
                            "instance_url": inst_url,
                            "tee_wallet": getattr(inst, "tee_wallet_address", None),
                            "zk_verified": getattr(inst, "zk_verified", None),
                            "status": {
                                "value": getattr(inst_status, "value", inst_status),
                                "name": getattr(inst_status, "name", str(inst_status)),
                            },
                        }

                        # 2) Only probe/operate on ACTIVE instances
                        if inst_status != InstanceStatus.ACTIVE or not inst_url:
                            results.append(row)
                            continue

                        probe = await self._probe_health(client, inst_url)
                        row["connection"] = probe
                        if not probe.get("connected"):
                            results.append(row)
                            continue

                        # 3) Derive fixed key and compare across nodes
                        try:
                            resp = await self._signed_request(
                                client,
                                "POST",
                                f"{inst_url.rstrip('/')}/kms/derive",
                                json={"path": fixed_path},
                            )
                            resp.raise_for_status()
                            body = self._get_response_json(resp)
                            key_b64 = body.get("key")
                            if expected_key is None and key_b64:
                                expected_key = key_b64
                            row["derive"] = {
                                "path": fixed_path,
                                "key": key_b64,
                                "matches_cluster": (expected_key == key_b64) if expected_key else None,
                                "http_status": resp.status_code,
                            }
                        except Exception as exc:
                            row["derive"] = {"error": str(exc)}

                        reachable.append({"operator": op, "url": inst_url, "instance_id": getattr(inst, "instance_id", None)})
                        results.append(row)
                    except Exception as exc:
                        row["instance"] = {"error": str(exc)}
                        results.append(row)

                # 4) Write timestamp KV to one reachable node
                write_result: dict = {"performed": False}
                if reachable:
                    target = min(reachable, key=lambda n: int(n.get("instance_id") or 0))
                    write_result = {
                        "performed": True,
                        "node_url": target["url"],
                        "key": data_key,
                        "timestamp": ts_value,
                    }
                    try:
                        resp = await self._signed_request(
                            client,
                            "PUT",
                            f"{target['url'].rstrip('/')}/kms/data",
                            json={"key": data_key, "value": ts_b64, "ttl_ms": 0},
                        )
                        resp.raise_for_status()
                        write_result["http_status"] = resp.status_code
                    except Exception as exc:
                        write_result["error"] = str(exc)

                # 5) Read from all reachable nodes (retry on 404 to allow sync)
                for row in results:
                    inst = row.get("instance") or {}
                    url = inst.get("instance_url")
                    if not url or not row.get("connection", {}).get("connected"):
                        continue
                    read_info: dict = {"key": data_key}
                    try:
                        last_exc: Optional[Exception] = None
                        for _ in range(3):
                            try:
                                r = await self._signed_request(
                                    client,
                                    "GET",
                                    f"{url.rstrip('/')}/kms/data/{data_key}",
                                )
                                if r.status_code == 404:
                                    await asyncio.sleep(1)
                                    continue
                                r.raise_for_status()
                                payload = self._get_response_json(r)
                                val_b64 = payload.get("value")
                                val = base64.b64decode(val_b64).decode("utf-8") if val_b64 else None
                                read_info.update({
                                    "http_status": r.status_code,
                                    "value": val,
                                    "matches_written": (val == ts_value) if write_result.get("performed") else None,
                                })
                                last_exc = None
                                break
                            except Exception as exc:
                                last_exc = exc
                                await asyncio.sleep(1)
                        if last_exc is not None:
                            raise last_exc
                    except Exception as exc:
                        read_info["error"] = str(exc)
                    row["data"] = read_info

            # 6) Summarize
            mismatched_keys = [
                r for r in results
                if r.get("derive")
                and isinstance(r["derive"], dict)
                and r["derive"].get("matches_cluster") is False
            ]
            reads_missing = [
                r for r in results
                if r.get("connection", {}).get("connected")
                and (not r.get("data") or r["data"].get("matches_written") is False)
            ]
            overall = "Success" if (not mismatched_keys and not reads_missing) else "Partial"

            self._log(
                "ScanSummary",
                overall,
                details={
                    "node_count": len(nodes),
                    "reachable_count": len(reachable),
                    "fixed_derive_path": fixed_path,
                    "expected_derived_key": expected_key,
                    "write": write_result,
                    "results": results,
                },
            )
        except asyncio.CancelledError:
            # Normal during Ctrl+C / application shutdown; don't surface as an error.
            logger.info("Scan cycle cancelled (shutdown)")
            return
        except Exception as exc:
            logger.error(f"Scan cycle failed: {exc}")
            self._log("ScanSummary", "Failed", error=str(exc))

    def _log(self, action: str, status: str, kms_node_url: str = "N/A", details: Optional[Dict] = None, error: Optional[str] = None):
        entry_dict = {
            "timestamp_ms": int(time.time() * 1000),
            "kms_node_url": kms_node_url,
            "action": action,
            "status": status,
            "details": details,
            "error": error,
        }

        # For the periodic run summary, also store a human-readable text block.
        if action == "ScanSummary":
            try:
                entry_dict["text"] = _format_scan_summary(entry_dict)
            except Exception as exc:
                entry_dict["text"] = f"(failed to format log: {exc})"

        entry = LogEntry(**entry_dict)
        request_logs.appendleft(entry.model_dump())  # Newest first
        logger.info(f"[{status}] {action} (Node: {kms_node_url}): {error if error else ''}")


# Initialize Client
kms_client = KMSClient()

# Initialize Scheduler
scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Nova KMS Client...")
    
    # 1. Wait for Helios (if configured)
    from chain import wait_for_helios
    try:
        # Run in thread pool to avoid blocking async loop
        logger.info("Waiting for Helios sync...")
        await asyncio.to_thread(wait_for_helios, timeout=120)
        logger.info("Helios synced.")
    except Exception as e:
         logger.warning(f"Helios sync warning: {e}")

    # Verify Odyn connection
    try:
        addr = kms_client.odyn.eth_address()
        logger.info(f"Client TEE Identity: {addr}")
    except Exception as e:
        logger.error(f"Failed to connect to Odyn: {e}")
    
    scheduler.add_job(kms_client.run_test_cycle, 'interval', seconds=config.TEST_CYCLE_INTERVAL_SECONDS)
    scheduler.start()
    
    # Trigger one run immediately
    asyncio.create_task(kms_client.run_test_cycle())
    
    yield
    
    # Shutdown
    scheduler.shutdown()
    logger.info("Shutting down...")

app = FastAPI(title="Nova KMS Client", lifespan=lifespan)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/logs", response_class=PlainTextResponse)
def get_logs():
    # Render newest-first run history as plain text.
    blocks: List[str] = []
    for e in list(request_logs):
        if isinstance(e, dict) and e.get("text"):
            blocks.append(str(e["text"]))
        else:
            # Fallback for non-ScanSummary entries
            ts_ms = e.get("timestamp_ms") if isinstance(e, dict) else None
            try:
                ts_s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((ts_ms or 0) / 1000))
            except Exception:
                ts_s = str(ts_ms)
            blocks.append(
                f"{ts_s} | action={e.get('action') if isinstance(e, dict) else ''} "
                f"status={e.get('status') if isinstance(e, dict) else ''} "
                + (f"error={e.get('error')}" if isinstance(e, dict) and e.get("error") else "")
            )
    separator = "\n" + "=" * 100 + "\n"
    return separator.join(blocks) if blocks else "(no logs yet)"

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
