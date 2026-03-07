import asyncio
import base64
import os
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
ENCLAVE_DIR = ROOT / "demo-client" / "enclave"
if str(ENCLAVE_DIR) not in sys.path:
    sys.path.append(str(ENCLAVE_DIR))

os.environ["IN_ENCLAVE"] = "false"

sys.modules.setdefault("chain", MagicMock())
sys.modules["chain"].wait_for_helios = MagicMock()
sys.modules["chain"].function_selector = MagicMock()
sys.modules["chain"].encode_uint256 = MagicMock()
sys.modules["chain"].encode_address = MagicMock()
sys.modules["chain"].get_chain = MagicMock()

sys.modules.setdefault("web3", MagicMock())
sys.modules.setdefault("web3.exceptions", MagicMock())

mock_w3 = MagicMock()
mock_contract = MagicMock()
sys.modules["chain"].get_chain.return_value.w3 = mock_w3
mock_w3.eth.contract.return_value = mock_contract

import config

config.NOVA_APP_REGISTRY_ADDRESS = "0xMockNovaRegistry"
config.KMS_APP_ID = 49

import app
import nova_registry


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")

    def json(self):
        return self._payload


class ScanSummaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        app.request_logs.clear()

    def _build_active_node(self):
        inst = SimpleNamespace(
            instance_id=1,
            app_id=49,
            version_id=16,
            operator="0xOp1",
            instance_url="https://kms.example",
            tee_wallet_address="0x0317307729a732c09bebd3961fc7dfdfc8fce886",
            zk_verified=True,
            status=nova_registry.InstanceStatus.ACTIVE,
        )
        return [{"instance": inst}]

    async def test_run_test_cycle_marks_missing_derive_key_as_partial(self):
        fixed_time = 1772844533
        read_value_b64 = base64.b64encode(str(fixed_time - 90).encode("utf-8")).decode("utf-8")

        async def fake_signed_request(_client, method, url, json=None):
            del json
            if method == "POST" and url.endswith("/kms/derive"):
                return FakeResponse(200, {})
            if method == "GET" and "/kms/data/" in url:
                return FakeResponse(200, {"value": read_value_b64})
            if method == "PUT" and url.endswith("/kms/data"):
                return FakeResponse(200, {"updated_at_ms": fixed_time})
            raise AssertionError(f"unexpected request: {method} {url}")

        with patch.object(app, "NovaRegistry", return_value=MagicMock()):
            client = app.KMSClient()

        with patch.object(client, "get_kms_nodes", return_value=self._build_active_node()):
            with patch.object(client, "_probe_health", return_value={"connected": True, "http_status": 200, "probe_ms": 1}):
                with patch.object(app.random, "choice", side_effect=lambda items: items[0]):
                    with patch.object(
                        client,
                        "_signed_request",
                        new=AsyncMock(side_effect=fake_signed_request),
                    ):
                        with patch.object(app.time, "time", return_value=fixed_time):
                            await client.run_test_cycle()

        latest = app.request_logs[0]
        self.assertEqual(latest["status"], "Partial")
        row = latest["details"]["results"][0]
        self.assertEqual(row["derive"]["http_status"], 200)
        self.assertIn("missing key field", row["derive"]["error"])

    def test_format_scan_summary_flags_connected_row_with_missing_derive(self):
        entry = {
            "timestamp_ms": int(time.time() * 1000),
            "status": "Success",
            "details": {
                "node_count": 1,
                "reachable_count": 1,
                "fixed_derive_path": "nova-kms-client/fixed-derive",
                "results": [
                    {
                        "operator": "0x0317307729a732c09bebd3961fc7dfdfc8fce886",
                        "instance": {
                            "tee_wallet": "0x0317307729a732c09bebd3961fc7dfdfc8fce886",
                            "instance_url": "https://kms.example",
                            "status": {"name": "ACTIVE"},
                            "zk_verified": True,
                            "version_id": 16,
                        },
                        "connection": {"connected": True},
                        "derive": None,
                        "data": {
                            "key": "nova-kms-client/timestamp",
                            "value": "1772844533",
                            "http_status": 200,
                            "matches_written": True,
                        },
                    }
                ],
                "write": {"performed": False},
            },
        }

        rendered = app._format_scan_summary(entry)
        self.assertIn("derive_not_recorded", rendered)

    async def test_run_test_cycle_serializes_concurrent_calls(self):
        with patch.object(app, "NovaRegistry", return_value=MagicMock()):
            client = app.KMSClient()

        entered = asyncio.Event()
        release = asyncio.Event()
        in_flight = 0
        max_in_flight = 0

        async def fake_get_kms_nodes():
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            entered.set()
            await release.wait()
            in_flight -= 1
            return []

        with patch.object(client, "get_kms_nodes", side_effect=fake_get_kms_nodes):
            first = asyncio.create_task(client.run_test_cycle())
            await entered.wait()

            second = asyncio.create_task(client.run_test_cycle())
            await asyncio.sleep(0.05)
            self.assertEqual(max_in_flight, 1)

            release.set()
            await asyncio.gather(first, second)

        self.assertEqual(max_in_flight, 1)


if __name__ == "__main__":
    unittest.main()
