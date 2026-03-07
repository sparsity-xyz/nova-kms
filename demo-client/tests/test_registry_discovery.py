import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
ENCLAVE_DIR = ROOT / "demo-client" / "enclave"
if str(ENCLAVE_DIR) not in sys.path:
    sys.path.insert(0, str(ENCLAVE_DIR))

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


class RegistryDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def _make_instance(self, wallet: str, url: str):
        return SimpleNamespace(
            instance_id=1,
            app_id=49,
            version_id=16,
            operator="0xOperator",
            instance_url=url,
            tee_wallet_address=wallet,
            zk_verified=True,
            status=nova_registry.InstanceStatus.ACTIVE,
        )

    async def test_get_kms_nodes_fetches_registry_on_every_call(self):
        first_inst = self._make_instance(
            "0x0317307729a732c09bebd3961fc7dfdfc8fce886",
            "https://384.ntsfp9.sparsity.cloud/",
        )
        second_inst = self._make_instance(
            "0x5ce32db75f834583676441c06918e4bf8bbb43df",
            "https://387.ntsfp9.sparsity.cloud/",
        )

        with patch.object(app, "NovaRegistry", return_value=MagicMock()) as registry_ctor:
            client = app.KMSClient()

        registry = registry_ctor.return_value
        registry.get_active_instances.side_effect = [
            [first_inst.tee_wallet_address],
            [second_inst.tee_wallet_address],
        ]
        registry.get_instance_by_wallet.side_effect = [first_inst, second_inst]

        with patch.object(app, "verify_instance_identity", return_value=True):
            first = await client.get_kms_nodes()
            second = await client.get_kms_nodes()

        self.assertEqual(registry.get_active_instances.call_count, 2)
        self.assertEqual(registry.get_instance_by_wallet.call_count, 2)
        self.assertEqual(first[0]["instance_url"], "https://384.ntsfp9.sparsity.cloud/")
        self.assertEqual(second[0]["instance_url"], "https://387.ntsfp9.sparsity.cloud/")


if __name__ == "__main__":
    unittest.main()
