"""
=============================================================================
Simulation Mode (simulation.py)
=============================================================================

Provides fake / in-memory implementations of on-chain components for local
development and testing.  When ``SIMULATION_MODE`` is enabled:

- No blockchain RPC connection is needed (no Helios, no Chain).
- No Odyn SDK is needed.
- Peer nodes are configured statically in ``config.py`` or env vars.
- ``AppAuthorizer`` uses the same real class but backed by the simulation
    registries, so the auth logic still executes.

Usage
-----
Toggle via **environment variable** or **config constant**::

    SIMULATION_MODE=1 python app.py          # env-var (recommended)

Or set ``config.SIMULATION_MODE = True`` and run ``python app.py``.

Multiple local nodes can be launched on different ports::

    SIMULATION_MODE=1 SIM_PORT=8001 SIM_NODE_INDEX=1 python app.py
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from nova_registry import App, AppVersion, RuntimeInstance

logger = logging.getLogger("nova-kms.simulation")


_SIM_PRIV_BY_WALLET: Dict[str, str] = {}


def _derive_sim_private_key_hex(seed: bytes) -> str:
    # 32-byte hex private key
    return hashlib.sha256(b"nova-kms-sim-peer|" + seed).hexdigest()


def _derive_wallet_from_private_key_hex(private_key_hex: str) -> str:
    from eth_account import Account

    pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
    return Account.from_key(bytes.fromhex(pk)).address


def get_sim_private_key_hex(wallet: str) -> Optional[str]:
    """Return the deterministic simulation private key for a given sim wallet."""
    if not wallet:
        return None
    return _SIM_PRIV_BY_WALLET.get(wallet.lower())


def get_sim_odyn_for_wallet(wallet: str) -> Optional["SimOdyn"]:
    """Return a SimOdyn signer whose address is `wallet` (simulation only)."""
    pk = get_sim_private_key_hex(wallet)
    if not pk:
        return None
    return SimOdyn(pk)


class SimOdyn:
    """Local-only signer used in simulation mode.

    This avoids relying on an external Odyn service while still supporting
    PoP-based auth flows.
    """

    def __init__(self, private_key_hex: str):
        from eth_account import Account

        pk = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex
        self._account = Account.from_key(bytes.fromhex(pk))

    def eth_address(self) -> str:
        return self._account.address

    def sign_message(self, message: str, include_attestation: bool = False) -> dict:
        from eth_account.messages import encode_defunct

        signed = self._account.sign_message(encode_defunct(text=message))
        return {"signature": signed.signature.hex()}


# =============================================================================
# Simulated peer definition
# =============================================================================

@dataclass
class SimPeer:
    """One simulated KMS node."""

    tee_wallet: str
    node_url: str
    operator: str = ""

    def __post_init__(self):
        if not self.operator:
            self.operator = self.tee_wallet


# =============================================================================
# Default simulation topology
# =============================================================================

def _make_default_sim_peers() -> List[SimPeer]:
    peers: List[SimPeer] = []
    for idx, url in enumerate(("http://localhost:4000", "http://localhost:4001", "http://localhost:4002")):
        priv_hex = _derive_sim_private_key_hex(f"peer-{idx}".encode("utf-8"))
        wallet = _derive_wallet_from_private_key_hex(priv_hex)
        _SIM_PRIV_BY_WALLET[wallet.lower()] = priv_hex
        peers.append(SimPeer(tee_wallet=wallet, node_url=url))
    return peers


DEFAULT_SIM_PEERS: List[SimPeer] = _make_default_sim_peers()

DEFAULT_SIM_APP_ID = 9999
DEFAULT_SIM_VERSION_ID = 1
DEFAULT_SIM_CODE_MEASUREMENT = b"\x00" * 32


# =============================================================================
# SimKMSRegistryClient
# =============================================================================

class SimKMSRegistryClient:
    """
    In-memory KMSRegistry that returns a configured set of operators.

    Drop-in replacement for ``KMSRegistryClient`` — exposes the same
    read-only methods but never touches the network.
    """

    def __init__(self, peers: Optional[List[SimPeer]] = None):
        peers = peers if peers is not None else DEFAULT_SIM_PEERS
        self._operators: List[str] = [p.tee_wallet for p in peers]
        self._lower_set = {w.lower() for w in self._operators}

    # -- Views (match KMSRegistryClient API) ---------------------------------

    def get_operators(self) -> List[str]:
        return list(self._operators)

    def is_operator(self, wallet: str) -> bool:
        return wallet.lower() in self._lower_set

    def operator_count(self) -> int:
        return len(self._operators)

    def operator_at(self, index: int) -> str:
        if index < 0 or index >= len(self._operators):
            raise IndexError(f"operator index {index} out of range")
        return self._operators[index]


# =============================================================================
# SimNovaRegistry
# =============================================================================

class SimNovaRegistry:
    """
    In-memory NovaAppRegistry that returns fake App / Version / Instance
    objects for any configured peer wallet.

    It also accepts *any* wallet in ``get_instance_by_wallet`` (for client
    auth simulation): an unknown wallet still returns a valid instance so
    that dev requests with arbitrary ``x-tee-wallet`` headers succeed.
    """

    def __init__(
        self,
        peers: Optional[List[SimPeer]] = None,
        *,
        kms_app_id: int = DEFAULT_SIM_APP_ID,
        version_id: int = DEFAULT_SIM_VERSION_ID,
        code_measurement: bytes = DEFAULT_SIM_CODE_MEASUREMENT,
        open_auth: bool = True,
    ):
        from nova_registry import (
            App,
            AppStatus,
            AppVersion,
            InstanceStatus,
            RuntimeInstance,
            VersionStatus,
        )

        self._peers = peers if peers is not None else DEFAULT_SIM_PEERS
        self._kms_app_id = kms_app_id
        self._version_id = version_id
        self._code_measurement = code_measurement
        self._open_auth = open_auth

        # Pre-build lookup by lower-case wallet
        self._instances: Dict[str, RuntimeInstance] = {}
        for idx, p in enumerate(self._peers, start=1):
            self._instances[p.tee_wallet.lower()] = RuntimeInstance(
                instance_id=idx,
                app_id=kms_app_id,
                version_id=version_id,
                operator=p.operator,
                instance_url=p.node_url,
                tee_pubkey=b"\x04" + hashlib.sha256(p.tee_wallet.encode()).digest(),
                tee_wallet_address=p.tee_wallet,
                zk_verified=True,
                status=InstanceStatus.ACTIVE,
                registered_at=0,
            )

        # Cached App / Version objects
        self._app = App(
            app_id=kms_app_id,
            owner="0x" + "00" * 20,
            tee_arch=b"\x00" * 32,
            dapp_contract="0x" + "00" * 20,
            metadata_uri="",
            latest_version_id=version_id,
            created_at=0,
            status=AppStatus.ACTIVE,
        )
        self._version = AppVersion(
            version_id=version_id,
            version_name="sim-v1",
            code_measurement=code_measurement,
            image_uri="",
            audit_url="",
            audit_hash="",
            github_run_id="",
            status=VersionStatus.ENROLLED,
            enrolled_at=0,
            enrolled_by="0x" + "00" * 20,
        )

    # -- API (matches NovaRegistry) ------------------------------------------

    def get_instance_by_wallet(self, wallet: str) -> "RuntimeInstance":
        from nova_registry import InstanceStatus, RuntimeInstance

        inst = self._instances.get(wallet.lower())
        if inst:
            return inst
        # In open_auth mode, fabricate an instance for unknown wallets
        # so that dev requests with arbitrary x-tee-wallet headers work.
        if self._open_auth:
            wid = int(hashlib.sha256(wallet.encode()).hexdigest()[:8], 16)
            return RuntimeInstance(
                instance_id=wid,
                app_id=self._kms_app_id,
                version_id=self._version_id,
                operator=wallet,
                instance_url="",
                tee_pubkey=b"",
                tee_wallet_address=wallet,
                zk_verified=True,
                status=InstanceStatus.ACTIVE,
                registered_at=0,
            )
        raise ValueError(f"Instance not found for wallet {wallet}")

    def get_app(self, app_id: int) -> "App":
        return self._app

    def get_version(self, app_id: int, version_id: int) -> "AppVersion":
        return self._version

    def get_instance(self, instance_id: int) -> "RuntimeInstance":
        for inst in self._instances.values():
            if inst.instance_id == instance_id:
                return inst
        raise ValueError(f"Instance {instance_id} not found")


# =============================================================================
# Helpers
# =============================================================================

def is_simulation_mode() -> bool:
    """
    Return True when simulation mode is active.

    Safety guard: always returns False when running inside a Nitro Enclave
    (IN_ENCLAVE=true), regardless of the SIMULATION_MODE setting.
    """
    import config as _cfg

    # Hard safety guard: never allow simulation in a real enclave
    if getattr(_cfg, "IN_ENCLAVE", False):
        return False

    # Environment variable takes precedence
    env = os.getenv("SIMULATION_MODE", "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    if env in ("0", "false", "no"):
        return False
    return getattr(_cfg, "SIMULATION_MODE", False)


def get_sim_port() -> int:
    """Return the port for this simulation node (default 4000)."""
    return int(os.getenv("SIM_PORT", "4000"))


def get_sim_node_index() -> int:
    """Return the index into SIM_PEERS for this node (default 0)."""
    return int(os.getenv("SIM_NODE_INDEX", "0"))


def get_sim_peers() -> List[SimPeer]:
    """Build the peer list from config or env overrides."""
    import config as _cfg

    peers: List[SimPeer] = getattr(_cfg, "SIM_PEERS", None) or []
    if not peers:
        peers = list(DEFAULT_SIM_PEERS)

    # Allow env-var override in "wallet:url,wallet:url" compact form
    env_peers = os.getenv("SIM_PEERS_CSV", "").strip()
    if env_peers:
        peers = []
        for entry in env_peers.split(","):
            parts = entry.strip().split("|")
            if len(parts) == 2:
                peers.append(SimPeer(tee_wallet=parts[0], node_url=parts[1]))
    return peers


def get_sim_master_secret() -> bytes:
    """Return a deterministic or configured master secret for sim mode."""
    import config as _cfg

    hex_secret = os.getenv("SIM_MASTER_SECRET", "") or getattr(_cfg, "SIM_MASTER_SECRET_HEX", "")
    if hex_secret:
        return bytes.fromhex(hex_secret.replace("0x", ""))
    # Default deterministic secret for reproducible dev runs
    return hashlib.sha256(b"nova-kms-simulation-master-secret").digest()


def build_sim_components(
    peers: Optional[List[SimPeer]] = None,
    *,
    kms_app_id: Optional[int] = None,
    scheduler: Optional[Any] = None,  # Pass False to disable
) -> dict:
    """
    Factory that assembles all simulation-mode components.

    Returns a dict with keys:
        tee_wallet, node_url, kms_registry, nova_registry,
        authorizer, odyn, master_secret, sync_manager, data_store
    """
    import config as _cfg
    from auth import AppAuthorizer
    from data_store import DataStore
    from kdf import MasterSecretManager
    from sync_manager import PeerCache, SyncManager

    if peers is None:
        peers = get_sim_peers()

    node_idx = get_sim_node_index()
    if node_idx < 0 or node_idx >= len(peers):
        node_idx = 0

    this_node = peers[node_idx]
    app_id = kms_app_id or getattr(_cfg, "KMS_APP_ID", None) or DEFAULT_SIM_APP_ID

    kms_registry = SimKMSRegistryClient(peers)
    nova_registry = SimNovaRegistry(peers, kms_app_id=app_id)

    authorizer = AppAuthorizer(registry=nova_registry)
    master_secret = get_sim_master_secret()

    # Deterministic per-node signer for PoP in simulation.
    priv_hex = get_sim_private_key_hex(this_node.tee_wallet) or _derive_sim_private_key_hex(
        f"peer-fallback|{node_idx}".encode("utf-8")
    )
    odyn = SimOdyn(priv_hex)

    port = get_sim_port()
    node_url = f"http://localhost:{port}"

    logger.info(
        f"Simulation mode: wallet={this_node.tee_wallet}, "
        f"url={node_url}, peers={len(peers)}, app_id={app_id}"
    )

    data_store = DataStore(node_id=this_node.tee_wallet)
    peer_cache = PeerCache(kms_registry_client=kms_registry, nova_registry=nova_registry)
    
    # KDF manager
    master_mgr = MasterSecretManager()
    if master_secret:
        master_mgr.initialize_from_peer(master_secret)

    sync_manager = SyncManager(
        data_store=data_store,
        node_wallet=this_node.tee_wallet,
        peer_cache=peer_cache,
        odyn=odyn,
        scheduler=scheduler,
    )
    sync_manager.set_sync_key(master_mgr.derive(0, "sync_key"))

    return {
        "tee_wallet": this_node.tee_wallet,
        "node_url": node_url,
        "kms_registry": kms_registry,
        "nova_registry": nova_registry,
        "authorizer": authorizer,
        "odyn": odyn,
        "master_secret": master_secret,
        "master_secret_mgr": master_mgr,
        "sync_manager": sync_manager,
        "data_store": data_store,
    }
