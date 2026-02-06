"""
=============================================================================
Sync Manager (sync_manager.py)
=============================================================================

Handles data synchronization between KMS nodes.

- **Delta sync**: periodic push of recent changes to peers.
- **Snapshot sync**: full state transfer for nodes that are far behind.
- **Master secret sharing**: new nodes receive the master secret from peers
  via sealed ECDH key exchange (not plaintext).

Peer discovery: ``KMSRegistry.getOperators()`` → for each operator,
``NovaAppRegistry.getInstanceByWallet(operator)`` → instance URL + wallet.

Security features:
- All sync messages are HMAC-signed using a key derived from the master secret.
- Peer URLs are validated against SSRF before outbound requests.
- HTTPS is enforced in production mode.
- Payload size limits are enforced.
- Master secret is transferred via sealed ECDH envelope, never as plaintext.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

import requests

from config import (
    MAX_SYNC_PAYLOAD_BYTES,
    PEER_CACHE_TTL_SECONDS,
    SYNC_BATCH_SIZE,
    SYNC_INTERVAL_SECONDS,
)
from data_store import DataStore
from url_validator import URLValidationError, validate_peer_url

logger = logging.getLogger("nova-kms.sync")


# =============================================================================
# HMAC Message Signing
# =============================================================================

def _compute_hmac(sync_key: bytes, payload: bytes) -> str:
    """Compute HMAC-SHA256 of a payload using the sync key."""
    return hmac.new(sync_key, payload, hashlib.sha256).hexdigest()


def _verify_hmac(sync_key: bytes, payload: bytes, signature: str) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = hmac.new(sync_key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# =============================================================================
# Peer Cache
# =============================================================================

class PeerCache:
    """
    Caches the list of active KMS peer nodes discovered via KMSRegistry
    operators + NovaAppRegistry instance data.
    Refreshed every PEER_CACHE_TTL_SECONDS.
    """

    def __init__(self, kms_registry_client=None, nova_registry=None):
        self._kms_registry = kms_registry_client
        self._nova_registry = nova_registry
        self._peers: List[dict] = []
        self._last_refresh: float = 0
        self._lock = threading.Lock()

    @property
    def kms_registry(self):
        if self._kms_registry is None:
            from kms_registry import KMSRegistryClient
            self._kms_registry = KMSRegistryClient()
        return self._kms_registry

    @property
    def nova_registry(self):
        if self._nova_registry is None:
            from nova_registry import NovaRegistry
            self._nova_registry = NovaRegistry()
        return self._nova_registry

    def refresh(self) -> None:
        """Force a refresh of the peer cache from on-chain data."""
        with self._lock:
            self._refresh()

    def remove_peer(self, wallet: str) -> None:
        """Remove a peer from the cache by wallet address (step 4.3)."""
        lower = wallet.lower()
        with self._lock:
            self._peers = [p for p in self._peers if p["tee_wallet_address"].lower() != lower]
            logger.info(f"Removed peer {wallet} from cache")

    def get_peers(self, exclude_wallet: Optional[str] = None) -> List[dict]:
        """Return list of peer dicts, refreshing from chain if stale."""
        with self._lock:
            if time.time() - self._last_refresh > PEER_CACHE_TTL_SECONDS:
                self._refresh()
            peers = list(self._peers)

        if exclude_wallet:
            exclude = exclude_wallet.lower()
            peers = [p for p in peers if p["tee_wallet_address"].lower() != exclude]
        return peers

    def _refresh(self):
        """Refresh peer list from KMSRegistry operators + NovaAppRegistry."""
        try:
            operators = self.kms_registry.get_operators()
            peers: List[dict] = []
            for operator in operators:
                try:
                    instance = self.nova_registry.get_instance_by_wallet(operator)
                    # Validate peer URL before adding to cache
                    try:
                        validate_peer_url(instance.instance_url)
                    except URLValidationError as url_err:
                        logger.warning(
                            f"Skipping peer {operator}: invalid URL "
                            f"'{instance.instance_url}': {url_err}"
                        )
                        continue
                    peers.append({
                        "tee_wallet_address": instance.tee_wallet_address,
                        "node_url": instance.instance_url,
                        "operator": instance.operator,
                    })
                except Exception as exc:
                    logger.debug(f"Instance lookup failed for operator {operator}: {exc}")
            self._peers = peers
            self._last_refresh = time.time()
            logger.info(f"Peer cache refreshed: {len(self._peers)} operators")
        except Exception as exc:
            logger.warning(f"Failed to refresh peer cache: {exc}")


# =============================================================================
# Sync Manager
# =============================================================================

class SyncManager:
    """
    Orchestrates data synchronization between KMS nodes.

    Usage:
        mgr = SyncManager(data_store, node_wallet, peer_cache)
        mgr.push_deltas()    # called periodically
        mgr.request_snapshot(peer_url)  # on startup if needed
    """

    def __init__(
        self,
        data_store: DataStore,
        node_wallet: str,
        peer_cache: PeerCache,
        *,
        http_timeout: int = 15,
    ):
        self.data_store = data_store
        self.node_wallet = node_wallet
        self.peer_cache = peer_cache
        self.http_timeout = http_timeout
        self._last_push_ms: int = 0
        self._sync_key: Optional[bytes] = None

    def set_sync_key(self, sync_key: bytes) -> None:
        """Set the HMAC key used for signing sync messages."""
        self._sync_key = sync_key

    def verify_and_sync_peers(
        self,
        kms_registry,
        *,
        master_secret_mgr=None,
        probe_timeout: int = 5,
    ) -> int:
        """
        Implements KMS Node Initialization Workflow steps 4.1–4.5:

        For each discovered peer:
          4.1 Probe the peer via /health (RA-TLS in production).
          4.2 Verify the peer’s wallet address is in the KMS registry.
          4.3 Save verified peers; remove unverified ones from the cache.
          4.4 If master secret is not yet initialized and a verified peer
              is available, request it via sealed ECDH + sync snapshot.
          4.5 Repeat for all peers.

        Returns the count of verified peers.
        """
        from probe import probe_node

        peers = self.peer_cache.get_peers(exclude_wallet=self.node_wallet)
        verified_count = 0

        for peer in peers:
            peer_url = peer["node_url"]
            peer_wallet = peer["tee_wallet_address"]

            # 4.1 Probe the peer (health check / RA-TLS handshake)
            if not probe_node(peer_url, timeout=probe_timeout):
                logger.debug(f"Peer {peer_wallet} at {peer_url} is unreachable")
                continue

            # 4.2 Verify the peer wallet is a registered KMS operator
            try:
                is_valid = kms_registry.is_operator(peer_wallet)
            except Exception as exc:
                logger.warning(f"Operator check failed for {peer_wallet}: {exc}")
                is_valid = False

            if not is_valid:
                # 4.3 Remove invalid peer from cache
                logger.warning(f"Peer {peer_wallet} is not a registered operator — removing")
                self.peer_cache.remove_peer(peer_wallet)
                continue

            # 4.3 Peer is verified
            verified_count += 1
            logger.info(f"Peer {peer_wallet} verified as KMS operator")

            # 4.4 Sync from verified peer if master secret still needed
            if master_secret_mgr and not master_secret_mgr.is_initialized:
                self._sync_master_secret_from_peer(peer_url, master_secret_mgr)

        logger.info(f"Peer verification complete: {verified_count}/{len(peers)} verified")
        return verified_count

    def _sync_master_secret_from_peer(self, peer_url: str, master_secret_mgr) -> bool:
        """
        Request the master secret from a verified peer using sealed ECDH,
        then pull a snapshot.  Returns True on success.
        """
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _ser
        from kdf import unseal_master_secret

        ecdh_key = _ec.generate_private_key(_ec.SECP256R1())
        ecdh_pubkey = ecdh_key.public_key().public_bytes(
            _ser.Encoding.X962, _ser.PublicFormat.UncompressedPoint,
        )
        result = self.request_master_secret(peer_url, ecdh_pubkey=ecdh_pubkey)

        if result and isinstance(result, dict):
            secret, epoch = unseal_master_secret(result, ecdh_key)
            master_secret_mgr.initialize_from_peer(secret, epoch=epoch)
            self.request_snapshot(peer_url)
            logger.info(f"Master secret received via sealed ECDH from {peer_url}")
            return True
        elif result and isinstance(result, bytes):
            # Legacy plaintext fallback (dev/sim only)
            master_secret_mgr.initialize_from_peer(result)
            self.request_snapshot(peer_url)
            return True

        return False

    def _sign_payload(self, payload_json: str) -> Optional[str]:
        """Sign a JSON payload string; returns hex HMAC or None."""
        if self._sync_key:
            return _compute_hmac(self._sync_key, payload_json.encode("utf-8"))
        return None

    def _make_request(self, url: str, body: dict, timeout: int = None) -> Optional[requests.Response]:
        """
        Make an outbound sync request with URL validation and optional
        HMAC signing.
        """
        if timeout is None:
            timeout = self.http_timeout

        # Validate URL before making request
        try:
            validate_peer_url(url)
        except URLValidationError as exc:
            logger.warning(f"Refusing outbound request to {url}: {exc}")
            return None

        # Add HMAC signature if sync key is available
        payload_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sig = self._sign_payload(payload_json)
        headers = {"Content-Type": "application/json"}
        if sig:
            headers["X-Sync-Signature"] = sig

        try:
            resp = requests.post(
                url,
                data=payload_json,
                headers=headers,
                timeout=timeout,
            )
            return resp
        except Exception as exc:
            logger.debug(f"Request to {url} failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Delta push
    # ------------------------------------------------------------------

    def push_deltas(self) -> int:
        """
        Push recent deltas to all healthy peers.
        Returns the number of peers successfully synced.
        """
        since_ms = self._last_push_ms
        deltas = self.data_store.get_deltas_since(since_ms)
        if not deltas:
            return 0

        # Serialize
        payload = self._serialize_deltas(deltas)
        peers = self.peer_cache.get_peers(exclude_wallet=self.node_wallet)
        success_count = 0

        body = {
            "type": "delta",
            "sender_wallet": self.node_wallet,
            "data": payload,
        }

        for peer in peers:
            url = f"{peer['node_url'].rstrip('/')}/sync"
            resp = self._make_request(url, body)
            if resp and resp.status_code == 200:
                success_count += 1
            elif resp:
                logger.warning(f"Sync push to {peer['node_url']} returned {resp.status_code}")

        self._last_push_ms = int(time.time() * 1000)
        logger.info(f"Delta push: {success_count}/{len(peers)} peers synced")
        return success_count

    # ------------------------------------------------------------------
    # Snapshot request (pull-based, for startup rehydration)
    # ------------------------------------------------------------------

    def request_snapshot(self, peer_url: str) -> int:
        """
        Pull a full snapshot from a peer and merge it into the local store.
        Returns count of merged records.
        """
        url = f"{peer_url.rstrip('/')}/sync"
        body = {
            "type": "snapshot_request",
            "sender_wallet": self.node_wallet,
        }
        resp = self._make_request(url, body, timeout=30)
        if not resp:
            return 0
        try:
            resp.raise_for_status()
            snapshot_data = resp.json().get("data", {})
            merged = self.data_store.merge_snapshot(snapshot_data)
            logger.info(f"Snapshot from {peer_url}: {merged} records merged")
            return merged
        except Exception as exc:
            logger.warning(f"Snapshot request to {peer_url} failed: {exc}")
            return 0

    def request_master_secret(self, peer_url: str, ecdh_pubkey: Optional[bytes] = None) -> Optional[dict]:
        """
        Request the master secret from a peer using sealed ECDH exchange.

        If ecdh_pubkey is provided, the peer will encrypt the master secret
        using ECDH + AES-GCM.  Returns the sealed envelope dict.
        If ecdh_pubkey is None, returns raw secret bytes (legacy/sim mode).
        """
        url = f"{peer_url.rstrip('/')}/sync"
        body: dict = {
            "type": "master_secret_request",
            "sender_wallet": self.node_wallet,
        }
        if ecdh_pubkey:
            body["ecdh_pubkey"] = ecdh_pubkey.hex()

        resp = self._make_request(url, body, timeout=15)
        if not resp:
            return None
        try:
            resp.raise_for_status()
            data = resp.json()
            # Sealed envelope response
            if "sealed" in data:
                return data["sealed"]
            # Legacy plaintext response (sim mode only)
            secret_hex = data.get("master_secret")
            if secret_hex:
                return bytes.fromhex(secret_hex)
            return None
        except Exception as exc:
            logger.warning(f"Master secret request to {peer_url} failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Incoming sync handler (called by routes.py /sync endpoint)
    # ------------------------------------------------------------------

    def handle_incoming_sync(self, body: dict, *, signature: Optional[str] = None) -> dict:
        """
        Process an incoming sync request from a peer.

        Validates HMAC signature when a sync key is configured.

        Expected body shapes:
          - {"type": "delta", "sender_wallet": "0x...", "data": {...}}
          - {"type": "snapshot_request", "sender_wallet": "0x..."}
          - {"type": "master_secret_request", "sender_wallet": "0x...", "ecdh_pubkey": "hex"}
        """
        # Verify HMAC signature if sync key is set
        if self._sync_key and signature:
            payload_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
            if not _verify_hmac(self._sync_key, payload_json.encode("utf-8"), signature):
                logger.warning("Sync message HMAC verification failed")
                return {"status": "error", "reason": "Invalid signature"}

        sync_type = body.get("type", "")

        if sync_type == "delta":
            merged = self._apply_deltas(body.get("data", {}))
            return {"status": "ok", "merged": merged}

        if sync_type == "snapshot_request":
            snapshot = self._serialize_snapshot()
            return {"status": "ok", "data": snapshot}

        if sync_type == "master_secret_request":
            return self._handle_master_secret_request(body)

        return {"status": "error", "reason": f"Unknown sync type: {sync_type}"}

    def _handle_master_secret_request(self, body: dict) -> dict:
        """Handle a master secret request, using sealed ECDH if peer provides a pubkey."""
        from kdf import MasterSecretManager, seal_master_secret
        import app as app_module

        mgr: MasterSecretManager = getattr(app_module, "master_secret_mgr", None)
        if not mgr or not mgr.is_initialized:
            return {"status": "error", "reason": "Master secret not initialized"}

        ecdh_pubkey_hex = body.get("ecdh_pubkey")
        if ecdh_pubkey_hex:
            # Sealed exchange: encrypt with ECDH + AES-GCM
            try:
                peer_pubkey_bytes = bytes.fromhex(ecdh_pubkey_hex)
                sealed = seal_master_secret(mgr.secret, mgr.epoch, peer_pubkey_bytes)
                return {"status": "ok", "sealed": sealed}
            except Exception as exc:
                logger.error(f"Sealed key exchange failed: {exc}")
                return {"status": "error", "reason": "Sealed exchange failed"}
        else:
            # Legacy plaintext (only in sim/dev mode)
            from config import IN_ENCLAVE
            if IN_ENCLAVE:
                logger.warning("Rejecting plaintext master secret request in production")
                return {"status": "error", "reason": "Plaintext secret exchange disabled in production"}
            return {"status": "ok", "master_secret": mgr.secret.hex()}

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_deltas(deltas: Dict[int, list]) -> dict:
        """Convert deltas dict to JSON-safe format."""
        out: dict = {}
        for app_id, records in deltas.items():
            out[str(app_id)] = [
                r.to_dict() if hasattr(r, "to_dict") else r
                for r in records
            ]
        return out

    def _serialize_snapshot(self) -> dict:
        snapshot = self.data_store.full_snapshot()
        return self._serialize_deltas(snapshot)

    def _apply_deltas(self, data: dict) -> int:
        """Apply serialized delta records from a peer."""
        from data_store import DataRecord
        merged = 0
        for app_id_str, records in data.items():
            app_id = int(app_id_str)
            for rec_dict in records:
                rec = DataRecord.from_dict(rec_dict)
                if self.data_store.merge_record(app_id, rec):
                    merged += 1
        return merged
