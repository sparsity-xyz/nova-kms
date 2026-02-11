"""
=============================================================================
Sync Manager (sync_manager.py)
=============================================================================

Handles data synchronization between KMS nodes.

- **Delta sync**: periodic push of recent changes to peers.
- **Snapshot sync**: full state transfer for nodes that are far behind.
- **Master secret sharing**: new nodes receive the master secret from peers
  via sealed ECDH key exchange (not plaintext).

Peer discovery: ``NovaAppRegistry`` → ``KMS_APP_ID`` → ENROLLED versions → ACTIVE instances.

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
from eth_hash.auto import keccak

import config as config_module

from config import (
    MAX_SYNC_PAYLOAD_BYTES,
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

PEER_CACHE_TTL_SECONDS = 30


class PeerCache:
    """
    Caches the list of active KMS peer nodes discovered via NovaAppRegistry:
    KMS_APP_ID -> ENROLLED versions -> ACTIVE instances.
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

    def _is_stale(self) -> bool:
        """Check if the cache needs refreshing."""
        return (time.time() - self._last_refresh) > PEER_CACHE_TTL_SECONDS

    def get_peers(self, exclude_wallet: Optional[str] = None) -> List[dict]:
        """Return list of peer dicts, auto-refreshing if stale."""
        if self._is_stale():
            with self._lock:
                if self._is_stale():  # double-check inside lock
                    self._refresh()

        with self._lock:
            peers = list(self._peers)

        if exclude_wallet:
            exclude = exclude_wallet.lower()
            peers = [p for p in peers if p["tee_wallet_address"].lower() != exclude]
        return peers

    def get_wallet_by_url(self, url: str) -> Optional[str]:
        """Look up a peer's wallet address by their base URL."""
        base = url.rstrip("/")
        with self._lock:
            for p in self._peers:
                if p["node_url"].rstrip("/") == base:
                    return p["tee_wallet_address"]
        return None

    def _refresh(self):
        """Refresh peer list from NovaAppRegistry."""
        try:
            from config import KMS_APP_ID
            from nova_registry import InstanceStatus, VersionStatus

            kms_app_id = int(KMS_APP_ID or 0)
            if kms_app_id <= 0:
                raise ValueError("KMS_APP_ID not configured")

            app = self.nova_registry.get_app(kms_app_id)
            latest_version_id = int(getattr(app, "latest_version_id", 0) or 0)

            peers: List[dict] = []
            seen_wallets: set[str] = set()

            for version_id in range(1, latest_version_id + 1):
                try:
                    ver = self.nova_registry.get_version(kms_app_id, version_id)
                except Exception:
                    continue

                if getattr(ver, "status", None) != VersionStatus.ENROLLED:
                    continue

                try:
                    instance_ids = self.nova_registry.get_instances_for_version(kms_app_id, version_id) or []
                except Exception as exc:
                    logger.debug(f"Instances lookup failed for version {version_id}: {exc}")
                    continue

                for instance_id in instance_ids:
                    try:
                        instance = self.nova_registry.get_instance(int(instance_id))
                    except Exception as exc:
                        logger.debug(f"Instance lookup failed for id {instance_id}: {exc}")
                        continue

                    if getattr(instance, "status", None) != InstanceStatus.ACTIVE:
                        continue

                    wallet = (getattr(instance, "tee_wallet_address", "") or "").lower()
                    if not wallet or wallet in seen_wallets:
                        continue

                    # Validate peer URL before adding to cache
                    try:
                        validate_peer_url(instance.instance_url)
                    except URLValidationError as url_err:
                        logger.warning(
                            f"Skipping peer {wallet}: invalid URL "
                            f"'{instance.instance_url}': {url_err}"
                        )
                        continue

                    peers.append(
                        {
                            "tee_wallet_address": instance.tee_wallet_address,
                            "node_url": instance.instance_url,
                            "operator": instance.operator,
                            "status": instance.status,
                            "version_id": instance.version_id,
                            "instance_id": instance.instance_id,
                        }
                    )
                    seen_wallets.add(wallet)
            self._peers = peers
            self._last_refresh = time.time()
            logger.info(f"Peer cache refreshed: {len(self._peers)} active KMS instances")
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
        odyn=None,
        http_timeout: int = 15,
    ):
        self.data_store = data_store
        self.node_wallet = node_wallet
        self.peer_cache = peer_cache
        self.odyn = odyn
        self.http_timeout = http_timeout

        # Periodic node-tick state
        self._seed_stable_rounds: int = 0
        self._last_push_deltas_at: float = 0.0
        self._last_push_ms: int = 0
        self._sync_key: Optional[bytes] = None

    def set_sync_key(self, sync_key: bytes) -> None:
        """Set the HMAC key used for signing sync messages."""
        self._sync_key = sync_key

    def verify_and_sync_peers(
        self,
        nova_registry=None,
        *,
        master_secret_mgr=None,
        probe_timeout: int = 5,
    ) -> int:
        """
        Implements KMS Node Initialization Workflow steps 4.1–4.5:

        For each discovered peer:
          4.1 Probe the peer via /health.
          4.2 Verify the peer’s wallet address is an ACTIVE KMS instance
              in the NovaAppRegistry (by KMS_APP_ID).
          4.3 Save verified peers; remove unverified ones from the cache.
          4.4 If master secret is not yet initialized and a verified peer
              is available, request it via sealed ECDH + sync snapshot.
          4.5 Repeat for all peers.

        Returns the count of verified peers.
        """
        from probe import probe_node
        from nova_registry import InstanceStatus

        if nova_registry is None:
            nova_registry = self.peer_cache.nova_registry

        from config import KMS_APP_ID
        kms_app_id = int(KMS_APP_ID or 0)

        peers = self.peer_cache.get_peers(exclude_wallet=self.node_wallet)
        verified_count = 0

        for peer in peers:
            peer_url = peer["node_url"]
            peer_wallet = peer["tee_wallet_address"]

            # 4.1 Probe the peer (health check)
            if not probe_node(peer_url, timeout=probe_timeout):
                logger.debug(f"Peer {peer_wallet} at {peer_url} is unreachable")
                continue

            # 4.2 Verify the peer wallet is an ACTIVE KMS instance via NovaAppRegistry
            is_valid = False
            try:
                instance = nova_registry.get_instance_by_wallet(peer_wallet)
                is_valid = (
                    getattr(instance, "instance_id", 0) != 0
                    and getattr(instance, "app_id", None) == kms_app_id
                    and getattr(instance, "status", None) == InstanceStatus.ACTIVE
                )
            except Exception as exc:
                logger.warning(f"NovaAppRegistry check failed for {peer_wallet}: {exc}")

            if not is_valid:
                # 4.3 Remove invalid peer from cache
                logger.warning(f"Peer {peer_wallet} is not a valid KMS instance — removing")
                self.peer_cache.remove_peer(peer_wallet)
                continue

            # 4.3 Peer is verified
            verified_count += 1
            logger.info(f"Peer {peer_wallet} verified as active KMS instance")

            # 4.4 Sync from verified peer if master secret still needed
            if master_secret_mgr and not master_secret_mgr.is_initialized:
                self._sync_master_secret_from_peer(peer_url, master_secret_mgr)

        logger.info(f"Peer verification complete: {verified_count}/{len(peers)} verified")
        return verified_count

    # ------------------------------------------------------------------
    # Single periodic node tick (operator + ACTIVE gating, init, sync)
    # ------------------------------------------------------------------

    def node_tick(self, master_secret_mgr) -> None:
        """Single periodic task implementing the KMS node lifecycle.

                Rules:
                    1) Discover KMS node list from NovaAppRegistry (ENROLLED versions, ACTIVE instances).
                         If self is not in this list -> offline (503) and do nothing.
                    2) Read on-chain KMSRegistry masterSecretHash.
                         - If hash == 0: ensure local master secret exists, compute hash, attempt to set on-chain.
                             If set fails -> offline.
                         - If hash != 0: if local secret missing or hash mismatch -> sync master secret from peers.
                             If synced secret hash still mismatches -> offline.
                    3) If online: sync data with other KMS nodes.
        """

        import routes as routes_module

        def _set_unavailable(reason: str) -> None:
            try:
                routes_module.set_service_availability(False, reason=reason)
            except Exception:
                # If routes isn't initialized yet, just proceed silently.
                pass

        def _set_available() -> None:
            try:
                routes_module.set_service_availability(True, reason="")
            except Exception:
                pass

        # Always refresh KMS node list from chain each tick
        try:
            self.peer_cache.refresh()
        except Exception as exc:
            logger.warning(f"Peer cache refresh failed: {exc}")

        peers = self.peer_cache.get_peers()
        self_wallet = self.node_wallet.lower()
        kms_wallets = {
            (p.get("tee_wallet_address") or "").lower() for p in peers if p.get("tee_wallet_address")
        }

        # 1) If self not in kms node list -> offline and do nothing.
        if self_wallet not in kms_wallets:
            _set_unavailable("self not in KMS node list")
            return

        # 2) Read on-chain master secret hash
        kms_reg = self.peer_cache.kms_registry
        try:
            chain_hash = kms_reg.get_master_secret_hash()
        except Exception as exc:
            logger.warning(f"Failed to read masterSecretHash: {exc}")
            _set_unavailable("cannot read master secret hash")
            return

        chain_hash_is_zero = (chain_hash == b"\x00" * 32)

        def _local_secret_hash() -> Optional[bytes]:
            if not master_secret_mgr.is_initialized:
                return None
            # master secret bytes are stored on the manager
            secret = getattr(master_secret_mgr, "secret", None)
            if not isinstance(secret, (bytes, bytearray)):
                return None
            return keccak(bytes(secret))

        # 3.1 If chain hash is 0: generate (if needed) and attempt to set
        if chain_hash_is_zero:
            if not master_secret_mgr.is_initialized:
                if not self.odyn:
                    _set_unavailable("cannot generate master secret (no Odyn RNG)")
                    return
                try:
                    master_secret_mgr.initialize_from_random(self.odyn)
                except Exception as exc:
                    logger.warning(f"Master secret generation failed: {exc}")
                    _set_unavailable("master secret generation failed")
                    return

            local_hash = _local_secret_hash()
            if not local_hash or len(local_hash) != 32:
                _set_unavailable("local master secret hash unavailable")
                return

            # Attempt to set on-chain (one try per tick)
            try:
                if not self.odyn:
                    raise RuntimeError("Odyn unavailable for tx signing")
                tx_hash = kms_reg.set_master_secret_hash(
                    self.odyn,
                    setter_wallet=self.node_wallet,
                    secret_hash32=local_hash,
                )
                logger.info(f"Submitted setMasterSecretHash tx: {tx_hash}")
            except Exception as exc:
                logger.warning(f"Failed to set masterSecretHash on-chain: {exc}")
                _set_unavailable("failed to set master secret hash")
                return

            # Stay offline until the chain hash is non-zero and matches our local hash.
            _set_unavailable("awaiting on-chain master secret hash")
            return
        else:
            # 3.2 chain hash non-zero: ensure local secret matches, else sync
            local_hash = _local_secret_hash()
            if local_hash != chain_hash:
                # Need to sync master secret from peers
                if master_secret_mgr.is_initialized:
                    logger.warning("Local master secret hash mismatch; attempting to resync from peers")
                else:
                    logger.info("Local master secret missing; attempting sync from peers")

                synced = False
                for peer in peers:
                    peer_wallet = (peer.get("tee_wallet_address") or "").lower()
                    if not peer_wallet or peer_wallet == self_wallet:
                        continue
                    peer_url = peer.get("node_url")
                    if not peer_url:
                        continue
                    try:
                        if self._sync_master_secret_from_peer(peer_url, master_secret_mgr):
                            synced = True
                            break
                    except Exception as exc:
                        logger.warning(f"Master secret sync attempt from {peer_url} failed: {exc}")

                if not synced:
                    _set_unavailable("master secret sync failed")
                    return

                # Validate synced hash against chain
                local_hash = _local_secret_hash()
                if local_hash != chain_hash:
                    _set_unavailable("synced master secret hash mismatch")
                    return

                # sync_key set below (outside the if block)

            # Always (re-)derive and set sync key before going online
            try:
                self.set_sync_key(master_secret_mgr.get_sync_key())
            except Exception as exc:
                logger.warning(f"Failed to set sync key: {exc}")

            _set_available()

        # 4) If online: sync data with peers (paced)
        now = time.time()
        # Use config constant directly (imported at top)
        if now - self._last_push_deltas_at >= config_module.SYNC_INTERVAL_SECONDS:
            try:
                self.push_deltas()
            finally:
                self._last_push_deltas_at = now

    def _sync_master_secret_from_peer(self, peer_url: str, master_secret_mgr) -> bool:
        """
        Request the master secret from a verified peer using sealed ECDH,
        then pull a snapshot.  Returns True on success.
        """
        from kdf import unseal_master_secret
        from secure_channel import generate_ecdh_keypair

        ecdh_key, ecdh_pubkey_der = generate_ecdh_keypair()
        result = self.request_master_secret(peer_url, ecdh_pubkey=ecdh_pubkey_der)

        if result and isinstance(result, dict):
            secret = unseal_master_secret(result, ecdh_key)
            master_secret_mgr.initialize_from_peer(secret, peer_url=peer_url)
            self.request_snapshot(peer_url)
            logger.info(f"Master secret received via sealed ECDH from {peer_url}")
            return True
        elif result and isinstance(result, bytes):
            # Legacy plaintext fallback — ONLY allowed outside enclave (dev/sim).
            # C1 fix: production nodes must never accept an unencrypted master secret.
            if config_module.IN_ENCLAVE:
                logger.warning(
                    f"Rejecting plaintext master secret from {peer_url}: "
                    "plaintext exchange is disabled in production (IN_ENCLAVE=true)"
                )
                return False
            master_secret_mgr.initialize_from_peer(result, peer_url=peer_url)
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
        Make an outbound sync request with URL validation, optional
        HMAC signing, and PoP mutual authentication.
        """
        if timeout is None:
            timeout = self.http_timeout

        # Validate URL before making request
        try:
            validate_peer_url(url)
        except URLValidationError as exc:
            logger.warning(f"Refusing outbound request to {url}: {exc}")
            return None

        headers = {"Content-Type": "application/json"}

        # Derive base URL (used for /nonce) from the endpoint URL.
        # All callers pass URLs like "{peer_base}/sync".
        base_url = url.rsplit("/", 1)[0].rstrip("/")

        # 1. Lightweight PoP Signature (Handshake)
        # fetch peer's wallet from cache to bind signature to the intended recipient.
        peer_wallet = self.peer_cache.get_wallet_by_url(base_url)

        # PoP requires an explicit recipient wallet binding.
        # If we can't determine the peer wallet, refuse to send the request.
        if not peer_wallet:
            logger.warning(f"Refusing sync request to {url}: unknown peer wallet for {base_url}")
            return None

        # H1 fix: verify peer teePubkey against on-chain registry before
        # transmitting any data to the peer.  This prevents MitM by a host
        # that intercepts the TLS connection but cannot forge the on-chain
        # teePubkey registration.
        from secure_channel import verify_peer_identity
        if not verify_peer_identity(peer_wallet, self.peer_cache.nova_registry):
            logger.warning(
                f"Refusing sync request to {url}: peer {peer_wallet} failed "
                "teePubkey verification"
            )
            return None

        # Prevent self-sync: do not send requests to ourselves.
        if peer_wallet.lower() == self.node_wallet.lower():
            logger.warning(f"Refusing sync request to {url}: destination wallet match self ({peer_wallet})")
            return None
        
        try:
            # A. Fetch nonce from peer
            nonce_resp = requests.get(f"{base_url}/nonce", timeout=5)
            nonce_resp.raise_for_status()
            nonce_b64 = nonce_resp.json().get("nonce")
            
            if nonce_b64 and self.odyn and peer_wallet:
                import time
                timestamp = int(time.time())
                # B. Sign message: NovaKMS:Auth:{nonce_b64}:{peer_wallet}:{timestamp}
                # Using Wallet_B (peer's wallet) protects against signature re-use for other nodes
                message = f"NovaKMS:Auth:{nonce_b64}:{peer_wallet}:{timestamp}"
                sig_res = self.odyn.sign_message(message)
                
                headers["X-KMS-Signature"] = sig_res["signature"]
                headers["X-KMS-Wallet"] = self.node_wallet
                headers["X-KMS-Timestamp"] = str(timestamp)
                headers["X-KMS-Nonce"] = nonce_b64
        except Exception as exc:
            logger.warning(f"Failed to perform PoP handshake with {url}: {exc}")

        # Do not proceed without PoP headers.
        if "X-KMS-Signature" not in headers:
            return None

        # 2. HMAC signing (using sync key)
        payload_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sig = self._sign_payload(payload_json)
        if sig:
            headers["X-Sync-Signature"] = sig

        try:
            resp = requests.post(
                url,
                data=payload_json,
                headers=headers,
                timeout=timeout,
            )
            
            # 3. Verify Peer response signature for mutual auth
            resp_sig = resp.headers.get("X-KMS-Peer-Signature")
            if not resp_sig:
                logger.warning(f"Rejecting sync response from {url}: missing peer signature")
                return None

            from auth import verify_wallet_signature
            client_sig = headers.get("X-KMS-Signature")
            resp_msg = f"NovaKMS:Response:{client_sig}:{peer_wallet}"
            if not verify_wallet_signature(peer_wallet, resp_msg, resp_sig):
                logger.warning(f"KMS Peer response signature verification failed for {peer_wallet}")
                return None

            logger.debug(f"Mutual PoP verified for {peer_wallet}")

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

    def handle_incoming_sync(
        self,
        body: dict,
        *,
        signature: Optional[str] = None,
        kms_pop: Optional[dict] = None,
    ) -> dict:
        """
        Process an incoming sync request from a peer.

        Validates HMAC signature when a sync key is configured.

        Expected body shapes:
          - {"type": "delta", "sender_wallet": "0x...", "data": {...}}
          - {"type": "snapshot_request", "sender_wallet": "0x..."}
          - {"type": "master_secret_request", "sender_wallet": "0x...", "ecdh_pubkey": "hex"}
        """
        from auth import (
            verify_wallet_signature,
            recover_wallet_from_signature,
            _nonce_store,
            _require_fresh_timestamp,
        )

        # 1. Verify Lightweight PoP Signature (KMS Peer Identity)
        if not kms_pop:
            return {"status": "error", "reason": "Missing PoP headers"}

        p_sig = kms_pop.get("signature")
        p_ts = kms_pop.get("timestamp")
        p_nonce_b64 = kms_pop.get("nonce")

        p_wallet = kms_pop.get("wallet")

        if not all([p_sig, p_ts, p_nonce_b64]):
            return {"status": "error", "reason": "Incomplete PoP headers"}

        # Timestamp freshness check (limits replay window)
        try:
            _require_fresh_timestamp(str(p_ts))
        except Exception as exc:
            return {"status": "error", "reason": str(exc)}

        # A. Validate and consume nonce
        import base64
        try:
            nonce_bytes = base64.b64decode(p_nonce_b64)
            if not _nonce_store.validate_and_consume(nonce_bytes):
                return {"status": "error", "reason": "Invalid or expired nonce"}
        except Exception:
            return {"status": "error", "reason": "Invalid nonce encoding"}

        # B. Verify signature: NovaKMS:Auth:<Nonce>:<Recipient_Wallet>:<Timestamp>
        message = f"NovaKMS:Auth:{p_nonce_b64}:{self.node_wallet}:{p_ts}"
        try:
            recovered = recover_wallet_from_signature(message, p_sig)
        except Exception as exc:
            logger.warning(f"Peer PoP signature recovery crashed: {exc}")
            return {"status": "error", "reason": "Signature recovery failed"}

        if not recovered:
            logger.warning(
                f"Peer PoP signature invalid | "
                f"Message='{message}' | "
                f"Sig='{p_sig}'"
            )
            return {"status": "error", "reason": "Invalid KMS signature"}

        # Optional explicit wallet header must match recovered signer.
        if p_wallet and recovered.lower() != p_wallet.lower():
            logger.warning(
                f"Peer PoP wallet mismatch | "
                f"Header='{p_wallet}' | "
                f"Recovered='{recovered}'"
            )
            return {"status": "error", "reason": "KMS wallet header does not match signature"}

        p_wallet = recovered

        # Bind body.sender_wallet to the recovered PoP wallet to avoid spoofing/confusing logs.
        body_sender = body.get("sender_wallet") if isinstance(body, dict) else None
        if body_sender and body_sender.lower() != p_wallet.lower():
            return {"status": "error", "reason": "sender_wallet does not match PoP signature"}

        # C. Verify wallet is a registered KMS instance with valid teePubkey (H1 fix)
        from secure_channel import verify_peer_in_kms_operator_set
        try:
            if not verify_peer_in_kms_operator_set(
                p_wallet,
                self.peer_cache.nova_registry,
            ):
                return {"status": "error", "reason": "Peer identity verification failed (operator + teePubkey)"}
        except Exception as exc:
            logger.warning(f"Peer identity verification failed for {p_wallet}: {exc}")
            return {"status": "error", "reason": "Peer identity verification failed"}

        logger.debug(f"KMS PoP verified for {p_wallet}")

        sync_type = body.get("type", "")

        # 2. Verify HMAC signature if sync key is set.
        # Bootstrap exception: allow master_secret_request without HMAC so a
        # new ACTIVE operator can pull the master secret before it has a sync key.
        if self._sync_key and sync_type != "master_secret_request":
            if not signature:
                logger.warning("Sync message rejected: HMAC signature required but not provided")
                return {"status": "error", "reason": "Missing HMAC signature"}
            payload_json = json.dumps(body, sort_keys=True, separators=(",", ":"))
            if not _verify_hmac(self._sync_key, payload_json.encode("utf-8"), signature):
                logger.warning("Sync message HMAC verification failed")
                return {"status": "error", "reason": "Invalid HMAC signature"}
        result: dict = {"status": "ok"}

        if sync_type == "delta":
            result["merged"] = self._apply_deltas(body.get("data", {}))
        elif sync_type == "snapshot_request":
            result["data"] = self._serialize_snapshot()
        elif sync_type == "master_secret_request":
            result = self._handle_master_secret_request(body)
        else:
            return {"status": "error", "reason": f"Unknown sync type: {sync_type}"}

        # 3. Add own signature to response if requested / for mutual auth
        if self.odyn and kms_pop:
            # Sign the client's signature to prove we processed this specific request
            resp_msg = f"NovaKMS:Response:{p_sig}:{self.node_wallet}"
            sig_res = self.odyn.sign_message(resp_msg)
            result["_kms_response_sig"] = sig_res["signature"]

        return result

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
                sealed = seal_master_secret(mgr.secret, peer_pubkey_bytes)
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
