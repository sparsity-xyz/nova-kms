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

from config import PEER_CACHE_TTL_SECONDS
from typing import Dict, List, Optional

import requests
from eth_hash.auto import keccak

import config as config_module

from data_store import DataStore
from url_validator import URLValidationError, validate_peer_url

logger = logging.getLogger("nova-kms.sync")


# =============================================================================
# Helpers
# =============================================================================


def _normalize_wallet(wallet: Optional[str]) -> str:
    """Canonical wallet string for PoP binding.

    For real Ethereum addresses (0x + 40 hex chars), enforce lowercase.
    For non-standard/test identifiers (e.g., "0xTestNode"), preserve case
    to avoid breaking fixtures that use symbolic wallet strings.
    """
    w = (wallet or "").strip()
    if not w:
        return ""
    if len(w) == 42 and w.startswith("0x"):
        hex_part = w[2:]
        if all(c in "0123456789abcdefABCDEF" for c in hex_part):
            return w.lower()
    return w


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
    Caches the list of active KMS peer nodes discovered via NovaAppRegistry:
    KMS_APP_ID -> ENROLLED versions -> ACTIVE instances.
    Refreshed every PEER_CACHE_TTL_SECONDS.
    """

    def __init__(self, kms_registry_client=None, nova_registry=None):
        self._kms_registry = kms_registry_client
        self._nova_registry = nova_registry
        self._peers: List[dict] = []
        self._last_refresh: float = 0
        self._blacklist: Dict[str, float] = {}  # wallet -> expiry_ts
        self._lock = threading.Lock()
        self._refresh_lock = threading.Lock()

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

    def refresh(self, skip_if_refreshing: bool = False) -> bool:
        """
        Force a refresh of the peer cache from on-chain data.
        
        Optimized to avoid holding the lock during slow network calls.
        1. Fetch data from chain (slow, no lock).
        2. Update cache (fast, with lock).
        
        Args:
            skip_if_refreshing: If True, returns immediately if another thread is already refreshing.
            
        Returns:
            True if a refresh was performed, False otherwise.
        """
        if skip_if_refreshing:
            acquired = self._refresh_lock.acquire(blocking=False)
            if not acquired:
                return False
        else:
            self._refresh_lock.acquire()

        try:
            # 1. Fetch from chain (slow IO, no lock)
            new_peers = self._fetch_peers_from_chain()
            
            # 2. Update cache (fast, exclusive lock)
            with self._lock:
                self._update_cache(new_peers)
            
            logger.info(f"Peer cache refreshed: {len(self._peers)} active KMS instances")
            return True
        except Exception as exc:
            logger.warning(f"Failed to refresh peer cache: {exc}")
            return False
        finally:
            self._refresh_lock.release()

    def remove_peer(self, wallet: str) -> None:
        """Remove a peer from the cache by wallet address (step 4.3)."""
        lower = wallet.lower()
        with self._lock:
            self._peers = [p for p in self._peers if p["tee_wallet_address"].lower() != lower]
            logger.info(f"Removed peer {wallet} from cache")

    def blacklist_peer(self, wallet: str, duration: Optional[int] = None) -> None:
        """Temporarily blacklist a peer by wallet address."""
        from config import PEER_BLACKLIST_DURATION_SECONDS
        if duration is None:
            duration = PEER_BLACKLIST_DURATION_SECONDS
            
        lower = wallet.lower()
        expiry = time.time() + duration
        with self._lock:
            self._blacklist[lower] = expiry
            # Also remove from active list immediately
            self._peers = [p for p in self._peers if p["tee_wallet_address"].lower() != lower]
            logger.info(f"Blacklisted peer {wallet} for {duration}s")

    def _purge_blacklist(self) -> None:
        """Remove expired entries from the blacklist. REQUIRES LOCK."""
        now = time.time()
        expired = [w for w, exp in self._blacklist.items() if exp < now]
        for w in expired:
            del self._blacklist[w]
        if expired:
            logger.debug(f"Purged {len(expired)} expired entries from peer blacklist")

    def _is_stale(self) -> bool:
        """Check if the cache needs refreshing."""
        with self._lock:
            return (time.time() - self._last_refresh) > PEER_CACHE_TTL_SECONDS

    def get_peers(self, exclude_wallet: Optional[str] = None, refresh_if_stale: bool = True) -> List[dict]:
        """
        Return list of peer dicts.
        
        Args:
            exclude_wallet: Optional wallet address to filter out.
            refresh_if_stale: If True (default), triggers a synchronous refresh if the cache 
                              is stale. Set to False for latency-sensitive endpoints (e.g. /status)
                              that prefer slightly stale data over blocking.
        """
        # Optimized: Check staleness with a read lock (or just access atomic float)
        # If stale and refresh_if_stale is True, perform refresh efficiently.
        if refresh_if_stale and self._is_stale():
            # Singleflight refresh: one caller refreshes, others return stale cache.
            self.refresh(skip_if_refreshing=True)

        with self._lock:
            self._purge_blacklist()
            peers = [p for p in self._peers if p["tee_wallet_address"].lower() not in self._blacklist]

        if exclude_wallet:
            exclude = exclude_wallet.lower()
            peers = [p for p in peers if p["tee_wallet_address"].lower() != exclude]
        return peers

    def get_peer_by_wallet(self, wallet: str, refresh_if_stale: bool = True) -> Optional[dict]:
        """Look up a cached peer entry by wallet address."""
        target = (wallet or "").lower()
        if not target:
            return None
        if refresh_if_stale and self._is_stale():
            self.refresh(skip_if_refreshing=True)
        with self._lock:
            self._purge_blacklist()
            if target in self._blacklist:
                return None
            for p in self._peers:
                if (p.get("tee_wallet_address") or "").lower() == target:
                    return p
        return None

    @staticmethod
    def _normalize_tee_pubkey_hex(tee_pubkey: object) -> Optional[str]:
        if isinstance(tee_pubkey, bytes):
            return tee_pubkey.hex()
        if isinstance(tee_pubkey, str):
            normalized = tee_pubkey.lower().removeprefix("0x")
            return normalized or None
        return None

    def get_wallet_by_url(self, url: str) -> Optional[str]:
        """Look up a peer's wallet address by their base URL."""
        base = url.rstrip("/")
        with self._lock:
            for p in self._peers:
                if p["node_url"].rstrip("/") == base:
                    return p["tee_wallet_address"]
        return None

    def get_tee_pubkey_by_wallet(self, wallet: str, refresh_if_stale: bool = True) -> Optional[str]:
        """Look up a peer's cached teePubkey (hex) by wallet."""
        peer = self.get_peer_by_wallet(wallet, refresh_if_stale=refresh_if_stale)
        if not peer:
            return None
        return self._normalize_tee_pubkey_hex(peer.get("tee_pubkey"))

    def get_tee_pubkey_by_url(self, url: str) -> Optional[str]:
        """Look up a peer's cached teePubkey (hex) by base URL."""
        base = url.rstrip("/")
        with self._lock:
            for p in self._peers:
                if p["node_url"].rstrip("/") == base:
                    return self._normalize_tee_pubkey_hex(p.get("tee_pubkey"))
        return None

    @staticmethod
    def _probe_status_endpoint(node_url: str, timeout: float = 3.0) -> dict:
        """Probe peer /status and return lightweight connectivity metadata."""
        checked_at_ms = int(time.time() * 1000)
        start = time.time()
        status_url = f"{node_url.rstrip('/')}/status"
        try:
            resp = requests.get(status_url, timeout=timeout)
            probe_ms = int((time.time() - start) * 1000)
            return {
                "status_reachable": resp.status_code == 200,
                "status_http_code": resp.status_code,
                "status_probe_ms": probe_ms,
                "status_checked_at_ms": checked_at_ms,
            }
        except Exception:
            probe_ms = int((time.time() - start) * 1000)
            return {
                "status_reachable": False,
                "status_http_code": None,
                "status_probe_ms": probe_ms,
                "status_checked_at_ms": checked_at_ms,
            }

    def verify_kms_peer(self, wallet: str) -> dict:
        """Fast KMS peer verification using cached PeerCache data (no RPC calls).

        Checks:
          1. Peer is in the cache (refreshed during node_tick)
          2. status == ACTIVE
          3. zk_verified == True
          4. app_id == KMS_APP_ID
          5. teePubkey is present

        If the wallet is not in the cache, the sync is rejected.
        The sender must wait until the next PeerCache refresh cycle.

        Returns:
            dict with keys: authorized (bool), tee_pubkey (str|None), reason (str|None)
        """
        from config import KMS_APP_ID
        from nova_registry import InstanceStatus

        peer = self.get_peer_by_wallet(wallet, refresh_if_stale=False)
        if not peer:
            return {
                "authorized": False,
                "tee_pubkey": None,
                "reason": f"Peer {wallet} not found in PeerCache (not yet discovered or blacklisted)",
            }

        # Status must be ACTIVE
        if peer.get("status") != InstanceStatus.ACTIVE:
            return {
                "authorized": False,
                "tee_pubkey": None,
                "reason": f"Peer {wallet} status is {peer.get('status')} (expected ACTIVE)",
            }

        # Must be zk-verified
        if not peer.get("zk_verified"):
            return {
                "authorized": False,
                "tee_pubkey": None,
                "reason": f"Peer {wallet} not zk-verified",
            }

        # app_id must match KMS_APP_ID
        kms_app_id = int(KMS_APP_ID or 0)
        if kms_app_id and peer.get("app_id") != kms_app_id:
            return {
                "authorized": False,
                "tee_pubkey": None,
                "reason": f"Peer {wallet} app_id {peer.get('app_id')} != KMS_APP_ID {kms_app_id}",
            }

        # teePubkey must be present
        tee_pubkey_hex = self._normalize_tee_pubkey_hex(peer.get("tee_pubkey"))
        if not tee_pubkey_hex:
            return {
                "authorized": False,
                "tee_pubkey": None,
                "reason": f"Peer {wallet} has no teePubkey in cache",
            }

        return {
            "authorized": True,
            "tee_pubkey": tee_pubkey_hex,
            "reason": None,
        }

    def _fetch_peers_from_chain(self) -> List[dict]:
        """Fetch peer list from NovaAppRegistry using getActiveInstances. Slow IO, NO LOCK."""
        from config import KMS_APP_ID
        from nova_registry import InstanceStatus, VersionStatus

        kms_app_id = int(KMS_APP_ID or 0)
        if kms_app_id <= 0:
            raise ValueError("KMS_APP_ID not configured")

        peers: List[dict] = []
        seen_wallets: set[str] = set()

        # New optimization: Get all active instance wallets directly from registry
        # This filters for non-revoked versions and active status on-chain.
        try:
            active_wallets = self.nova_registry.get_active_instances(kms_app_id) or []
            logger.debug(f"Peer discovery: Registry returned {len(active_wallets)} active instances")
        except Exception as exc:
            logger.warning(f"Failed to get active instances from registry: {exc}")
            return []

        for wallet in active_wallets:
            wallet = _normalize_wallet(wallet)
            if not wallet or wallet in seen_wallets:
                continue

            try:
                # Fetch full instance details to get URL and other metadata
                instance = self.nova_registry.get_instance_by_wallet(wallet)
            except Exception as exc:
                logger.debug(f"Instance lookup failed for wallet {wallet}: {exc}")
                continue

            # Double-check status (though getActiveInstances should guarantee it)
            if getattr(instance, "status", None) != InstanceStatus.ACTIVE:
                logger.debug(f"Skipping instance {wallet}: status is {instance.status} (expected ACTIVE)")
                continue

            # Require zk verification for any peer that can receive sync payloads.
            if not bool(getattr(instance, "zk_verified", False)):
                logger.debug(f"Skipping instance {wallet}: not zk-verified")
                continue

            # Check version status (safety check)
            try:
                version = self.nova_registry.get_version(kms_app_id, instance.version_id)
                if version.status not in (VersionStatus.ENROLLED, VersionStatus.DEPRECATED):
                    logger.debug(
                        f"Skipping instance {wallet}: version {instance.version_id} "
                        f"status is {version.status} (expected ENROLLED/DEPRECATED)"
                    )
                    continue
            except Exception as exc:
                logger.debug(f"Version lookup failed for {instance.version_id}: {exc}")
                # Fail closed: if version metadata is unavailable, peer is not trusted.
                continue

            # Validate peer URL before making request
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
                    "tee_wallet_address": wallet,
                    "node_url": instance.instance_url,
                    "tee_pubkey": (
                        (getattr(instance, "tee_pubkey", b"") or b"").hex()
                        if isinstance(getattr(instance, "tee_pubkey", b""), (bytes, bytearray))
                        else str(getattr(instance, "tee_pubkey", "") or "").lower().removeprefix("0x")
                    ),
                    "app_id": instance.app_id,
                    "operator": _normalize_wallet(getattr(instance, "operator", "")),
                    "status": instance.status,
                    "zk_verified": bool(getattr(instance, "zk_verified", False)),
                    "version_id": instance.version_id,
                    "instance_id": instance.instance_id,
                    "registered_at": getattr(instance, "registered_at", 0),
                }
            )
            if config_module.IN_ENCLAVE:
                # Refresh peer connectivity metadata out-of-band from request paths.
                peers[-1].update(self._probe_status_endpoint(instance.instance_url))
            seen_wallets.add(wallet)
            logger.debug(f"Added peer {wallet}")

        return peers

    def _update_cache(self, peers: List[dict]) -> None:
        """Update internal cache state. Fast, REQUIRES LOCK."""
        # Enforce normalization on all stored wallet addresses
        for p in peers:
            if "tee_wallet_address" in p:
                p["tee_wallet_address"] = p["tee_wallet_address"].lower()
            if "operator" in p and p["operator"]:
                 p["operator"] = p["operator"].lower()
        self._peers = peers
        self._last_refresh = time.time()



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
        node_info: Optional[dict] = None,
        http_timeout: int = 15,
    ):
        self.data_store = data_store
        self.node_wallet = _normalize_wallet(node_wallet)
        self.peer_cache = peer_cache
        self.odyn = odyn
        self.node_info = node_info
        self.http_timeout = http_timeout

        # Periodic node-tick state
        self._seed_stable_rounds: int = 0
        self._last_push_deltas_at: float = 0.0
        self._last_push_ms: int = 0
        self._sync_key: Optional[bytes] = None
        # Store the active MasterSecretManager reference provided by node_tick.
        # This avoids relying on importing a global singleton from an 'app' module,
        # which can be ambiguous depending on how the service is launched.
        self._master_secret_mgr = None

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
        from nova_registry import InstanceStatus, VersionStatus

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
                version = nova_registry.get_version(kms_app_id, instance.version_id)
                is_valid = (
                    getattr(instance, "instance_id", 0) != 0
                    and getattr(instance, "app_id", None) == kms_app_id
                    and getattr(instance, "status", None) == InstanceStatus.ACTIVE
                    and getattr(version, "status", None) in (VersionStatus.ENROLLED, VersionStatus.DEPRECATED)
                )
            except Exception as exc:
                logger.warning(f"NovaAppRegistry check failed for {peer_wallet}: {exc}")

            if not is_valid:
                # 4.3 Blacklist invalid peer
                logger.warning(f"Peer {peer_wallet} is not a valid KMS instance — blacklisting")
                self.peer_cache.blacklist_peer(peer_wallet)
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

        # Persist the reference so /sync handlers can answer master_secret_request
        # using the same manager instance the lifecycle tick is evaluating.
        self._master_secret_mgr = master_secret_mgr

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
        logger.debug(f"Node tick: found {len(peers)} peers in cache")

        self_wallet = self.node_wallet.lower()
        kms_wallets = {
            (p.get("tee_wallet_address") or "").lower() for p in peers if p.get("tee_wallet_address")
        }

        # 1) If self not in kms node list -> offline and do nothing.
        if self_wallet not in kms_wallets:
            logger.debug(f"Node tick: self ({self_wallet}) not in KMS node list. Peers: {kms_wallets}")
            if self.node_info is not None:
                self.node_info["is_operator"] = False
            _set_unavailable("self not in KMS node list")
            return
        
        if self.node_info is not None:
            self.node_info["is_operator"] = True

            # If NODE_URL was not configured, backfill it from the ACTIVE KMS
            # instance list discovered via NovaAppRegistry.
            cur_url = (self.node_info.get("node_url") or "").strip()
            if not cur_url:
                for p in peers:
                    if (p.get("tee_wallet_address") or "").lower() == self_wallet:
                        own_url = (p.get("node_url") or "").strip()
                        if own_url:
                            self.node_info["node_url"] = own_url
                        break
        logger.debug("Node tick: Self is in KMS node list. Proceeding to check master secret.")

        # 2) Read on-chain master secret hash
        kms_reg = self.peer_cache.kms_registry
        try:
            chain_hash = kms_reg.get_master_secret_hash()
        except Exception as exc:
            logger.warning(f"Failed to read masterSecretHash: {exc}")
            _set_unavailable("cannot read master secret hash")
            return

        chain_hash_is_zero = (chain_hash == b"\x00" * 32)
        logger.debug(f"Node tick: masterSecretHash on-chain is {'ZERO' if chain_hash_is_zero else 'SET'}")

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
                    logger.debug("Master secret generated successfully")
                except Exception as exc:
                    logger.warning(f"Master secret generation failed: {exc}")
                    _set_unavailable("master secret generation failed")
                    return

            logger.debug("Attempting to retrieve local master secret hash for on-chain setting...")
            local_hash = _local_secret_hash()
            if not local_hash or len(local_hash) != 32:
                _set_unavailable("local master secret hash unavailable")
                return

            logger.debug("Attempting to set master secret hash on-chain...")
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
                if hasattr(exc, "response") and exc.response is not None:
                    logger.warning(f"Failed to set masterSecretHash on-chain: {exc} Body: {exc.response.text}")
                else:
                    logger.warning(f"Failed to set masterSecretHash on-chain: {exc}")
                _set_unavailable("failed to set master secret hash")
                return

            # Stay offline until the chain hash is non-zero and matches our local hash.
            _set_unavailable("awaiting on-chain master secret hash")
            return
        else:
            # 3.2 chain hash non-zero: ensure local secret matches, else sync
            logger.debug("Node tick: Chain hash non-zero; ensuring local secret matches...")
            local_hash = _local_secret_hash()
            if local_hash != chain_hash:
                logger.debug(f"Node tick: Local hash {local_hash.hex() if local_hash else 'None'} != Chain hash {chain_hash.hex()}")
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
                        logger.debug(f"Attempting to sync master secret from {peer_url}...")
                        if self._sync_master_secret_from_peer(peer_url, master_secret_mgr):
                            synced = True
                            break
                        logger.debug(f"Master secret sync attempt from {peer_url} failed")
                    except Exception as exc:
                        logger.warning(f"Master secret sync attempt from {peer_url} failed: {exc}")

                if not synced:
                    logger.debug("Master secret sync failed; remaining offline")
                    _set_unavailable("master secret sync failed")
                    return

                # Validate synced hash against chain
                local_hash = _local_secret_hash()
                if local_hash != chain_hash:
                    logger.debug("Master secret hash mismatch; remaining offline")
                    _set_unavailable("synced master secret hash mismatch")
                    return

                # sync_key set below (outside the if block)

            # Always (re-)derive and set sync key before going online
            try:
                self.set_sync_key(master_secret_mgr.get_sync_key())
            except Exception as exc:
                logger.warning(f"Failed to set sync key: {exc}")

            logger.debug("Node tick: Online; setting available...")
            _set_available()

        # 4) Data sync is now handled by an independent scheduled task (sync_tick).

    def sync_tick(self) -> None:
        """
        Independent scheduled task for data synchronization.
        Pushes local deltas to peers if the node is online.
        """
        # Only sync if the master secret is initialized (we have the sync key)
        if not self._sync_key:
            return

        # Ensure routes are initialized before checking availability
        import routes as routes_module
        try:
            available, _ = routes_module.get_service_availability()
            if not available:
                return
        except Exception:
            # If routes module is not ready, skip sync
            return

        try:
            self.push_deltas()
            logger.debug("Sync tick: Pushed deltas")
        except Exception as exc:
            logger.debug(f"Sync tick push_deltas failed: {exc}")

    def _sync_master_secret_from_peer(self, peer_url: str, master_secret_mgr) -> bool:
        """
        Request the master secret from a verified peer using sealed ECDH,
        then pull a snapshot.  Returns True on success.
        """
        logger.debug(f"Syncing master secret from {peer_url}...")
        from kdf import unseal_master_secret
        from secure_channel import generate_ecdh_keypair

        ecdh_key, ecdh_pubkey_der = generate_ecdh_keypair()
        result = self.request_master_secret(peer_url, ecdh_pubkey=ecdh_pubkey_der)

        if result and isinstance(result, dict):
            secret = unseal_master_secret(result, ecdh_key)
            master_secret_mgr.initialize_from_peer(secret, peer_url=peer_url)

            # As soon as we have the master secret, derive the sync HMAC key so
            # follow-up sync calls (snapshot/delta) include X-Sync-Signature.
            try:
                self.set_sync_key(master_secret_mgr.get_sync_key())
            except Exception as exc:
                logger.warning(f"Failed to derive sync key after master secret sync: {exc}")

            self.request_snapshot(peer_url)
            logger.info(f"Master secret received via sealed ECDH from {peer_url}")
            return True
        return False

    def _sign_payload(self, payload_json: str) -> Optional[str]:
        """Sign a JSON payload string; returns hex HMAC or None."""
        if self._sync_key:
            return _compute_hmac(self._sync_key, payload_json.encode("utf-8"))
        return None

    def _make_request(self, url: str, body: dict, timeout: int = None) -> Optional[requests.Response]:
        """
        Make an outbound sync request with URL validation, E2E encryption,
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
        peer_wallet = _normalize_wallet(self.peer_cache.get_wallet_by_url(base_url))

        # PoP requires an explicit recipient wallet binding.
        # If we can't determine the peer wallet, refuse to send the request.
        if not peer_wallet:
            logger.warning(f"Refusing sync request to {url}: unknown peer wallet for {base_url}")
            return None

        # H1 fix: verify peer identity against on-chain registry before
        # transmitting any data to the peer. This prevents MitM by a host
        # that intercepts TLS but cannot satisfy on-chain identity checks.
        # 4b. Identify peer public key
        from secure_channel import verify_peer_identity, get_tee_pubkey_der_hex

        if not verify_peer_identity(
            peer_wallet,
            self.peer_cache.nova_registry,
            require_zk_verified=True,
        ):
            logger.warning(f"Refusing sync request to {url}: peer is not an authorized zk-verified KMS instance")
            return None

        peer_tee_pubkey_hex = self.peer_cache.get_tee_pubkey_by_url(base_url)
        if not peer_tee_pubkey_hex:
            # Fallback for legacy cache entries that predate tee_pubkey caching.
            peer_tee_pubkey_hex = get_tee_pubkey_der_hex(peer_wallet, self.peer_cache.nova_registry)
        if not peer_tee_pubkey_hex:
            logger.warning(f"Refusing sync request to {url}: peer teePubkey missing or invalid")
            return None

        # 4c. Encrypt to the peer
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
                # Use the actual signing wallet address from Odyn, not the static node_wallet
                # This prevents mismatch errors if keys are rotated differently
                headers["X-KMS-Wallet"] = _normalize_wallet(self.odyn.eth_address())
                headers["X-KMS-Timestamp"] = str(timestamp)
                headers["X-KMS-Nonce"] = nonce_b64
        except Exception as exc:
            logger.warning(f"Failed to perform PoP handshake with {url}: {exc}")

        # Do not proceed without PoP headers.
        if "X-KMS-Signature" not in headers:
            return None

        # 2. E2E encrypt the body using peer's teePubkey
        from secure_channel import encrypt_json_envelope
        try:
            encrypted_body = encrypt_json_envelope(self.odyn, body, peer_tee_pubkey_hex)
        except Exception as exc:
            logger.warning(f"Failed to encrypt sync request body: {exc}")
            return None

        # 3. HMAC signing (using sync key) - sign the encrypted envelope
        payload_json = json.dumps(encrypted_body, sort_keys=True, separators=(",", ":"))
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

            # Check HTTP status first — error responses won't have mutual auth headers
            if not resp.ok:
                try:
                    err_body = resp.json()
                    err_detail = (
                        err_body.get("message")
                        or err_body.get("detail")
                        or err_body.get("error")
                        or resp.text[:200]
                    )
                except Exception:
                    err_detail = resp.text[:200]
                logger.warning(
                    f"Sync request to {url} returned HTTP {resp.status_code}: {err_detail}"
                )
                return None
            
            # 4. Verify Peer response signature for mutual auth
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

            # 5. Decrypt the response body (E2E)
            try:
                from secure_channel import decrypt_json_envelope
                resp_data = resp.json()
                # Check if response is encrypted envelope
                if all(k in resp_data for k in ("sender_tee_pubkey", "nonce", "encrypted_data")):
                    decrypted_data = decrypt_json_envelope(self.odyn, resp_data)
                    # Create a new response-like object with decrypted data
                    resp._decrypted_json = decrypted_data
            except Exception as exc:
                logger.debug(f"Response decryption skipped: {exc}")

            return resp
        except Exception as exc:
            logger.debug(f"Request to {url} failed: {exc}")
            return None

    # ------------------------------------------------------------------
    # Delta push
    # ------------------------------------------------------------------

    def _get_response_json(self, resp: requests.Response) -> dict:
        """Get JSON from response, preferring decrypted data if available."""
        if hasattr(resp, "_decrypted_json") and resp._decrypted_json is not None:
            return resp._decrypted_json
        return resp.json()

    def push_deltas(self) -> int:
        """
        Push recent deltas to all healthy peers.
        Returns the number of peers successfully synced.
        """
        # Capture current time before fetching deltas to prevent race conditions 
        # where records inserted during the push are missed by the next push.
        push_start_ms = int(time.time() * 1000)
        
        # Overlap by 1ms to catch boundary cases
        since_ms = max(0, self._last_push_ms - 1)
        
        deltas = self.data_store.get_deltas_since(since_ms)
        if not deltas:
            logger.debug("Push deltas: No new deltas to push")
            self._last_push_ms = push_start_ms
            return 0
        
        logger.debug(f"Push deltas: Found {len(deltas)} records since {since_ms}")

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
            try:
                resp = self._make_request(url, body)
                if resp and resp.status_code == 200:
                    success_count += 1
                elif resp:
                    logger.warning(f"Sync push to {peer['node_url']} returned {resp.status_code}")
            except Exception as exc:
                logger.warning(f"Sync push to {peer['node_url']} failed: {exc}")
                continue

        self._last_push_ms = push_start_ms
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
        logger.debug(f"Requesting snapshot from {peer_url}...")
        resp = self._make_request(url, body, timeout=30)
        if not resp:
            return 0
        try:
            resp.raise_for_status()
            snapshot_data = self._get_response_json(resp).get("data", {})
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
        """
        url = f"{peer_url.rstrip('/')}/sync"
        body: dict = {
            "type": "master_secret_request",
            "sender_wallet": self.node_wallet,
        }
        if ecdh_pubkey:
            body["ecdh_pubkey"] = ecdh_pubkey.hex()

        resp = self._make_request(url, body, timeout=45)
        if not resp:
            return None
        try:
            resp.raise_for_status()
            data = self._get_response_json(resp)
            # Sealed envelope response
            if "sealed" in data:
                return data["sealed"]
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
        signature_payload: Optional[dict] = None,
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
            recover_wallet_from_signature,
            _nonce_store,
            _require_fresh_timestamp,
        )

        # 1. Verify Lightweight PoP Signature (KMS Peer Identity)
        if not kms_pop:
            logger.warning("Sync rejected: Missing PoP headers")
            return {"status": "error", "reason": "Missing PoP headers"}

        p_sig = kms_pop.get("signature")
        p_ts = kms_pop.get("timestamp")
        p_nonce_b64 = kms_pop.get("nonce")

        p_wallet = _normalize_wallet(kms_pop.get("wallet"))

        logger.debug(f"Incoming sync from {p_wallet}: type={body.get('type')}")

        if not all([p_sig, p_ts, p_nonce_b64]):
            logger.warning(f"Sync rejected from {p_wallet}: Incomplete PoP headers (sig={bool(p_sig)}, ts={bool(p_ts)}, nonce={bool(p_nonce_b64)})")
            return {"status": "error", "reason": "Incomplete PoP headers"}

        # Timestamp freshness check (limits replay window)
        try:
            _require_fresh_timestamp(str(p_ts))
        except RuntimeError as exc:
            logger.warning(f"Sync rejected from {p_wallet}: Timestamp freshness check failed: {exc}")
            return {"status": "error", "reason": str(exc)}

        # A. Validate and consume nonce
        import base64
        import binascii
        try:
            nonce_bytes = base64.b64decode(p_nonce_b64, validate=True)
            if not _nonce_store.validate_and_consume(nonce_bytes):
                logger.warning(f"Sync rejected from {p_wallet}: Invalid or expired nonce")
                return {"status": "error", "reason": "Invalid or expired nonce"}
        except (binascii.Error, ValueError, TypeError):
            logger.warning(f"Sync rejected from {p_wallet}: Invalid nonce encoding")
            return {"status": "error", "reason": "Invalid nonce encoding"}

        # B. Verify signature: NovaKMS:Auth:<Nonce>:<Recipient_Wallet>:<Timestamp>
        # Enforce a single canonical wallet string format (lowercase) across sender/receiver.
        message = f"NovaKMS:Auth:{p_nonce_b64}:{self.node_wallet}:{p_ts}"
        recovered = recover_wallet_from_signature(message, p_sig)

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

        p_wallet = recovered.lower()

        # Bind body.sender_wallet to the recovered PoP wallet to avoid spoofing/confusing logs.
        body_sender = body.get("sender_wallet") if isinstance(body, dict) else None
        if body_sender and body_sender.lower() != p_wallet:
            logger.warning(f"Sync rejected: sender_wallet {body_sender} does not match PoP signer {p_wallet}")
            return {"status": "error", "reason": "sender_wallet does not match PoP signature"}

        # C. Verify peer KMS authorization (cache-only, no RPC calls).
        # PeerCache is refreshed during node_tick. If peer is not yet cached,
        # the sync is rejected — sender must wait for the next refresh cycle.
        cache_auth = self.peer_cache.verify_kms_peer(p_wallet)
        if not cache_auth["authorized"]:
            logger.warning(f"Peer authorization failed for {p_wallet}: {cache_auth['reason']}")
            return {"status": "error", "reason": f"Peer authorization failed: {cache_auth['reason']}"}

        logger.debug(f"KMS PoP verified for {p_wallet}")

        sync_type = body.get("type", "")

        # 2. Verify HMAC signature if sync key is set.
        # Bootstrap exception: allow master_secret_request without HMAC so a
        # new ACTIVE operator can pull the master secret before it has a sync key.
        if self._sync_key and sync_type != "master_secret_request":
            if not signature:
                logger.warning("Sync message rejected: HMAC signature required but not provided")
                return {"status": "error", "reason": "Missing HMAC signature"}
            # Verify over the *on-the-wire* JSON payload when available.
            # For encrypted sync requests, senders sign the canonical JSON of the
            # E2E envelope dict, not the decrypted inner message.
            payload_obj = signature_payload if signature_payload is not None else body
            payload_json = json.dumps(payload_obj, sort_keys=True, separators=(",", ":"))
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
            logger.warning(f"Sync rejected from {p_wallet}: Unknown sync type: {sync_type}")
            return {"status": "error", "reason": f"Unknown sync type: {sync_type}"}

        # 3. Add own signature to response if requested / for mutual auth
        if self.odyn and kms_pop:
            # Sign the client's signature to prove we processed this specific request
            # Use current Odyn wallet to match the key used for signing
            current_wallet = _normalize_wallet(self.odyn.eth_address())
            resp_msg = f"NovaKMS:Response:{p_sig}:{current_wallet}"
            sig_res = self.odyn.sign_message(resp_msg)
            result["_kms_response_sig"] = sig_res["signature"]

        return result

    def _handle_master_secret_request(self, body: dict) -> dict:
        """Handle a master secret request, using sealed ECDH if peer provides a pubkey."""
        from kdf import MasterSecretManager, seal_master_secret

        mgr: MasterSecretManager = self._master_secret_mgr
        if mgr is None:
            return {"status": "error", "reason": "Master secret manager unavailable"}
        if not mgr.is_initialized:
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
            # Sealed exchange required — reject requests without ECDH pubkey
            return {"status": "error", "reason": "Sealed ECDH pubkey required for master secret exchange"}

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
