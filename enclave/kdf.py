"""
=============================================================================
Key Derivation Function (kdf.py)
=============================================================================

HKDF-based key derivation and CA certificate signing for Nova KMS.

The cluster master secret is generated once (from Odyn randomness) and
shared across KMS nodes via the sync protocol.  All key derivation is
deterministic given the same (master_secret, app_id, path) tuple.

M1 fix: epoch-based rotation has been removed.  The original design
included an ``epoch`` counter in key derivation but provided no mechanism
to rotate the master secret or coordinate epoch bumps across nodes.
Keeping the parameter added complexity and confusion with no benefit.
Key rotation can be re-introduced in the future with a proper on-chain
coordination protocol.

See architecture.md §3.4 for the design.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


logger = logging.getLogger("nova-kms.kdf")




# =============================================================================
# Key Derivation
# =============================================================================

def derive_app_key(
    master_secret: bytes,
    app_id: int,
    path: str,
    *,
    length: int = 32,
    context: str = "",
) -> bytes:
    """
    Derive a deterministic key for an application.

    Parameters
    ----------
    master_secret : bytes
        The cluster-wide master secret (256-bit minimum recommended).
    app_id : int
        The NovaAppRegistry application ID.
    path : str
        An arbitrary derivation path string (e.g. "disk_encryption", "tls").
    length : int
        Output key length in bytes (default 32 = 256-bit).
    context : str
        Optional additional context string mixed into the info parameter.

    Returns
    -------
    bytes
        The derived key material.
    """
    salt = f"nova-kms:app:{app_id}".encode("utf-8")
    info = f"{path}:{context}".encode("utf-8") if context else path.encode("utf-8")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(master_secret)


def derive_data_key(master_secret: bytes, app_id: int) -> bytes:
    """Derive the per-app data encryption key (for in-memory KV store)."""
    return derive_app_key(master_secret, app_id, "data_key")


def derive_sync_key(master_secret: bytes) -> bytes:
    """Derive a symmetric key used for HMAC signing of sync messages."""
    return derive_app_key(master_secret, 0, "sync_hmac_key")


# =============================================================================
# Master Secret Management
# =============================================================================

class MasterSecretManager:
    """
    Manages the cluster master secret.

    On first boot the secret is generated from Odyn hardware randomness.
    On subsequent boots it is received from healthy peers via /sync.
    """

    def __init__(self):
        self._secret: Optional[bytes] = None
        self._init_state: str = "uninitialized"  # uninitialized | generated | synced
        self._synced_from: Optional[str] = None

    @property
    def is_initialized(self) -> bool:
        return self._secret is not None

    @property
    def init_state(self) -> str:
        """Return how the master secret was initialized.

        Values: uninitialized | generated | synced
        """
        return self._init_state

    @property
    def synced_from(self) -> Optional[str]:
        """If init_state==synced, optionally record which peer URL provided it."""
        return self._synced_from

    @property
    def secret(self) -> bytes:
        if self._secret is None:
            raise RuntimeError("Master secret not initialized")
        return self._secret

    @property
    def epoch(self) -> int:
        """Always returns 0.  Kept for backward-compatible status reporting."""
        return 0

    def get_sync_key(self) -> bytes:
        """Derive the HMAC sync key from the master secret."""
        if self._secret is None:
            raise RuntimeError("Master secret not initialized")
        return derive_sync_key(self._secret)

    def initialize_from_random(self, odyn) -> None:
        """Generate a new master secret from Odyn hardware RNG."""
        self._secret = odyn.get_random_bytes()
        # Ensure at least 32 bytes
        while len(self._secret) < 32:
            self._secret += odyn.get_random_bytes()
        self._secret = self._secret[:32]
        self._init_state = "generated"
        self._synced_from = None
        logger.info("Master secret initialized from hardware RNG")

    def initialize_from_peer(self, secret: bytes, peer_url: Optional[str] = None, **_kwargs) -> None:
        """Set the master secret received from a peer during sync.

        The ``epoch`` and other keyword arguments are accepted for
        backward-compatibility but ignored (epoch is always 0).
        """
        if len(secret) < 32:
            raise ValueError("Master secret must be at least 32 bytes")
        self._secret = secret[:32]
        self._init_state = "synced"
        self._synced_from = peer_url
        logger.info(
            "Master secret initialized from peer sync"
            + (f" from {peer_url}" if peer_url else "")
        )

    def derive(self, app_id: int, path: str, **kwargs) -> bytes:
        """Convenience wrapper around derive_app_key."""
        # Silently drop legacy 'epoch' kwarg if passed
        kwargs.pop("epoch", None)
        return derive_app_key(self.secret, app_id, path, **kwargs)


# =============================================================================
# Sealed Key Exchange
# =============================================================================


def seal_master_secret(master_secret: bytes, peer_pubkey_bytes: bytes) -> dict:
    """
    Encrypt the master secret for a specific peer using ECDH + AES-GCM.

    Uses P-384 (secp384r1) to match the enclave's teePubkey curve.
    The peer provides their P-384 public key (DER/SPKI or uncompressed
    SEC1 point format); an ephemeral P-384 keypair is generated for the
    exchange.

    Parameters
    ----------
    master_secret : bytes
        The 32-byte master secret to protect.
    peer_pubkey_bytes : bytes
        The peer's P-384 public key (DER/SPKI or uncompressed SEC1).

    Returns
    -------
    dict with keys: ephemeral_pubkey (hex, DER), ciphertext (hex), nonce (hex)
    """
    from secure_channel import parse_tee_pubkey

    # Generate ephemeral P-384 keypair
    ephemeral_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_pub = ephemeral_key.public_key()

    # Load peer public key (P-384, DER or SEC1)
    peer_pubkey = parse_tee_pubkey(peer_pubkey_bytes)

    # ECDH shared secret
    shared_secret = ephemeral_key.exchange(ec.ECDH(), peer_pubkey)

    # KDF the shared secret into an AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nova-kms:sealed-master-secret",
        info=b"aes-gcm-key",
    ).derive(shared_secret)

    # Encrypt master_secret
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, master_secret, None)

    return {
        "ephemeral_pubkey": ephemeral_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).hex(),
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
    }


def unseal_master_secret(sealed: dict, my_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Decrypt a sealed master secret envelope.

    The ephemeral public key in the envelope is a P-384 DER/SPKI key.

    Returns
    -------
    master_secret : bytes  (32 bytes)
    """
    from secure_channel import parse_tee_pubkey

    ephemeral_pub_bytes = bytes.fromhex(sealed["ephemeral_pubkey"])
    ciphertext = bytes.fromhex(sealed["ciphertext"])
    nonce = bytes.fromhex(sealed["nonce"])

    ephemeral_pub = parse_tee_pubkey(ephemeral_pub_bytes)

    # ECDH
    shared_secret = my_private_key.exchange(ec.ECDH(), ephemeral_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nova-kms:sealed-master-secret",
        info=b"aes-gcm-key",
    ).derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    master_secret = plaintext[:32]
    return master_secret


