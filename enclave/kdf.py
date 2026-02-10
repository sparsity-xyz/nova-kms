"""
=============================================================================
Key Derivation Function (kdf.py)
=============================================================================

HKDF-based key derivation and CA certificate signing for Nova KMS.

The cluster master secret is generated once (from Odyn randomness) and
shared across KMS nodes via the sync protocol.  All key derivation is
deterministic given the same (master_secret, app_id, path) tuple.

Key rotation is supported through an epoch counter that is included in
the HKDF salt.  When the epoch increments, all derived keys change.

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
    epoch: int = 0,
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
    epoch : int
        Key rotation epoch.  Incrementing this produces entirely new keys.

    Returns
    -------
    bytes
        The derived key material.
    """
    salt = f"nova-kms:app:{app_id}:epoch:{epoch}".encode("utf-8")
    info = f"{path}:{context}".encode("utf-8") if context else path.encode("utf-8")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(master_secret)


def derive_data_key(master_secret: bytes, app_id: int, epoch: int = 0) -> bytes:
    """Derive the per-app data encryption key (for in-memory KV store)."""
    return derive_app_key(master_secret, app_id, "data_key", epoch=epoch)


def derive_sync_key(master_secret: bytes, epoch: int = 0) -> bytes:
    """Derive a symmetric key used for HMAC signing of sync messages."""
    return derive_app_key(master_secret, 0, "sync_hmac_key", epoch=epoch)


# =============================================================================
# Master Secret Management
# =============================================================================

class MasterSecretManager:
    """
    Manages the cluster master secret with epoch-based rotation.

    On first boot the secret is generated from Odyn hardware randomness.
    On subsequent boots it is received from healthy peers via /sync.
    """

    def __init__(self):
        self._secret: Optional[bytes] = None
        self._epoch: int = 0

    @property
    def is_initialized(self) -> bool:
        return self._secret is not None

    @property
    def secret(self) -> bytes:
        if self._secret is None:
            raise RuntimeError("Master secret not initialized")
        return self._secret

    @property
    def epoch(self) -> int:
        return self._epoch

    def initialize_from_random(self, odyn) -> None:
        """Generate a new master secret from Odyn hardware RNG."""
        self._secret = odyn.get_random_bytes()
        # Ensure at least 32 bytes
        while len(self._secret) < 32:
            self._secret += odyn.get_random_bytes()
        self._secret = self._secret[:32]
        self._epoch = 0
        logger.info("Master secret initialized from hardware RNG (epoch 0)")

    def initialize_from_peer(self, secret: bytes, epoch: int = 0) -> None:
        """Set the master secret received from a peer during sync."""
        if len(secret) < 32:
            raise ValueError("Master secret must be at least 32 bytes")
        self._secret = secret[:32]
        self._epoch = epoch
        logger.info(f"Master secret initialized from peer sync (epoch {epoch})")

    def rotate(self) -> int:
        """
        Increment the epoch counter.  All subsequently derived keys will
        change, but the master secret itself stays the same.
        Returns the new epoch.
        """
        if not self.is_initialized:
            raise RuntimeError("Cannot rotate: master secret not initialized")
        self._epoch += 1
        logger.info(f"Master secret rotated to epoch {self._epoch}")
        return self._epoch

    def derive(self, app_id: int, path: str, **kwargs) -> bytes:
        """Convenience wrapper around derive_app_key."""
        kwargs.setdefault("epoch", self._epoch)
        return derive_app_key(self.secret, app_id, path, **kwargs)

    def get_sync_key(self) -> bytes:
        """Return the HMAC key used for signing sync messages."""
        return derive_sync_key(self.secret, self._epoch)


# =============================================================================
# Sealed Key Exchange
# =============================================================================


def seal_master_secret(master_secret: bytes, epoch: int, peer_pubkey_bytes: bytes) -> dict:
    """
    Encrypt the master secret for a specific peer using ECDH + AES-GCM.

    Parameters
    ----------
    master_secret : bytes
        The 32-byte master secret to protect.
    epoch : int
        Current epoch counter.
    peer_pubkey_bytes : bytes
        The peer's ephemeral ECDH public key (uncompressed SEC1 format).

    Returns
    -------
    dict with keys: ephemeral_pubkey (hex), ciphertext (hex), nonce (hex), epoch (int)
    """
    # Generate ephemeral keypair
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub = ephemeral_key.public_key()

    # Load peer public key
    peer_pubkey = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pubkey_bytes)

    # ECDH shared secret
    shared_secret = ephemeral_key.exchange(ec.ECDH(), peer_pubkey)

    # KDF the shared secret into an AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"nova-kms:sealed-master-secret",
        info=b"aes-gcm-key",
    ).derive(shared_secret)

    # Encrypt master_secret + epoch
    nonce = os.urandom(12)
    plaintext = master_secret + epoch.to_bytes(4, "big")
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        "ephemeral_pubkey": ephemeral_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex(),
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "epoch": epoch,
    }


def unseal_master_secret(sealed: dict, my_private_key: ec.EllipticCurvePrivateKey) -> tuple:
    """
    Decrypt a sealed master secret envelope.

    Returns
    -------
    (master_secret: bytes, epoch: int)
    """
    ephemeral_pub_bytes = bytes.fromhex(sealed["ephemeral_pubkey"])
    ciphertext = bytes.fromhex(sealed["ciphertext"])
    nonce = bytes.fromhex(sealed["nonce"])

    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pub_bytes)

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
    epoch = int.from_bytes(plaintext[32:36], "big")
    return master_secret, epoch


