"""
=============================================================================
Odyn SDK (odyn.py)
=============================================================================

Platform-provided interface to TEE (Trusted Execution Environment) services.
Copied from the Nova app-template with minor additions for KMS usage.

┌─────────────────────────────────────────────────────────────────────────────┐
│  DO NOT MODIFY THIS FILE                                                    │
│  This is the standard SDK provided by Nova Platform.                        │
└─────────────────────────────────────────────────────────────────────────────┘
"""

import base64
import os
from typing import Dict, Any, Optional, Union

import requests


class Odyn:
    """
    Wrapper for enclaver's Odyn API.

    IN_ENCLAVE=true  → Production (localhost:18000)
    IN_ENCLAVE=false → Development (mock API)
    """

    DEFAULT_MOCK_ODYN_API = "http://odyn.sparsity.cloud:18000"

    def __init__(self, endpoint: Optional[str] = None):
        if endpoint:
            self.endpoint = endpoint
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "False").lower() == "true"
            self.endpoint = "http://localhost:18000" if is_enclave else self.DEFAULT_MOCK_ODYN_API

    def _call(self, method: str, path: str, payload: Any = None) -> Any:
        url = f"{self.endpoint}{path}"
        if method.upper() == "POST":
            res = requests.post(url, json=payload, timeout=10)
        else:
            res = requests.get(url, timeout=10)
        res.raise_for_status()
        return res.json()

    # =========================================================================
    # Identity & Signing
    # =========================================================================

    def eth_address(self) -> str:
        """Get the Enclave's Ethereum address (derived from secp256k1 key).

        Calls GET /v1/eth/address.

        Full API response::

            {
                "address":    "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",  # EIP-55 checksummed
                "public_key": "0x04..."                                      # Uncompressed secp256k1 (65 bytes)
            }

        Returns
        -------
        str
            The checksummed Ethereum address, e.g. ``"0x742d35Cc6634..."``
        """
        return self._call("GET", "/v1/eth/address")["address"]

    def sign_tx(self, tx: dict) -> dict:
        """Sign an Ethereum transaction (EIP-1559) with the Enclave's secp256k1 key.

        Calls POST /v1/eth/sign-tx.

        Accepts either a web3-style tx dict or Odyn's native ``structured`` format.
        Web3-style dicts are auto-converted (see source).

        Returns
        -------
        dict
            ::

                {
                    "raw_transaction":  "0x02f8...",   # RLP-encoded signed tx (ready for broadcast)
                    "transaction_hash": "0xabcd...",   # keccak256 of the signed tx
                    "signature":        "0x...",       # 65-byte recoverable signature (r ‖ s ‖ v)
                    "address":          "0x...",       # Signer's Ethereum address
                    "attestation":      null           # Base64 attestation doc (if requested)
                }
        """
        if "kind" not in tx:
            # Convert web3-style tx dict to Odyn "structured" payload format.
            # Odyn only accepts "structured" or "raw_rlp", NOT "transaction".
            tx = {
                "kind": "structured",
                "chain_id": hex(tx["chainId"]),
                "nonce": hex(tx["nonce"]),
                "max_priority_fee_per_gas": hex(tx["maxPriorityFeePerGas"]),
                "max_fee_per_gas": hex(tx["maxFeePerGas"]),
                "gas_limit": hex(tx["gas"]),
                "to": tx["to"],
                "value": hex(tx.get("value", 0)),
                "data": tx["data"],
            }
        return self._call("POST", "/v1/eth/sign-tx", {"payload": tx})

    def sign_message(self, message: str, include_attestation: bool = False) -> dict:
        """Sign a message using EIP-191 personal_sign.

        Calls POST /v1/eth/sign. The Enclave automatically prepends
        ``"\\x19Ethereum Signed Message:\\n<len>"`` before signing.

        Parameters
        ----------
        message : str
            The plaintext message to sign (must be non-empty).
        include_attestation : bool
            If True, the response includes a Base64-encoded attestation
            document with the message hash as nonce.

        Returns
        -------
        dict
            ::

                {
                    "signature":   "0x...",   # 65-byte EIP-191 signature (r ‖ s ‖ v), hex-encoded
                    "address":     "0x...",   # Signer's Ethereum address
                    "attestation": null       # Base64 attestation doc (if include_attestation=True)
                }
        """
        payload = {"message": message, "include_attestation": include_attestation}
        return self._call("POST", "/v1/eth/sign", payload)

    # =========================================================================
    # Randomness & Attestation
    # =========================================================================

    def get_random_bytes(self) -> bytes:
        """Get 32 cryptographically-secure random bytes from the Nitro Secure Module.

        Calls GET /v1/random. In production, uses hardware-backed NSM RNG;
        in mock/dev mode, uses OS-level CSPRNG.

        Full API response::

            {
                "random_bytes": "0x..."  # 32 random bytes, hex-encoded with 0x prefix
            }

        Returns
        -------
        bytes
            32 raw random bytes.
        """
        res_json = self._call("GET", "/v1/random")
        random_hex = res_json["random_bytes"]
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)

    def get_attestation(
        self, nonce: Optional[str] = "", user_data: Optional[Union[str, bytes]] = None
    ) -> bytes:
        """Get an AWS Nitro attestation document.

        Calls POST /v1/attestation. The Enclave's P-384 encryption public key
        (PEM) is automatically embedded in the attestation document.

        Parameters
        ----------
        nonce : str, optional
            Base64-encoded nonce to include in the attestation.
        user_data : str or bytes, optional
            Additional user data to bind into the attestation.
            If bytes, it is Base64-encoded automatically.

        Returns
        -------
        bytes
            Raw CBOR-encoded attestation document (binary).
            Contains: PCR values, AWS Nitro signature chain, and
            the embedded public_key (if provided).

            **Note**: Unlike other methods, this returns raw bytes
            (Content-Type: application/cbor), NOT a JSON dict.
        """
        url = f"{self.endpoint}/v1/attestation"
        payload: Dict[str, Any] = {"nonce": nonce or ""}
        try:
            enc_pub = self.get_encryption_public_key()
            if "public_key_pem" in enc_pub:
                payload["public_key"] = enc_pub["public_key_pem"]
        except Exception:
            pass
        if user_data is not None:
            if isinstance(user_data, bytes):
                payload["user_data"] = base64.b64encode(user_data).decode("utf-8")
            else:
                payload["user_data"] = user_data
        res = requests.post(url, json=payload, timeout=10)
        res.raise_for_status()
        return res.content

    # =========================================================================
    # Encryption (P-384 ECDH + HKDF-SHA256 + AES-256-GCM)
    # =========================================================================

    def get_encryption_public_key(self) -> dict:
        """Get the Enclave's P-384 ECDH public key in multiple formats.

        Calls GET /v1/encryption/public_key.

        This key is regenerated on every Enclave boot (ephemeral per-boot key).
        It is used for ECDH key agreement to establish shared AES-256 keys
        for end-to-end encrypted communication.

        Returns
        -------
        dict
            ::

                {
                    "public_key_der": "0x3076...",   # DER/SPKI format, hex-encoded with 0x prefix
                    "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
                }

            - ``public_key_der``: ~120 bytes DER (SubjectPublicKeyInfo), hex-encoded.
              Use this for ECDH operations and on-chain registration.
            - ``public_key_pem``: PEM format, suitable for standard crypto libraries.
        """
        return self._call("GET", "/v1/encryption/public_key")

    def get_encryption_public_key_der(self) -> bytes:
        """Convenience: get the Enclave's P-384 public key as raw DER bytes.

        Calls :meth:`get_encryption_public_key` and decodes the
        ``public_key_der`` hex field.

        Returns
        -------
        bytes
            Raw DER-encoded P-384 public key (~120 bytes, SPKI format).
        """
        pub_data = self.get_encryption_public_key()
        pub_key_hex = pub_data.get("public_key_der", "")
        if pub_key_hex.startswith("0x"):
            pub_key_hex = pub_key_hex[2:]
        return bytes.fromhex(pub_key_hex)

    def encrypt(self, plaintext: str, client_public_key: str) -> dict:
        """Encrypt data for a client using ECDH + AES-256-GCM.

        Calls POST /v1/encryption/encrypt.

        Internally, the Enclave:
        1. Performs ECDH between the Enclave private key and client_public_key
        2. Generates a fresh 12-byte random nonce
        3. Derives AES-256 key via HKDF-SHA256:
           salt = sorted(enclave_pubkey_sec1, client_pubkey_sec1) ‖ nonce
           info = "enclaver-ecdh-aes256gcm-v1"
        4. Encrypts with AES-256-GCM (produces ciphertext + 16-byte auth tag)

        Parameters
        ----------
        plaintext : str
            The UTF-8 string to encrypt.
        client_public_key : str
            The client's P-384 public key in DER format, hex-encoded.
            A ``0x`` prefix is added automatically if missing.

        Returns
        -------
        dict
            ::

                {
                    "encrypted_data":    "...",  # Ciphertext + GCM auth tag, hex-encoded (no 0x)
                    "enclave_public_key": "...", # Enclave P-384 DER public key, hex-encoded (no 0x)
                    "nonce":             "..."   # 12-byte nonce, hex-encoded (no 0x)
                }
        """
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        payload = {"plaintext": plaintext, "client_public_key": client_public_key}
        return self._call("POST", "/v1/encryption/encrypt", payload)

    def decrypt(self, nonce: str, client_public_key: str, encrypted_data: str) -> str:
        """Decrypt data from a client using ECDH + AES-256-GCM.

        Calls POST /v1/encryption/decrypt.

        Internally, the Enclave:
        1. Performs ECDH between the Enclave private key and client_public_key
        2. Derives AES-256 key via HKDF-SHA256:
           salt = sorted(enclave_pubkey_sec1, client_pubkey_sec1) ‖ nonce
           info = "enclaver-ecdh-aes256gcm-v1"
        3. Checks for nonce reuse (rejects duplicate (client_public_key, nonce) pairs)
        4. Decrypts with AES-256-GCM and verifies auth tag

        Parameters
        ----------
        nonce : str
            The 12-byte nonce, hex-encoded. A ``0x`` prefix is added if missing.
        client_public_key : str
            The client's P-384 public key in DER format, hex-encoded.
        encrypted_data : str
            The ciphertext + GCM auth tag, hex-encoded.

        Returns
        -------
        str
            The decrypted plaintext string.

        Raises
        ------
        requests.HTTPError
            On HTTP 400 if: nonce is not 12 bytes, nonce reuse detected,
            invalid public key, decryption/auth tag verification failed,
            or result is not valid UTF-8.
        """
        if not nonce.startswith("0x"):
            nonce = f"0x{nonce}"
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        if not encrypted_data.startswith("0x"):
            encrypted_data = f"0x{encrypted_data}"
        
        payload = {
            "nonce": nonce,
            "client_public_key": client_public_key,
            "encrypted_data": encrypted_data,
        }
        
        return self._call("POST", "/v1/encryption/decrypt", payload)["plaintext"]

    # =========================================================================
    # S3 Storage (via Enclaver internal API)
    # =========================================================================

    def s3_put(self, key: str, value: bytes, content_type: Optional[str] = None) -> bool:
        """Upload an object to S3 storage via the Enclaver internal API.

        Calls POST /v1/s3/put.

        The object is stored under the app-scoped prefix configured
        in ``enclaver.yaml`` (``storage.s3.prefix``).

        Parameters
        ----------
        key : str
            Object key relative to the configured prefix.
        value : bytes
            Raw bytes to store (automatically Base64-encoded for transport).
        content_type : str, optional
            Optional MIME type metadata for the object.

        Returns
        -------
        bool
            True if the upload succeeded, False otherwise.

            Full API response::

                {
                    "success": true
                }
        """
        payload: Dict[str, Any] = {"key": key, "value": base64.b64encode(value).decode()}
        if content_type:
            payload["content_type"] = content_type
        res = requests.post(f"{self.endpoint}/v1/s3/put", json=payload, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_get(self, key: str) -> Optional[bytes]:
        """Fetch an object from S3 storage via the Enclaver internal API.

        Calls POST /v1/s3/get.

        Parameters
        ----------
        key : str
            Object key relative to the configured prefix.

        Returns
        -------
        bytes or None
            Raw bytes of the object, or None if the key does not exist (HTTP 404).

            Full API response (200)::

                {
                    "value": "base64-encoded-content"
                }
        """
        res = requests.post(f"{self.endpoint}/v1/s3/get", json={"key": key}, timeout=30)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return base64.b64decode(res.json()["value"])

    def s3_delete(self, key: str) -> bool:
        """Delete an object from S3 storage via the Enclaver internal API.

        Calls POST /v1/s3/delete.

        Parameters
        ----------
        key : str
            Object key relative to the configured prefix.

        Returns
        -------
        bool
            True if the deletion succeeded, False otherwise.

            Full API response::

                {
                    "success": true
                }
        """
        res = requests.post(f"{self.endpoint}/v1/s3/delete", json={"key": key}, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_list(
        self,
        prefix: Optional[str] = None,
        continuation_token: Optional[str] = None,
        max_keys: Optional[int] = None,
    ) -> Dict[str, Any]:
        """List objects under the configured S3 prefix.

        Calls POST /v1/s3/list. Supports pagination via continuation_token.

        Parameters
        ----------
        prefix : str, optional
            Optional sub-prefix to filter within the app namespace.
        continuation_token : str, optional
            Token from a previous response to fetch the next page.
        max_keys : int, optional
            Maximum number of keys to return per page.

        Returns
        -------
        dict
            ::

                {
                    "keys":               ["key1", "key2", ...],  # List of object keys
                    "continuation_token":  "...",                  # Token for next page (if truncated)
                    "is_truncated":        true                    # Whether more results exist
                }
        """
        payload: Dict[str, Any] = {}
        if prefix is not None:
            payload["prefix"] = prefix
        if continuation_token is not None:
            payload["continuation_token"] = continuation_token
        if max_keys is not None:
            payload["max_keys"] = max_keys
        res = requests.post(f"{self.endpoint}/v1/s3/list", json=payload, timeout=30)
        res.raise_for_status()
        return res.json()


if __name__ == "__main__":
    o = Odyn()
    try:
        print(f"Testing Odyn at {o.endpoint}")
        print(f"TEE Address: {o.eth_address()}")
    except Exception as e:
        print(f"Could not connect to Odyn: {e}")
