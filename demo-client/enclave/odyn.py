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
import json
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
        return self._call("GET", "/v1/eth/address")["address"]

    def sign_tx(self, tx: dict) -> dict:
        return self._call("POST", "/v1/eth/sign-tx", {"payload": tx})

    def sign_message(self, message: str, include_attestation: bool = False) -> dict:
        payload = {"message": message, "include_attestation": include_attestation}
        return self._call("POST", "/v1/eth/sign", payload)

    # =========================================================================
    # Randomness & Attestation
    # =========================================================================

    def get_random_bytes(self) -> bytes:
        res_json = self._call("GET", "/v1/random")
        random_hex = res_json["random_bytes"]
        if random_hex.startswith("0x"):
            random_hex = random_hex[2:]
        return bytes.fromhex(random_hex)

    def get_attestation(
        self, nonce: Optional[str] = "", user_data: Optional[Union[str, bytes]] = None
    ) -> bytes:
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
    # Encryption (ECDH + AES-256-GCM)
    # =========================================================================

    def get_encryption_public_key(self) -> dict:
        return self._call("GET", "/v1/encryption/public_key")

    def get_encryption_public_key_der(self) -> bytes:
        pub_data = self.get_encryption_public_key()
        pub_key_hex = pub_data.get("public_key_der", "")
        if pub_key_hex.startswith("0x"):
            pub_key_hex = pub_key_hex[2:]
        return bytes.fromhex(pub_key_hex)

    def encrypt(self, plaintext: str, client_public_key: str) -> dict:
        if not client_public_key.startswith("0x"):
            client_public_key = f"0x{client_public_key}"
        payload = {"plaintext": plaintext, "client_public_key": client_public_key}
        return self._call("POST", "/v1/encryption/encrypt", payload)

    def decrypt(self, nonce: str, client_public_key: str, encrypted_data: str) -> str:
        nonce_hex = nonce[2:] if nonce.startswith("0x") else nonce
        try:
            nonce_bytes = bytes.fromhex(nonce_hex)
            if len(nonce_bytes) > 12:
                nonce_hex = nonce_bytes[:12].hex()
        except Exception:
            nonce_hex = nonce_hex[:24]
        nonce = f"0x{nonce_hex}"
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
        payload: Dict[str, Any] = {"key": key, "value": base64.b64encode(value).decode()}
        if content_type:
            payload["content_type"] = content_type
        res = requests.post(f"{self.endpoint}/v1/s3/put", json=payload, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_get(self, key: str) -> Optional[bytes]:
        res = requests.post(f"{self.endpoint}/v1/s3/get", json={"key": key}, timeout=30)
        if res.status_code == 404:
            return None
        res.raise_for_status()
        return base64.b64decode(res.json()["value"])

    def s3_delete(self, key: str) -> bool:
        res = requests.post(f"{self.endpoint}/v1/s3/delete", json={"key": key}, timeout=30)
        res.raise_for_status()
        return res.json().get("success", False)

    def s3_list(
        self,
        prefix: Optional[str] = None,
        continuation_token: Optional[str] = None,
        max_keys: Optional[int] = None,
    ) -> Dict[str, Any]:
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
