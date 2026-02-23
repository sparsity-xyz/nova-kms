"""Minimal Odyn helper for KMS endpoints exposed by enclaver."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests


def _truncate(text: str, max_len: int = 4096) -> str:
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}...(truncated)"


def _extract_error_message(res: requests.Response) -> str:
    try:
        payload = res.json()
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        for key in ("error", "message", "detail"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return _truncate(value.strip())
        return _truncate(str(payload))

    if payload is not None:
        return _truncate(str(payload))

    text = (res.text or "").strip()
    if text:
        return _truncate(text)
    return "<empty response body>"


def _float_env(name: str, default: float, minimum: float = 0.1) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= minimum else minimum


class Odyn:
    DEFAULT_MOCK_ODYN_API = "http://odyn.sparsity.cloud:18000"

    def __init__(self, endpoint: Optional[str] = None, timeout_seconds: Optional[float] = None):
        env_endpoint = os.getenv("ODYN_ENDPOINT", "").strip()
        if endpoint:
            self.endpoint = endpoint
        elif env_endpoint:
            self.endpoint = env_endpoint
        else:
            is_enclave = os.getenv("IN_ENCLAVE", "false").lower() == "true"
            self.endpoint = "http://localhost:18000" if is_enclave else self.DEFAULT_MOCK_ODYN_API
        if timeout_seconds is None:
            timeout_seconds = _float_env("ODYN_TIMEOUT_SECONDS", 10.0)
        self.timeout_seconds = timeout_seconds
        self._session = requests.Session()

    def close(self) -> None:
        self._session.close()

    def _call(self, method: str, path: str, payload: Any = None) -> Dict[str, Any]:
        url = f"{self.endpoint}{path}"
        verb = method.upper()
        if verb == "POST":
            res = self._session.post(url, json=payload, timeout=self.timeout_seconds)
        elif verb == "GET":
            res = self._session.get(url, timeout=self.timeout_seconds)
        else:
            raise ValueError(f"Unsupported method: {method}")
        if res.status_code >= 400:
            reason = (getattr(res, "reason", "") or "").strip()
            reason_suffix = f" {reason}" if reason else ""
            body = _extract_error_message(res)
            raise RuntimeError(
                f"Odyn API request failed: {verb} {path} -> HTTP {res.status_code}{reason_suffix}; "
                f"url={url}; response={body}"
            )
        try:
            data = res.json()
        except ValueError as exc:
            raise RuntimeError(f"Odyn returned non-JSON response for path {path}") from exc
        if not isinstance(data, dict):
            raise RuntimeError(f"Odyn returned unexpected JSON type for path {path}: {type(data).__name__}")
        return data

    def eth_address(self) -> str:
        return self._call("GET", "/v1/eth/address")["address"]

    def kms_derive(self, path: str, context: str = "", length: int = 32) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"path": path, "length": length}
        if context:
            payload["context"] = context
        return self._call("POST", "/v1/kms/derive", payload)

    def kms_kv_get(self, key: str) -> Dict[str, Any]:
        return self._call("POST", "/v1/kms/kv/get", {"key": key})

    def kms_kv_put(self, key: str, value: str, ttl_ms: int = 0) -> Dict[str, Any]:
        return self._call("POST", "/v1/kms/kv/put", {"key": key, "value": value, "ttl_ms": ttl_ms})

    def kms_kv_delete(self, key: str) -> Dict[str, Any]:
        return self._call("POST", "/v1/kms/kv/delete", {"key": key})
