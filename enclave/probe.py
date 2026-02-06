"""
=============================================================================
Liveness Probe Helpers (probe.py)
=============================================================================

Client-side probing utilities.  KMS nodes don't send heartbeats on-chain;
instead, peers (and clients) probe /health to determine liveness.
"""

from __future__ import annotations

import logging
import time
from typing import List, Optional

import requests

logger = logging.getLogger("nova-kms.probe")


def probe_node(node_url: str, *, timeout: int = 5) -> bool:
    """
    Return True if the node's /health endpoint responds with HTTP 200
    within the given timeout.
    """
    try:
        url = f"{node_url.rstrip('/')}/health"
        resp = requests.get(url, timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False


def probe_nodes(
    nodes: List[dict],
    *,
    timeout: int = 5,
) -> List[dict]:
    """
    Probe a list of node dicts and annotate each with ``healthy: bool``
    and ``probe_ms: int``.
    """
    results = []
    for node in nodes:
        start = time.time()
        healthy = probe_node(node.get("node_url", ""), timeout=timeout)
        elapsed_ms = int((time.time() - start) * 1000)
        results.append({**node, "healthy": healthy, "probe_ms": elapsed_ms})
    return results


def find_healthy_peer(
    nodes: List[dict],
    *,
    exclude_wallet: Optional[str] = None,
    timeout: int = 5,
) -> Optional[dict]:
    """Return the first healthy peer (excluding our own wallet)."""
    for node in nodes:
        if exclude_wallet and node.get("tee_wallet_address", "").lower() == exclude_wallet.lower():
            continue
        if probe_node(node.get("node_url", ""), timeout=timeout):
            return node
    return None
