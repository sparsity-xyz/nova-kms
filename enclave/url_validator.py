"""
=============================================================================
URL Validator (url_validator.py)
=============================================================================

SSRF protection for outbound HTTP requests to KMS peers.

Validates peer URLs before making requests to prevent Server-Side Request
Forgery attacks where a malicious on-chain URL could cause the KMS node
to make requests to internal services.
"""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

import config


class URLValidationError(Exception):
    """Raised when a URL fails validation."""


def validate_peer_url(
    url: str,
    *,
    allowed_schemes: Optional[List[str]] = None,
    allow_private_ips: Optional[bool] = None,
) -> str:
    """
    Validate and sanitize a peer URL for outbound requests.

    Simplified implementation:
    - Checks scheme (http/https).
    - Checks for presence of hostname.
    - Checks for absence of embedded credentials.
    - Does NOT check DNS, IP addresses, or ports (relies on egress proxy).

    Parameters
    ----------
    url : str
        The URL to validate.
    allowed_schemes : list of str, optional
        Allowed URL schemes.  Defaults to config.ALLOWED_PEER_URL_SCHEMES.
    allow_private_ips : bool, optional
        Deprecated/Ignored in this simplified version.

    Returns
    -------
    str
        The validated and normalized URL.

    Raises
    ------
    URLValidationError
        If the URL fails any basic format check.
    """
    if allowed_schemes is None:
        allowed_schemes = config.ALLOWED_PEER_URL_SCHEMES
    
    # allow_private_ips is ignored in this simplified version because
    # we no longer resolve DNS or check IPs.

    if not url or not isinstance(url, str):
        raise URLValidationError("Empty or invalid URL")

    # Basic parsing
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise URLValidationError(f"Invalid URL format: {exc}")

    # 1. Scheme validation
    if parsed.scheme not in allowed_schemes:
        raise URLValidationError(
            f"URL scheme '{parsed.scheme}' not allowed. "
            f"Permitted: {allowed_schemes}"
        )

    # 2. Hostname must be present
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL has no hostname")

    # 3. No credentials in URL
    if parsed.username or parsed.password:
        raise URLValidationError("URLs with embedded credentials are not allowed")

    # Return cleaned URL (strip trailing whitespace, etc.)
    return url.strip()
