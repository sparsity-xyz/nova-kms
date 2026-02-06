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

import ipaddress
import logging
import socket
from typing import List, Optional
from urllib.parse import urlparse

import config

logger = logging.getLogger("nova-kms.url_validator")

# Private / reserved IP ranges that should never be contacted as peers.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # ULA
    ipaddress.ip_network("fe80::/10"),  # link-local v6
]


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

    Parameters
    ----------
    url : str
        The URL to validate.
    allowed_schemes : list of str, optional
        Allowed URL schemes.  Defaults to config.ALLOWED_PEER_URL_SCHEMES.
    allow_private_ips : bool, optional
        If False, blocks requests to private/reserved IP ranges.
        Defaults to True in dev/sim mode, False in production.

    Returns
    -------
    str
        The validated and normalized URL.

    Raises
    ------
    URLValidationError
        If the URL fails any validation check.
    """
    if allowed_schemes is None:
        allowed_schemes = config.ALLOWED_PEER_URL_SCHEMES
    if allow_private_ips is None:
        allow_private_ips = not config.IN_ENCLAVE

    if not url or not isinstance(url, str):
        raise URLValidationError("Empty or invalid URL")

    parsed = urlparse(url)

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

    # 3. Port validation (block commonly abused ports)
    port = parsed.port
    if port is not None and port in (25, 587, 465, 6379, 11211, 5432, 3306, 27017):
        raise URLValidationError(f"Port {port} is not allowed for peer communication")

    # 4. IP address validation (SSRF protection)
    if not allow_private_ips:
        try:
            # Try parsing as IP directly
            ip = ipaddress.ip_address(hostname)
            _check_ip_blocked(ip)
        except ValueError:
            # It's a hostname — resolve and check all IPs
            try:
                addrs = socket.getaddrinfo(hostname, port or 443, proto=socket.IPPROTO_TCP)
                for family, _, _, _, sockaddr in addrs:
                    ip = ipaddress.ip_address(sockaddr[0])
                    _check_ip_blocked(ip)
            except socket.gaierror as exc:
                raise URLValidationError(f"Cannot resolve hostname '{hostname}': {exc}")

    # 5. No credentials in URL
    if parsed.username or parsed.password:
        raise URLValidationError("URLs with embedded credentials are not allowed")

    # Return cleaned URL (strip trailing whitespace, etc.)
    return url.strip()


def _check_ip_blocked(ip: ipaddress._BaseAddress) -> None:
    """Raise URLValidationError if the IP is in a blocked range."""
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            raise URLValidationError(
                f"IP address {ip} is in a blocked range ({net}). "
                "Peer URLs must resolve to public IP addresses."
            )
