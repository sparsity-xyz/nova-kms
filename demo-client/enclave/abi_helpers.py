"""
=============================================================================
ABI Helpers (abi_helpers.py)
=============================================================================

Shared utility functions for ABI encoding / decoding used by nova_registry.py.
Extracted to eliminate duplicate code.
"""

from __future__ import annotations

from typing import Any


def abi_type_to_eth_abi_str(abi_item: dict) -> str:
    """Convert an ABI type descriptor to an eth_abi-compatible type string.

    Supports tuples (structs) and tuple arrays.
    """
    abi_type = abi_item["type"]
    if not abi_type.startswith("tuple"):
        return abi_type

    # Supports tuple and tuple[]
    suffix = abi_type[len("tuple"):]
    components = abi_item.get("components") or []
    inner = ",".join(abi_type_to_eth_abi_str(c) for c in components)
    return f"({inner}){suffix}"


def decode_outputs(fn_abi: dict, raw_result: Any):
    """Decode raw EVM call result bytes using the function's output ABI."""
    from eth_abi import decode as abi_decode
    from hexbytes import HexBytes

    outputs = fn_abi.get("outputs") or []
    if not outputs:
        return tuple()
    output_types = [abi_type_to_eth_abi_str(o) for o in outputs]
    return abi_decode(output_types, HexBytes(raw_result))
