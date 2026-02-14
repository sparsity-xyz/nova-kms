"""
tests/test_address_normalization.py

Dedicated test suite to verify wallet address normalization (case-insensitivity)
across auth, sync_manager, and other core components.
"""

import pytest
from enclave.auth import _canonical_eth_wallet, verify_wallet_signature, recover_wallet_from_signature
from enclave.sync_manager import _normalize_wallet

def test_canonical_eth_wallet_normalization():
    """Verify _canonical_eth_wallet handles various Ethereum address formats."""
    addr_lower = "0x1234567890abcdef1234567890abcdef12345678"
    addr_upper = "0x1234567890ABCDEF1234567890ABCDEF12345678"
    addr_no_prefix = "1234567890abcdef1234567890abcdef12345678"
    addr_checksum = "0x1234567890AbCdEf1234567890AbCdEf12345678"

    assert _canonical_eth_wallet(addr_lower) == addr_lower
    assert _canonical_eth_wallet(addr_upper) == addr_lower
    assert _canonical_eth_wallet(addr_no_prefix) == addr_lower
    assert _canonical_eth_wallet(addr_checksum) == addr_lower

    with pytest.raises(ValueError):
        _canonical_eth_wallet("0x123")  # Too short
    
    with pytest.raises(ValueError):
        _canonical_eth_wallet("not-an-address")

def test_sync_manager_normalize_wallet():
    """Verify _normalize_wallet handles standard addresses and symbolic names."""
    eth_addr = "0x1234567890abcdef1234567890abcdef12345678"
    eth_addr_mixed = "0x1234567890ABCDEF1234567890abcdef12345678"
    symbolic = "0xTestNode"
    
    assert _normalize_wallet(eth_addr) == eth_addr
    assert _normalize_wallet(eth_addr_mixed) == eth_addr
    assert _normalize_wallet(symbolic) == symbolic  # Symbolic should remain unchanged
    assert _normalize_wallet(None) == ""
    assert _normalize_wallet("  0x123  ") == "0x123" # Whitespace stripped but too short for eth-normalization

def test_verify_wallet_signature_case_insensitivity():
    """Verify that verify_wallet_signature is case-insensitive for the wallet address."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    
    acct = Account.create()
    msg = "test message"
    msghash = encode_defunct(text=msg)
    sig = Account.sign_message(msghash, acct.key).signature.hex()
    
    # Test with various wallet formats
    assert verify_wallet_signature(acct.address, msg, sig) is True
    assert verify_wallet_signature(acct.address.upper(), msg, sig) is True
    assert verify_wallet_signature(acct.address.lower(), msg, sig) is True

def test_recover_wallet_from_signature_normalization():
    """Verify recover_wallet_from_signature returns normalized (lowercase) addresses."""
    from eth_account import Account
    from eth_account.messages import encode_defunct
    
    acct = Account.create()
    msg = "test message"
    msghash = encode_defunct(text=msg)
    sig = Account.sign_message(msghash, acct.key).signature.hex()
    
    recovered = recover_wallet_from_signature(msg, sig)
    # Our update ensures it returns lowercase, not checksummed
    assert recovered == acct.address.lower()
    assert recovered != acct.address  # Assuming acct.address is checksummed (mixed case)

def test_client_identity_normalization():
    """Verify ClientIdentity enforces lowercase normalization."""
    from enclave.auth import ClientIdentity
    
    mixed_wallet = "0xAbCdEf1234567890abcdef1234567890abcdef12"
    identity = ClientIdentity(tee_wallet=mixed_wallet)
    assert identity.tee_wallet == mixed_wallet.lower()
    
    identity.tee_wallet = mixed_wallet.upper()
    identity.__post_init__()
    assert identity.tee_wallet == mixed_wallet.lower()
