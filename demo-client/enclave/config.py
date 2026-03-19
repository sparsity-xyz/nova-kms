"""nova-kms-client/enclave/config.py

Static configuration for the Nova KMS Client example.

This client is intended to run on Nova Platform and discover KMS nodes via:
KMSRegistry -> NovaAppRegistry.

Registry discovery parameters remain static in this file. Transport/runtime
selection still uses environment variables such as ``IN_ENCLAVE``,
``HELIOS_RPC_URL`` and ``CAPSULE_ENDPOINT`` in the surrounding helper modules,
so update the constants below before building/deploying and use env vars for
endpoint selection when needed.
"""

# =============================================================================
# Chain / Registry
# =============================================================================

# Base Sepolia
CHAIN_ID: int = 84532

# Minimum confirmations before trusting eth_call results.
CONFIRMATION_DEPTH: int = 6

# Registry Addresses (MUST be configured for discovery)
NOVA_APP_REGISTRY_ADDRESS: str = "0x0f68E6e699f2E972998a1EcC000c7ce103E64cc8"  # e.g. "0x..." (NovaAppRegistry proxy)

# KMS App ID in the NovaAppRegistry
KMS_APP_ID: int = 49

# =============================================================================
# Scheduler
# =============================================================================

TEST_CYCLE_INTERVAL_SECONDS: int = 30
