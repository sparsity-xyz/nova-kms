"""Runtime configuration for the simplified KMS demo client."""

import os


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(value, minimum)


TEST_CYCLE_INTERVAL_SECONDS: int = _int_env("TEST_CYCLE_INTERVAL_SECONDS", 30)
FIXED_DERIVE_PATH: str = os.getenv("FIXED_DERIVE_PATH", "nova-kms-client/fixed-derive")
KV_DATA_KEY: str = os.getenv("KV_DATA_KEY", "nova-kms-client/timestamp")
