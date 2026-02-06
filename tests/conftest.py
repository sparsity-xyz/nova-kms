"""
conftest.py — ensure the enclave package is importable from tests.
"""

import sys
from pathlib import Path

# Add the enclave directory to sys.path so test modules can import
# enclave modules directly (e.g. `from data_store import DataStore`).
enclave_dir = Path(__file__).resolve().parent.parent / "enclave"
if str(enclave_dir) not in sys.path:
    sys.path.insert(0, str(enclave_dir))
