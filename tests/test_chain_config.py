"""
Tests for chain endpoint selection defaults and overrides.
"""

from chain import Chain


def test_chain_defaults_to_registry_helios_port_in_enclave(monkeypatch):
    monkeypatch.delenv("HELIOS_RPC_URL", raising=False)
    monkeypatch.setenv("IN_ENCLAVE", "true")

    chain = Chain()

    assert chain.endpoint == "http://127.0.0.1:18545"


def test_chain_uses_mock_rpc_outside_enclave(monkeypatch):
    monkeypatch.delenv("HELIOS_RPC_URL", raising=False)
    monkeypatch.setenv("IN_ENCLAVE", "false")

    chain = Chain()

    assert chain.endpoint == Chain.DEFAULT_MOCK_RPC


def test_chain_uses_helios_rpc_url_env_override(monkeypatch):
    monkeypatch.setenv("IN_ENCLAVE", "true")
    monkeypatch.setenv("HELIOS_RPC_URL", "http://127.0.0.1:19999")

    chain = Chain()

    assert chain.endpoint == "http://127.0.0.1:19999"


def test_chain_explicit_rpc_url_takes_precedence(monkeypatch):
    monkeypatch.setenv("IN_ENCLAVE", "true")
    monkeypatch.setenv("HELIOS_RPC_URL", "http://127.0.0.1:19999")

    chain = Chain(rpc_url="http://localhost:1234")

    assert chain.endpoint == "http://localhost:1234"
