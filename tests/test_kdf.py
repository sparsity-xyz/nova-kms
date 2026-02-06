"""
Tests for kdf.py — Key Derivation and Certificate Authority.
"""

import pytest

from kdf import CertificateAuthority, MasterSecretManager, derive_app_key, derive_data_key


class TestDeriveAppKey:
    def test_deterministic(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_a")
        assert k1 == k2

    def test_different_path(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 42, "path_a")
        k2 = derive_app_key(secret, 42, "path_b")
        assert k1 != k2

    def test_different_app_id(self):
        secret = b"a" * 32
        k1 = derive_app_key(secret, 1, "path")
        k2 = derive_app_key(secret, 2, "path")
        assert k1 != k2

    def test_different_secret(self):
        k1 = derive_app_key(b"a" * 32, 1, "path")
        k2 = derive_app_key(b"b" * 32, 1, "path")
        assert k1 != k2

    def test_custom_length(self):
        key = derive_app_key(b"x" * 32, 1, "p", length=64)
        assert len(key) == 64

    def test_context(self):
        k1 = derive_app_key(b"x" * 32, 1, "p", context="v1")
        k2 = derive_app_key(b"x" * 32, 1, "p", context="v2")
        assert k1 != k2


class TestDeriveDataKey:
    def test_returns_32_bytes(self):
        key = derive_data_key(b"s" * 32, 100)
        assert len(key) == 32


class TestMasterSecretManager:
    def test_not_initialized(self):
        mgr = MasterSecretManager()
        assert not mgr.is_initialized
        with pytest.raises(RuntimeError):
            _ = mgr.secret

    def test_initialize_from_peer(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\x01" * 32)
        assert mgr.is_initialized
        assert mgr.secret == b"\x01" * 32

    def test_reject_short_secret(self):
        mgr = MasterSecretManager()
        with pytest.raises(ValueError):
            mgr.initialize_from_peer(b"short")

    def test_derive(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xab" * 32)
        key = mgr.derive(42, "test_path")
        assert len(key) == 32


class TestCertificateAuthority:
    def _make_csr(self) -> bytes:
        """Generate a self-signed CSR for testing."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509 import CertificateSigningRequestBuilder, Name, NameAttribute
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            CertificateSigningRequestBuilder()
            .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, "test.app")]))
            .sign(key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives.serialization import Encoding
        return csr.public_bytes(Encoding.PEM)

    def test_sign_csr(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xcc" * 32)
        ca = CertificateAuthority(mgr)

        csr_pem = self._make_csr()
        cert_pem = ca.sign_csr(csr_pem)
        assert b"BEGIN CERTIFICATE" in cert_pem

    def test_ca_cert(self):
        mgr = MasterSecretManager()
        mgr.initialize_from_peer(b"\xdd" * 32)
        ca = CertificateAuthority(mgr)

        ca_pem = ca.get_ca_cert_pem()
        assert b"BEGIN CERTIFICATE" in ca_pem

    def test_deterministic_ca(self):
        """Two CAs created with the same secret produce the same CA cert."""
        secret = b"\xee" * 32

        mgr1 = MasterSecretManager()
        mgr1.initialize_from_peer(secret)
        ca1 = CertificateAuthority(mgr1)

        mgr2 = MasterSecretManager()
        mgr2.initialize_from_peer(secret)
        ca2 = CertificateAuthority(mgr2)

        # CA public keys should be identical (derived from same secret)
        from cryptography.x509 import load_pem_x509_certificate
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        cert1 = load_pem_x509_certificate(ca1.get_ca_cert_pem())
        cert2 = load_pem_x509_certificate(ca2.get_ca_cert_pem())
        pub1 = cert1.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        pub2 = cert2.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        assert pub1 == pub2
