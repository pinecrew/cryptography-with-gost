# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

import pytest

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import gost

from ...utils import load_vectors_from_file

requires_gost = pytest.mark.supported(
    only_if=lambda backend: backend.gost_supported(),
    skip_message="Requires the gostprov OpenSSL provider",
)

# Vector file stem, key type, key size.
KEYS = [
    ("gost2001-a", "gost2001", 256),
    ("gost2012-256-a", "gost2012_256", 256),
    ("gost2012-256-tcb", "gost2012_256", 256),
    ("gost2012-512-a", "gost2012_512", 512),
    ("gost2012-512-c", "gost2012_512", 512),
]


def _vector(name: str) -> bytes:
    return load_vectors_from_file(
        os.path.join("asymmetric", "GOST", name),
        lambda f: f.read(),
        mode="rb",
    )


def _private_key(name: str) -> gost.GostPrivateKey:
    key = serialization.load_pem_private_key(_vector(f"{name}.pem"), None)
    assert isinstance(key, gost.GostPrivateKey)
    return key


def _public_key(name: str) -> gost.GostPublicKey:
    key = serialization.load_pem_public_key(_vector(f"{name}-pub.pem"))
    assert isinstance(key, gost.GostPublicKey)
    return key


@requires_gost
@pytest.mark.parametrize(("name", "key_type", "key_size"), KEYS)
class TestGostKey:
    def test_load(self, name, key_type, key_size, backend):
        key = _private_key(name)
        assert key.key_type == key_type
        assert key.key_size == key_size
        public_key = key.public_key()
        assert isinstance(public_key, gost.GostPublicKey)
        assert public_key.key_type == key_type
        assert public_key.key_size == key_size
        assert public_key == _public_key(name)

    def test_sign_verify(self, name, key_type, key_size, backend):
        key = _private_key(name)
        signature = key.sign(b"test data")
        assert len(signature) == key_size // 4
        key.public_key().verify(signature, b"test data")
        _public_key(name).verify(signature, b"test data")

    def test_signature_is_randomized(self, name, key_type, key_size, backend):
        key = _private_key(name)
        first = key.sign(b"test data")
        second = key.sign(b"test data")
        assert first != second
        key.public_key().verify(first, b"test data")
        key.public_key().verify(second, b"test data")

    def test_verify_invalid(self, name, key_type, key_size, backend):
        key = _private_key(name)
        public_key = key.public_key()
        signature = key.sign(b"test data")
        with pytest.raises(InvalidSignature):
            public_key.verify(signature, b"other data")
        corrupted = bytes([signature[0] ^ 1]) + signature[1:]
        with pytest.raises(InvalidSignature):
            public_key.verify(corrupted, b"test data")
        with pytest.raises(InvalidSignature):
            public_key.verify(signature[:-1], b"test data")

    def test_private_bytes(self, name, key_type, key_size, backend):
        key = _private_key(name)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        assert pem == _vector(f"{name}.pem")
        der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        loaded = serialization.load_der_private_key(der, None)
        assert isinstance(loaded, gost.GostPrivateKey)
        assert loaded.public_key() == key.public_key()

    @pytest.mark.parametrize(
        "encoding", [serialization.Encoding.PEM, serialization.Encoding.DER]
    )
    def test_private_bytes_encrypted(
        self, name, key_type, key_size, encoding, backend
    ):
        key = _private_key(name)
        encrypted = key.private_bytes(
            encoding,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"password"),
        )
        if encoding is serialization.Encoding.PEM:
            loader = serialization.load_pem_private_key
        else:
            loader = serialization.load_der_private_key
        loaded = loader(encrypted, b"password")
        assert loaded.public_key() == key.public_key()
        with pytest.raises(ValueError):
            loader(encrypted, b"wrong password")

    def test_public_bytes(self, name, key_type, key_size, backend):
        public_key = _private_key(name).public_key()
        pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert pem == _vector(f"{name}-pub.pem")
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert serialization.load_der_public_key(der) == public_key


@requires_gost
class TestGostKeyErrors:
    @pytest.mark.parametrize(
        ("encoding", "fmt"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
            ),
            (serialization.Encoding.Raw, serialization.PrivateFormat.Raw),
            (serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH),
        ],
    )
    def test_private_bytes_unsupported_format(self, encoding, fmt, backend):
        key = _private_key("gost2012-256-a")
        with pytest.raises(ValueError):
            key.private_bytes(encoding, fmt, serialization.NoEncryption())

    def test_private_bytes_unsupported_encoding(self, backend):
        key = _private_key("gost2012-256-a")
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.SMIME,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    @pytest.mark.parametrize(
        ("encoding", "fmt"),
        [
            (serialization.Encoding.PEM, serialization.PublicFormat.PKCS1),
            (serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            (
                serialization.Encoding.OpenSSH,
                serialization.PublicFormat.OpenSSH,
            ),
            (
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            ),
        ],
    )
    def test_public_bytes_unsupported_format(self, encoding, fmt, backend):
        public_key = _private_key("gost2012-256-a").public_key()
        with pytest.raises(ValueError):
            public_key.public_bytes(encoding, fmt)

    def test_public_bytes_unsupported_encoding(self, backend):
        public_key = _private_key("gost2012-256-a").public_key()
        with pytest.raises(TypeError):
            public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def test_sign_requires_bytes(self, backend):
        key = _private_key("gost2012-256-a")
        with pytest.raises(TypeError):
            key.sign("test data")  # type: ignore[arg-type]

    def test_public_key_equality(self, backend):
        a = _private_key("gost2012-256-a").public_key()
        b = _private_key("gost2012-256-tcb").public_key()
        assert a == _public_key("gost2012-256-a")
        assert a != b
        assert a != object()

    def test_certificate_public_key(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "gost", "leaf.pem"),
            lambda f: x509.load_pem_x509_certificate(f.read()),
            mode="rb",
        )
        key = load_vectors_from_file(
            os.path.join("x509", "custom", "gost", "leaf-key.pem"),
            lambda f: serialization.load_pem_private_key(f.read(), None),
            mode="rb",
        )
        public_key = cert.public_key()
        assert isinstance(public_key, gost.GostPublicKey)
        assert public_key == key.public_key()


@pytest.mark.supported(
    only_if=lambda backend: not backend.gost_supported(),
    skip_message="The gostprov OpenSSL provider is loaded",
)
def test_unsupported_without_provider(backend):
    with pytest.raises(UnsupportedAlgorithm):
        serialization.load_pem_private_key(_vector("gost2012-256-a.pem"), None)
    with pytest.raises(UnsupportedAlgorithm):
        serialization.load_pem_public_key(_vector("gost2012-256-a-pub.pem"))
