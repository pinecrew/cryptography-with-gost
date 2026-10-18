# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

import pytest

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import gost

from ..utils import load_vectors_from_file

requires_gost = pytest.mark.supported(
    only_if=lambda backend: backend.gost_supported(),
    skip_message="Requires the gostprov OpenSSL provider",
)

# GOST R 34.10-2012 signature algorithms (RFC 9215).
SIGNATURE_2012_256 = "1.2.643.7.1.1.3.2"
SIGNATURE_2012_512 = "1.2.643.7.1.1.3.3"


def load_gost_cert(name: str) -> x509.Certificate:
    """Certificates of the chain root (512 bit) -> ca -> leaf (256 bit)."""
    return load_vectors_from_file(
        os.path.join("x509", "custom", "gost", f"{name}.pem"),
        lambda f: x509.load_pem_x509_certificate(f.read()),
        mode="rb",
    )


def corrupt_signature(cert: x509.Certificate) -> x509.Certificate:
    der = bytearray(cert.public_bytes(serialization.Encoding.DER))
    # The signature BIT STRING ends the certificate.
    der[-1] ^= 0x01
    return x509.load_der_x509_certificate(bytes(der))


@requires_gost
class TestGostCertificate:
    @pytest.mark.parametrize(
        ("name", "issuer", "signature_oid"),
        [
            ("root", "root", SIGNATURE_2012_512),
            ("ca", "root", SIGNATURE_2012_512),
            ("leaf", "ca", SIGNATURE_2012_256),
        ],
    )
    def test_verify_directly_issued_by(
        self, name, issuer, signature_oid, backend
    ):
        cert = load_gost_cert(name)
        assert cert.signature_algorithm_oid.dotted_string == signature_oid
        assert isinstance(cert.public_key(), gost.GostPublicKey)
        cert.verify_directly_issued_by(load_gost_cert(issuer))

    def test_verify_directly_issued_by_wrong_issuer(self, backend):
        with pytest.raises(ValueError):
            load_gost_cert("leaf").verify_directly_issued_by(
                load_gost_cert("root")
            )

    @pytest.mark.parametrize(
        ("name", "issuer"), [("ca", "root"), ("leaf", "ca")]
    )
    def test_verify_directly_issued_by_invalid_signature(
        self, name, issuer, backend
    ):
        cert = corrupt_signature(load_gost_cert(name))
        with pytest.raises(InvalidSignature):
            cert.verify_directly_issued_by(load_gost_cert(issuer))

    def test_verify_directly_issued_by_key_mismatch(self, backend):
        # An issuer with the right name but another key of the same type:
        # the intermediate CA certificate with its SubjectPublicKeyInfo
        # replaced.
        ca = load_gost_cert("ca")
        leaf = load_gost_cert("leaf")
        der = bytearray(ca.public_bytes(serialization.Encoding.DER))
        ca_spki = ca.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        other_spki = (
            serialization.load_pem_private_key(
                load_vectors_from_file(
                    os.path.join("asymmetric", "GOST", "gost2012-256-a.pem"),
                    lambda f: f.read(),
                    mode="rb",
                ),
                None,
            )
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        assert len(ca_spki) == len(other_spki)
        offset = der.index(ca_spki)
        der[offset : offset + len(ca_spki)] = other_spki
        impostor = x509.load_der_x509_certificate(bytes(der))
        with pytest.raises(InvalidSignature):
            leaf.verify_directly_issued_by(impostor)
