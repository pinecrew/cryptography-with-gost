# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime

import pytest

from cryptography.x509.general_name import RFC822Name
from cryptography.x509.verification import (
    PolicyBuilder,
    Store,
    VerificationError,
)
from tests.x509.test_x509_gost import corrupt_signature, load_gost_cert

# Within the validity of the whole chain (the client certificate is valid
# during 2025).
VALID_TIME = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)


def _verify(leaf, intermediates, time=VALID_TIME):
    verifier = (
        PolicyBuilder()
        .store(Store([load_gost_cert("root")]))
        .time(time)
        .build_client_verifier()
    )
    return verifier.verify(leaf, intermediates)


@pytest.mark.supported(
    only_if=lambda backend: backend.gost_supported(),
    skip_message="Requires the gostprov OpenSSL provider",
)
class TestGostClientVerifier:
    def test_verify(self, backend):
        root, ca, leaf = (load_gost_cert(n) for n in ("root", "ca", "leaf"))
        verified = _verify(leaf, [ca])
        assert verified.chain == [leaf, ca, root]
        assert verified.subjects == [RFC822Name("client@example.com")]

    def test_invalid_signature(self, backend):
        leaf = corrupt_signature(load_gost_cert("leaf"))
        with pytest.raises(VerificationError):
            _verify(leaf, [load_gost_cert("ca")])

    def test_invalid_intermediate_signature(self, backend):
        ca = corrupt_signature(load_gost_cert("ca"))
        with pytest.raises(VerificationError):
            _verify(load_gost_cert("leaf"), [ca])

    def test_expired(self, backend):
        with pytest.raises(VerificationError):
            _verify(
                load_gost_cert("leaf"),
                [load_gost_cert("ca")],
                datetime.datetime(2026, 6, 1, tzinfo=datetime.timezone.utc),
            )

    def test_missing_intermediate(self, backend):
        with pytest.raises(VerificationError):
            _verify(load_gost_cert("leaf"), [])
