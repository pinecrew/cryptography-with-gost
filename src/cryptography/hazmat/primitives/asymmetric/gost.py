# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
GOST R 34.10-2001 / 34.10-2012 keys.

Keys are backed by OpenSSL and require the ``gostprov`` provider from
https://github.com/gost-engine/engine. They are returned by
``load_pem_private_key``, ``load_der_private_key``, ``load_*_public_key``,
``Certificate.public_key()`` and the PKCS#12 loaders.
"""

from __future__ import annotations

from cryptography.hazmat.bindings._rust import openssl as rust_openssl

if hasattr(rust_openssl, "gost"):
    GostPrivateKey = rust_openssl.gost.GostPrivateKey
    GostPublicKey = rust_openssl.gost.GostPublicKey
else:  # LibreSSL, BoringSSL and AWS-LC have no GOST support.

    class GostPrivateKey:  # type: ignore[no-redef]
        pass

    class GostPublicKey:  # type: ignore[no-redef]
        pass


__all__ = ["GostPrivateKey", "GostPublicKey"]
