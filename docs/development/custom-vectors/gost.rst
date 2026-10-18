GOST vector creation
====================

This page documents the code that was used to generate the GOST R 34.10
keys, the GOST certificate chain and the PKCS12 files in the format exported
by CryptoPro CSP.

Creation
--------

Keys and certificates are generated with the ``openssl`` command line tool
(OpenSSL 3.4 or newer) and the ``gostprov`` provider from `gost-engine`_. The
CryptoPro CSP key bag (PBE ``1.2.840.113549.1.12.1.80``) cannot be created by
OpenSSL, the script assembles the PKCS12 files itself and uses ``libcrypto``
only for the GOST 28147-89, GOST R 34.11-94, HMAC, RC2 and PKCS12 KDF
primitives. The structure of the files, including the attributes and the
order of the bags, follows a file exported by CryptoPro CSP; the 4-byte field
that ends the exported key blob is not interpreted by ``gostprov`` and is set
to zero.

.. code-block:: console

    $ OPENSSL_CONF=openssl-gost.cnf python generate_gost.py \
        /path/to/bin/openssl /path/to/libcrypto.so vectors/cryptography_vectors

where ``openssl-gost.cnf`` activates the ``default``, ``legacy`` and
``gostprov`` providers.

.. literalinclude:: /development/custom-vectors/gost/generate_gost.py

Download link: :download:`generate_gost.py
</development/custom-vectors/gost/generate_gost.py>`

Verification
------------

The PKCS12 files were decrypted with the independent ``gostprov`` decoder:

.. code-block:: console

    $ OPENSSL_CONF=openssl-gost.cnf openssl pkcs12 -nodes -nocerts \
        -in cryptopro-ascii.pfx -passin pass:cryptography

The private key matches ``x509/custom/gost/leaf-key.pem`` for every file, and
a wrong password is rejected.

.. _`gost-engine`: https://github.com/gost-engine/engine
