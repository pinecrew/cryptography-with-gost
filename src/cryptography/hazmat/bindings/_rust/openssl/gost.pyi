# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer

class GostPrivateKey:
    @property
    def key_type(self) -> str: ...
    @property
    def key_size(self) -> int: ...
    def sign(self, data: Buffer) -> bytes: ...
    def public_key(self) -> GostPublicKey: ...
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes: ...

class GostPublicKey:
    @property
    def key_type(self) -> str: ...
    @property
    def key_size(self) -> int: ...
    def verify(self, signature: Buffer, data: Buffer) -> None: ...
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes: ...
