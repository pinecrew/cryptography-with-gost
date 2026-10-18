// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! GOST R 34.10 keys are not parsed natively: they are handed over to OpenSSL,
//! which can decode them when a GOST provider (for example `gostprov`) is
//! loaded.

use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

const GOST_KEY_OIDS: [asn1::ObjectIdentifier; 3] = [
    // id-GostR3410-2001
    asn1::oid!(1, 2, 643, 2, 2, 19),
    // id-tc26-gost3410-12-256
    asn1::oid!(1, 2, 643, 7, 1, 1, 1, 1),
    // id-tc26-gost3410-12-512
    asn1::oid!(1, 2, 643, 7, 1, 1, 1, 2),
];

pub(crate) fn is_gost_key_oid(oid: &asn1::ObjectIdentifier) -> bool {
    GOST_KEY_OIDS.contains(oid)
}

/// Decodes a DER `PrivateKeyInfo` with a GOST key through OpenSSL.
pub(crate) fn parse_private_key(
    data: &[u8],
    oid: &asn1::ObjectIdentifier,
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    openssl::pkey::PKey::private_key_from_pkcs8(data)
        .map_err(|_| KeyParsingError::UnsupportedKeyType(oid.clone()))
}

/// Decodes a DER `SubjectPublicKeyInfo` with a GOST key through OpenSSL.
pub(crate) fn parse_public_key(
    data: &[u8],
    oid: &asn1::ObjectIdentifier,
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    openssl::pkey::PKey::public_key_from_der(data)
        .map_err(|_| KeyParsingError::UnsupportedKeyType(oid.clone()))
}

/// Encodes a GOST key as a DER `PrivateKeyInfo` through OpenSSL.
pub(crate) fn serialize_private_key(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> KeySerializationResult<Vec<u8>> {
    Ok(pkey.private_key_to_pkcs8()?)
}

/// Encodes a GOST key as a DER `SubjectPublicKeyInfo` through OpenSSL.
pub(crate) fn serialize_public_key(
    pkey: &openssl::pkey::PKeyRef<impl openssl::pkey::HasPublic>,
) -> KeySerializationResult<Vec<u8>> {
    Ok(pkey.public_key_to_der()?)
}
