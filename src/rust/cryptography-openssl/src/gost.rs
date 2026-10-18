// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Helpers for GOST R 34.10 keys provided by an external OpenSSL provider
//! (for example `gostprov` from https://github.com/gost-engine/engine).
//! Provider-only keys report `EVP_PKEY_KEYMGMT` (-1) from `EVP_PKEY_get_id()`,
//! so they have to be identified by name.

use foreign_types_shared::ForeignTypeRef;
use openssl_sys as ffi;

/// OpenSSL short names of the GOST R 34.10 signature key types.
pub const GOST_KEY_TYPES: [&std::ffi::CStr; 3] = [c"gost2001", c"gost2012_256", c"gost2012_512"];

/// Returns the short name of the GOST key type, if `pkey` is a GOST key.
pub fn gost_key_type<T>(pkey: &openssl::pkey::PKeyRef<T>) -> Option<&'static str> {
    GOST_KEY_TYPES
        .iter()
        // SAFETY: `pkey` is a valid EVP_PKEY and the name is a NUL-terminated
        // string.
        .find(|name| unsafe { ffi::EVP_PKEY_is_a(pkey.as_ptr(), name.as_ptr()) == 1 })
        .map(|name| name.to_str().unwrap())
}

pub fn is_gost_pkey<T>(pkey: &openssl::pkey::PKeyRef<T>) -> bool {
    gost_key_type(pkey).is_some()
}
