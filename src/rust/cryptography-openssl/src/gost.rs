// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Helpers for GOST R 34.10 keys provided by an external OpenSSL provider
//! (for example `gostprov` from https://github.com/gost-engine/engine).
//! Provider-only keys report `EVP_PKEY_KEYMGMT` (-1) from `EVP_PKEY_get_id()`,
//! so they have to be identified by name.

use foreign_types_shared::{ForeignType, ForeignTypeRef};
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

// Primitives for RFC 9337 / RFC 9548 password-based protection of PFX.
// Streebog and the GOST R 34.12-2015 ciphers exist only in the GOST
// provider, so they are fetched by name instead of the legacy NID lookups.

extern "C" {
    // Not exposed by openssl-sys.
    fn EVP_CIPHER_CTX_set_params(
        ctx: *mut ffi::EVP_CIPHER_CTX,
        params: *const ffi::OSSL_PARAM,
    ) -> std::os::raw::c_int;
}

/// GOST R 34.12-2015 block ciphers in CTR-ACPKM mode (RFC 8645).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CtrAcpkmCipher {
    /// 64-bit block, 12-octet ukm.
    Magma,
    /// 128-bit block, 16-octet ukm.
    Kuznyechik,
}

impl CtrAcpkmCipher {
    fn name(self) -> &'static str {
        match self {
            CtrAcpkmCipher::Magma => "magma-ctr-acpkm",
            CtrAcpkmCipher::Kuznyechik => "kuznyechik-ctr-acpkm",
        }
    }

    /// Size of the `ukm` field of Gost3412-15-Encryption-Parameters
    /// (RFC 9337 Section 7.3).
    pub fn ukm_length(self) -> usize {
        match self {
            CtrAcpkmCipher::Magma => 12,
            CtrAcpkmCipher::Kuznyechik => 16,
        }
    }
}

fn streebog512() -> crate::OpenSSLResult<openssl::md::Md> {
    openssl::md::Md::fetch(None, "md_gost12_512", None)
}

/// PBKDF2 with HMAC_GOSTR3411_2012_512 as the PRF (RFC 9337 Section 4).
pub fn pbkdf2_hmac_streebog512(
    password: &[u8],
    salt: &[u8],
    iterations: usize,
    out: &mut [u8],
) -> crate::OpenSSLResult<()> {
    let md = streebog512()?;
    // SAFETY: `md` outlives every use of `digest`.
    let digest = unsafe { openssl::hash::MessageDigest::from_ptr(md.as_ptr()) };
    openssl::pkcs5::pbkdf2_hmac(password, salt, iterations, digest, out)
}

/// HMAC_GOSTR3411_2012_512 (RFC 7836).
pub fn hmac_streebog512(key: &[u8], data: &[u8]) -> crate::OpenSSLResult<Vec<u8>> {
    let md = streebog512()?;
    // SAFETY: `md` outlives every use of `digest`.
    let digest = unsafe { openssl::hash::MessageDigest::from_ptr(md.as_ptr()) };
    let pkey = openssl::pkey::PKey::hmac(key)?;
    let mut signer = openssl::sign::Signer::new(digest, &pkey)?;
    signer.update(data)?;
    signer.sign_to_vec()
}

/// Encrypts (or, CTR being symmetric, decrypts) `data` with a GOST
/// R 34.12-2015 cipher in CTR-ACPKM mode.
///
/// `alg_params_der` is the DER encoding of Gost3412-15-Encryption-Parameters.
/// It is handed to the provider as the AlgorithmIdentifier parameters, so the
/// provider derives the IV from `ukm` and picks the ACPKM section size exactly
/// as it does for PKCS#12/CMS (256 KiB for Kuznyechik, 8 KiB for Magma).
pub fn ctr_acpkm_encrypt(
    cipher: CtrAcpkmCipher,
    key: &[u8],
    alg_params_der: &[u8],
    data: &[u8],
) -> crate::OpenSSLResult<Vec<u8>> {
    let evp_cipher = openssl::cipher::Cipher::fetch(None, cipher.name(), None)?;
    let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
    ctx.encrypt_init(Some(&evp_cipher), None, None)?;

    // SAFETY: the parameter array and the data it points to outlive the call;
    // the provider copies what it needs.
    unsafe {
        let params = [
            ffi::OSSL_PARAM_construct_octet_string(
                c"alg_id_param".as_ptr(),
                alg_params_der.as_ptr() as *mut std::ffi::c_void,
                alg_params_der.len(),
            ),
            ffi::OSSL_PARAM_construct_end(),
        ];
        crate::cvt(EVP_CIPHER_CTX_set_params(
            ctx.as_ptr(),
            params.as_ptr(),
        ))?;
    }

    ctx.encrypt_init(None, Some(key), None)?;
    let mut out = Vec::with_capacity(data.len());
    ctx.cipher_update_vec(data, &mut out)?;
    ctx.cipher_final_vec(&mut out)?;
    Ok(out)
}
