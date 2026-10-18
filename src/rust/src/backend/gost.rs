// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! GOST R 34.10-2001 / 34.10-2012 keys. All operations are delegated to
//! OpenSSL, so a GOST provider (for example `gostprov` from
//! https://github.com/gost-engine/engine) has to be loaded.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;
use crate::serialization::{Encoding, PrivateFormat, PublicFormat};

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.gost")]
pub(crate) struct GostPrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.gost")]
pub(crate) struct GostPublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> GostPrivateKey {
    GostPrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> GostPublicKey {
    GostPublicKey {
        pkey: pkey.to_owned(),
    }
}

fn key_type<T>(pkey: &openssl::pkey::PKeyRef<T>) -> &'static str {
    cryptography_openssl::gost::gost_key_type(pkey).unwrap_or("unknown")
}

#[pyo3::pymethods]
impl GostPrivateKey {
    /// OpenSSL name of the key type: `gost2001`, `gost2012_256` or
    /// `gost2012_512`.
    #[getter]
    fn key_type(&self) -> &'static str {
        key_type(&self.pkey)
    }

    #[getter]
    fn key_size(&self) -> u32 {
        self.pkey.bits()
    }

    /// Signs `data` with the digest mandated by the key (GOST R 34.11-94 or
    /// GOST R 34.11-2012 of the matching size).
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        let data_bytes = data.as_bytes();
        let signature = py.detach(|| -> Result<Vec<u8>, openssl::error::ErrorStack> {
            signer.update(data_bytes)?;
            signer.sign_to_vec()
        })?;
        Ok(pyo3::types::PyBytes::new(py, &signature))
    }

    fn public_key(&self) -> CryptographyResult<GostPublicKey> {
        let der = self.pkey.public_key_to_der()?;
        Ok(GostPublicKey {
            pkey: openssl::pkey::PKey::public_key_from_der(&der)?,
        })
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: Encoding,
        format: PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            false,
            false,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }

    fn __repr__(&self) -> String {
        format!("<GostPrivateKey(key_type={})>", key_type(&self.pkey))
    }
}

#[pyo3::pymethods]
impl GostPublicKey {
    #[getter]
    fn key_type(&self) -> &'static str {
        key_type(&self.pkey)
    }

    #[getter]
    fn key_size(&self) -> u32 {
        self.pkey.bits()
    }

    fn verify(
        &self,
        py: pyo3::Python<'_>,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<()> {
        let mut verifier = openssl::sign::Verifier::new_without_digest(&self.pkey)?;
        let sig_bytes = signature.as_bytes();
        let data_bytes = data.as_bytes();
        let valid = py
            .detach(|| -> Result<bool, openssl::error::ErrorStack> {
                verifier.update(data_bytes)?;
                verifier.verify(sig_bytes)
            })
            .unwrap_or(false);
        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }
        Ok(())
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: Encoding,
        format: PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, false, false)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }

    fn __repr__(&self) -> String {
        format!("<GostPublicKey(key_type={})>", key_type(&self.pkey))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod gost {
    #[pymodule_export]
    use super::{GostPrivateKey, GostPublicKey};
}
