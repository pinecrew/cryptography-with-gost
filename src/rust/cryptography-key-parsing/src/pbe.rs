// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::{KeySerializationError, KeySerializationResult};

pub enum EncryptionAlgorithm {
    PBESHA1And3KeyTripleDESCBC,
    PBESv2SHA256AndAES256CBC,
    /// RFC 9337: PBES2 with PBKDF2-HMAC_GOSTR3411_2012_512 and a GOST
    /// R 34.12-2015 cipher in CTR-ACPKM mode. Requires the GOST provider.
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    PBESv2GostR3411_2012_512AndCtrAcpkm(cryptography_openssl::gost::CtrAcpkmCipher),
}

impl EncryptionAlgorithm {
    pub fn salt_length(&self) -> usize {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => 8,
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => 16,
            // RFC 9548 Section 8 recommends at least 32 octets.
        #[cfg(not(any(
            CRYPTOGRAPHY_IS_LIBRESSL,
            CRYPTOGRAPHY_IS_BORINGSSL,
            CRYPTOGRAPHY_IS_AWSLC
        )))]
            EncryptionAlgorithm::PBESv2GostR3411_2012_512AndCtrAcpkm(_) => 32,
        }
    }

    /// Whether the PFX has to use the RFC 9548 integrity scheme
    /// (HMAC_GOSTR3411_2012_512 keyed by PBKDF2) instead of RFC 7292 MAC.
    pub fn is_gost(&self) -> bool {
        match self {
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            EncryptionAlgorithm::PBESv2GostR3411_2012_512AndCtrAcpkm(_) => true,
            _ => false,
        }
    }

    pub fn algorithm_identifier<'a>(
        &self,
        cipher_kdf_iter: u64,
        salt: &'a [u8],
        iv: &'a [u8],
    ) -> cryptography_x509::common::AlgorithmIdentifier<'a> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::PbeWithShaAnd3KeyTripleDesCbc(cryptography_x509::common::Pkcs12PbeParams{
                        salt,
                        iterations: cipher_kdf_iter,
                    }),
                }
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let kdf_algorithm_identifier = cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbkdf2(
                        cryptography_x509::common::PBKDF2Params {
                            salt,
                            iteration_count: cipher_kdf_iter,
                            key_length: None,
                            prf: Box::new(cryptography_x509::common::AlgorithmIdentifier {
                                oid: asn1::DefinedByMarker::marker(),
                                params:
                                    cryptography_x509::common::AlgorithmParameters::HmacWithSha256(
                                        Some(()),
                                    ),
                            }),
                        },
                    ),
                };
                let encryption_algorithm_identifier =
                    cryptography_x509::common::AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: cryptography_x509::common::AlgorithmParameters::Aes256Cbc(
                            iv[..16].try_into().unwrap(),
                        ),
                    };

                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbes2(
                        cryptography_x509::common::PBES2Params {
                            key_derivation_func: Box::new(kdf_algorithm_identifier),
                            encryption_scheme: Box::new(encryption_algorithm_identifier),
                        },
                    ),
                }
            }
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            EncryptionAlgorithm::PBESv2GostR3411_2012_512AndCtrAcpkm(cipher) => {
                let kdf_algorithm_identifier = cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbkdf2(
                        cryptography_x509::common::PBKDF2Params {
                            salt,
                            iteration_count: cipher_kdf_iter,
                            key_length: None,
                            prf: Box::new(cryptography_x509::common::AlgorithmIdentifier {
                                oid: asn1::DefinedByMarker::marker(),
                                params: cryptography_x509::common::AlgorithmParameters::HmacWithGostR3411_2012_512(
                                    Some(()),
                                ),
                            }),
                        },
                    ),
                };
                let params = gost_encryption_params(*cipher, iv);
                let encryption_algorithm_identifier =
                    cryptography_x509::common::AlgorithmIdentifier {
                        oid: asn1::DefinedByMarker::marker(),
                        params: match cipher {
                            cryptography_openssl::gost::CtrAcpkmCipher::Magma => {
                                cryptography_x509::common::AlgorithmParameters::MagmaCtrAcpkm(params)
                            }
                            cryptography_openssl::gost::CtrAcpkmCipher::Kuznyechik => {
                                cryptography_x509::common::AlgorithmParameters::KuznyechikCtrAcpkm(
                                    params,
                                )
                            }
                        },
                    };

                cryptography_x509::common::AlgorithmIdentifier {
                    oid: asn1::DefinedByMarker::marker(),
                    params: cryptography_x509::common::AlgorithmParameters::Pbes2(
                        cryptography_x509::common::PBES2Params {
                            key_derivation_func: Box::new(kdf_algorithm_identifier),
                            encryption_scheme: Box::new(encryption_algorithm_identifier),
                        },
                    ),
                }
            }
        }
    }

    pub fn encrypt(
        &self,
        password: &[u8],
        cipher_kdf_iter: u64,
        salt: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> KeySerializationResult<Vec<u8>> {
        match self {
            EncryptionAlgorithm::PBESHA1And3KeyTripleDESCBC => {
                let password = std::str::from_utf8(password)
                    .map_err(|_| KeySerializationError::PasswordMustBeUtf8)?;

                let key = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_ENCRYPTION_KEY_ID,
                    cipher_kdf_iter,
                    24,
                    openssl::hash::MessageDigest::sha1(),
                )?;
                let iv = cryptography_crypto::pkcs12::kdf(
                    password,
                    salt,
                    cryptography_crypto::pkcs12::KDF_IV_ID,
                    cipher_kdf_iter,
                    8,
                    openssl::hash::MessageDigest::sha1(),
                )?;

                Ok(openssl::symm::encrypt(
                    openssl::symm::Cipher::des_ede3_cbc(),
                    &key,
                    Some(&iv),
                    data,
                )?)
            }
            EncryptionAlgorithm::PBESv2SHA256AndAES256CBC => {
                let sha256 = openssl::hash::MessageDigest::sha256();

                let mut key = [0; 32];
                openssl::pkcs5::pbkdf2_hmac(
                    password,
                    salt,
                    cipher_kdf_iter.try_into().unwrap(),
                    sha256,
                    &mut key,
                )?;

                Ok(openssl::symm::encrypt(
                    openssl::symm::Cipher::aes_256_cbc(),
                    &key,
                    Some(iv),
                    data,
                )?)
            }
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            EncryptionAlgorithm::PBESv2GostR3411_2012_512AndCtrAcpkm(cipher) => {
                // RFC 9337 Section 5.1.1: DK = PBKDF2(P, S, c, 32), P is UTF-8.
                let mut key = [0; 32];
                cryptography_openssl::gost::pbkdf2_hmac_streebog512(
                    password,
                    salt,
                    cipher_kdf_iter.try_into().unwrap(),
                    &mut key,
                )?;
                let params = asn1::write_single(&gost_encryption_params(*cipher, iv))?;
                Ok(cryptography_openssl::gost::ctr_acpkm_encrypt(
                    *cipher, &key, &params, data,
                )?)
            }
        }
    }
}

/// Gost3412-15-Encryption-Parameters with `ukm` taken from the start of the
/// random `iv` buffer (which must be at least 16 octets long).
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
fn gost_encryption_params(
    cipher: cryptography_openssl::gost::CtrAcpkmCipher,
    iv: &[u8],
) -> cryptography_x509::common::Gost3412EncryptionParams<'_> {
    cryptography_x509::common::Gost3412EncryptionParams {
        ukm: &iv[..cipher.ukm_length()],
    }
}

/// RFC 9548 Section 7: the PFX MAC is HMAC_GOSTR3411_2012_512 keyed with the
/// last 32 octets of PBKDF2(P, S, c, 96).
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
pub fn gost_pfx_mac(
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    data: &[u8],
) -> KeySerializationResult<Vec<u8>> {
    let mut dk = [0; 96];
    cryptography_openssl::gost::pbkdf2_hmac_streebog512(
        password,
        salt,
        iterations.try_into().unwrap(),
        &mut dk,
    )?;
    Ok(cryptography_openssl::gost::hmac_streebog512(&dk[64..], data)?)
}

#[cfg(test)]
#[cfg(not(any(
    CRYPTOGRAPHY_IS_LIBRESSL,
    CRYPTOGRAPHY_IS_BORINGSSL,
    CRYPTOGRAPHY_IS_AWSLC
)))]
mod gost_tests {
    //! Test vectors from RFC 9548 Appendix A.
    use super::{gost_pfx_mac, EncryptionAlgorithm};
    use cryptography_openssl::gost::CtrAcpkmCipher;

    // "Пароль для PFX"
    const PASSWORD: &[u8] = "\u{41f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} \u{434}\u{43b}\u{44f} PFX".as_bytes();
    const A2_AUTH_SAFE: &str = concat!(
        "308204ad308202cc06092a864886f70d010701a08202bd048202b9308202b5308202b1060b2a864886f70d010c0a0103",
        "a082024a30820246060a2a864886f70d01091601a0820236048202323082022e308201dba0030201020204018cba8430",
        "0a06082a850307010103023038310d300b060355040a1304544b3236312730250603550403131e434120544b32363a20",
        "474f53542033342e31302d3132203235362d626974301e170d3031303130313030303030305a170d3439313233313030",
        "303030305a303b310d300b060355040a1304544b3236312a3028060355040313214f524947494e41544f523a20474f53",
        "542033342e31302d3132203531322d6269743081a0301706082a85030701010102300b06092a85030701020102010381",
        "8400048180b48bb75abc290e18655c62a14fb52d5f50844ecc1d1f6004487b4b5c9534696ab7bfab346e5516a9ab3cce",
        "f8adb52c3a5855f0cfb364aa6b5dd937e4ecfc9525bf9f6a085076718a45c81ff4921e3e2bbf72bf3eebf3ee16134126",
        "65ff13dda7bf275268eb11ae9de707d7f1b884cb6cf4760b9f16f024330d546b881d5ea0cea381873081843063060355",
        "1d23045c305a8014ac6c0e4c4466a24296e29f093b2566f3cba4532aa13ca43a3038310d300b060355040a1304544b32",
        "36312730250603550403131e434120544b32363a20474f53542033342e31302d3132203235362d6269748204018cba81",
        "301d0603551d0e041604147e065709980cad6b08a857ee7900583ac9d7a0a4300a06082a850307010103020341000a5e",
        "a9f1d01ba62f4793ede680cc88d16221d7b22b96b4a9fe607417b67332df17503d43c33dc9aeb9f17979df32f380e417",
        "5427d842c8380c5401acfc8704103154302306092a864886f70d01091531160414795574f9d4b6e4c20224286998673f",
        "f00a14c04d302d06092a864886f70d01091431201e1e0070003100320046007200690065006e0064006c0079004e0061",
        "006d0065308201d906092a864886f70d010701a08201ca048201c6308201c2308201be060b2a864886f70d010c0a0102",
        "a082015730820153305906092a864886f70d01050d304c302906092a864886f70d01050c301c0408a7f837b34cc2e82a",
        "02020800300c06082a850307010104020500301f06092a850307010105020230120410259add960df68f265b00b3498b",
        "2a09730481f50ccbc469c6db5913435529d724b5b2818acaa22a5d3a30c0ff61c49c1677e2e14e2cd85e52a88aa423e8",
        "1696d1d8606255855354af626e273381a71a1106330d7b5c4b440264ec692967ed78095b7492c2fd2a8fbab3d8c8a8b4",
        "3154543d13a16e2b050120d3dfc1c31f50e1d1d2f97fa81ae1a3d62eb59b6e05844453a838fca1e03a2d94f177ec040e",
        "c22123b1bcb2447ab71e06d689ac5046e0217aa1ce9f8415198f76fc716f27bbb74dc9d074b5a14defe58754472cd177",
        "4675ed37d89ff730b6de568364e896669954c8bad489309b1ebb67d51a693c398b14d32df5d27b28a80290e8bb666e67",
        "86a3c285bcb05f5df071f63154302306092a864886f70d01091531160414795574f9d4b6e4c20224286998673ff00a14",
        "c04d302d06092a864886f70d01091431201e1e0070003100320046007200690065006e0064006c0079004e0061006d00",
        "65",
    );
    const A2_MAC: &str = concat!(
        "09012b0e22867ee9488613121bb46dcbd33d98c8dd6815c429145653ac73cd06ebd10a1443939ce6c624648a279d542a",
        "43ac5c5d1aefe54165fdc171555087d5",
    );
    const A2_MAC_SALT: &str = concat!(
        "8544b4ef95a6eb24",
    );
    const A3_AUTH_SAFE: &str = concat!(
        "3082050e3082034106092a864886f70d010706a08203323082032e0201003082032706092a864886f70d010701305506",
        "092a864886f70d01050d3048302906092a864886f70d01050c301c040814b92546b12c068d02020800300c06082a8503",
        "07010104020500301b06092a8503070101050102300e040cf4793775a82d4b8f3e1bfc7e808202c1618fab1c4dfac4eb",
        "29baee45ff51e586bd71fe40b4ed5faea3277f57942df99999383f05d139d5043e55b9e1defd649aca6bea1dbe7b85a5",
        "8be9dd11e0961ba03a5ff1b6da1fd10075b662b5667fa7025b15be62bab34f887ff1140bffd85aba70f92e61cf2d5b18",
        "ac46a2d0ec1b8176b20d2c004552502d062ab0b36664ae5588df9f4624b9c2ccd527702d56af04b8fb78d5a4042b03f2",
        "da0987e12e969a74110ba5bb6a8aa62227c53c910d24d9f92b633527accd112b3a6c5b5834a300acdaadbefdeb8a863a",
        "78069a2f2e8057a963b1e926aa87479908ef6387848a826cd318695e1658ebd3d74fe641787bfa31285e061c17ab101d",
        "d43aad3d369f32334af2ba8a09aa7d4ed3c6bce36fa395bd760c1e83145143396e9bc7735789b55bd02ae16eedf3f51c",
        "c43591cf793a8a314f946680f7ef1931310e44784146f33a398dbf54d3716e0c567c662e3f1a528b762709920f98111e",
        "e6553f5efeca8f316eb06337f05f1847ad64e3f40da4a235414bfbd7860a7da510ce7b21186cc82efd4d1880fada9975",
        "f89237bee6b08b698332b9a4b8cf50154f6ffe444ff9cdae0470ee386114512361174f29efec37bf1a656ad1965c7f5f",
        "988b0f05d9367f7c249feaf0a2aac4ba28cc23f6c2032954fccd0330a840a3d8f7d5461265d8b87ec7d15980c932affc",
        "14f9fdeadba8fa80a96eabf7354c2964cffc2e2e31aa04c7b58c3ff9f446d3f3fa5da74d122208fd36237a72df5475e3",
        "00739526c55e0aefeddc4b0c60741d74d0a1ac593f21cd8f74840ec81e3f7a7a56d2aaca7a049bc9936e175588e33978",
        "988f3d2fc753401524872e39c905d99430fc93512b61db5d12c3edcffe33b92a5b9e6c021084683ae497b46b893feb5b",
        "71611744a336501822dea063a67ec3535f0cb6cad133da4375a765f264ff55f87df81f1d641655c6042eef494c3c419e",
        "c5b524607b850829f28bd27457dd92b5b233125c656b555e6e308201c506092a864886f70d010701a08201b6048201b2",
        "308201ae308201aa060b2a864886f70d010c0a0102a08201433082013f305506092a864886f70d01050d304830290609",
        "2a864886f70d01050c301c0408fd04424d0ed6dc2f02020800300c06082a850307010104020500301b06092a85030701",
        "01050101300e040cf0c52aa000000000000000000481e52a8fd988dd10df2b984c77411e630b3b7e864aff900daf6c14",
        "84fe6a9c38c06609fbea513127ec2ebe59d2f4f0a17d656e82f765ffd5c9810befafd0aee293a1e08097a65721732d1d",
        "1a4fcccc8b474550b9c0ada74f1c10e24293906f7184b173a03d7a761b6a5f4fbf75083d1bca44e44cc20486115cb9b5",
        "02b733f64eca56c4c9b8d32316bafb110bae4ebf340134903adb2ae74ce9172ae9ce754f182ace7488e9ca667135dbf0",
        "e3c6d9c6a4ed4550f1098013386ab3d29c070a55942c70fd2c86a32cc0761a104ac90c3aba322596d26cd13f9635d5ff",
        "013d852e2d4b1524b7f828fd3154302306092a864886f70d01091531160414795574f9d4b6e4c20224286998673ff00a",
        "14c04d302d06092a864886f70d01091431201e1e0070003100320046007200690065006e0064006c0079004e0061006d",
        "0065",
    );
    const A3_MAC: &str = concat!(
        "e9e1edb62665dd9ef474c40f7dc90bb342e27ca7105e3a9b0b9b675942ab771637b9cea5b5ba4ffb54e71f579af66ca9",
        "bc9ec2ceb36acf4fc8413a878066f388",
    );
    const A3_MAC_SALT: &str = concat!(
        "c62141f0e888c6d9",
    );
    const A3_KEY_ALGORITHM: &str = concat!(
        "305506092a864886f70d01050d3048302906092a864886f70d01050c301c0408fd04424d0ed6dc2f02020800300c0608",
        "2a850307010104020500301b06092a8503070101050101300e040cf0c52aa00000000000000000",
    );
    const A3_KEY_CIPHERTEXT: &str = concat!(
        "2a8fd988dd10df2b984c77411e630b3b7e864aff900daf6c1484fe6a9c38c06609fbea513127ec2ebe59d2f4f0a17d65",
        "6e82f765ffd5c9810befafd0aee293a1e08097a65721732d1d1a4fcccc8b474550b9c0ada74f1c10e24293906f7184b1",
        "73a03d7a761b6a5f4fbf75083d1bca44e44cc20486115cb9b502b733f64eca56c4c9b8d32316bafb110bae4ebf340134",
        "903adb2ae74ce9172ae9ce754f182ace7488e9ca667135dbf0e3c6d9c6a4ed4550f1098013386ab3d29c070a55942c70",
        "fd2c86a32cc0761a104ac90c3aba322596d26cd13f9635d5ff013d852e2d4b1524b7f828fd",
    );
    const A3_KEY_PLAINTEXT: &str = concat!(
        "3081e2020101301706082a85030701010102300b06092a85030701020102010440116925f9e6e5b075acf3a48d8112aa",
        "4b130e80685bbd1fee679fd659f74d1b56b1bd4c158697172310d9526cd0b8dcea24192c788edfe7f2635f24c5445d5a",
        "f981818101b48bb75abc290e18655c62a14fb52d5f50844ecc1d1f6004487b4b5c9534696ab7bfab346e5516a9ab3cce",
        "f8adb52c3a5855f0cfb364aa6b5dd937e4ecfc9525bf9f6a085076718a45c81ff4921e3e2bbf72bf3eebf3ee16134126",
        "65ff13dda7bf275268eb11ae9de707d7f1b884cb6cf4760b9f16f024330d546b881d5ea0ce",
    );

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Loads the GOST provider once per process: concurrent loads from
    /// parallel tests may fail.
    fn gost_provider() -> Option<&'static openssl::provider::Provider> {
        static PROVIDER: std::sync::LazyLock<Option<openssl::provider::Provider>> =
            std::sync::LazyLock::new(|| {
                openssl::provider::Provider::try_load(None, "gostprov", true).ok()
            });
        if PROVIDER.is_none() {
            eprintln!("gostprov is not available, skipping GOST test");
        }
        PROVIDER.as_ref()
    }

    #[test]
    fn test_rfc9548_mac() {
        let Some(_provider) = gost_provider() else {
            return;
        };
        for (auth_safe, salt, mac) in [
            (A2_AUTH_SAFE, A2_MAC_SALT, A2_MAC),
            (A3_AUTH_SAFE, A3_MAC_SALT, A3_MAC),
        ] {
            assert_eq!(
                gost_pfx_mac(PASSWORD, &hex(salt), 2048, &hex(auth_safe))
                    .ok()
                    .unwrap(),
                hex(mac)
            );
        }
    }

    #[test]
    fn test_rfc9548_magma_key_bag() {
        let Some(_provider) = gost_provider() else {
            return;
        };
        let algorithm = EncryptionAlgorithm::PBESv2GostR3411_2012_512AndCtrAcpkm(CtrAcpkmCipher::Magma);
        let salt = hex("FD04424D0ED6DC2F");
        // ukm (12 octets) followed by unused padding of the 16-octet IV buffer.
        let iv = hex("F0C52AA0000000000000000000000000");

        let encoded = asn1::write_single(&algorithm.algorithm_identifier(2048, &salt, &iv)).unwrap();
        assert_eq!(encoded, hex(A3_KEY_ALGORITHM));

        let ciphertext = algorithm
            .encrypt(PASSWORD, 2048, &salt, &iv, &hex(A3_KEY_PLAINTEXT))
            .ok()
            .unwrap();
        assert_eq!(ciphertext, hex(A3_KEY_CIPHERTEXT));
    }
}
