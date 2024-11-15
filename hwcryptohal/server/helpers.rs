/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Helper functions that includes data transformation for AIDL types.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    AesCipherMode::AesCipherMode, AesKey::AesKey, CipherModeParameters::CipherModeParameters,
    ExplicitKeyMaterial::ExplicitKeyMaterial, HmacKey::HmacKey, KeyType::KeyType, KeyUse::KeyUse,
    SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
};
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use kmr_common::crypto::{
    self, aes, hmac, KeyMaterial, OpaqueOr, SymmetricOperation as KmSymmetricOperation,
};
use kmr_wire::keymint;

use crate::opaque_key::OpaqueKey;

fn aidl_hmac_explicit_key_to_rust_key_material(
    hmac_key_material: &[u8],
) -> Result<KeyMaterial, HwCryptoError> {
    let mut ekm = Vec::new();
    ekm.try_reserve(hmac_key_material.len())?;
    ekm.extend_from_slice(hmac_key_material);
    Ok(KeyMaterial::Hmac(OpaqueOr::Explicit(hmac::Key(ekm))))
}

pub(crate) fn aidl_explicit_key_to_rust_key_material(
    key_material: &ExplicitKeyMaterial,
) -> Result<KeyMaterial, HwCryptoError> {
    match key_material {
        ExplicitKeyMaterial::Aes(AesKey::Aes128(km)) => {
            Ok(KeyMaterial::Aes(OpaqueOr::Explicit(aes::Key::Aes128(*km))))
        }
        ExplicitKeyMaterial::Aes(AesKey::Aes256(km)) => {
            Ok(KeyMaterial::Aes(OpaqueOr::Explicit(aes::Key::Aes256(*km))))
        }
        ExplicitKeyMaterial::Hmac(HmacKey::Sha256(km)) => {
            aidl_hmac_explicit_key_to_rust_key_material(km)
        }
        ExplicitKeyMaterial::Hmac(HmacKey::Sha512(km)) => {
            aidl_hmac_explicit_key_to_rust_key_material(km)
        }
    }
}

pub(crate) fn symmetric_encryption_block_based(
    parameters: &SymmetricCryptoParameters,
) -> Result<bool, HwCryptoError> {
    match parameters {
        SymmetricCryptoParameters::Aes(aes_params) => match aes_params {
            AesCipherMode::Ctr(_) => Ok(false),
            _ => Ok(true),
        },
    }
}

pub(crate) fn aidl_to_rust_digest(key_type: &KeyType) -> Result<keymint::Digest, HwCryptoError> {
    match *key_type {
        KeyType::HMAC_SHA256 => Ok(keymint::Digest::Sha256),
        KeyType::HMAC_SHA512 => Ok(keymint::Digest::Sha512),
        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported key type to get digest: {:?}", key_type)),
    }
}

pub(crate) fn aidl_to_rust_aes_cipher_params(
    params: &SymmetricCryptoParameters,
    opaque_key: &OpaqueKey,
) -> Result<crypto::aes::CipherMode, HwCryptoError> {
    let SymmetricCryptoParameters::Aes(aes_params) = params;
    match aes_params {
        AesCipherMode::Cbc(CipherModeParameters { nonce }) => {
            // TODO: change clone() into something like a try_clone()
            let nonce = nonce.clone();
            let nonce_len = nonce.len();
            match opaque_key.get_key_type() {
                KeyType::AES_128_CBC_NO_PADDING | KeyType::AES_256_CBC_NO_PADDING => {
                    Ok(crypto::aes::CipherMode::CbcNoPadding {
                        nonce: nonce.try_into().map_err(|_| {
                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
                        })?,
                    })
                }
                KeyType::AES_128_CBC_PKCS7_PADDING | KeyType::AES_256_CBC_PKCS7_PADDING => {
                    Ok(crypto::aes::CipherMode::CbcPkcs7Padding {
                        nonce: nonce.try_into().map_err(|_| {
                            hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len)
                        })?,
                    })
                }
                _ => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "unsupporte key type for CBC: {:?}",
                    opaque_key.get_key_type()
                )),
            }
        }
        AesCipherMode::Ctr(CipherModeParameters { nonce }) => {
            let nonce_len = nonce.len();
            // TODO: change clone() into something like a try_clone()
            Ok(crypto::aes::CipherMode::Ctr {
                nonce: nonce
                    .clone()
                    .try_into()
                    .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "bad nonce length: {}", nonce_len))?,
            })
        }
    }
}

pub(crate) fn aidl_to_rust_symmetric_direction(
    dir: SymmetricOperation,
) -> Result<KmSymmetricOperation, HwCryptoError> {
    match dir {
        SymmetricOperation::ENCRYPT => Ok(KmSymmetricOperation::Encrypt),
        SymmetricOperation::DECRYPT => Ok(KmSymmetricOperation::Decrypt),
        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported symmetric operation: {:?}", dir)),
    }
}

pub(crate) fn direction_to_key_usage(
    operation: &SymmetricOperation,
) -> Result<KeyUse, HwCryptoError> {
    match *operation {
        SymmetricOperation::ENCRYPT => Ok(KeyUse::ENCRYPT),
        SymmetricOperation::DECRYPT => Ok(KeyUse::DECRYPT),
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "invalid operation type: {:?}", operation)),
    }
}
