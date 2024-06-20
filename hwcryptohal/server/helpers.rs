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
    ExplicitKeyMaterial::ExplicitKeyMaterial, KeyType::KeyType, KeyUse::KeyUse,
    SymmetricCryptoParameters::SymmetricCryptoParameters, SymmetricOperation::SymmetricOperation,
};
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use kmr_common::crypto::{
    self, aes, KeyMaterial, OpaqueOr, SymmetricOperation as KmSymmetricOperation,
};

use crate::opaque_key::OpaqueKey;

/// Macro to create enums that can easily be used as cose labels for serialization
/// It expects the macro definition to have the following form:
///
/// cose_enum_gen! {
///     enum CoseEnumName {
///         CoseEnumField1 = value1,
///         CoseEnumField2 = value2,
///     }
/// }
#[macro_export]
macro_rules! cose_enum_gen {
    (enum $name:ident {$($field:ident = $field_val:literal),+ $(,)*}) => {
        enum $name {
            $($field = $field_val),+
        }

        impl TryFrom<i64> for $name {
            type Error = hwcryptohal_common::err::HwCryptoError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
                    _ => Err(hwcrypto_err!(SERIALIZATION_ERROR, "unsupported COSE enum label val {}", value)),
                }
            }
        }

        impl TryFrom<ciborium::value::Integer> for $name {
            type Error = coset::CoseError;

            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
                let value: i64 = value.try_into()?;
                Ok(value.try_into().map_err(|_| coset::CoseError::EncodeFailed)?)
            }
        }
    }
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
