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

//! Module that provides access to a device specific key for this application and serialize the
//! necessary information to derive the same key to a cose-encrypt0 type header

use ciborium::Value;
use coset::{AsCborValue, CborSerializable, Header, ProtectedHeader};
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::DeviceKeys;
use hwcryptohalplatform::{AesImpl, DeviceKeysImpl, HmacImpl, RngImpl};
use kmr_common::{
    crypto::{self, Aes, Hkdf, Rng},
    FallibleAllocExt,
};

/// Size of the base encryption key used by the service to derive other versioned context encryption
/// keys
const SERVICE_KEK_LENGTH: usize = 32;

/// Size of the random context used to derive a versioned context specific encryption key
pub(crate) const KEY_DERIVATION_CTX_LENGTH: usize = 32;

/// Nonce value of all zeroes used in AES-GCM key encryption.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

const KEY_DERIVATION_CTX_COSE_LABEL: i64 = -65539;
const KEY_DERIVATION_VERSION_COSE_LABEL: i64 = -65540;
const WRAPPED_CONTENT_TYPE_COSE_LABEL: i64 = -65541;

// `EncryptionHeaderKey` defines if we derive a device key bound to HwCrypto service or if we use a
// provided key for that. This key will then be used to encrypt some content.
pub(crate) enum EncryptionHeaderKey<'a> {
    // `KeyGenerationContext` will be used to derive a key from a key bounded to HwCrypto service
    KeyGenerationContext(&'a [u8]),
    // `ProvidedHkdfKey` will be directly fed to the hkdf algorithm.
    ProvidedHkdfKey(Vec<u8>),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum EncryptedContent {
    ClientPolicy = 1,
    WrappedKeyMaterial = 2,
    KeyMaterial = 3,
}

impl TryFrom<u64> for EncryptedContent {
    type Error = HwCryptoError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == EncryptedContent::ClientPolicy as u64 => Ok(EncryptedContent::ClientPolicy),
            x if x == EncryptedContent::WrappedKeyMaterial as u64 => {
                Ok(EncryptedContent::WrappedKeyMaterial)
            }
            x if x == EncryptedContent::KeyMaterial as u64 => Ok(EncryptedContent::KeyMaterial),
            _ => Err(hwcrypto_err!(
                SERIALIZATION_ERROR,
                "invalid value for EncryptedContent: {}",
                value
            )),
        }
    }
}

impl TryFrom<ciborium::value::Integer> for EncryptedContent {
    type Error = HwCryptoError;

    fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
        let value: u64 = value.try_into().map_err(|_| {
            hwcrypto_err!(SERIALIZATION_ERROR, "couldn't convert CBOR integer into u64")
        })?;
        value.try_into().map_err(|_| {
            hwcrypto_err!(
                SERIALIZATION_ERROR,
                "Error converting encrypted content type from ciborium value"
            )
        })
    }
}

impl From<EncryptedContent> for ciborium::value::Integer {
    fn from(value: EncryptedContent) -> Self {
        (value as u64).into()
    }
}

// Header used to derive a different key per each encrypted context. Encryption of the context is
// similar to what KeyMint does to wrap keys.
pub(crate) struct EncryptionHeader {
    key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
    header_version: Vec<u8>,
    wrapped_content_type: EncryptedContent,
}

impl EncryptionHeader {
    fn new(
        key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
        header_version: Vec<u8>,
        wrapped_content_type: EncryptedContent,
    ) -> Self {
        Self { key_derivation_context, header_version, wrapped_content_type }
    }

    pub(crate) fn generate(wrapped_content_type: EncryptedContent) -> Result<Self, HwCryptoError> {
        let header_version = get_service_current_version()?;
        Ok(Self::generate_with_version(header_version, wrapped_content_type))
    }

    pub(crate) fn generate_with_version(
        header_version: Vec<u8>,
        wrapped_content_type: EncryptedContent,
    ) -> Self {
        let key_derivation_context = get_new_key_derivation_context();
        Self::new(key_derivation_context, header_version, wrapped_content_type)
    }

    // Function used to generate different device bound encryption keys tied to the HWCrypto service
    // to be used for different purposes, which include VersionContext encryption and key wrapping.
    pub(crate) fn derive_raw_service_encryption_key(
        &self,
        encryption_key: EncryptionHeaderKey,
    ) -> Result<Vec<u8>, HwCryptoError> {
        let encryption_key = match encryption_key {
            EncryptionHeaderKey::KeyGenerationContext(key_context) => {
                get_encryption_key(self.header_version.as_slice(), key_context)?
            }
            EncryptionHeaderKey::ProvidedHkdfKey(key) => {
                if key.len() != SERVICE_KEK_LENGTH {
                    return Err(hwcrypto_err!(
                        INVALID_KEY,
                        "We only support hkdf keys of length {}",
                        SERVICE_KEK_LENGTH
                    ));
                }
                key
            }
        };
        derive_key_hkdf(&encryption_key, &self.key_derivation_context[..])
    }

    pub(crate) fn derive_service_encryption_key(
        &self,
        encryption_key: EncryptionHeaderKey,
    ) -> Result<crypto::aes::Key, HwCryptoError> {
        let raw_key = self.derive_raw_service_encryption_key(encryption_key)?;
        let key_material = crypto::aes::Key::Aes256(
            raw_key
                .try_into()
                .expect("should not fail, call with SERVICE_KEK_LENGTH returns 32 bytes"),
        );
        Ok(key_material)
    }

    /// Encrypt CBOR serializable data using a device key derived using `key_context`
    pub(crate) fn encrypt_content_service_encryption_key<T: AsCborValue>(
        &self,
        key_context: EncryptionHeaderKey,
        content: T,
    ) -> Result<Vec<u8>, HwCryptoError> {
        let kek = self.derive_service_encryption_key(key_context)?;
        let cose_encrypt = coset::CoseEncrypt0Builder::new()
            .protected(self.try_into()?)
            .try_create_ciphertext::<_, HwCryptoError>(
                &content.to_cbor_value()?.to_vec()?,
                &[],
                move |pt, aad| {
                    let mut op = AesImpl.begin_aead(
                        kek.into(),
                        crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
                        crypto::SymmetricOperation::Encrypt,
                    )?;
                    op.update_aad(aad)?;
                    let mut ct = op.update(pt)?;
                    ct.try_extend_from_slice(&op.finish()?)?;
                    Ok(ct)
                },
            )?
            .build();
        Ok(cose_encrypt.to_vec()?)
    }

    /// Decrypt CBOR serializable data using a device key derived using `key_context`. Data needs to
    /// include an `EncryptionHeader` on the COSE protected header.
    pub(crate) fn decrypt_content_service_encryption_key(
        encrypted_context: &[u8],
        key_context: EncryptionHeaderKey,
        wrapped_content_type: EncryptedContent,
    ) -> Result<(Self, Vec<u8>), HwCryptoError> {
        let context: coset::CoseEncrypt0 = coset::CborSerializable::from_slice(encrypted_context)?;
        let encryption_header: EncryptionHeader = (&context.protected).try_into()?;
        let kek = encryption_header.derive_service_encryption_key(key_context)?;

        if encryption_header.wrapped_content_type != wrapped_content_type {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "provided content has wrong content. Expected {:?}",
                wrapped_content_type
            ));
        }

        let mut op = AesImpl.begin_aead(
            kek.into(),
            crypto::aes::GcmMode::GcmTag16 { nonce: ZERO_NONCE },
            crypto::SymmetricOperation::Decrypt,
        )?;
        let extended_aad = coset::enc_structure_data(
            coset::EncryptionContext::CoseEncrypt0,
            context.protected.clone(),
            &[], // no external AAD
        );
        op.update_aad(&extended_aad)?;
        let mut pt_data = op.update(&context.ciphertext.unwrap_or_default())?;
        pt_data.try_extend_from_slice(
            &op.finish()
                .map_err(|e| hwcrypto_err!(INVALID_KEY, "failed to decrypt context: {:?}", e))?,
        )?;
        Ok((encryption_header, pt_data))
    }
}

// Implementing conversion functions to easily convert from/to COSE headers and  `EncryptionHeader`s
impl TryFrom<&ProtectedHeader> for EncryptionHeader {
    type Error = HwCryptoError;

    fn try_from(value: &ProtectedHeader) -> Result<EncryptionHeader, Self::Error> {
        let cose_header_rest = &value.header.rest;
        if cose_header_rest.len() != 3 {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "header length was {} instead of 3",
                cose_header_rest.len()
            ));
        }
        let mut key_derivation_context = None;
        let mut header_version = None;
        let mut wrapped_content_type: Option<EncryptedContent> = None;
        for element in cose_header_rest {
            let label: i64 = element
                .0
                .clone()
                .to_cbor_value()?
                .into_integer()
                .map_err(|_| {
                    hwcrypto_err!(
                        SERIALIZATION_ERROR,
                        "unsupported string header label {:?}",
                        element.0
                    )
                })?
                .try_into()
                .map_err(|_| {
                    hwcrypto_err!(
                        SERIALIZATION_ERROR,
                        "error converting cose label {:?}",
                        element.0
                    )
                })?;
            match label {
                KEY_DERIVATION_CTX_COSE_LABEL => {
                    key_derivation_context =
                        Some(parse_cborium_bytes_to_fixed_array(&element.1, "KEK context")?);
                }
                KEY_DERIVATION_VERSION_COSE_LABEL => {
                    let value_bytes = element.1.as_bytes().ok_or(hwcrypto_err!(
                        SERIALIZATION_ERROR,
                        "wrong type when trying to parse bytes for header version"
                    ))?;
                    header_version = Some(value_bytes);
                }
                WRAPPED_CONTENT_TYPE_COSE_LABEL => {
                    wrapped_content_type = Some(
                        element
                            .1
                            .as_integer()
                            .ok_or(hwcrypto_err!(
                                BAD_PARAMETER,
                                "wrapped_content_type was not an integer"
                            ))?
                            .try_into()?,
                    );
                }
                _ => return Err(hwcrypto_err!(BAD_PARAMETER, "unknown label {}", label)),
            }
        }
        let key_derivation_context = key_derivation_context
            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse key context"))?;
        let header_version_ref = header_version
            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse header version"))?;
        let wrapped_content_type = wrapped_content_type
            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse content type"))?;
        let mut header_version = Vec::<u8>::new();
        header_version.try_extend_from_slice(header_version_ref.as_slice())?;
        Ok(Self::new(key_derivation_context, header_version, wrapped_content_type))
    }
}

impl TryFrom<&EncryptionHeader> for Header {
    type Error = HwCryptoError;

    fn try_from(value: &EncryptionHeader) -> Result<Header, Self::Error> {
        let mut key_derivation_context = Vec::<u8>::new();
        key_derivation_context.try_extend_from_slice(&value.key_derivation_context[..])?;
        let mut header_version = Vec::<u8>::new();
        header_version.try_extend_from_slice(value.header_version.as_slice())?;
        let cose_header = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .value(KEY_DERIVATION_CTX_COSE_LABEL, Value::Bytes(key_derivation_context))
            .value(KEY_DERIVATION_VERSION_COSE_LABEL, Value::Bytes(header_version))
            .value(
                WRAPPED_CONTENT_TYPE_COSE_LABEL,
                Value::Integer(value.wrapped_content_type.into()),
            )
            .build();
        Ok(cose_header)
    }
}

/// Get the base versioned encryption key used by the service to derive other versioned context
/// encryption keys
fn get_encryption_key(header_version: &[u8], key_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
    DeviceKeysImpl.derive_caller_unique_key(key_context, header_version, SERVICE_KEK_LENGTH)
}

// Create an AES key compatible with the current crypto backend used
fn derive_key_hkdf(
    derivation_key: &[u8],
    derivation_context: &[u8],
) -> Result<Vec<u8>, HwCryptoError> {
    Ok(HmacImpl.hkdf(&[], derivation_key, derivation_context, SERVICE_KEK_LENGTH)?)
}

fn get_new_key_derivation_context() -> [u8; KEY_DERIVATION_CTX_LENGTH] {
    let mut key_ctx = [0u8; KEY_DERIVATION_CTX_LENGTH];
    RngImpl.fill_bytes(&mut key_ctx[..]);
    key_ctx
}

pub(crate) fn parse_cborium_bytes_to_fixed_array(
    value: &ciborium::value::Value,
    name: &str,
) -> Result<[u8; KEY_DERIVATION_CTX_LENGTH], HwCryptoError> {
    let value_bytes = value.as_bytes().ok_or(hwcrypto_err!(
        SERIALIZATION_ERROR,
        "wrong type when trying to parse bytes for {}",
        name,
    ))?;
    if value_bytes.len() != KEY_DERIVATION_CTX_LENGTH {
        return Err(hwcrypto_err!(
            SERIALIZATION_ERROR,
            "wrong number of bytes for {}, found {}, expected {}",
            name,
            value_bytes.len(),
            KEY_DERIVATION_CTX_LENGTH
        ));
    }
    Ok(value_bytes.as_slice().try_into().expect("Shouldn't fail, we checked size already"))
}

pub(crate) fn get_service_current_version() -> Result<Vec<u8>, HwCryptoError> {
    DeviceKeysImpl.get_caller_current_security_version()
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{expect, expect_eq};

    #[test]
    fn header_encryption_decryption() {
        let header = EncryptionHeader::generate(EncryptedContent::ClientPolicy);
        expect!(header.is_ok(), "couldn't generate header");
        let header = header.unwrap();
        let encrypted_content = header.encrypt_content_service_encryption_key(
            EncryptionHeaderKey::KeyGenerationContext(b"fake_context"),
            Value::Bytes(b"test_data".to_vec()),
        );
        expect!(encrypted_content.is_ok(), "couldn't generate header");
        let encrypted_content = encrypted_content.unwrap();
        let decrypted_data = EncryptionHeader::decrypt_content_service_encryption_key(
            &encrypted_content[..],
            EncryptionHeaderKey::KeyGenerationContext(b"fake_context"),
            EncryptedContent::ClientPolicy,
        );
        expect!(decrypted_data.is_ok(), "couldn't generate header");
        let (decrypted_header, decrypted_content) = decrypted_data.unwrap();
        let decrypted_content =
            Value::from_slice(&decrypted_content[..]).unwrap().into_bytes().unwrap();
        expect_eq!(
            header.key_derivation_context,
            decrypted_header.key_derivation_context,
            "header key derivation context do not match"
        );
        expect_eq!(
            header.header_version,
            decrypted_header.header_version,
            "header version do not match"
        );
        expect_eq!(decrypted_content, b"test_data", "decrypted data do not match");
    }
}
