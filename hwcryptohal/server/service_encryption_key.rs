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
use hwkey::{Hwkey, OsRollbackVersion, RollbackVersionSource};
use kmr_common::{
    crypto::{self, Aes, Hkdf, Rng},
    FallibleAllocExt,
};

use crate::crypto_provider;

/// Size of the base encryption key used by the service to derive other versioned context encryption
/// keys
const SERVICE_KEK_LENGTH: usize = 32;

/// Size of the random context used to derive a versioned context specific encryption key
pub(crate) const KEY_DERIVATION_CTX_LENGTH: usize = 32;

/// Nonce value of all zeroes used in AES-GCM key encryption.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

const KEY_DERIVATION_CTX_COSE_LABEL: i64 = -65539;
const KEY_DERIVATION_VERSION_COSE_LABEL: i64 = -65540;

// Header used to derive a different key per each encrypted context. Encryption of the context is
// similar to what KeyMint does to wrap keys.
pub(crate) struct EncryptionHeader {
    key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH],
    header_version: u32,
}

impl EncryptionHeader {
    fn new(key_derivation_context: [u8; KEY_DERIVATION_CTX_LENGTH], header_version: u32) -> Self {
        Self { key_derivation_context, header_version }
    }

    pub(crate) fn generate() -> Result<Self, HwCryptoError> {
        let header_version = get_service_current_version()?;
        Ok(Self::generate_with_version(header_version))
    }

    pub(crate) fn generate_with_version(header_version: u32) -> Self {
        let key_derivation_context = get_new_key_derivation_context();
        Self::new(key_derivation_context, header_version)
    }

    // Function used to generate different device bound encryption keys tied to the HWCrypto service
    // to be used for different purposes, which include VersionContext encryption and key wrapping.
    fn derive_service_encryption_key(
        &self,
        key_context: &[u8],
    ) -> Result<crypto::aes::Key, HwCryptoError> {
        let encryption_key = get_encryption_key(self.header_version, key_context)?;
        derive_key_hkdf(&encryption_key, &self.key_derivation_context[..])
    }

    /// Encrypt CBOR serializable data using a device key derived using `key_context`
    pub(crate) fn encrypt_content_service_encryption_key<T: AsCborValue>(
        &self,
        key_context: &[u8],
        content: T,
    ) -> Result<Vec<u8>, HwCryptoError> {
        let kek = self.derive_service_encryption_key(key_context)?;
        let aes = crypto_provider::AesImpl;
        let cose_encrypt = coset::CoseEncrypt0Builder::new()
            .protected(self.try_into()?)
            .try_create_ciphertext::<_, HwCryptoError>(
                &content.to_cbor_value()?.to_vec()?,
                &[],
                move |pt, aad| {
                    let mut op = aes.begin_aead(
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
        key_context: &[u8],
    ) -> Result<(Self, Vec<u8>), HwCryptoError> {
        let context: coset::CoseEncrypt0 = coset::CborSerializable::from_slice(encrypted_context)?;
        let encryption_header: EncryptionHeader = (&context.protected).try_into()?;
        let kek = encryption_header.derive_service_encryption_key(key_context)?;

        let aes = crypto_provider::AesImpl;
        let mut op = aes.begin_aead(
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
        if cose_header_rest.len() != 2 {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "header length was {} instead of 2",
                cose_header_rest.len()
            ));
        }
        let mut key_derivation_context = None;
        let mut header_version = None;
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
                    header_version = Some(parse_cborium_u32(&element.1, "header version")?);
                }
                _ => return Err(hwcrypto_err!(BAD_PARAMETER, "unknown label {}", label)),
            }
        }
        let key_derivation_context = key_derivation_context
            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse key context"))?;
        let header_version = header_version
            .ok_or(hwcrypto_err!(SERIALIZATION_ERROR, "couldn't parse header version"))?;
        Ok(Self::new(key_derivation_context, header_version))
    }
}

impl TryFrom<&EncryptionHeader> for Header {
    type Error = HwCryptoError;

    fn try_from(value: &EncryptionHeader) -> Result<Header, Self::Error> {
        let mut key_derivation_context = Vec::<u8>::new();
        key_derivation_context.try_extend_from_slice(&value.key_derivation_context[..])?;
        let cose_header = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .value(KEY_DERIVATION_CTX_COSE_LABEL, Value::Bytes(key_derivation_context))
            .value(KEY_DERIVATION_VERSION_COSE_LABEL, Value::Integer(value.header_version.into()))
            .build();
        Ok(cose_header)
    }
}

/// Get the base versioned encryption key used by the service to derive other versioned context
/// encryption keys
fn get_encryption_key(header_version: u32, key_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
    let mut key = Vec::<u8>::new();
    key.try_reserve(SERVICE_KEK_LENGTH)?;
    key.resize(SERVICE_KEK_LENGTH, 0);
    let hwkey_session = Hwkey::open()
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not connect to hwkey service {:?}", e))?;
    hwkey_session
        .derive_key_req()
        .unique_key()
        .rollback_version_source(RollbackVersionSource::CommittedVersion)
        .os_rollback_version(OsRollbackVersion::Version(header_version))
        .derive(key_context, &mut key[..])
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could derive key {:?}", e))?;
    Ok(key)
}

// Create an AES key compatible with the current crypto backend used
fn derive_key_hkdf(
    derivation_key: &[u8],
    derivation_context: &[u8],
) -> Result<crypto::aes::Key, HwCryptoError> {
    let kdf = crypto_provider::HmacImpl;
    let raw_key = kdf.hkdf(&[], &derivation_key, &derivation_context, SERVICE_KEK_LENGTH)?;
    let key_material = crypto::aes::Key::Aes256(
        raw_key.try_into().expect("should not fail, call with SERVICE_KEK_LENGTH returns 32 bytes"),
    );
    Ok(key_material)
}

fn get_new_key_derivation_context() -> [u8; KEY_DERIVATION_CTX_LENGTH] {
    let mut rng = crypto_provider::RngImpl::default();
    let mut key_ctx = [0u8; KEY_DERIVATION_CTX_LENGTH];
    rng.fill_bytes(&mut key_ctx[..]);
    key_ctx
}

fn parse_cborium_bytes_to_fixed_array(
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

fn parse_cborium_u32(
    value: &ciborium::value::Value,
    value_name: &str,
) -> Result<u32, HwCryptoError> {
    let integer_value = value.as_integer().ok_or(hwcrypto_err!(
        SERIALIZATION_ERROR,
        "wrong type when trying to parse a u32 from {}",
        value_name
    ))?;
    integer_value.try_into().map_err(|e| {
        hwcrypto_err!(SERIALIZATION_ERROR, "Error converting {} to u32: {}", value_name, e)
    })
}

pub(crate) fn get_service_current_version() -> Result<u32, HwCryptoError> {
    let hwkey_session = Hwkey::open()?;

    match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
        Ok(OsRollbackVersion::Version(n)) => Ok(n),
        _ => Err(hwcrypto_err!(GENERIC_ERROR, "error communicating with HwKey service")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{expect, expect_eq};

    #[test]
    fn header_encryption_decryption() {
        let header = EncryptionHeader::generate();
        expect!(header.is_ok(), "couldn't generate header");
        let header = header.unwrap();
        let encrypted_content = header.encrypt_content_service_encryption_key(
            b"fake_context",
            Value::Bytes(b"test_data".to_vec()),
        );
        expect!(encrypted_content.is_ok(), "couldn't generate header");
        let encrypted_content = encrypted_content.unwrap();
        let decrypted_data = EncryptionHeader::decrypt_content_service_encryption_key(
            &encrypted_content[..],
            b"fake_context",
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
