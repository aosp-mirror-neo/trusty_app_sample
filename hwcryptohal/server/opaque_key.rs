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

//! Implementation of the `IOpaqueKey` AIDL interface. It is used as a handle to key material

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IOpaqueKey::{BnOpaqueKey, IOpaqueKey},
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see::binder;
use core::fmt;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use kmr_common::{
    crypto::{self, Aes, CurveType, Hmac, KeyMaterial, OpaqueOr, Rng},
    FallibleAllocExt,
};
use kmr_wire::keymint::EcCurve;
use std::sync::OnceLock;

use crate::crypto_provider;

/// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
const UNIQUE_VALUE_SIZEOF: usize = 32;

/// Struct to wrap boot unique counter. It is used to tag objects to the current boot.
#[derive(Clone)]
struct BootUniqueValue([u8; UNIQUE_VALUE_SIZEOF]);

impl fmt::Debug for BootUniqueValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[BootUniqueValue size: {}; data redacted]", UNIQUE_VALUE_SIZEOF)
    }
}

impl PartialEq for BootUniqueValue {
    fn eq(&self, other: &Self) -> bool {
        openssl::memcmp::eq(&self.0, &other.0)
    }
}

impl Eq for BootUniqueValue {}

impl BootUniqueValue {
    fn new() -> Result<BootUniqueValue, HwCryptoError> {
        get_boot_unique_value()
    }
}

// Boot unique value is lazily initialized on the first call to retrieve it
static BOOT_UNIQUE_VALUE: OnceLock<BootUniqueValue> = OnceLock::new();

/// Retrieves boot unique value used to check if the key material was created on this boot. It
/// lazily initializes it.
fn get_boot_unique_value() -> Result<BootUniqueValue, HwCryptoError> {
    // The function returns a `Result` even if it is currently infallible to allow replacing its
    // current implementation with one that can fail when trying to retrieve a random number.
    // If the RNG changes to a fallible one we could use `get_or_try_init`.
    let boot_unique_value = BOOT_UNIQUE_VALUE.get_or_init(|| {
        let mut rng = crypto_provider::RngImpl::default();
        let mut new_boot_unique_value = BootUniqueValue([0u8; UNIQUE_VALUE_SIZEOF]);
        rng.fill_bytes(&mut new_boot_unique_value.0[..]);
        new_boot_unique_value
    });
    Ok(boot_unique_value.clone())
}

/// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
/// the key.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct KeyHeader {
    boot_unique_value: BootUniqueValue,
    expiration_time: Option<u64>,
    key_lifetime: KeyLifetime,
    key_permissions: Vec<KeyPermissions>,
    key_usage: KeyUse,
    key_type: KeyType,
    management_key: bool,
}

impl KeyHeader {
    fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_extend_from_slice(&policy.keyPermissions[..])?;
        Ok(Self {
            boot_unique_value: BootUniqueValue::new()?,
            expiration_time: None,
            key_lifetime: policy.keyLifetime,
            key_permissions,
            key_usage: policy.usage,
            key_type: policy.keyType,
            management_key: policy.keyManagementKey,
        })
    }

    fn get_policy(&self) -> Result<KeyPolicy, HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_extend_from_slice(&self.key_permissions[..])?;
        Ok(KeyPolicy {
            usage: self.key_usage,
            keyLifetime: self.key_lifetime,
            keyPermissions: key_permissions,
            keyType: self.key_type,
            keyManagementKey: self.management_key,
        })
    }
}

/// `IOpaqueKey` implementation.
#[allow(dead_code)]
pub struct OpaqueKey {
    pub(crate) key_header: KeyHeader,
    pub(crate) key_material: KeyMaterial,
}

impl OpaqueKey {
    pub(crate) fn new_binder(
        policy: &KeyPolicy,
        key_material: KeyMaterial,
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_header = KeyHeader::new(policy)?;
        check_key_material_with_policy(&key_material, policy)?;
        let opaque_key = OpaqueKey { key_header, key_material };
        let opaque_keybinder =
            BnOpaqueKey::new_binder(opaque_key, binder::BinderFeatures::default());
        Ok(opaque_keybinder)
    }

    #[allow(unused)]
    pub(crate) fn generate_opaque_key(
        policy: &KeyPolicy,
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_material = generate_key_material(&policy.keyType)?;
        OpaqueKey::new_binder(policy, key_material)
    }
}

impl binder::Interface for OpaqueKey {}

impl IOpaqueKey for OpaqueKey {
    fn exportWrappedKey(
        &self,
        _wrapping_key: &binder::Strong<dyn IOpaqueKey>,
    ) -> binder::Result<Vec<u8>> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("export_wrapped_key has not been implemented yet"),
        ))
    }

    fn getKeyPolicy(&self) -> binder::Result<KeyPolicy> {
        Ok(self.key_header.get_policy()?)
    }

    fn getPublicKey(&self) -> binder::Result<Vec<u8>> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("get_public_key has not been implemented yet"),
        ))
    }
}

pub(crate) fn check_key_material_with_policy(
    key_material: &KeyMaterial,
    policy: &KeyPolicy,
) -> Result<(), HwCryptoError> {
    let key_type = &policy.keyType;
    // `KeyMaterial` doesn't fully describe the cryptographic algorithm as `KeyType` does, so we can
    //  only check if both of them are compatible, not provide a 1:1 mapping
    match key_material {
        KeyMaterial::Aes(aes_key) => match aes_key {
            OpaqueOr::Opaque(_) => Err(hwcrypto_err!(BAD_PARAMETER, "opaque aes key provided")),
            OpaqueOr::Explicit(aes_key) => match aes_key {
                crypto::aes::Key::Aes128(km) => match *key_type {
                    KeyType::AES_128_CBC_NO_PADDING
                    | KeyType::AES_128_CBC_PKCS7_PADDING
                    | KeyType::AES_128_CTR
                    | KeyType::AES_128_GCM
                    | KeyType::AES_128_CMAC => Ok(()),
                    _ => Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "type mismatch: key material {:?} key type: {:?}",
                        km,
                        key_type
                    )),
                },
                crypto::aes::Key::Aes192(_) => {
                    Err(hwcrypto_err!(BAD_PARAMETER, "AES keys of length 192 are not supported"))
                }
                crypto::aes::Key::Aes256(km) => match *key_type {
                    KeyType::AES_256_CBC_NO_PADDING
                    | KeyType::AES_256_CBC_PKCS7_PADDING
                    | KeyType::AES_256_CTR
                    | KeyType::AES_256_GCM
                    | KeyType::AES_256_CMAC => Ok(()),
                    _ => Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "type mismatch: key material {:?} key type: {:?}",
                        km,
                        key_type
                    )),
                },
            },
        },
        KeyMaterial::TripleDes(_) => {
            Err(hwcrypto_err!(BAD_PARAMETER, "TDES is not currently supported"))
        }
        KeyMaterial::Hmac(hmac_key) => match hmac_key {
            OpaqueOr::Opaque(_) => Err(hwcrypto_err!(BAD_PARAMETER, "opaque HMAC key provided")),
            OpaqueOr::Explicit(_) => match *key_type {
                KeyType::HMAC_SHA256 => Ok(()),
                KeyType::HMAC_SHA512 => Ok(()),
                _ => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "type mismatch for HMAC key key type: {:?}",
                    key_type
                )),
            },
        },
        KeyMaterial::Rsa(rsa_key) => match rsa_key {
            OpaqueOr::Opaque(_) => Err(hwcrypto_err!(BAD_PARAMETER, "opaque RSA key provided")),
            OpaqueOr::Explicit(rsa_key) => {
                let key_size = rsa_key.size();
                match (key_size, *key_type) {
                    (2048, KeyType::RSA2048_PSS_SHA256) => Ok(()),
                    (2048, KeyType::RSA2048_PKCS1_5_SHA256) => Ok(()),
                    _ => Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "type mismatch for RSA key length {} and type: {:?}",
                        key_size,
                        key_type
                    )),
                }
            }
        },
        KeyMaterial::Ec(curve, curve_type, _) => match (curve, *key_type) {
            (EcCurve::P256, KeyType::ECC_NIST_P256_SIGN_NO_PADDING) => Ok(()),
            (EcCurve::P256, KeyType::ECC_NIST_P256_SIGN_SHA256) => Ok(()),
            (EcCurve::P521, KeyType::ECC_NIST_P521_SIGN_NO_PADDING) => Ok(()),
            (EcCurve::P521, KeyType::ECC_NIST_P521_SIGN_SHA512) => Ok(()),
            (EcCurve::Curve25519, _) => match (curve_type, *key_type) {
                (CurveType::EdDsa, KeyType::ECC_ED25519_SIGN) => Ok(()),
                _ => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "type mismatch for Ec Key curve {:?} and type: {:?}",
                    curve,
                    key_type
                )),
            },
            _ => Err(hwcrypto_err!(
                BAD_PARAMETER,
                "type mismatch for Ec Key curve {:?} and type: {:?}",
                curve,
                key_type
            )),
        },
    }
}

// Translating a policy AES `KeyType` into the type understood by the cryptographic backend we are
// currently used
// TODO: change this into a `TryFrom` once we refactor `KeyType` to be a newtype.
fn get_aes_variant(key_type: &KeyType) -> Result<crypto::aes::Variant, HwCryptoError> {
    match *key_type {
        KeyType::AES_128_CBC_NO_PADDING
        | KeyType::AES_128_CBC_PKCS7_PADDING
        | KeyType::AES_128_CTR
        | KeyType::AES_128_GCM
        | KeyType::AES_128_CMAC => Ok(crypto::aes::Variant::Aes128),
        KeyType::AES_256_CBC_NO_PADDING
        | KeyType::AES_256_CBC_PKCS7_PADDING
        | KeyType::AES_256_CTR
        | KeyType::AES_256_GCM
        | KeyType::AES_256_CMAC => Ok(crypto::aes::Variant::Aes256),
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "not an AES key type: {:?}", key_type)),
    }
}

// Use the cryptographic backend to create key material based on the policy `KeyType`. Because HMAC
// keys can have arbitrary sizes, include an optional `key_size_bits` for that case.
fn generate_key_material(key_type: &KeyType) -> Result<KeyMaterial, HwCryptoError> {
    let aes = crypto_provider::AesImpl;
    let hmac = crypto_provider::HmacImpl;
    let mut rng = crypto_provider::RngImpl::default();
    match *key_type {
        KeyType::AES_128_CBC_NO_PADDING
        | KeyType::AES_128_CBC_PKCS7_PADDING
        | KeyType::AES_128_CTR
        | KeyType::AES_128_GCM
        | KeyType::AES_128_CMAC
        | KeyType::AES_256_CBC_NO_PADDING
        | KeyType::AES_256_CBC_PKCS7_PADDING
        | KeyType::AES_256_CTR
        | KeyType::AES_256_GCM
        | KeyType::AES_256_CMAC => {
            let variant = get_aes_variant(key_type)?;
            Ok(aes.generate_key(&mut rng, variant, &[])?)
        }
        KeyType::HMAC_SHA256 => {
            Ok(hmac.generate_key(&mut rng, kmr_wire::KeySizeInBits(256), &[])?)
        }
        KeyType::HMAC_SHA512 => {
            Ok(hmac.generate_key(&mut rng, kmr_wire::KeySizeInBits(512), &[])?)
        }
        _ => unimplemented!("key material other than AES and HMAC not implemented yet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{expect, expect_eq};

    #[test]
    fn boot_unique_values_match() {
        let boot_value = BootUniqueValue::new().expect("couldn't get boot unique value");
        let boot_value2 = BootUniqueValue::new().expect("couldn't get boot unique value");
        expect_eq!(boot_value, boot_value2, "boot unique values should match");
    }

    #[test]
    fn generate_key_material_test() {
        let usage = KeyUse::ENCRYPT;
        let key_type = KeyType::AES_256_GCM;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let key_material = generate_key_material(&policy.keyType);
        expect!(key_material.is_ok(), "couldn't retrieve key material");
        let key_material = key_material.unwrap();
        let check_result = check_key_material_with_policy(&key_material, &policy);
        expect!(check_result.is_ok(), "wrong key type");
    }
}
