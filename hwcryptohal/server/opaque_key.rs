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
use hwcryptohal_common::err::HwCryptoError;
use kmr_common::{
    crypto::{KeyMaterial, Rng},
    FallibleAllocExt,
};
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
}

/// `IOpaqueKey` implementation.
#[allow(dead_code)]
pub struct OpaqueKey {
    pub(crate) key_header: KeyHeader,
    pub(crate) key_material: KeyMaterial,
}

impl OpaqueKey {
    #[allow(dead_code)]
    pub(crate) fn new_opaque_key(
        policy: &KeyPolicy,
        key_material: KeyMaterial,
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_header = KeyHeader::new(policy)?;
        // TODO: Add checks that the provided `KeyPolicy` is compatible with the `KeyMaterial`
        let opaque_key = OpaqueKey { key_header, key_material };
        let opaque_keybinder =
            BnOpaqueKey::new_binder(opaque_key, binder::BinderFeatures::default());
        Ok(opaque_keybinder)
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
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("get_key_policy has not been implemented yet"),
        ))
    }

    fn getPublicKey(&self) -> binder::Result<Vec<u8>> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("get_public_key has not been implemented yet"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::expect_eq;

    #[test]
    fn boot_unique_values_match() {
        let boot_value = BootUniqueValue::new().expect("couldn't get boot unique value");
        let boot_value2 = BootUniqueValue::new().expect("couldn't get boot unique value");
        expect_eq!(boot_value, boot_value2, "boot unique values should match");
    }
}
