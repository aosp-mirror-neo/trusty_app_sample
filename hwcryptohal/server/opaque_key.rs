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

use alloc::collections::btree_map::BTreeMap;
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
    AesCipherMode::AesCipherMode, KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions,
    KeyType::KeyType, KeyUse::KeyUse, OpaqueKeyToken::OpaqueKeyToken, OperationType::OperationType,
    ProtectionId::ProtectionId, SymmetricCryptoParameters::SymmetricCryptoParameters,
    SymmetricOperation::SymmetricOperation,
};
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    IHwCryptoKey::{
        DeviceKeyId::DeviceKeyId, DiceBoundDerivationKey::DiceBoundDerivationKey,
        DiceBoundKeyResult::DiceBoundKeyResult,
    },
    IOpaqueKey::{BnOpaqueKey, IOpaqueKey},
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see_hwcrypto::binder;
use binder::binder_impl::Binder;
use ciborium::Value;
use core::fmt;
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohalinterfaces::DeviceTime;
use hwcryptohalplatform::{AesImpl, DeviceTimeImpl, HmacImpl, RngImpl};
use hwcryptohal_common::{
    aidl_enum_wrapper, cose_enum_gen,
    err::HwCryptoError,
    hwcrypto_err,
    policy::{
        self, cbor_policy_to_aidl, cbor_serialize_key_policy, KeyLifetimeSerializable,
        KeyTypeSerializable, KeyUseSerializable,
    },
};
use kmr_common::{
    crypto::{self, Aes, CurveType, Hkdf, Hmac, KeyMaterial, OpaqueOr, Rng},
    explicit, FallibleAllocExt,
};
use kmr_wire::{keymint::EcCurve, AsCborValue as _};
use std::sync::{Mutex, OnceLock};

use crate::helpers;
use crate::hwcrypto_device_key::HwCryptoKey;
use crate::service_encryption_key::{EncryptedContent, EncryptionHeader, EncryptionHeaderKey};

/// Number of bytes of unique value used to check if a key was created on current HWCrypto boot.
const UNIQUE_VALUE_SIZEOF: usize = 32;

const SEALING_KEY_DERIVATION_HMAC_256_CTX: &[u8] = b"SEALING_KEY_DERIVATION_HMAC_256_CTX";

const HW_CRYPTO_WRAP_KEY_HMAC_256_CTX: &[u8] = b"HW_CRYPTO_WRAP_KEY_HMAC_256_CTX";

const TOKEN_EXPORT_EXPIRATION_TIME_10S: u64 = 10;

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
        let mut new_boot_unique_value = BootUniqueValue([0u8; UNIQUE_VALUE_SIZEOF]);
        RngImpl.fill_bytes(&mut new_boot_unique_value.0[..]);
        new_boot_unique_value
    });
    Ok(boot_unique_value.clone())
}

#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone)]
pub(crate) enum HkdfOperationType {
    DiceBoundDerivation = 1,
    ClearKeyDerivation = 3,
    OpaqueKeyDerivation = 4,
    InternalSealingKeyDerivation = 5,
}

pub(crate) struct DerivationContext {
    context_components: Vec<Value>,
}

impl DerivationContext {
    pub(crate) fn new(op_type: HkdfOperationType) -> Result<Self, HwCryptoError> {
        let mut context_components = Vec::new();
        context_components.try_reserve(1)?;
        context_components.push(Value::Integer((op_type as u8).into()));
        Ok(Self { context_components })
    }

    pub(crate) fn add_binary_string(&mut self, binary_string: &[u8]) -> Result<(), HwCryptoError> {
        self.context_components.try_reserve(1)?;
        let mut context = Vec::new();
        context.try_reserve(binary_string.len())?;
        context.extend_from_slice(binary_string);
        self.context_components.push(Value::Bytes(context));
        Ok(())
    }

    pub(crate) fn add_owned_binary_string(
        &mut self,
        binary_string: Vec<u8>,
    ) -> Result<(), HwCryptoError> {
        self.context_components.try_reserve(1)?;
        self.context_components.push(Value::Bytes(binary_string));
        Ok(())
    }

    pub(crate) fn add_unsigned_integer(&mut self, value: u64) -> Result<(), HwCryptoError> {
        self.context_components.try_reserve(1)?;
        self.context_components.push(Value::Integer(value.into()));
        Ok(())
    }

    pub(crate) fn create_key_derivation_context(self) -> Result<Vec<u8>, HwCryptoError> {
        let context = Value::Array(self.context_components);
        Ok(context.to_vec()?)
    }
}

#[derive(Debug)]
struct KeyHeaderPolicy {
    key_lifetime: KeyLifetimeSerializable,
    key_permissions: Vec<KeyPermissions>,
    key_usage: KeyUseSerializable,
    key_type: KeyTypeSerializable,
    management_key: bool,
}

impl KeyHeaderPolicy {
    fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_extend_from_slice(&policy.keyPermissions[..])?;
        Ok(Self {
            key_lifetime: KeyLifetimeSerializable(policy.keyLifetime),
            key_permissions,
            key_usage: KeyUseSerializable(policy.usage),
            key_type: KeyTypeSerializable(policy.keyType),
            management_key: policy.keyManagementKey,
        })
    }

    fn get_policy(&self) -> Result<KeyPolicy, HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_extend_from_slice(&self.key_permissions[..])?;
        Ok(KeyPolicy {
            usage: self.key_usage.0,
            keyLifetime: self.key_lifetime.0,
            keyPermissions: key_permissions,
            keyType: self.key_type.0,
            keyManagementKey: self.management_key,
        })
    }

    fn try_clone(&self) -> Result<Self, HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_extend_from_slice(&self.key_permissions[..])?;
        Ok(Self {
            key_lifetime: self.key_lifetime,
            key_permissions,
            key_usage: self.key_usage,
            key_type: self.key_type,
            management_key: self.management_key,
        })
    }
}

fn check_protection_id_settings(
    protection_id: &ProtectionIdSerializable,
    settings: &ProtectionSetting,
) -> Result<bool, HwCryptoError> {
    match protection_id.0 {
        ProtectionId::WIDEVINE_OUTPUT_BUFFER => {
            // For Widevine buffers we cannot create a key that can read into this area
            Ok(!settings.read_protection)
        }
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "unsupported protection_id {:?}", protection_id,)),
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ExpirationTime {
    set_time_ms: u64,
    valid_period_ms: u64,
}

impl ExpirationTime {
    fn new(expiration_time_sec: u64) -> Result<Self, HwCryptoError> {
        let set_time_ms = DeviceTimeImpl::current_epoch_time_ms()?;
        let valid_period_ms = expiration_time_sec
            .checked_mul(1000)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "validity period is too big",))?;
        Ok(ExpirationTime { set_time_ms, valid_period_ms })
    }

    pub(crate) fn check_validity(&self) -> Result<bool, HwCryptoError> {
        let current_time_ms = DeviceTimeImpl::current_epoch_time_ms()?;
        if current_time_ms < self.set_time_ms {
            return Err(hwcrypto_err!(INVALID_KEY, "current time is before expiry set time",));
        }
        let valid_until_ms = self
            .set_time_ms
            .checked_add(self.valid_period_ms)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "couldn't calculate validity period",))?;
        Ok(current_time_ms < valid_until_ms)
    }
}

impl AsCborValue for ExpirationTime {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((ExpirationTimeCoseLabels::SetTime as i64).into());
        let value = Value::Integer(self.set_time_ms.into());
        cbor_map.push((key, value));

        let key = Value::Integer((ExpirationTimeCoseLabels::ValidPeriod as i64).into());
        let value = Value::Integer(self.valid_period_ms.into());
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        if opaque_key_map.len() != 2 {
            return Err(CoseError::ExtraneousData);
        }

        let mut set_time_ms: Option<u64> = None;
        let mut valid_period_ms: Option<u64> = None;
        for (map_key, map_val) in opaque_key_map {
            match map_key {
                Value::Integer(key) => match key.try_into()? {
                    ExpirationTimeCoseLabels::SetTime => {
                        set_time_ms = Some(
                            map_val
                                .into_integer()
                                .map_err(|_| {
                                    CoseError::UnexpectedItem("not an integer", "integer")
                                })?
                                .try_into()
                                .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
                        );
                    }
                    ExpirationTimeCoseLabels::ValidPeriod => {
                        valid_period_ms = Some(
                            map_val
                                .into_integer()
                                .map_err(|_| {
                                    CoseError::UnexpectedItem("not an integer", "integer")
                                })?
                                .try_into()
                                .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
                        );
                    }
                },
                _ => return Err(CoseError::UnexpectedItem("not an integer", "integer map key")),
            }
        }

        let set_time_ms = set_time_ms.ok_or(CoseError::EncodeFailed)?;
        let valid_period_ms = valid_period_ms.ok_or(CoseError::EncodeFailed)?;

        Ok(Self { set_time_ms, valid_period_ms })
    }
}

#[derive(Debug)]
struct KeyHeaderMetadata {
    expiration_time: Option<ExpirationTime>,
    protection_id_settings: BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
}

impl KeyHeaderMetadata {
    fn new() -> Self {
        Self { expiration_time: None, protection_id_settings: BTreeMap::new() }
    }

    // While the current metadata definition wouldn't fail on this operation, we are doing this
    // division to add an element to metadata that could fail while trying to clone
    fn try_clone(&self) -> Result<Self, HwCryptoError> {
        let mut protection_id_settings = BTreeMap::new();
        protection_id_settings.extend(self.protection_id_settings.iter());
        Ok(Self { expiration_time: self.expiration_time, protection_id_settings })
    }

    fn add_protection_id(
        &mut self,
        protection_id: ProtectionId,
        allowed_operations: &[OperationType],
    ) -> Result<(), HwCryptoError> {
        if allowed_operations.is_empty() {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "didn't receive any allowed operations for add_protection_id",
            ));
        }
        let protection_id = ProtectionIdSerializable::try_from(protection_id).map_err(|e| {
            hwcrypto_err!(GENERIC_ERROR, "couldn't convert from protection id {:?}", e,)
        })?;
        if self.protection_id_settings.contains_key(&protection_id) {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "settings for protection id {:?} have already been set",
                protection_id
            ));
        }
        let mut protection_setting =
            ProtectionSetting { write_protection: false, read_protection: false };
        for operation in allowed_operations {
            match *operation {
                OperationType::READ => protection_setting.read_protection = true,
                OperationType::WRITE => protection_setting.write_protection = true,
                _ => {
                    return Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "received unsupported OperationType {:?}",
                        operation
                    ))
                }
            }
        }
        if !check_protection_id_settings(&protection_id, &protection_setting)? {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "unsupported setting for permissions {:?}: {:?}",
                protection_id,
                protection_setting
            ));
        }
        self.protection_id_settings.insert(protection_id, protection_setting);
        Ok(())
    }

    fn get_metadata_as_cbor(&self) -> Result<Value, HwCryptoError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2)?;

        // Adding expiration time
        let expiration_time_value = if let Some(expiration_time) = self.expiration_time {
            expiration_time.to_cbor_value().map_err(|_| {
                hwcrypto_err!(BAD_PARAMETER, "couldn't get cbor representation of expiration time")
            })?
        } else {
            Value::Null
        };
        let key = Value::Integer((KeyMetadataCoseLabels::KeyExpirationPeriod as i64).into());
        cbor_map.push((key, expiration_time_value));

        // Adding protection IDs
        let mut protection_id_cbor_map = Vec::<(Value, Value)>::new();
        protection_id_cbor_map.try_reserve(self.protection_id_settings.len())?;
        for (protection_id, protection_id_setting) in &self.protection_id_settings {
            let protection_id_key = ciborium::Value::Integer((*protection_id).into());
            protection_id_cbor_map.push((
                protection_id_key,
                protection_id_setting.to_cbor_value().map_err(|_| {
                    hwcrypto_err!(
                        BAD_PARAMETER,
                        "couldn't get cbor representation of protection id setting"
                    )
                })?,
            ))
        }
        let key = Value::Integer((KeyMetadataCoseLabels::ProtectionIdSettings as i64).into());
        cbor_map.push((key, ciborium::Value::Map(protection_id_cbor_map)));
        Ok(Value::Map(cbor_map))
    }

    fn set_metadata_from_cbor(&mut self, metadata_as_cbor: Value) -> Result<(), HwCryptoError> {
        let metadata = metadata_as_cbor
            .into_map()
            .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received cbor wasn't a map"))?;

        let mut protection_id_settings: Option<
            BTreeMap<ProtectionIdSerializable, ProtectionSetting>,
        > = None;
        let mut expiration_time: Option<Option<ExpirationTime>> = None;

        for (map_key, map_val) in metadata {
            let key = map_key
                .into_integer()
                .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received map key wasn't an integer"))?;
            match key.try_into()? {
                KeyMetadataCoseLabels::KeyExpirationPeriod => {
                    expiration_time = if map_val.is_null() {
                        Some(None)
                    } else {
                        let value = ExpirationTime::from_cbor_value(map_val).map_err(|_| {
                            hwcrypto_err!(
                                BAD_PARAMETER,
                                "couldn't transform expiration time to CBOR"
                            )
                        })?;
                        Some(Some(value))
                    }
                }
                KeyMetadataCoseLabels::ProtectionIdSettings => {
                    let mut settings = BTreeMap::new();
                    for (protection_id, protection_setting) in map_val
                        .into_map()
                        .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "received cbor wasn't a map"))?
                    {
                        //settings.try_reserve(1).map_err(|_| CoseError::EncodeFailed)?;
                        let protection_id: ProtectionIdSerializable = protection_id
                            .into_integer()
                            .map_err(|_| {
                                hwcrypto_err!(BAD_PARAMETER, "protection id key wasn't an integer")
                            })?
                            .try_into()
                            .map_err(|_| {
                                hwcrypto_err!(BAD_PARAMETER, "couldn't decode protection ID")
                            })?;
                        let protection_setting =
                            ProtectionSetting::from_cbor_value(protection_setting)?;
                        if settings.contains_key(&protection_id) {
                            return Err(hwcrypto_err!(
                                BAD_PARAMETER,
                                "received duplicated protection ID entry"
                            ));
                        }
                        settings.insert(protection_id, protection_setting);
                    }
                    protection_id_settings = Some(settings);
                }
            }
        }
        self.expiration_time = expiration_time
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "didn't find expiration time on metadata"))?;
        self.protection_id_settings = protection_id_settings.ok_or(hwcrypto_err!(
            BAD_PARAMETER,
            "didn't find protection_ id settings on metadata"
        ))?;
        Ok(())
    }

    fn set_expiration_time(&mut self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
        self.expiration_time = Some(ExpirationTime::new(expiration_time_sec)?);
        Ok(())
    }

    fn expiration_time_set(&self) -> bool {
        self.expiration_time.is_some()
    }

    fn expiration_time_valid(&self) -> Result<bool, HwCryptoError> {
        if !self.expiration_time_set() {
            Ok(true)
        } else {
            // expiration time is set, so unwrap will not panic
            self.expiration_time.unwrap().check_validity()
        }
    }
}

/// Header for a `ClearKey` which contains the key policy along with some data needed to manipulate
/// the key.
#[derive(Debug)]
pub(crate) struct KeyHeader {
    boot_unique_value: BootUniqueValue,
    key_policy: KeyHeaderPolicy,
    key_metadata: Mutex<KeyHeaderMetadata>,
}

impl KeyHeader {
    fn new(policy: &KeyPolicy) -> Result<Self, HwCryptoError> {
        let boot_unique_value = BootUniqueValue::new()?;
        Self::new_with_boot_value(policy, boot_unique_value)
    }

    fn new_with_boot_value(
        policy: &KeyPolicy,
        boot_unique_value: BootUniqueValue,
    ) -> Result<Self, HwCryptoError> {
        let key_policy = KeyHeaderPolicy::new(policy)?;
        let key_metadata = Mutex::new(KeyHeaderMetadata::new());
        Ok(Self { boot_unique_value, key_policy, key_metadata })
    }

    fn get_policy(&self) -> Result<KeyPolicy, HwCryptoError> {
        self.key_policy.get_policy()
    }

    fn try_clone(&self) -> Result<Self, HwCryptoError> {
        let key_policy = self.key_policy.try_clone()?;
        let key_metadata = self.key_metadata.lock()?.try_clone()?;
        Ok(Self {
            boot_unique_value: self.boot_unique_value.clone(),
            key_policy,
            key_metadata: Mutex::new(key_metadata),
        })
    }

    fn get_metadata_as_cbor(&self) -> Result<Value, HwCryptoError> {
        self.key_metadata.lock()?.get_metadata_as_cbor()
    }

    fn set_metadata_from_cbor(&mut self, metadata_as_cbor: Value) -> Result<(), HwCryptoError> {
        self.key_metadata.lock()?.set_metadata_from_cbor(metadata_as_cbor)
    }

    fn set_expiration_time(&self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
        self.key_metadata.lock()?.set_expiration_time(expiration_time_sec)
    }

    fn expiration_time_set(&self) -> Result<bool, HwCryptoError> {
        Ok(self.key_metadata.lock()?.expiration_time_set())
    }

    fn expiration_time_valid(&self) -> Result<bool, HwCryptoError> {
        self.key_metadata.lock()?.expiration_time_valid()
    }
}

cose_enum_gen! {
    enum OpaqueKeyCoseLabels {
        KeyMaterial = -66000,
        KeyPolicy = -66001,
        BootValue = -66002,
        KeyMetadata = -66003,
    }
}

cose_enum_gen! {
    enum ProtectionSettingsCoseLabels {
        WriteProtection = -67000,
        ReadProtection = -67001,
    }
}

cose_enum_gen! {
    enum KeyMetadataCoseLabels {
        KeyExpirationPeriod = -68000,
        ProtectionIdSettings = -68001,
    }
}

cose_enum_gen! {
    enum ExpirationTimeCoseLabels {
        SetTime = -69000,
        ValidPeriod = -69001,
    }
}

aidl_enum_wrapper! {
    aidl_name: ProtectionId,
    wrapper_name: ProtectionIdSerializable,
    fields: [WIDEVINE_OUTPUT_BUFFER]
}

#[derive(Debug, Copy, Clone)]
struct ProtectionSetting {
    write_protection: bool,
    read_protection: bool,
}

impl AsCborValue for ProtectionSetting {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((ProtectionSettingsCoseLabels::WriteProtection as i64).into());
        let value = Value::Bool(self.write_protection);
        cbor_map.push((key, value));

        let key = Value::Integer((ProtectionSettingsCoseLabels::ReadProtection as i64).into());
        let value = Value::Bool(self.read_protection);
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        if opaque_key_map.len() != 2 {
            return Err(CoseError::ExtraneousData);
        }

        let mut write_protection: Option<bool> = None;
        let mut read_protection: Option<bool> = None;
        for (map_key, map_val) in opaque_key_map {
            match map_key {
                Value::Integer(key) => match key.try_into()? {
                    ProtectionSettingsCoseLabels::WriteProtection => {
                        write_protection = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
                    }
                    ProtectionSettingsCoseLabels::ReadProtection => {
                        read_protection = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
                    }
                },
                _ => return Err(CoseError::ExtraneousData),
            }
        }

        let write_protection = write_protection.ok_or(CoseError::EncodeFailed)?;
        let read_protection = read_protection.ok_or(CoseError::EncodeFailed)?;

        Ok(Self { write_protection, read_protection })
    }
}

fn get_dice_sealing_key_derivation_context() -> Result<Vec<u8>, HwCryptoError> {
    let mut context = Vec::<u8>::new();

    context.try_reserve(SEALING_KEY_DERIVATION_HMAC_256_CTX.len() + UNIQUE_VALUE_SIZEOF)?;
    context.extend_from_slice(SEALING_KEY_DERIVATION_HMAC_256_CTX);
    context.extend_from_slice(&get_boot_unique_value()?.0);

    Ok(context)
}

/// `IOpaqueKey` implementation.
pub struct OpaqueKey {
    pub(crate) key_header: KeyHeader,
    pub(crate) key_material: KeyMaterial,
    pub(crate) key_in_owner_control: bool,
    client_id: Option<Vec<u8>>,
}

impl From<OpaqueKey> for binder::Strong<dyn IOpaqueKey> {
    fn from(value: OpaqueKey) -> binder::Strong<dyn IOpaqueKey> {
        BnOpaqueKey::new_binder(value, binder::BinderFeatures::default())
    }
}

impl TryFrom<&binder::Strong<dyn IOpaqueKey>> for OpaqueKey {
    type Error = HwCryptoError;

    fn try_from(value: &binder::Strong<dyn IOpaqueKey>) -> Result<OpaqueKey, Self::Error> {
        let binder = value.as_binder();
        let remote = binder.is_remote();
        if remote {
            return Err(hwcrypto_err!(UNSUPPORTED, "binder is not local"));
        }
        let binder_key: Binder<BnOpaqueKey> =
            binder.try_into().expect("because binder is local this should not fail");
        let opaque_key_material = (*binder_key).downcast_binder::<OpaqueKey>();
        match opaque_key_material {
            Some(key) => key.try_clone(),
            None => Err(hwcrypto_err!(UNSUPPORTED, "couldn't cast back key")),
        }
    }
}

impl AsCborValue for OpaqueKey {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(4).map_err(|_| CoseError::EncodeFailed)?;
        let key = Value::Integer((OpaqueKeyCoseLabels::KeyPolicy as i64).into());
        let key_policy = self.getKeyPolicy().map_err(|_| CoseError::EncodeFailed)?;
        let cbor_key_policy =
            cbor_serialize_key_policy(&key_policy).map_err(|_| CoseError::EncodeFailed)?;
        cbor_map.push((key, Value::Bytes(cbor_key_policy)));

        let key = Value::Integer((OpaqueKeyCoseLabels::KeyMaterial as i64).into());
        cbor_map
            .push((key, self.key_material.to_cbor_value().map_err(|_| CoseError::EncodeFailed)?));

        let key = Value::Integer((OpaqueKeyCoseLabels::BootValue as i64).into());
        let mut boot_value = Vec::new();
        boot_value
            .try_reserve(self.key_header.boot_unique_value.0.len())
            .map_err(|_| CoseError::EncodeFailed)?;
        boot_value.extend_from_slice(&self.key_header.boot_unique_value.0);
        cbor_map.push((key, Value::Bytes(boot_value)));

        let key = Value::Integer((OpaqueKeyCoseLabels::KeyMetadata as i64).into());
        cbor_map.push((
            key,
            self.key_header.get_metadata_as_cbor().map_err(|_| CoseError::EncodeFailed)?,
        ));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let opaque_key_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        if opaque_key_map.len() != 4 {
            return Err(CoseError::ExtraneousData);
        }
        let mut key_material: Option<KeyMaterial> = None;
        let mut key_policy: Option<KeyPolicy> = None;
        let mut boot_value: Option<BootUniqueValue> = None;
        let mut key_metadata: Option<Value> = None;
        for (map_key, map_val) in opaque_key_map {
            match map_key {
                Value::Integer(key) => match key.try_into()? {
                    OpaqueKeyCoseLabels::KeyMaterial => {
                        key_material = Some(
                            KeyMaterial::from_cbor_value(map_val)
                                .map_err(|_| CoseError::EncodeFailed)?,
                        )
                    }
                    OpaqueKeyCoseLabels::KeyPolicy => {
                        let policy_bytes = map_val.as_bytes().ok_or(CoseError::EncodeFailed)?;
                        key_policy = Some(
                            cbor_policy_to_aidl(policy_bytes.as_slice())
                                .map_err(|_| CoseError::EncodeFailed)?,
                        )
                    }
                    OpaqueKeyCoseLabels::BootValue => {
                        let boot_value_bytes = map_val.as_bytes().ok_or(CoseError::EncodeFailed)?;
                        boot_value = Some(BootUniqueValue(
                            (boot_value_bytes.clone())
                                .try_into()
                                .map_err(|_| CoseError::EncodeFailed)?,
                        ))
                    }
                    OpaqueKeyCoseLabels::KeyMetadata => key_metadata = Some(map_val),
                },
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        let key_material = key_material.ok_or(CoseError::EncodeFailed)?;
        let key_policy = key_policy.ok_or(CoseError::EncodeFailed)?;
        let boot_value = boot_value.ok_or(CoseError::EncodeFailed)?;
        let mut key_header = KeyHeader::new_with_boot_value(&key_policy, boot_value)
            .map_err(|_| CoseError::EncodeFailed)?;
        let key_metadata = key_metadata.ok_or(CoseError::EncodeFailed)?;
        key_header.set_metadata_from_cbor(key_metadata).map_err(|_| CoseError::EncodeFailed)?;
        Ok(OpaqueKey { key_material, key_header, key_in_owner_control: false, client_id: None })
    }
}

impl OpaqueKey {
    pub(crate) fn new_binder(
        policy: &KeyPolicy,
        key_material: KeyMaterial,
        client_conn_id: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_header = KeyHeader::new(policy)?;
        check_key_material_with_policy(&key_material, policy)?;
        let mut client_id = Vec::new();
        client_id
            .try_reserve(client_conn_id.len())
            .map_err(|_| hwcrypto_err!(ALLOCATION_ERROR, "couldn't allcoate client id"))?;
        client_id.extend_from_slice(client_conn_id);
        let opaque_key = OpaqueKey {
            key_header,
            key_material,
            key_in_owner_control: true,
            client_id: Some(client_id),
        };
        let opaque_keybinder =
            BnOpaqueKey::new_binder(opaque_key, binder::BinderFeatures::default());
        Ok(opaque_keybinder)
    }

    fn check_clear_import_policy(policy: &KeyPolicy) -> Result<(), HwCryptoError> {
        if policy.keyLifetime != KeyLifetime::PORTABLE {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "imported clear keys should have a PORTABLE lifetime"
            ));
        }
        Ok(())
    }

    pub(crate) fn import_key_material(
        policy: &KeyPolicy,
        key_material: KeyMaterial,
        client_conn_id: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        check_key_material_with_policy(&key_material, policy)?;
        Self::check_clear_import_policy(policy)?;
        Self::new_binder(policy, key_material, client_conn_id)
    }

    fn check_ownership(&self) -> bool {
        self.key_in_owner_control
    }

    // Create a key token sealed using the receiver DICE policy. This means that only the
    // intended token receiver can import this token. The token has 2 levels of encryption,
    // the outer layer is provided by a device key bounded to the HwCrypto service and the
    // outer layer is generated using the receiver DICE policy.
    fn create_token(&self, sealing_dice_policy: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
        if !self.check_ownership() {
            // We haven't created this key, so we cannot export it
            // TODO: Change the error type to UNAUTORIZED
            return Err(hwcrypto_err!(GENERIC_ERROR, "only the owner of a key can export it"));
        }
        let key: OpaqueKey = self.try_clone()?;
        key.set_expiration_time(TOKEN_EXPORT_EXPIRATION_TIME_10S)?;
        let token_creator = EncryptionHeader::generate(EncryptedContent::KeyMaterial)?;

        let mut client_id = Vec::new();
        let client_conn_id =
            self.client_id.as_ref().ok_or(hwcrypto_err!(GENERIC_ERROR, "key has no client id"))?;
        client_id.try_reserve(client_conn_id.len())?;
        client_id.extend_from_slice(client_conn_id.as_slice());
        let hw_device_key = HwCryptoKey { client_id };

        // Create a DICE key bound to the receiver policy.
        let DiceBoundKeyResult { diceBoundKey: sealing_dice_key, dicePolicyWasCurrent: _ } =
            hw_device_key.derive_dice_policy_bound_key(
                &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
                sealing_dice_policy,
                false,
            )?;
        let sealing_dice_key: OpaqueKey = sealing_dice_key
            .as_ref()
            .ok_or(hwcrypto_err!(GENERIC_ERROR, "shouldn't happen, sealing key is local"))?
            .try_into()?;
        let context = get_dice_sealing_key_derivation_context()?;
        let sealing_key = sealing_dice_key
            .derive_internal_sealing_key(&context, get_key_size_in_bytes(&KeyType::HMAC_SHA256)?)?;
        // Inner encryption using the DICE policy bound key
        let inner_content = token_creator.encrypt_content_service_encryption_key(
            EncryptionHeaderKey::ProvidedHkdfKey(sealing_key),
            key,
        )?;

        // External encryption using the HwCrypto service key
        let token_creator = EncryptionHeader::generate(EncryptedContent::WrappedKeyMaterial)?;
        let content = token_creator.encrypt_content_service_encryption_key(
            EncryptionHeaderKey::KeyGenerationContext(HW_CRYPTO_WRAP_KEY_HMAC_256_CTX),
            Value::Bytes(inner_content),
        )?;
        Ok(content)
    }

    pub(crate) fn import_token(
        key_token: &[u8],
        sealing_dice_key: OpaqueKey,
        _client_conn_id: &[u8],
    ) -> Result<Self, HwCryptoError> {
        // External encryption layer used a HwCrypto service device key
        let (_, content) = EncryptionHeader::decrypt_content_service_encryption_key(
            key_token,
            EncryptionHeaderKey::KeyGenerationContext(HW_CRYPTO_WRAP_KEY_HMAC_256_CTX),
            EncryptedContent::WrappedKeyMaterial,
        )?;

        sealing_dice_key.expiration_time_valid()?;

        let context = get_dice_sealing_key_derivation_context()?;
        // Preparing internal encryption DICE policy bound key
        let sealing_key = sealing_dice_key
            .derive_internal_sealing_key(&context, get_key_size_in_bytes(&KeyType::HMAC_SHA256)?)?;

        let cbor_bytes = Value::from_slice(content.as_slice())?;
        let inner_content = cbor_bytes.as_bytes().ok_or(hwcrypto_err!(
            GENERIC_ERROR,
            "shouldn't happen, inner content was encrypted by us"
        ))?;

        let (_, inner_key) = EncryptionHeader::decrypt_content_service_encryption_key(
            inner_content,
            EncryptionHeaderKey::ProvidedHkdfKey(sealing_key),
            EncryptedContent::KeyMaterial,
        )?;

        // We are not propagating _client_conn_id into the imported key. Currently connection
        // information is only used to export keys and keys imported by the client should not be
        // re-exported.
        let opaque_key = Self::from_cbor_value(Value::from_slice(inner_key.as_slice())?)?;
        if !opaque_key.expiration_time_set()? {
            return Err(hwcrypto_err!(
                INVALID_KEY,
                "importer tokens should have an expiration time"
            ));
        }
        opaque_key.expiration_time_valid()?;
        Ok(opaque_key)
    }

    #[allow(unused)]
    pub(crate) fn generate_opaque_key(
        policy: &KeyPolicy,
        client_conn_id: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_material = generate_key_material(&policy.keyType, None)?;
        OpaqueKey::new_binder(policy, key_material, client_conn_id)
    }

    fn try_clone(&self) -> Result<Self, HwCryptoError> {
        let key_header = self.key_header.try_clone()?;
        let key_material = self.key_material.clone();
        let client_id = if self.client_id.is_some() {
            let mut client_id = Vec::new();
            let client_conn_id = self.client_id.as_ref().unwrap();
            client_id.try_reserve(client_conn_id.len())?;
            client_id.extend_from_slice(client_conn_id.as_slice());
            Some(client_id)
        } else {
            None
        };
        Ok(OpaqueKey {
            key_header,
            key_material,
            key_in_owner_control: self.key_in_owner_control,
            client_id,
        })
    }

    pub(crate) fn new_opaque_key_from_raw_bytes(
        policy: &KeyPolicy,
        key_material: Vec<u8>,
        client_conn_id: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_material = generate_key_material(&policy.keyType, Some(key_material))?;
        OpaqueKey::new_binder(policy, key_material, client_conn_id)
    }

    pub(crate) fn check_key_derivation_parameters(
        &self,
        policy: &KeyPolicy,
    ) -> Result<(), HwCryptoError> {
        // Check that we are trying to derive a supported key type
        check_type_derived_key(policy.keyType)?;
        // Check that the requested lifetime is compatible with the provided key lifetime
        if !self.derivation_allowed_lifetime(policy.keyLifetime)? {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "requested lifetime cannot be used {:?}",
                &policy.keyLifetime
            ));
        }
        // check that the key hasn't expired
        self.expiration_time_valid()?;
        // Check that the derivation key can be used to derive keys (KeyPermissions/KeyPolicies)
        self.key_can_be_used_for_derivation()
    }

    // All key derivation functions that uses an `OpaqueKey` as key material should use this
    // function. If the key derivation do not fit one of the current use cases defined in
    // `HkdfOperationType`, a new enum value should be added to `HkdfOperationType` for the use
    // case.
    fn derive_raw_key_material(
        &self,
        context: DerivationContext,
        derived_key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError> {
        let context_with_op_type = context.create_key_derivation_context()?;
        match &self.key_material {
            KeyMaterial::Hmac(key) => {
                let explicit_key = explicit!(key).map_err(|_| {
                    hwcrypto_err!(BAD_PARAMETER, "only explicit HMAC keys supported")
                })?;
                let raw_key = HmacImpl
                    .hkdf(&[], &explicit_key.0, context_with_op_type.as_slice(), derived_key_size)
                    .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "couldn't derive key {:?}", e))?;
                Ok(raw_key)
            }
            _ => Err(hwcrypto_err!(BAD_PARAMETER, "only HMAC keys supported")),
        }
    }

    fn derive_clear_key_from_derivation_context(
        &self,
        mut op_context: DerivationContext,
        context: &[u8],
        derived_key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError> {
        op_context.add_unsigned_integer(derived_key_size as u64)?;
        op_context.add_binary_string(context)?;
        self.derive_raw_key_material(op_context, derived_key_size)
    }

    pub(crate) fn derive_internal_sealing_key(
        &self,
        context: &[u8],
        derived_key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError> {
        self.expiration_time_valid()?;
        let op_context = DerivationContext::new(HkdfOperationType::InternalSealingKeyDerivation)?;
        self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
    }

    pub(crate) fn derive_clear_key_material(
        &self,
        context: &[u8],
        derived_key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError> {
        self.expiration_time_valid()?;
        let op_context = DerivationContext::new(HkdfOperationType::ClearKeyDerivation)?;
        self.derive_clear_key_from_derivation_context(op_context, context, derived_key_size)
    }

    pub(crate) fn derive_opaque_key(
        &self,
        policy: &[u8],
        context: &[u8],
        client_conn_id: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        self.expiration_time_valid()?;
        let aidl_policy = policy::cbor_policy_to_aidl(policy)?;
        self.check_key_derivation_parameters(&aidl_policy)?;
        let derived_key_size = get_key_size_in_bytes(&aidl_policy.keyType)?;
        let mut op_context = DerivationContext::new(HkdfOperationType::OpaqueKeyDerivation)?;
        op_context.add_binary_string(policy)?;
        op_context.add_binary_string(context)?;
        let raw_key_material = self.derive_raw_key_material(op_context, derived_key_size)?;
        Self::new_opaque_key_from_raw_bytes(&aidl_policy, raw_key_material, client_conn_id)
    }

    fn derivation_allowed_lifetime(
        &self,
        derived_key_lifetime: KeyLifetime,
    ) -> Result<bool, HwCryptoError> {
        validate_lifetime(self.key_header.key_policy.key_lifetime.0)?;
        validate_lifetime(derived_key_lifetime)?;
        match self.key_header.key_policy.key_lifetime.0 {
            //ephemeral keys can be used to derive/wrap any other key
            KeyLifetime::EPHEMERAL => Ok(true),
            KeyLifetime::HARDWARE => {
                // Hardware keys cannot be used to derive/wrap ephemeral keys
                if derived_key_lifetime.0 == KeyLifetime::EPHEMERAL.0 {
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            KeyLifetime::PORTABLE => {
                // portable keys can only derive/wrap other portable keys
                if derived_key_lifetime.0 == KeyLifetime::PORTABLE.0 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(hwcrypto_err!(
                UNSUPPORTED,
                "unsupported Key lifetime {:?}",
                self.key_header.key_policy.key_lifetime
            )),
        }
    }

    fn key_can_be_used_for_derivation(&self) -> Result<(), HwCryptoError> {
        match self.key_material {
            KeyMaterial::Hmac(_) => Ok(()),
            _ => Err(hwcrypto_err!(UNSUPPORTED, "Only HMAC keys can be used for key derivation")),
        }?;
        if self.key_header.key_policy.key_usage.0 != KeyUse::DERIVE {
            return Err(hwcrypto_err!(BAD_PARAMETER, "key was not exclusively a derive key"));
        }
        Ok(())
    }

    pub(crate) fn key_usage_supported(&self, usage: KeyUse) -> bool {
        (usage.0 & self.key_header.key_policy.key_usage.0 .0) == usage.0
    }

    pub fn get_key_type(&self) -> KeyType {
        self.key_header.key_policy.key_type.0
    }

    pub fn supports_pattern_encryption(&self) -> Result<(), HwCryptoError> {
        match self.key_header.key_policy.key_type.0 {
            KeyType::AES_128_CBC_NO_PADDING => Ok(()),
            _ => Err(hwcrypto_err!(BAD_PARAMETER, "only AES CBC supports pattern encryption")),
        }
    }

    /// Checks if the requested operation (encrypt/decrypt) can be done with this key
    pub(crate) fn symmetric_operation_is_compatible(
        &self,
        direction: SymmetricOperation,
    ) -> Result<(), HwCryptoError> {
        self.expiration_time_valid()?;
        let dir = helpers::direction_to_key_usage(&direction)?;
        if !self.key_usage_supported(dir) {
            Err(hwcrypto_err!(BAD_PARAMETER, "provided key do not support {:?}", dir))
        } else {
            Ok(())
        }
    }

    /// Checks if the requested algorithm parameters are compatible with this key
    pub(crate) fn parameters_are_compatible_symmetric_cipher(
        &self,
        parameters: &SymmetricCryptoParameters,
    ) -> Result<(), HwCryptoError> {
        self.expiration_time_valid()?;
        match parameters {
            SymmetricCryptoParameters::Aes(aes_parameters) => match aes_parameters {
                AesCipherMode::Cbc(_) => match self.get_key_type() {
                    KeyType::AES_128_CBC_NO_PADDING
                    | KeyType::AES_128_CBC_PKCS7_PADDING
                    | KeyType::AES_256_CBC_NO_PADDING
                    | KeyType::AES_256_CBC_PKCS7_PADDING => Ok(()),
                    _ => Err(hwcrypto_err!(BAD_PARAMETER, "provided incompatible AES key for CBC")),
                },
                AesCipherMode::Ctr(_) => match self.get_key_type() {
                    KeyType::AES_128_CTR | KeyType::AES_256_CTR => Ok(()),
                    _ => Err(hwcrypto_err!(BAD_PARAMETER, "provided incompatible AES key for CTR")),
                },
            },
        }
    }

    fn set_expiration_time(&self, expiration_time_sec: u64) -> Result<(), HwCryptoError> {
        self.key_header.set_expiration_time(expiration_time_sec)
    }

    pub(crate) fn expiration_time_set(&self) -> Result<bool, HwCryptoError> {
        self.key_header.expiration_time_set()
    }

    pub(crate) fn expiration_time_valid(&self) -> Result<(), HwCryptoError> {
        if !self.key_header.expiration_time_valid()? {
            Err(hwcrypto_err!(INVALID_KEY, "key is no longer valid"))
        } else {
            Ok(())
        }
    }

    fn add_protection_id(
        &self,
        protection_id: ProtectionId,
        allowed_operations: &[OperationType],
    ) -> Result<(), HwCryptoError> {
        if !self.check_ownership() {
            // We haven't created this key, so we cannot export it
            // TODO: Change the error type to UNAUTORIZED
            return Err(hwcrypto_err!(
                GENERIC_ERROR,
                "only the owner of a key can modify protection IDs"
            ));
        }
        self.key_header.key_metadata.lock()?.add_protection_id(protection_id, allowed_operations)
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

    fn getShareableToken(&self, sealing_dice_policy: &[u8]) -> binder::Result<OpaqueKeyToken> {
        self.expiration_time_valid()?;
        Ok(OpaqueKeyToken { keyToken: self.create_token(sealing_dice_policy)? })
    }

    fn setProtectionId(
        &self,
        protection_id: ProtectionId,
        allowed_operations: &[OperationType],
    ) -> Result<(), binder::Status> {
        Ok(self.add_protection_id(protection_id, allowed_operations)?)
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
            OpaqueOr::Explicit(km) => match *key_type {
                KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
                    let expected_size = get_key_size_in_bytes(key_type)?;
                    let km_size = km.0.len();
                    match policy.usage {
                        KeyUse::SIGN | KeyUse::DERIVE => Ok(()),
                        _ => Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "wrong key use for hmac key, received {:?}",
                            policy.usage
                        )),
                    }?;
                    if km_size == expected_size {
                        Ok(())
                    } else {
                        Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "bad len for hmac key received {} bytes, expected {} bytes",
                            km_size,
                            expected_size
                        ))
                    }
                }
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

// Get key size given the backend AES key type. Used to check if we received enough bytes from the
// caller for an AES key.
fn get_aes_variant_key_size(variant: &crypto::aes::Variant) -> usize {
    match variant {
        crypto::aes::Variant::Aes128 => 16,
        crypto::aes::Variant::Aes192 => 24,
        crypto::aes::Variant::Aes256 => 32,
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

// Return a keysize given a `KeyType`. Because HMAC key sizes can be defined by the
// caller, `key_size_bits` is needed to cover all cases.
pub(crate) fn get_key_size_in_bytes(key_type: &KeyType) -> Result<usize, HwCryptoError> {
    match *key_type {
        KeyType::AES_128_CBC_NO_PADDING
        | KeyType::AES_128_CBC_PKCS7_PADDING
        | KeyType::AES_128_CTR
        | KeyType::AES_128_GCM
        | KeyType::AES_128_CMAC => Ok(16),
        KeyType::AES_256_CBC_NO_PADDING
        | KeyType::AES_256_CBC_PKCS7_PADDING
        | KeyType::AES_256_CTR
        | KeyType::AES_256_GCM
        | KeyType::AES_256_CMAC => Ok(32),
        KeyType::HMAC_SHA256 => Ok(32),
        KeyType::HMAC_SHA512 => Ok(64),
        _ => unimplemented!("Only AES and HMAC has been implemented"),
    }
}

fn validate_lifetime(lifetime: KeyLifetime) -> Result<(), HwCryptoError> {
    match lifetime {
        KeyLifetime::EPHEMERAL | KeyLifetime::HARDWARE | KeyLifetime::PORTABLE => Ok(()),
        // AIDL structure have more values added than the ones defined on the AIDL file
        _ => Err(hwcrypto_err!(UNSUPPORTED, "unsupported Key lifetime {:?}", lifetime)),
    }
}

fn check_type_derived_key(key_type: KeyType) -> Result<(), HwCryptoError> {
    match key_type {
        KeyType::AES_128_CBC_NO_PADDING
        | KeyType::AES_128_CBC_PKCS7_PADDING
        | KeyType::AES_128_CTR
        | KeyType::AES_128_GCM
        | KeyType::AES_128_CMAC
        | KeyType::AES_256_CBC_NO_PADDING
        | KeyType::AES_256_CBC_PKCS7_PADDING
        | KeyType::AES_256_CTR
        | KeyType::AES_256_GCM
        | KeyType::AES_256_CMAC
        | KeyType::HMAC_SHA256
        | KeyType::HMAC_SHA512 => Ok(()),
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "Only HMAC and AES keys are supported")),
    }
}

fn key_vec_to_array<T, U: std::convert::TryInto<T>>(input: U) -> Result<T, HwCryptoError> {
    input
        .try_into()
        .map_err(|_| hwcrypto_err!(BAD_PARAMETER, "couldn't transform vector into array"))
}

// Create a backend-compatible cryptographic key from either a provided vector of uniform random
// bytes or, if this not provided, use the cryptographic backend to create it. The type is based on
// the policy `KeyType`. Because HMAC keys can have arbitrary sizes, include an optional
// `key_size_bits` for that case.
pub(crate) fn generate_key_material(
    key_type: &KeyType,
    key_random_bytes: Option<Vec<u8>>,
) -> Result<KeyMaterial, HwCryptoError> {
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
            if let Some(key_bytes) = key_random_bytes {
                if key_bytes.len() != get_aes_variant_key_size(&variant) {
                    return Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "for aes key needed {} bytes, received {}",
                        key_bytes.len(),
                        get_aes_variant_key_size(&variant)
                    ));
                }
                match variant {
                    crypto::aes::Variant::Aes128 => Ok(KeyMaterial::Aes(
                        crypto::aes::Key::Aes128(key_vec_to_array(key_bytes)?).into(),
                    )),
                    crypto::aes::Variant::Aes192 => Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "AES keys of length 192 are not supported",
                    )),
                    crypto::aes::Variant::Aes256 => Ok(KeyMaterial::Aes(
                        crypto::aes::Key::Aes256(key_vec_to_array(key_bytes)?).into(),
                    )),
                }
            } else {
                Ok(AesImpl.generate_key(&mut RngImpl, variant, &[])?)
            }
        }
        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
            let key_size_bytes = get_key_size_in_bytes(key_type)?;
            if let Some(key_bytes) = key_random_bytes {
                if key_bytes.len() != key_size_bytes {
                    Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "for hmac key needed {} bytes, received {}",
                        key_bytes.len(),
                        key_size_bytes
                    ))
                } else {
                    Ok(KeyMaterial::Hmac(crypto::hmac::Key::new(key_bytes).into()))
                }
            } else {
                Ok(HmacImpl.generate_key(
                    &mut RngImpl,
                    kmr_wire::KeySizeInBits((key_size_bytes * 8).try_into().map_err(|_| {
                        hwcrypto_err!(
                            GENERIC_ERROR,
                            "shouldn't happen, key_size_bytes * 8 should fit on an u32"
                        )
                    })?),
                    &[],
                )?)
            }
        }
        _ => unimplemented!("key material other than AES and HMAC not implemented yet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{assert_ok, expect, expect_eq};
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        CryptoOperation::CryptoOperation,
        KeyPolicy::KeyPolicy,
        OperationParameters::OperationParameters,
    };

    use crate::cmd_processing::CmdProcessorContext;
    use crate::tests::connection_info;

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
        let key_material = generate_key_material(&policy.keyType, None);
        expect!(key_material.is_ok(), "couldn't retrieve key material");
        let key_material = key_material.unwrap();
        let check_result = check_key_material_with_policy(&key_material, &policy);
        expect!(check_result.is_ok(), "wrong key type");
    }

    #[test]
    fn expiration_time_creation() {
        let expiration_time = ExpirationTime::new(10).expect("couldn't create expiration time");
        expect!(
            expiration_time.check_validity().expect("couldn't check validity"),
            "expiration time should have been valid"
        );
    }

    #[test]
    fn expiration_time_serialization() {
        let mut key_metadata = KeyHeaderMetadata::new();
        expect!(
            !key_metadata.expiration_time_set(),
            "expiration time should not have been set by default"
        );
        expect!(
            key_metadata.expiration_time_valid().expect("couldn't check validity"),
            "expiration time should be valid if it has not been set"
        );
        let cbor_metadata =
            key_metadata.get_metadata_as_cbor().expect("couldn't serialize metadata");
        key_metadata.set_metadata_from_cbor(cbor_metadata).expect("couldn't set metadata back");
        expect!(
            !key_metadata.expiration_time_set(),
            "expiration time should not have been set by default"
        );
        expect!(
            key_metadata.expiration_time_valid().expect("couldn't check validity"),
            "expiration time should be valid if it has not been set"
        );

        key_metadata.set_expiration_time(10).expect("couldn't set expiration time");
        expect!(
            key_metadata.expiration_time_set(),
            "expiration time should have been set at this point"
        );
        expect!(
            key_metadata.expiration_time_valid().expect("couldn't check validity"),
            "expiration time should be valid"
        );
        let cbor_metadata =
            key_metadata.get_metadata_as_cbor().expect("couldn't serialize metadata");
        key_metadata.set_metadata_from_cbor(cbor_metadata).expect("couldn't set metadata back");
        expect!(
            key_metadata.expiration_time_set(),
            "expiration time should have been set at this point"
        );
        expect!(
            key_metadata.expiration_time_valid().expect("couldn't check validity"),
            "expiration time should be valid"
        );
    }

    #[test]
    fn expiration_time_on_exported_token() {
        let usage = KeyUse::ENCRYPT;
        let key_type = KeyType::AES_256_GCM;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let uuid = connection_info();
        let key = OpaqueKey::generate_opaque_key(&policy, &uuid).expect("couldn't generate key");
        let hw_device_key = HwCryptoKey::new_binder(uuid);
        let sealing_dice_policy =
            hw_device_key.getCurrentDicePolicy().expect("couldn't get sealing policy");
        let token =
            key.getShareableToken(sealing_dice_policy.as_slice()).expect("couldn't generate token");
        let imported_key_binder = hw_device_key
            .keyTokenImport(&token, sealing_dice_policy.as_slice())
            .expect("couldn't import back token");
        let imported_key: OpaqueKey =
            (&imported_key_binder).try_into().expect("couldn't cast back key");
        expect!(
            imported_key.expiration_time_set().expect("couldn't check if expiration time was set"),
            "expiration time should have been set"
        );
        expect!(imported_key.expiration_time_valid().is_ok(), "expiration time should be valid");
    }

    #[test]
    fn aes_simple_test_expired_key() {
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let uuid = connection_info();
        let key = OpaqueKey::generate_opaque_key(&policy, &uuid).expect("couldn't generate key");
        let key: OpaqueKey = (&key).try_into().expect("couldn't cast back key");
        key.set_expiration_time(0).expect("couldn't set up expiration time");
        let binder_key = BnOpaqueKey::new_binder(key, binder::BinderFeatures::default());

        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(binder_key), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "shouldn't be able to run an operation with an expired key"
        )
    }

    #[test]
    fn protection_id_can_be_set() {
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let uuid = connection_info();
        let key =
            assert_ok!(OpaqueKey::generate_opaque_key(&policy, &uuid), "couldn't generate key");
        assert_ok!(
            key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &[OperationType::WRITE]),
            "couldn't set protectionID"
        )
    }
}
