/*
 * Copyright (C) 2025 The Android Open Source Project
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

//! utilities to interact with hwcryptohal from Android

extern crate alloc;

use alloc::collections::btree_set::BTreeSet;
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::{
    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
};
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use android_hardware_security_see_hwcrypto::binder;

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode;

/// Macro helper to wrap an AIDL enum and provide conversion implementations for it. It could
/// potentially be re-written using a procedural derive macro, but using a macro_rules for now for
/// simplicity.
/// It provides conversion helpers from u64 and from Ciborium::Integer types and should have the
/// following form:
///
/// aidl_enum_wrapper! {
///     aidl_name: AidlEnumName,
///     wrapper_name: NewRustEnumName,
///     fields: [AIDL_FIELD_1, AIDL_FIELD_2,...]
/// }
///
#[macro_export]
macro_rules! aidl_enum_wrapper {
    (aidl_name: $aidl_name:ident, wrapper_name: $wrapper_name:ident, fields: [$($field:ident),+ $(,)*]$(,)?) => {
        /// newtype wrapping the original type
        #[derive(Debug, Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $wrapper_name(pub $aidl_name);

        impl From<$wrapper_name> for $aidl_name {
            fn from(value: $wrapper_name) -> Self {
                value.0
            }
        }

        impl TryFrom<$aidl_name> for $wrapper_name {
            type Error = android_hardware_security_see_hwcrypto::binder::Status;

            fn try_from(value: $aidl_name) -> Result<Self, Self::Error> {
                let val = $wrapper_name(value);
                val.check_value()?;
                Ok(val)
            }
        }

        impl TryFrom<u64> for $wrapper_name {
            type Error = android_hardware_security_see_hwcrypto::binder::Status;

            fn try_from(value: u64) -> Result<Self, Self::Error> {
                let val = match value {
                    $(x if x == $aidl_name::$field.0 as u64 =>Ok($aidl_name::$field)),+,
                    _ => Err(
                        android_hardware_security_see_hwcrypto::binder::Status::new_service_specific_error(android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode::SERIALIZATION_ERROR, Some(c"unsupported COSE enum label val"))
                    ),
                }?;
                Ok($wrapper_name(val))
            }
        }

        impl TryFrom<ciborium::value::Integer> for $wrapper_name {
            type Error = coset::CoseError;

            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
                let value: u64 = value.try_into()?;
                value.try_into().map_err(|_| coset::CoseError::EncodeFailed)
            }
        }

        impl From<$wrapper_name> for ciborium::value::Integer {
            fn from(value: $wrapper_name) -> Self {
                (value.0.0 as u64).into()
            }
        }

        impl $wrapper_name {
            fn check_value(&self) -> Result<(), android_hardware_security_see_hwcrypto::binder::Status>  {
                // `TryInto` from a u64 will return an error if the enum value
                // is not one of the declared ones in `fields`
                let _: $wrapper_name =  (self.0.0 as u64).try_into()?;
                Ok(())
            }
        }
    }
}

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
            type Error = android_hardware_security_see_hwcrypto::binder::Status;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                match value {
                    $(x if x == $name::$field as i64 => Ok($name::$field)),+,
                    _ => Err(
                        android_hardware_security_see_hwcrypto::binder::Status::new_service_specific_error(android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::types::HalErrorCode::SERIALIZATION_ERROR, Some(c"unsupported COSE enum label val"))
                    ),
                }
            }
        }

        impl TryFrom<ciborium::value::Integer> for $name {
            type Error = coset::CoseError;

            fn try_from(value: ciborium::value::Integer) -> Result<Self, Self::Error> {
                let value: i64 = value.try_into()?;
                value.try_into().map_err(|_| coset::CoseError::EncodeFailed)
            }
        }
    }
}
aidl_enum_wrapper! {
    aidl_name: KeyUse,
    wrapper_name: KeyUseSerializable,
    fields: [ENCRYPT, DECRYPT, ENCRYPT_DECRYPT, SIGN, DERIVE, WRAP]
}

aidl_enum_wrapper! {
    aidl_name: KeyLifetime,
    wrapper_name: KeyLifetimeSerializable,
    fields: [EPHEMERAL, HARDWARE, PORTABLE]
}

aidl_enum_wrapper! {
    aidl_name: KeyType,
    wrapper_name: KeyTypeSerializable,
    fields: [AES_128_CBC_NO_PADDING, AES_128_CBC_PKCS7_PADDING, AES_128_CTR, AES_128_GCM, AES_128_CMAC,
    AES_256_CBC_NO_PADDING, AES_256_CBC_PKCS7_PADDING, AES_256_CTR, AES_256_GCM, AES_256_CMAC,
    HMAC_SHA256, HMAC_SHA512,
    RSA2048_PKCS1_5_SHA256, RSA2048_PSS_SHA256, ECC_NIST_P256_SIGN_NO_PADDING, ECC_NIST_P256_SIGN_SHA256,
    ECC_NIST_P521_SIGN_NO_PADDING, ECC_NIST_P521_SIGN_SHA512,
    ECC_ED25519_SIGN]
}

aidl_enum_wrapper! {
    aidl_name: KeyPermissions,
    wrapper_name: KeyPermissionsSerializable,
    fields: [ALLOW_EPHEMERAL_KEY_WRAPPING, ALLOW_HARDWARE_KEY_WRAPPING, ALLOW_PORTABLE_KEY_WRAPPING]
}

#[derive(Debug, PartialEq)]
struct SerializableKeyPolicy {
    key_lifetime: KeyLifetimeSerializable,
    key_permissions: BTreeSet<KeyPermissionsSerializable>,
    key_usage: KeyUseSerializable,
    key_type: KeyTypeSerializable,
    management_key: bool,
}

impl SerializableKeyPolicy {
    fn new(key_policy: &KeyPolicy) -> Result<Self, binder::Status> {
        let mut key_permissions = BTreeSet::new();
        for permission in &key_policy.keyPermissions {
            key_permissions.insert(KeyPermissionsSerializable(*permission));
        }
        Ok(Self {
            key_lifetime: KeyLifetimeSerializable(key_policy.keyLifetime),
            key_permissions,
            key_usage: KeyUseSerializable(key_policy.usage),
            key_type: KeyTypeSerializable(key_policy.keyType),
            management_key: key_policy.keyManagementKey,
        })
    }
}

impl TryFrom<&KeyPolicy> for SerializableKeyPolicy {
    type Error = binder::Status;

    fn try_from(value: &KeyPolicy) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<KeyPolicy> for SerializableKeyPolicy {
    type Error = binder::Status;

    fn try_from(value: KeyPolicy) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SerializableKeyPolicy> for KeyPolicy {
    type Error = binder::Status;

    fn try_from(value: &SerializableKeyPolicy) -> Result<Self, Self::Error> {
        let mut key_permissions = Vec::new();
        key_permissions.try_reserve(value.key_permissions.len()).map_err(|_| {
            binder::Status::new_service_specific_error(
                HalErrorCode::ALLOCATION_ERROR,
                Some(c"couldn't allocate permissions array"),
            )
        })?;
        // permissions on the returned key policy will be sorted because they are retrieved that
        // way from the SerializableKeyPolicy
        for permission in &value.key_permissions {
            key_permissions.push((*permission).into());
        }
        Ok(Self {
            keyLifetime: value.key_lifetime.into(),
            keyPermissions: key_permissions,
            usage: value.key_usage.into(),
            keyType: value.key_type.into(),
            keyManagementKey: value.management_key,
        })
    }
}

impl TryFrom<SerializableKeyPolicy> for KeyPolicy {
    type Error = binder::Status;

    fn try_from(value: SerializableKeyPolicy) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

cose_enum_gen! {
    enum HeaderCoseLabels {
        KeyUsage = -65701,
        KeyLifetime = -65702,
        KeyPermissions = -65703,
        KeyType = -65704,
        ManagementKey = -65705,
    }
}

impl AsCborValue for SerializableKeyPolicy {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        let key = Value::Integer((HeaderCoseLabels::KeyLifetime as i64).into());
        let value = Value::Integer(self.key_lifetime.into());
        cbor_map.try_reserve_exact(5).map_err(|_| CoseError::EncodeFailed)?;
        cbor_map.push((key, value));

        // Creating key permissions array
        // We need this array to always be sorted so the created CBOR structure will always match
        // if the input vector has the same permissions, this is currently provided by
        // `BTreeSet::into_iter` always returning the elements ordered in ascending order.
        let mut permissions = Vec::new();
        permissions.try_reserve(self.key_permissions.len()).map_err(|_| CoseError::EncodeFailed)?;
        for permission in self.key_permissions.into_iter() {
            permissions.push(Value::Integer(permission.into()));
        }
        let key = Value::Integer((HeaderCoseLabels::KeyPermissions as i64).into());
        let value = Value::Array(permissions);
        cbor_map.push((key, value));

        let key = Value::Integer((HeaderCoseLabels::KeyUsage as i64).into());
        let value = Value::Integer(self.key_usage.into());
        cbor_map.push((key, value));

        let key = Value::Integer((HeaderCoseLabels::KeyType as i64).into());
        let value = Value::Integer(self.key_type.into());
        cbor_map.push((key, value));

        let key = Value::Integer((HeaderCoseLabels::ManagementKey as i64).into());
        let value = Value::Bool(self.management_key);
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let key_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;

        let mut key_lifetime: Option<KeyLifetimeSerializable> = None;
        let mut key_permissions: Option<BTreeSet<KeyPermissionsSerializable>> = None;
        let mut key_usage: Option<KeyUseSerializable> = None;
        let mut key_type: Option<KeyTypeSerializable> = None;
        let mut management_key: Option<bool> = None;

        for (map_key, map_val) in key_policy {
            let key = map_key.into_integer().map_err(|_| CoseError::ExtraneousData)?;
            match key.try_into()? {
                HeaderCoseLabels::KeyLifetime => {
                    key_lifetime = Some(
                        map_val
                            .as_integer()
                            .ok_or(CoseError::EncodeFailed)?
                            .try_into()
                            .map_err(|_| CoseError::EncodeFailed)?,
                    );
                }
                HeaderCoseLabels::KeyPermissions => {
                    let mut permissions = BTreeSet::new();
                    for permission in map_val.as_array().ok_or(CoseError::EncodeFailed)? {
                        permissions.insert(
                            permission
                                .as_integer()
                                .ok_or(CoseError::EncodeFailed)?
                                .try_into()
                                .map_err(|_| CoseError::EncodeFailed)?,
                        );
                    }
                    key_permissions = Some(permissions);
                }
                HeaderCoseLabels::KeyUsage => {
                    key_usage = Some(
                        map_val
                            .as_integer()
                            .ok_or(CoseError::EncodeFailed)?
                            .try_into()
                            .map_err(|_| CoseError::EncodeFailed)?,
                    );
                }
                HeaderCoseLabels::KeyType => {
                    key_type = Some(
                        map_val
                            .as_integer()
                            .ok_or(CoseError::EncodeFailed)?
                            .try_into()
                            .map_err(|_| CoseError::EncodeFailed)?,
                    );
                }
                HeaderCoseLabels::ManagementKey => {
                    management_key = Some(map_val.as_bool().ok_or(CoseError::EncodeFailed)?);
                }
            }
        }

        let key_lifetime = key_lifetime.ok_or(CoseError::EncodeFailed)?;
        let key_permissions = key_permissions.ok_or(CoseError::EncodeFailed)?;
        let key_usage = key_usage.ok_or(CoseError::EncodeFailed)?;
        let key_type = key_type.ok_or(CoseError::EncodeFailed)?;
        let management_key = management_key.ok_or(CoseError::EncodeFailed)?;

        Ok(SerializableKeyPolicy {
            key_lifetime,
            key_permissions,
            key_usage,
            key_type,
            management_key,
        })
    }
}

/// Mask used for valid AES key uses
pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
/// Mask used for valid HMAC key uses
pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;

/// checks if the values contained on `key_policy` are valid
pub fn check_key_policy_values(key_policy: &KeyPolicy) -> Result<(), binder::Status> {
    match key_policy.keyType {
        KeyType::AES_128_CBC_NO_PADDING
        | KeyType::AES_128_CBC_PKCS7_PADDING
        | KeyType::AES_128_CTR
        | KeyType::AES_128_GCM
        | KeyType::AES_256_CBC_NO_PADDING
        | KeyType::AES_256_CBC_PKCS7_PADDING
        | KeyType::AES_256_CTR
        | KeyType::AES_256_GCM => {
            if (key_policy.usage.0 & !AES_SYMMETRIC_KEY_USES_MASK) != 0 {
                Err(binder::Status::new_service_specific_error(
                    HalErrorCode::BAD_PARAMETER,
                    Some(c"usage not supported for AES symmetric key"),
                ))
            } else {
                Ok(())
            }
        }
        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
            if (key_policy.usage.0 & !HMAC_KEY_USES_MASK) != 0 {
                Err(binder::Status::new_service_specific_error(
                    HalErrorCode::BAD_PARAMETER,
                    Some(c"usage not supported for HMAC key"),
                ))
            } else {
                Ok(())
            }
        }
        KeyType::AES_128_CMAC
        | KeyType::AES_256_CMAC
        | KeyType::RSA2048_PSS_SHA256
        | KeyType::RSA2048_PKCS1_5_SHA256
        | KeyType::ECC_NIST_P256_SIGN_NO_PADDING
        | KeyType::ECC_NIST_P256_SIGN_SHA256
        | KeyType::ECC_NIST_P521_SIGN_NO_PADDING
        | KeyType::ECC_NIST_P521_SIGN_SHA512
        | KeyType::ECC_ED25519_SIGN => Err(binder::Status::new_service_specific_error(
            HalErrorCode::UNSUPPORTED,
            Some(c"key type not supported yet"),
        )),
        _ => Err(binder::Status::new_service_specific_error(
            HalErrorCode::BAD_PARAMETER,
            Some(c"unknown keytype provided"),
        )),
    }
}

/// transforms an AIDL key policy into a CBOR object and returns it as a byte array
pub fn key_policy_to_cbor(key_policy: &KeyPolicy) -> Result<Vec<u8>, binder::Status> {
    let serializable_key_policy: SerializableKeyPolicy = key_policy.try_into()?;
    serializable_key_policy
        .to_cbor_value()
        .map_err(|_| {
            binder::Status::new_service_specific_error(
                HalErrorCode::SERIALIZATION_ERROR,
                Some(c"couldn't transform to cbor"),
            )
        })?
        .to_vec()
        .map_err(|_| {
            binder::Status::new_service_specific_error(
                HalErrorCode::SERIALIZATION_ERROR,
                Some(c"couldn't serialize policy"),
            )
        })
}

/// transforms a CBOR object passed as a byte slice into an AIDL key policy
pub fn cbor_to_key_policy(cbor_key_policy: &[u8]) -> Result<KeyPolicy, binder::Status> {
    let policy = SerializableKeyPolicy::from_cbor_value(
        Value::from_slice(cbor_key_policy).map_err(|_| {
            binder::Status::new_service_specific_error(
                HalErrorCode::SERIALIZATION_ERROR,
                Some(c"couldn't serialize policy"),
            )
        })?,
    )
    .map_err(|_| {
        binder::Status::new_service_specific_error(
            HalErrorCode::SERIALIZATION_ERROR,
            Some(c"couldn't serialize policy"),
        )
    })?
    .try_into()?;
    check_key_policy_values(&policy)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{expect, expect_eq};

    #[test]
    fn serialize_policy() {
        let policy = KeyPolicy {
            usage: KeyUse::ENCRYPT,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_GCM,
            keyManagementKey: false,
        };

        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_ok(), "couldn't deserialize policy");
        let deserialized_policy = deserialization.unwrap();
        let policy: SerializableKeyPolicy = policy.try_into().unwrap();
        let deserialized_policy: SerializableKeyPolicy = (&deserialized_policy).try_into().unwrap();
        expect_eq!(policy, deserialized_policy, "policies should match");
    }

    #[test]
    fn bad_policies() {
        let mut policy = KeyPolicy {
            usage: KeyUse::SIGN,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_GCM,
            keyManagementKey: false,
        };
        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.usage = KeyUse::DERIVE;
        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.keyType = KeyType::HMAC_SHA256;
        policy.usage = KeyUse::ENCRYPT;
        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.usage = KeyUse::DECRYPT;
        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.keyType = KeyType::HMAC_SHA512;
        policy.usage = KeyUse::ENCRYPT_DECRYPT;
        let serialize_result = key_policy_to_cbor(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_to_key_policy(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
    }
}
