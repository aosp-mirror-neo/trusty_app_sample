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

//! KeyPolicy serialization facilities

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    KeyLifetime::KeyLifetime, KeyPermissions::KeyPermissions, KeyType::KeyType, KeyUse::KeyUse,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};

use crate::{aidl_enum_wrapper, cose_enum_gen};
use crate::{err::HwCryptoError, hwcrypto_err};

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

struct SerializableKeyPolicy {
    key_lifetime: KeyLifetimeSerializable,
    key_permissions: Vec<KeyPermissionsSerializable>,
    key_usage: KeyUseSerializable,
    key_type: KeyTypeSerializable,
    management_key: bool,
}

impl SerializableKeyPolicy {
    fn new(key_policy: &KeyPolicy) -> Result<Self, crate::err::HwCryptoError> {
        let mut key_permissions = Vec::new();
        key_permissions.try_reserve(key_policy.keyPermissions.len())?;
        for permission in &key_policy.keyPermissions {
            key_permissions.push(KeyPermissionsSerializable(*permission));
        }
        key_permissions.sort();
        key_permissions.dedup();
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
    type Error = crate::err::HwCryptoError;

    fn try_from(value: &KeyPolicy) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&SerializableKeyPolicy> for KeyPolicy {
    type Error = crate::err::HwCryptoError;

    fn try_from(value: &SerializableKeyPolicy) -> Result<Self, Self::Error> {
        let mut key_permissions = Vec::new();
        key_permissions.try_reserve(value.key_permissions.len())?;
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
    type Error = crate::err::HwCryptoError;

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
        // Because we sort the array when we create a `SerializableKeyPolicy` and never modify it,
        // this array will be sorted at this point so the created CBOR structure will always match
        // if the input vector has the same permissions.
        let mut permissions = Vec::new();
        permissions.try_reserve(self.key_permissions.len()).map_err(|_| CoseError::EncodeFailed)?;
        for permission in self.key_permissions {
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
        let value = Value::Bool(self.management_key.into());
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let key_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;

        let mut key_lifetime: Option<KeyLifetimeSerializable> = None;
        let mut key_permissions: Option<Vec<KeyPermissionsSerializable>> = None;
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
                    let mut permissions = Vec::new();
                    for permission in map_val.as_array().ok_or(CoseError::EncodeFailed)? {
                        permissions.try_reserve(1).map_err(|_| CoseError::EncodeFailed)?;
                        permissions.push(
                            permission
                                .as_integer()
                                .ok_or(CoseError::EncodeFailed)?
                                .try_into()
                                .map_err(|_| CoseError::EncodeFailed)?,
                        )
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

pub static AES_SYMMETRIC_KEY_USES_MASK: i32 = KeyUse::ENCRYPT_DECRYPT.0 | KeyUse::WRAP.0;
pub static HMAC_KEY_USES_MASK: i32 = KeyUse::DERIVE.0;

pub fn check_key_policy(key_policy: &KeyPolicy) -> Result<(), HwCryptoError> {
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
                Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "usage not supported for AES symmetric key: {}",
                    key_policy.usage.0
                ))
            } else {
                Ok(())
            }
        }
        KeyType::HMAC_SHA256 | KeyType::HMAC_SHA512 => {
            if (key_policy.usage.0 & !HMAC_KEY_USES_MASK) != 0 {
                Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "usage not supported for HMAC key: {}",
                    key_policy.usage.0
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
        | KeyType::ECC_ED25519_SIGN => {
            Err(hwcrypto_err!(UNSUPPORTED, "key type not supported yet"))
        }
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "unknown keytype provided {:?}", key_policy.keyType)),
    }
}

pub fn cbor_serialize_key_policy(key_policy: &KeyPolicy) -> Result<Vec<u8>, HwCryptoError> {
    let serializable_key_policy: SerializableKeyPolicy = key_policy.try_into()?;
    serializable_key_policy
        .to_cbor_value()?
        .to_vec()
        .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't serialize policy"))
}

pub fn cbor_policy_to_aidl(cbor_key_policy: &[u8]) -> Result<KeyPolicy, HwCryptoError> {
    let policy =
        SerializableKeyPolicy::from_cbor_value(Value::from_slice(cbor_key_policy)?)?.try_into()?;
    check_key_policy(&policy)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::expect;

    // Because KeyPolicy is defined on an AIDL file we cannot directly derive Eq on them, so
    // we need this function to do this work.
    fn policies_match(policy1: &KeyPolicy, policy2: &KeyPolicy) -> bool {
        let mut policy_matches = true;
        policy_matches &= policy1.usage == policy2.usage;
        policy_matches &= policy1.keyLifetime == policy2.keyLifetime;
        policy_matches &= policy1.keyType == policy2.keyType;
        policy_matches &= policy1.keyManagementKey == policy1.keyManagementKey;
        policy_matches &= policy1.keyPermissions.len() == policy2.keyPermissions.len();
        for permission in &policy1.keyPermissions {
            policy_matches &= policy2.keyPermissions.contains(permission);
        }
        policy_matches
    }

    #[test]
    fn serialize_policy() {
        let policy = KeyPolicy {
            usage: KeyUse::ENCRYPT,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_GCM,
            keyManagementKey: false,
        };

        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_ok(), "couldn't deserialize policy");
        let deserialized_policy = deserialization.unwrap();
        expect!(policies_match(&policy, &deserialized_policy), "policies should match");
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
        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.usage = KeyUse::DERIVE;
        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.keyType = KeyType::HMAC_SHA256;
        policy.usage = KeyUse::ENCRYPT;
        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.usage = KeyUse::DECRYPT;
        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");

        policy.keyType = KeyType::HMAC_SHA512;
        policy.usage = KeyUse::ENCRYPT_DECRYPT;
        let serialize_result = cbor_serialize_key_policy(&policy);
        expect!(serialize_result.is_ok(), "couldn't serialize policy");
        let serialized_policy = serialize_result.unwrap();
        let deserialization = cbor_policy_to_aidl(serialized_policy.as_slice());
        expect!(deserialization.is_err(), "shouldn't be able to deserailize incorrect policy");
    }
}
