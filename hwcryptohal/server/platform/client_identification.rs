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

//! Module providing client identification functions.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::KeySlot::KeySlot;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::{ClientIdentification, ClientPolicyCheck, DeviceKeys};
use tipc::Uuid;

use crate::device_keys::bytes_to_version;

// enum used for serializing the `ClientPolicyUuidBased`
cose_enum_gen! {
    enum UuidPolicyCoseLabels {
        Uuid = -65537,
        Version = -65538,
    }
}

// Policy based on uuids for internal Trusty Connections. It is based on the Trusty security version
// retrievable from HwKey and the uuid of the caller. `ClientPolicyUuidBased` encryption is similar
// to what KeyMint uses to wrap keys.
struct ClientPolicyUuidBased {
    uuid: Uuid,
    version: u32,
}

impl ClientPolicyUuidBased {
    fn get_current_version() -> Result<u32, HwCryptoError> {
        let device_keys = crate::DeviceKeysImpl;
        bytes_to_version(device_keys.get_caller_current_security_version()?.as_slice())
    }

    fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
        let version = Self::get_current_version()?;
        Ok(ClientPolicyUuidBased { uuid, version })
    }

    fn check_identity(&self, uuid: &Uuid) -> Result<bool, HwCryptoError> {
        Ok(*uuid == self.uuid)
    }

    fn is_policy_current(&self) -> Result<bool, HwCryptoError> {
        let current_version = Self::get_current_version()?;
        Ok(self.version >= current_version)
    }
}

impl AsCborValue for ClientPolicyUuidBased {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((UuidPolicyCoseLabels::Uuid as i64).into());
        let value = Value::Text(self.uuid.to_string());
        cbor_map.push((key, value));

        let key = Value::Integer((UuidPolicyCoseLabels::Version as i64).into());
        let value = Value::Integer(self.version.into());
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let client_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        let mut uuid: Option<Uuid> = None;
        let mut version: Option<u32> = None;
        if client_policy.len() != 2 {
            return Err(CoseError::ExtraneousData);
        }
        for (map_key, map_val) in client_policy {
            match map_key {
                Value::Integer(key) => {
                    match key.try_into().map_err(|_| {
                        CoseError::UnexpectedItem("value not matching enum", "UuidPolicyCoseLabels")
                    })? {
                        UuidPolicyCoseLabels::Uuid => {
                            let uuid_str = map_val
                                .into_text()
                                .map_err(|_| CoseError::UnexpectedItem("other type", "string"))?;
                            let parsed_uuid = Uuid::new_from_string(&uuid_str)
                                .map_err(|_| CoseError::EncodeFailed)?;
                            uuid = Some(parsed_uuid);
                        }
                        UuidPolicyCoseLabels::Version => {
                            version = Some(
                                map_val
                                    .into_integer()
                                    .map_err(|_| {
                                        CoseError::UnexpectedItem("not an integer", "integer")
                                    })?
                                    .try_into()
                                    .map_err(|_| CoseError::OutOfRangeIntegerValue)?,
                            );
                        }
                    }
                }
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        let uuid = uuid.ok_or(CoseError::EncodeFailed)?;
        let version = version.ok_or(CoseError::EncodeFailed)?;
        Ok(ClientPolicyUuidBased { uuid, version })
    }
}

fn get_uuid(uuid_bytes: &[u8]) -> Result<Uuid, HwCryptoError> {
    let uuid_str = std::str::from_utf8(uuid_bytes)
        .map_err(|e| hwcrypto_err!(BAD_PARAMETER, "couldn't parse uuid {:?}", e))?;
    Ok(Uuid::new_from_string(uuid_str)?)
}

#[derive(Default)]
pub struct TrustyClientIdentification;

impl ClientIdentification for TrustyClientIdentification {
    fn check_client_policy(
        &self,
        client_id: &[u8],
        client_policy: &[u8],
    ) -> Result<ClientPolicyCheck, HwCryptoError> {
        let client_id = get_uuid(client_id)?;
        let client_policy =
            ClientPolicyUuidBased::from_cbor_value(Value::from_slice(client_policy)?)?;
        let policy_matches = client_policy.check_identity(&client_id)?;
        // there is no reason to check versions if the client is different
        let policy_is_current = policy_matches && client_policy.is_policy_current()?;
        Ok(ClientPolicyCheck { policy_matches, policy_is_current })
    }

    fn get_client_current_policy(&self, client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
        let client_id = get_uuid(client_id)?;
        Ok(ClientPolicyUuidBased::new_current(client_id)?.to_cbor_value()?.to_vec()?)
    }

    fn client_can_access_keyslot(
        &self,
        client_id: &[u8],
        _key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError> {
        let client_id = get_uuid(client_id)?;
        // Simple uuid check for host uuid until we have DICE
        Ok(client_id.to_string() != "00000000-0000-0000-0000-000000000000")
    }
}
