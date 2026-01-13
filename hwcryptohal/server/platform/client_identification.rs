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
use authmgr_be_lib::dice_policy_matching_service_client::get_dice_policy_matching_service;
use authmgr_dice_policy_matching_aidl::aidl::android::trusty::dice::policy::matching::PolicyMatchingResult::PolicyMatchingResult;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::{ClientIdentification, ClientPolicyCheck, DeviceKeys};
use log::{error, info};
use tipc::{ClientIdentifier, Uuid};

use crate::allowed_connections;
use crate::device_keys::bytes_to_version;

// enum values do not have a special meaning. HwCryptoHal server project uses for enums values above
// -64K and we assign different range of values to different files mainly to help with debug of
// serialized structures

// enum used for serializing the `ClientPolicyUuidBased`
cose_enum_gen! {
    enum UuidPolicyCoseLabels {
        Uuid = -65537,
        Version = -65538,
    }
}

// enum used for serializing the wrapper around the different identification policies
cose_enum_gen! {
    enum ClientPolicyCoseLabels {
        DicePolicyType = -65539,
        UuidPolicyType = -65540,
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
        bytes_to_version(crate::DeviceKeysImpl::get_caller_current_security_version()?.as_slice())
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

enum TaggedClientPolicy {
    DicePolicy(Vec<u8>),
    UuidPolicy(ClientPolicyUuidBased),
}

impl TaggedClientPolicy {
    fn new_dice_policy(policy: Vec<u8>) -> Self {
        Self::DicePolicy(policy)
    }

    fn new_uuid_policy(policy: ClientPolicyUuidBased) -> Self {
        Self::UuidPolicy(policy)
    }

    fn get_policy_as_cbor(self) -> Result<Value, CoseError> {
        match self {
            TaggedClientPolicy::DicePolicy(policy) => Ok(Value::Bytes(policy)),
            TaggedClientPolicy::UuidPolicy(policy) => policy.to_cbor_value(),
        }
    }

    fn verify_tag(&self, expected_type: ClientPolicyCoseLabels) -> Result<(), HwCryptoError> {
        let actual_type = self.get_tag();
        if expected_type != actual_type {
            error!(
                "Wrong policy type received. Expected {expected_type:?}, received{actual_type:?}"
            );
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "wrong policy type received. Expected {:?}, received{:?}",
                expected_type,
                actual_type
            ));
        }
        Ok(())
    }

    fn get_uuid_based_policy(&self) -> Result<&ClientPolicyUuidBased, HwCryptoError> {
        match self {
            TaggedClientPolicy::DicePolicy(_) => {
                Err(hwcrypto_err!(BAD_PARAMETER, "Tagged policy is not a uuid based one",))
            }
            TaggedClientPolicy::UuidPolicy(policy) => Ok(policy),
        }
    }

    fn get_dice_based_policy(&self) -> Result<&[u8], HwCryptoError> {
        match self {
            TaggedClientPolicy::DicePolicy(policy) => Ok(policy.as_slice()),
            TaggedClientPolicy::UuidPolicy(_) => {
                Err(hwcrypto_err!(BAD_PARAMETER, "Tagged policy is not a uuid based one",))
            }
        }
    }

    fn get_tag(&self) -> ClientPolicyCoseLabels {
        match self {
            TaggedClientPolicy::DicePolicy(_) => ClientPolicyCoseLabels::DicePolicyType,
            TaggedClientPolicy::UuidPolicy(_) => ClientPolicyCoseLabels::UuidPolicyType,
        }
    }
}

impl AsCborValue for TaggedClientPolicy {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(1).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((self.get_tag() as i64).into());
        let value = self.get_policy_as_cbor()?;
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let tagged_policy_map = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        if tagged_policy_map.len() != 1 {
            error!("Received tagged policy with wrong length");
            return Err(CoseError::EncodeFailed);
        }
        let mut tagged_client_policy: Option<TaggedClientPolicy> = None;
        for (map_key, map_val) in tagged_policy_map {
            match map_key {
                Value::Integer(key) => {
                    match key.try_into().map_err(|_| CoseError::EncodeFailed)? {
                        ClientPolicyCoseLabels::DicePolicyType => {
                            let policy =
                                map_val.into_bytes().map_err(|_| CoseError::EncodeFailed)?;
                            tagged_client_policy = Some(TaggedClientPolicy::new_dice_policy(policy))
                        }
                        ClientPolicyCoseLabels::UuidPolicyType => {
                            let policy = ClientPolicyUuidBased::from_cbor_value(map_val)?;
                            tagged_client_policy = Some(TaggedClientPolicy::new_uuid_policy(policy))
                        }
                    }
                }
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        tagged_client_policy.ok_or(CoseError::EncodeFailed)
    }
}

// Similar to ClientIdentification but uses concrete classes instead of byte vectors
trait TrustyClientIdentification {
    fn check_client_policy(
        &self,
        client_id: ClientIdentifier,
        client_policy: &TaggedClientPolicy,
    ) -> Result<ClientPolicyCheck, HwCryptoError>;

    fn get_client_current_policy(
        &self,
        client_id: ClientIdentifier,
    ) -> Result<TaggedClientPolicy, HwCryptoError>;

    fn client_can_access_keyslot(
        &self,
        client_id: ClientIdentifier,
        key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError>;

    fn get_policy_tag(&self) -> ClientPolicyCoseLabels;
}

struct TrustyUuidIdentification;

impl TrustyClientIdentification for TrustyUuidIdentification {
    fn check_client_policy(
        &self,
        client_id: ClientIdentifier,
        client_policy: &TaggedClientPolicy,
    ) -> Result<ClientPolicyCheck, HwCryptoError> {
        let uuid = get_uuid(client_id)?;
        let client_policy = client_policy.get_uuid_based_policy()?;
        let policy_matches = client_policy.check_identity(&uuid)?;
        // there is no reason to check versions if the client is different
        let policy_is_current = policy_matches && client_policy.is_policy_current()?;
        Ok(ClientPolicyCheck { policy_matches, policy_is_current })
    }

    fn get_client_current_policy(
        &self,
        client_id: ClientIdentifier,
    ) -> Result<TaggedClientPolicy, HwCryptoError> {
        let uuid = get_uuid(client_id)?;
        let untagged_policy = ClientPolicyUuidBased::new_current(uuid)?;
        Ok(TaggedClientPolicy::new_uuid_policy(untagged_policy))
    }

    fn client_can_access_keyslot(
        &self,
        client_id: ClientIdentifier,
        _key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError> {
        let uuid = get_uuid(client_id)?;
        // Simple uuid check for host uuid until we have DICE
        Ok(uuid.to_string() != "00000000-0000-0000-0000-000000000000")
    }

    fn get_policy_tag(&self) -> ClientPolicyCoseLabels {
        ClientPolicyCoseLabels::UuidPolicyType
    }
}

fn get_client_seq_number(client_id: ClientIdentifier) -> Result<i64, HwCryptoError> {
    match client_id {
        ClientIdentifier::ClientSeqNumber(seq_number) => Ok(seq_number),
        _ => {
            error!("Received {client_id:?} ID instead of an uuid");
            Err(hwcrypto_err!(
                BAD_PARAMETER,
                "received {:?} ID instead of client sequence number",
                client_id
            ))
        }
    }
}
struct TrustyDiceIdentification;

impl TrustyClientIdentification for TrustyDiceIdentification {
    fn check_client_policy(
        &self,
        client_id: ClientIdentifier,
        client_policy: &TaggedClientPolicy,
    ) -> Result<ClientPolicyCheck, HwCryptoError> {
        let service = get_dice_policy_matching_service()?;
        let seq_num = get_client_seq_number(client_id)?;
        let client_dice_policy = client_policy.get_dice_based_policy()?;
        let service_check_result =
            service.matchPolicy(seq_num, client_dice_policy).map_err(|e| {
                error!("Couldn't check dice policy: {e:?}");
                hwcrypto_err!(GENERIC_ERROR, "couldn't check dice policy {:?}", e)
            })?;
        let mut client_policy_check =
            ClientPolicyCheck { policy_matches: false, policy_is_current: false };
        if service_check_result != PolicyMatchingResult::FAILED {
            client_policy_check.policy_matches = true;
            if service_check_result == PolicyMatchingResult::SUCCESS {
                client_policy_check.policy_is_current = true;
            }
        }
        Ok(client_policy_check)
    }

    fn get_client_current_policy(
        &self,
        client_id: ClientIdentifier,
    ) -> Result<TaggedClientPolicy, HwCryptoError> {
        let service = get_dice_policy_matching_service()?;
        let seq_num = get_client_seq_number(client_id)?;
        let dice_policy = service.getPolicy(seq_num).map_err(|e| {
            error!("Couldn't get DICE policy: {e:?}");
            hwcrypto_err!(GENERIC_ERROR, "couldn't get DICE policy {:?}", e)
        })?;
        Ok(TaggedClientPolicy::new_dice_policy(dice_policy))
    }

    fn client_can_access_keyslot(
        &self,
        client_id: ClientIdentifier,
        key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError> {
        let service = get_dice_policy_matching_service()?;
        let seq_num = get_client_seq_number(client_id)?;
        let client_metadata = service.getClientMetaData(seq_num).map_err(|e| {
            error!("Couldn't get client metadata: {e:?}, sequence number: {seq_num}");
            hwcrypto_err!(GENERIC_ERROR, "couldn't get client metadata {:?}", e)
        })?;

        let connections = allowed_connections::get_allowed_connections(key_slot)?;
        let Some(allowed_connection) =
            connections.iter().find(|c| client_metadata.instanceIdentifier == c.instance_id)
        else {
            info!(
                "Access Denied: VM instance '{:?}' is not authorized for key slot {key_slot:?}.",
                client_metadata.instanceIdentifier
            );
            return Ok(false);
        };

        let Some(ref allowed_ids) = allowed_connection.client_ids else {
            info!(
                "Access Granted: Wildcard policy active for VM '{:?}' on key slot {key_slot:?}.",
                client_metadata.instanceIdentifier
            );
            return Ok(true);
        };

        let client_id_str = core::str::from_utf8(&client_metadata.clientIdentifier)
            .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "Invalid UTF-8 in client ID: {e:?}"))?;
        let client_uuid = Uuid::new_from_string(client_id_str)
            .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "Malformed client UUID string: {e:?}"))?;
        if allowed_ids.iter().any(|id| client_uuid == Uuid::from_bytes(id)) {
            info!(
                "Access Granted: TA '{}' in VM '{:?}' authorized for key slot {:?}.",
                client_uuid, client_metadata.instanceIdentifier, key_slot
            );
            Ok(true)
        } else {
            info!(
                "Access Denied: TA '{}' is not in the allowlist for VM '{:?}'.",
                client_uuid, client_metadata.instanceIdentifier
            );
            Ok(false)
        }
    }

    fn get_policy_tag(&self) -> ClientPolicyCoseLabels {
        ClientPolicyCoseLabels::DicePolicyType
    }
}

fn get_client_id(client_id_bytes: &[u8]) -> Result<ClientIdentifier, HwCryptoError> {
    let client_id = trusty_sys::TrustyPeerIdStorageSized::read_from_bytes(client_id_bytes);
    Ok(ClientIdentifier::try_from_c_repr(client_id.as_generic())?)
}

fn get_uuid(client_id: ClientIdentifier) -> Result<Uuid, HwCryptoError> {
    match client_id {
        ClientIdentifier::UUID(uuid) => Ok(uuid),
        _ => {
            error!("Received {client_id:?} ID instead of an uuid");
            Err(hwcrypto_err!(BAD_PARAMETER, "received {:?} ID instead of an uuid", client_id))
        }
    }
}

fn get_client_identifier(
    client_id_bytes: &[u8],
) -> Result<(ClientIdentifier, Box<dyn TrustyClientIdentification>), HwCryptoError> {
    let client_id = get_client_id(client_id_bytes)?;
    match client_id {
        ClientIdentifier::UUID(_) => Ok((client_id, Box::new(TrustyUuidIdentification))),
        ClientIdentifier::ClientSeqNumber(_) => Ok((client_id, Box::new(TrustyDiceIdentification))),
        ClientIdentifier::VMID(_) => {
            Err(hwcrypto_err!(BAD_PARAMETER, "VMIDs not supported for identification"))
        }
        _ => Err(hwcrypto_err!(BAD_PARAMETER, "Unsupported ClientIdentifier type")),
    }
}

/// Trusty implementation of the `ClientIdentification` trait.
pub struct TrustyClientIdentificationImpl;

impl ClientIdentification for TrustyClientIdentificationImpl {
    fn check_client_policy(
        client_id: &[u8],
        client_policy: &[u8],
    ) -> Result<ClientPolicyCheck, HwCryptoError> {
        let tagged_client_policy =
            TaggedClientPolicy::from_cbor_value(Value::from_slice(client_policy)?)?;
        let (client_id, client_identifier) = get_client_identifier(client_id)?;
        tagged_client_policy.verify_tag(client_identifier.get_policy_tag())?;
        client_identifier.check_client_policy(client_id, &tagged_client_policy)
    }

    fn get_client_current_policy(client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
        let (client_id, client_identifier) = get_client_identifier(client_id)?;
        let policy = client_identifier.get_client_current_policy(client_id)?;
        Ok(policy.to_cbor_value()?.to_vec()?)
    }

    fn client_can_access_keyslot(
        client_id: &[u8],
        key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError> {
        let (client_id, client_identifier) = get_client_identifier(client_id)?;
        client_identifier.client_can_access_keyslot(client_id, key_slot)
    }
}
