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

//! Implementation of the `IHwCryptoKey` AIDL interface. It can be use to generate and
//! retrieve device specific keys.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    types::{KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse},
    IHwCryptoKey::{
        BnHwCryptoKey, DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
        DeviceKeyId::DeviceKeyId, DiceBoundDerivationKey::DiceBoundDerivationKey,
        DiceBoundKeyResult::DiceBoundKeyResult,
        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
    },
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see::binder;
use ciborium::{cbor, Value};
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwkey::{Hwkey, KdfVersion};
use tipc::Uuid;

use crate::cose_enum_gen;
use crate::opaque_key;
use crate::service_encryption_key::{self, EncryptionHeader};

const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";
const DICE_BOUND_POLICY_CTX: &[u8] = b"dice_bound";

// enum used for serializing the `VersionContext`
cose_enum_gen! {
    enum VersionContextCoseLabels {
        Uuid = -65537,
        Version = -65538,
    }
}

// TODO: `ConnectionInformation` will be opaque to the HwCrypto service once we have a connection
//        manager.
struct ConnectionInformation {
    uuid: Uuid,
}

// Mock version object to be used until we have more DICE support. It is based on the trusty version
// retrievable from HwKey and the uuid of the caller. `VersionContext`` encryption is similar to
// what KeyMint uses to wrap keys.
struct VersionContext {
    uuid: Uuid,
    version: u32,
    header: Option<EncryptionHeader>,
}

impl VersionContext {
    fn get_current_version() -> Result<u32, HwCryptoError> {
        service_encryption_key::get_service_current_version()
    }

    fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
        let header = Some(EncryptionHeader::generate()?);
        let version = Self::get_current_version()?;
        Ok(VersionContext { uuid, version, header })
    }

    fn new_current_encrypted(uuid: Uuid) -> Result<Vec<u8>, HwCryptoError> {
        let ctx = Self::new_current(uuid)?;
        Ok(ctx.encrypt_context()?)
    }

    fn check_version(&self) -> Result<(), HwCryptoError> {
        let current_version = Self::get_current_version()?;
        if self.version > current_version {
            return Err(hwcrypto_err!(BAD_PARAMETER, "version is not valid"));
        }
        Ok(())
    }

    fn check_context(&self, connection: ConnectionInformation) -> Result<(), HwCryptoError> {
        if connection.uuid != self.uuid {
            return Err(hwcrypto_err!(BAD_PARAMETER, "uuid mismatch"));
        }
        self.check_version()
    }

    fn check_encrypted_context(
        encrypted_ctx: &[u8],
        connection: ConnectionInformation,
    ) -> Result<(), HwCryptoError> {
        let context = Self::decrypt_context(encrypted_ctx)?;
        context.check_context(connection)
    }

    fn is_context_current(encrypted_ctx: &[u8]) -> Result<bool, HwCryptoError> {
        let context = Self::decrypt_context(encrypted_ctx)?;
        let current_version = Self::get_current_version()?;
        Ok(context.version >= current_version)
    }

    fn decrypt_context(encrypted_context: &[u8]) -> Result<Self, HwCryptoError> {
        let (version_ctx_header, decrypted_data) =
            EncryptionHeader::decrypt_content_service_encryption_key(
                encrypted_context,
                DEVICE_KEY_CTX,
            )?;

        let mut version_context =
            VersionContext::from_cbor_value(Value::from_slice(&decrypted_data[..])?)?;
        version_context.header = Some(version_ctx_header);
        Ok(version_context)
    }

    fn encrypt_context(mut self) -> Result<Vec<u8>, HwCryptoError> {
        let header = self.header.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "no header found"))?;
        header.encrypt_content_service_encryption_key(DEVICE_KEY_CTX, self)
    }

    fn get_stable_context(encrypted_context: &[u8]) -> Result<Vec<u8>, HwCryptoError> {
        let decrypted_context = Self::decrypt_context(encrypted_context)?;
        Ok(decrypted_context.to_cbor_value()?.to_vec()?)
    }
}

impl AsCborValue for VersionContext {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        cbor!({
            (VersionContextCoseLabels::Uuid as i64) => self.uuid.to_string(),
            (VersionContextCoseLabels::Version as i64) => self.version,
        })
        .map_err(|_| CoseError::ExtraneousData)
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let version_context = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        let mut uuid: Option<Uuid> = None;
        let mut version: Option<u32> = None;
        for (map_key, map_val) in version_context {
            match map_key {
                Value::Integer(key) => {
                    match key.try_into().map_err(|_| CoseError::EncodeFailed)? {
                        VersionContextCoseLabels::Uuid => {
                            let uuid_str =
                                map_val.into_text().map_err(|_| CoseError::EncodeFailed)?;
                            let parsed_uuid = Uuid::new_from_string(&uuid_str)
                                .map_err(|_| CoseError::EncodeFailed)?;
                            uuid = Some(parsed_uuid);
                        }
                        VersionContextCoseLabels::Version => {
                            let parsed_version = map_val
                                .into_integer()
                                .map_err(|_| CoseError::EncodeFailed)?
                                .try_into()
                                .map_err(|_| CoseError::ExtraneousData)?;
                            version = Some(parsed_version);
                        }
                    }
                }
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        let uuid = uuid.ok_or(CoseError::EncodeFailed)?;
        let version = version.ok_or(CoseError::EncodeFailed)?;
        // Header travels in the clear, the decoded section only contains the encrypted fields
        Ok(VersionContext { uuid, version, header: None })
    }
}

/// The `IHwCryptoKey` implementation.
#[derive(Debug)]
pub struct HwCryptoKey {
    #[allow(dead_code)]
    uuid: Uuid,
}

impl binder::Interface for HwCryptoKey {}

impl HwCryptoKey {
    pub(crate) fn new_binder(uuid: Uuid) -> binder::Strong<dyn IHwCryptoKey> {
        let hwcrypto_device_key = HwCryptoKey { uuid };
        BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
    }

    fn derive_dice_policy_bound_key(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        dice_policy_for_key_version: &[u8],
    ) -> Result<DiceBoundKeyResult, HwCryptoError> {
        // Verifying provided DICE policy
        let connection_info = ConnectionInformation { uuid: self.uuid.clone() };
        VersionContext::check_encrypted_context(dice_policy_for_key_version, connection_info)?;
        // Getting back a stable DICE policy for context, so keys derived with the same version will
        // match
        let dice_context = VersionContext::get_stable_context(dice_policy_for_key_version)?;
        let mut concat_context = Vec::<u8>::new();
        concat_context.try_reserve(DICE_BOUND_POLICY_CTX.len())?;
        concat_context.extend_from_slice(DICE_BOUND_POLICY_CTX);
        concat_context.try_reserve(dice_context.len())?;
        concat_context.extend_from_slice(dice_context.as_slice());

        // The returned key will only be used for derivation, so fixing tis type to HMAC_SHA256
        let key_type = KeyType::HMAC_SHA256;
        let key_size = opaque_key::get_key_size_in_bytes(&key_type)?;
        // Create an array big enough to hold the bytes of the derived key material
        let mut derived_key = Vec::<u8>::new();
        derived_key.try_reserve(key_size)?;
        derived_key.resize(key_size, 0);

        match derivation_key {
            DiceBoundDerivationKey::KeyId(key_id) => {
                let hwkey_session = Hwkey::open().map_err(|e| {
                    hwcrypto_err!(GENERIC_ERROR, "could not connect to hwkey service {:?}", e)
                })?;
                let session_req = match *key_id {
                    DeviceKeyId::DEVICE_BOUND_KEY => {
                        Ok(hwkey_session.derive_key_req().unique_key())
                    }
                    DeviceKeyId::BATCH_KEY => Ok(hwkey_session.derive_key_req().shared_key()),
                    _ => Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id)),
                }?;

                session_req
                    .kdf(KdfVersion::Best)
                    .derive(&concat_context, &mut derived_key[..])
                    .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to derive key {:?}", e))?;

                let policy = KeyPolicy {
                    usage: KeyUse::DERIVE,
                    keyLifetime: KeyLifetime::EPHEMERAL,
                    keyPermissions: Vec::new(),
                    keyType: key_type,
                    keyManagementKey: false,
                };
                // Create a new opaque key from the generated key material
                let km = opaque_key::generate_key_material(&policy.keyType, Some(derived_key))?;
                let key = opaque_key::OpaqueKey::new_binder(&policy, km)
                    .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to create key {:?}", e))?;
                let dice_policy_current =
                    VersionContext::is_context_current(dice_policy_for_key_version)?;
                Ok(DiceBoundKeyResult {
                    diceBoundKey: Some(key),
                    dicePolicyWasCurrent: dice_policy_current,
                })
            }
            DiceBoundDerivationKey::OpaqueKey(_opaque_key) => Err(hwcrypto_err!(
                UNSUPPORTED,
                "derivation of DICE bound keys using opaque keys not supported yet"
            )),
        }
    }
}

impl IHwCryptoKey for HwCryptoKey {
    fn deriveCurrentDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
    ) -> binder::Result<DiceCurrentBoundKeyResult> {
        let dice_policy = VersionContext::new_current_encrypted(self.uuid.clone())?;
        let derived_key_result = self.derive_dice_policy_bound_key(derivation_key, &dice_policy)?;
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: policy_current } =
            derived_key_result;
        if !policy_current {
            return Err(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("generated a policy that was not the latest"),
            ));
        }
        Ok(DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: dice_policy })
    }

    fn deriveDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        dice_policy_for_key_version: &[u8],
    ) -> binder::Result<DiceBoundKeyResult> {
        Ok(self.derive_dice_policy_bound_key(derivation_key, dice_policy_for_key_version)?)
    }

    fn deriveKey(&self, _parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("operation has not been implemented yet"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{assert_ok, expect};

    #[test]
    fn derived_dice_bound_keys() {
        let hw_device_key = HwCryptoKey::new_binder(
            Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap(),
        );

        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
        let DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(policy.len() > 0, "should have received a DICE policy");
        let key_and_policy =
            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&derivation_key, &policy));
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: current_policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(current_policy, "policy should have been current");

        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::BATCH_KEY);
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
        let DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(policy.len() > 0, "should have received a DICE policy");
        let key_and_policy =
            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&derivation_key, &policy));
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: current_policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(current_policy, "policy should have been current");
    }
}
