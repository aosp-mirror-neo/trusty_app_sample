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

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::{
        ExplicitKeyMaterial::ExplicitKeyMaterial, KeyLifetime::KeyLifetime, KeyType::KeyType,
        KeyUse::KeyUse, OpaqueKeyToken::OpaqueKeyToken,
    },
    IHwCryptoKey::{
        BnHwCryptoKey, DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
        DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
        DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey, KeySlot::KeySlot,
    },
    IHwCryptoOperations::IHwCryptoOperations,
    IOpaqueKey::IOpaqueKey,
    KeyPolicy::KeyPolicy,
};
use android_hardware_security_see_hwcrypto::binder;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable, CoseError};
use hwcryptohal_common::{cose_enum_gen, err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::DeviceKeys;
use hwcryptohalplatform::DeviceKeysImpl;
use tipc::Uuid;

use crate::helpers;
use crate::hwcrypto_operations::HwCryptoOperations;
use crate::opaque_key::{self, DerivationContext, HkdfOperationType, OpaqueKey};
use crate::service_encryption_key::{
    self, EncryptedContent, EncryptionHeader, EncryptionHeaderKey,
};

const DEVICE_KEY_CTX: &[u8] = b"device_key_derivation_contextKEK";

// enum used for serializing the `ClientPolicyWrapper`
cose_enum_gen! {
    enum ClientPolicyWrapperCoseLabels {
        Uuid = -65537,
        Version = -65538,
    }
}

// TODO: `ConnectionInformation` will be opaque to the HwCrypto service once we have a connection
//        manager.
struct ConnectionInformation {
    uuid: Uuid,
}

// Object containing the Client policy and device key version. It will encrypt and decrypt them when
// interacting with the client. The current policy is based on the trusty version retrievable from
// HwKey and the uuid of the caller. Dice will be added once we have support for it. The device key
// version is used to retrieve a unique versioned key tied to the HwCrypto server.
// `ClientPolicyWrapper` encryption is similar to what KeyMint uses to wrap
// keys. While the stable policy returned by the `ClientPolicyWrapper` only includes the client
// policy, the generation of the derivation key consumes both this stable policy and the device key
// version.
struct ClientPolicyWrapper {
    uuid: Uuid,
    version: u32,
    device_key_version: Vec<u8>,
    header: Option<EncryptionHeader>,
}

impl ClientPolicyWrapper {
    // decrypts and returns a new `ClientPolicyWrapper`
    fn from_encrypted_slice(encrypted_wrapped_policy: &[u8]) -> Result<Self, HwCryptoError> {
        let (wrapped_policy_header, decrypted_data) =
            EncryptionHeader::decrypt_content_service_encryption_key(
                encrypted_wrapped_policy,
                EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
                EncryptedContent::DicePolicy,
            )?;

        let mut wrapped_policy =
            ClientPolicyWrapper::from_cbor_value(Value::from_slice(&decrypted_data[..])?)?;
        wrapped_policy.header = Some(wrapped_policy_header);
        Ok(wrapped_policy)
    }

    // returns the current version of the platform device key service
    fn get_device_key_service_current_version() -> Result<Vec<u8>, HwCryptoError> {
        service_encryption_key::get_service_current_version()
    }

    // returns a new `ClientPolicyWrapper` with the version set to the current client version
    fn new_current(uuid: Uuid) -> Result<Self, HwCryptoError> {
        let header = Some(EncryptionHeader::generate(EncryptedContent::DicePolicy)?);
        let device_key_version = Self::get_device_key_service_current_version()?;
        // TODO: Temporary workaround while we move to DICE based authentication. This is removed
        //       on the CL on above this one.
        let version = hwcryptohalplatform::bytes_to_version(&device_key_version)?;
        Ok(ClientPolicyWrapper { uuid, device_key_version, version, header })
    }

    // checks that the client policy version is correct for the current client version
    fn check_version(&self) -> Result<(), HwCryptoError> {
        // TODO: Temporary workaround while we move to DICE based authentication. This is removed
        //       on the CL on above this one.
        let current_version = hwcryptohalplatform::bytes_to_version(
            Self::get_device_key_service_current_version()?.as_slice(),
        )?;
        if self.version > current_version {
            return Err(hwcrypto_err!(BAD_PARAMETER, "version is not valid"));
        }
        Ok(())
    }

    // checks that the client policy is valid for the current client
    fn check_client_policy(&self, connection: ConnectionInformation) -> Result<(), HwCryptoError> {
        if connection.uuid != self.uuid {
            return Err(hwcrypto_err!(BAD_PARAMETER, "uuid mismatch"));
        }
        self.check_version()
    }

    // returns whether the current client version is greater or equal than the policy version
    fn is_policy_current(&self) -> Result<bool, HwCryptoError> {
        let current_version = hwcryptohalplatform::bytes_to_version(
            Self::get_device_key_service_current_version()?.as_slice(),
        )?;
        Ok(self.version >= current_version)
    }

    // consumes a `ClientPolicyWrapper` and returns it encrypted
    fn encrypt(mut self) -> Result<Vec<u8>, HwCryptoError> {
        let header = self.header.take().ok_or(hwcrypto_err!(BAD_PARAMETER, "no header found"))?;
        header.encrypt_content_service_encryption_key(
            EncryptionHeaderKey::KeyGenerationContext(DEVICE_KEY_CTX),
            self,
        )
    }

    // returns both the client policy and the device key version contained by the
    // `ClientPolicyWrapper`
    fn get_client_and_device_key_policies(self) -> Result<(Vec<u8>, Vec<u8>), HwCryptoError> {
        // Need for a clone is removed on next CL, when device key version and policy are separated
        let device_key = self.device_key_version.clone();
        Ok((self.to_cbor_value()?.to_vec()?, device_key))
    }
}

impl AsCborValue for ClientPolicyWrapper {
    fn to_cbor_value(self) -> Result<Value, CoseError> {
        let mut cbor_map = Vec::<(Value, Value)>::new();
        cbor_map.try_reserve(2).map_err(|_| CoseError::EncodeFailed)?;

        let key = Value::Integer((ClientPolicyWrapperCoseLabels::Uuid as i64).into());
        let value = Value::Text(self.uuid.to_string());
        cbor_map.push((key, value));

        let key = Value::Integer((ClientPolicyWrapperCoseLabels::Version as i64).into());
        let value = Value::Bytes(self.device_key_version);
        cbor_map.push((key, value));

        Ok(Value::Map(cbor_map))
    }

    fn from_cbor_value(value: Value) -> Result<Self, CoseError> {
        let wrapped_policy = value.into_map().map_err(|_| CoseError::ExtraneousData)?;
        let mut uuid: Option<Uuid> = None;
        let mut version: Option<Vec<u8>> = None;
        for (map_key, map_val) in wrapped_policy {
            match map_key {
                Value::Integer(key) => {
                    match key.try_into().map_err(|_| CoseError::EncodeFailed)? {
                        ClientPolicyWrapperCoseLabels::Uuid => {
                            let uuid_str =
                                map_val.into_text().map_err(|_| CoseError::EncodeFailed)?;
                            let parsed_uuid = Uuid::new_from_string(&uuid_str)
                                .map_err(|_| CoseError::EncodeFailed)?;
                            uuid = Some(parsed_uuid);
                        }
                        ClientPolicyWrapperCoseLabels::Version => {
                            let parsed_version =
                                map_val.into_bytes().map_err(|_| CoseError::EncodeFailed)?;
                            version = Some(parsed_version);
                        }
                    }
                }
                _ => return Err(CoseError::ExtraneousData),
            }
        }
        let uuid = uuid.ok_or(CoseError::EncodeFailed)?;
        let device_key_version = version.ok_or(CoseError::EncodeFailed)?;
        let version = hwcryptohalplatform::bytes_to_version(&device_key_version)
            .map_err(|_| CoseError::EncodeFailed)?;
        // Header travels in the clear, the decoded section only contains the encrypted fields
        Ok(ClientPolicyWrapper { uuid, version, device_key_version, header: None })
    }
}

/// The `IHwCryptoKey` implementation.
#[derive(Debug)]
pub struct HwCryptoKey {
    pub(crate) uuid: Uuid,
}

impl binder::Interface for HwCryptoKey {}

impl HwCryptoKey {
    pub(crate) fn new_binder(uuid: Uuid) -> binder::Strong<dyn IHwCryptoKey> {
        let hwcrypto_device_key = HwCryptoKey { uuid };
        BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
    }

    // check_client_policy_owner shall only be false for creating internal keys that can be used
    // to seal content bounded to another party DICE policy
    pub(crate) fn derive_dice_policy_bound_key(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        client_policy_for_key_version: &[u8],
        check_client_policy_owner: bool,
    ) -> Result<DiceBoundKeyResult, HwCryptoError> {
        // Verifying provided DICE policy
        let connection_info: ConnectionInformation =
            ConnectionInformation { uuid: self.uuid.clone() };
        let wrapped_client_policy =
            ClientPolicyWrapper::from_encrypted_slice(client_policy_for_key_version)?;
        if check_client_policy_owner {
            wrapped_client_policy.check_client_policy(connection_info)?;
        }
        let client_policy_current = wrapped_client_policy.is_policy_current()?;
        // Getting back a stable DICE policy for context, so keys derived with the same version will
        // match
        let (caller_dice_policy, device_key_version) =
            wrapped_client_policy.get_client_and_device_key_policies()?;
        let mut op_context = DerivationContext::new(HkdfOperationType::DiceBoundDerivation)?;
        op_context.add_owned_binary_string(caller_dice_policy)?;
        let concat_context = op_context.create_key_derivation_context()?;

        // The returned key will only be used for derivation, so fixing tis type to HMAC_SHA256
        let key_type = KeyType::HMAC_SHA256;
        let key_size = opaque_key::get_key_size_in_bytes(&key_type)?;

        match derivation_key {
            DiceBoundDerivationKey::KeyId(key_id) => {
                if DeviceKeyId::DEVICE_BOUND_KEY != *key_id {
                    return Err(hwcrypto_err!(UNSUPPORTED, "unknown key id {:?}", key_id));
                }
                let derived_key = DeviceKeysImpl.derive_caller_unique_key(
                    concat_context.as_slice(),
                    device_key_version.as_slice(),
                    key_size,
                )?;

                let policy = KeyPolicy {
                    usage: KeyUse::DERIVE,
                    keyLifetime: KeyLifetime::HARDWARE,
                    keyPermissions: Vec::new(),
                    keyType: key_type,
                    keyManagementKey: false,
                };
                // Create a new opaque key from the generated key material
                let km = opaque_key::generate_key_material(&policy.keyType, Some(derived_key))?;
                let key = opaque_key::OpaqueKey::new_binder(&policy, km, self.uuid.clone())
                    .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to create key {:?}", e))?;
                Ok(DiceBoundKeyResult {
                    diceBoundKey: Some(key),
                    dicePolicyWasCurrent: client_policy_current,
                })
            }
            DiceBoundDerivationKey::OpaqueKey(_opaque_key) => Err(hwcrypto_err!(
                UNSUPPORTED,
                "derivation of DICE bound keys using opaque keys not supported yet"
            )),
        }
    }

    fn check_caller_can_access_keyslot(&self, _keyslot: KeySlot) -> Result<(), HwCryptoError> {
        // Simple uuid check for host uuid until we have DICE
        if self.uuid.to_string() == "00000000-0000-0000-0000-000000000000" {
            Err(hwcrypto_err!(UNAUTHORIZED, "caller do not have permission to access this key"))
        } else {
            Ok(())
        }
    }
}

impl IHwCryptoKey for HwCryptoKey {
    fn deriveCurrentDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
    ) -> binder::Result<DiceCurrentBoundKeyResult> {
        let client_policy = ClientPolicyWrapper::new_current(self.uuid.clone())?.encrypt()?;
        let derived_key_result =
            self.derive_dice_policy_bound_key(derivation_key, &client_policy, true)?;
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: policy_current } =
            derived_key_result;
        if !policy_current {
            return Err(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("generated a policy that was not the latest"),
            ));
        }
        Ok(DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: client_policy })
    }

    fn deriveDicePolicyBoundKey(
        &self,
        derivation_key: &DiceBoundDerivationKey,
        client_policy_for_key_version: &[u8],
    ) -> binder::Result<DiceBoundKeyResult> {
        Ok(self.derive_dice_policy_bound_key(
            derivation_key,
            client_policy_for_key_version,
            true,
        )?)
    }

    fn getCurrentDicePolicy(&self) -> binder::Result<Vec<u8>> {
        Ok(ClientPolicyWrapper::new_current(self.uuid.clone())?.encrypt()?)
    }

    fn keyTokenImport(
        &self,
        key_token: &OpaqueKeyToken,
        sealing_client_policy: &[u8],
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        // We derive a normal DICE bound key. This will check that the policy matches
        // our DICE chain.
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: _ } = self
            .deriveDicePolicyBoundKey(
                &DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY),
                sealing_client_policy,
            )?;
        let key = key.ok_or(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("shouldn't happen, previous operation succeeded"),
        ))?;
        let sealing_key: OpaqueKey = (&key).try_into().map_err(|_| {
            binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("shouldn't happen, opaque key was local"),
            )
        })?;

        Ok(opaque_key::OpaqueKey::import_token(
            key_token.keyToken.as_slice(),
            sealing_key,
            self.uuid.clone(),
        )?
        .into())
    }

    fn deriveKey(&self, parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
        if let DerivedKeyPolicy::ClearKeyPolicy(policy) = &parameters.keyPolicy {
            if policy.keySizeBytes <= 0 {
                return Err(binder::Status::new_exception_str(
                    binder::ExceptionCode::UNSUPPORTED_OPERATION,
                    Some("we do not support keys of length less or equal to 0"),
                ));
            }
        }

        let derivation_key: OpaqueKey = parameters
            .derivationKey
            .as_ref()
            .ok_or(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("didn't receive a derivation key"),
            ))?
            .try_into()?;

        match &parameters.keyPolicy {
            DerivedKeyPolicy::ClearKeyPolicy(clear_policy) => {
                // Adding key size to the context as well for a similar reason as to add the key
                // policy to the context.
                let key_size = clear_policy.keySizeBytes.try_into().map_err(|_| {
                    binder::Status::new_exception_str(
                        binder::ExceptionCode::UNSUPPORTED_OPERATION,
                        Some("shouldn't happen, we checked that keySize was positive"),
                    )
                })?;

                let derived_key = derivation_key
                    .derive_clear_key_material(parameters.context.as_slice(), key_size)?;
                Ok(DerivedKey::ExplicitKey(derived_key))
            }
            DerivedKeyPolicy::OpaqueKey(key_policy) => {
                let derived_key = derivation_key.derive_opaque_key(
                    key_policy,
                    parameters.context.as_slice(),
                    self.uuid.clone(),
                )?;
                Ok(DerivedKey::Opaque(Some(derived_key)))
            }
        }
    }

    fn getHwCryptoOperations(&self) -> binder::Result<binder::Strong<dyn IHwCryptoOperations>> {
        Ok(HwCryptoOperations::new_binder())
    }

    fn importClearKey(
        &self,
        key_to_be_imported: &ExplicitKeyMaterial,
        new_key_policy: &KeyPolicy,
    ) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        let key_material = helpers::aidl_explicit_key_to_rust_key_material(key_to_be_imported)?;
        OpaqueKey::import_key_material(new_key_policy, key_material, self.uuid.clone())
    }

    fn getKeyslotData(&self, keyslot: KeySlot) -> binder::Result<binder::Strong<dyn IOpaqueKey>> {
        self.check_caller_can_access_keyslot(keyslot)?;
        match keyslot {
            KeySlot::KEYMINT_SHARED_HMAC_KEY => {
                let hmac_key = DeviceKeysImpl.get_keymint_shared_hmac_key()?.0;
                let mut hmac_key_vec = Vec::new();
                hmac_key_vec.try_reserve(hmac_key.len()).map_err(|e| {
                    hwcrypto_err!(ALLOCATION_ERROR, "failed to space for key key {:?}", e)
                })?;
                hmac_key_vec.extend_from_slice(&hmac_key);
                let policy = KeyPolicy {
                    usage: KeyUse::SIGN,
                    keyLifetime: KeyLifetime::HARDWARE,
                    keyPermissions: Vec::new(),
                    keyType: KeyType::HMAC_SHA256,
                    keyManagementKey: false,
                };
                OpaqueKey::new_opaque_key_from_raw_bytes(&policy, hmac_key_vec, self.uuid.clone())
            }
            _ => Err(binder::Status::new_exception_str(
                binder::ExceptionCode::UNSUPPORTED_OPERATION,
                Some("Unknown key slot requested"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, AesKey::AesKey,
            CipherModeParameters::CipherModeParameters, HmacKey::HmacKey,
            HmacOperationParameters::HmacOperationParameters, OperationData::OperationData,
            SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        CryptoOperation::CryptoOperation,
        CryptoOperationSet::CryptoOperationSet,
        IHwCryptoKey::ClearKeyPolicy::ClearKeyPolicy,
        OperationParameters::OperationParameters,
    };
    use binder::Strong;
    use rpcbinder::RpcSession;
    use test::{assert_ok, expect, expect_eq};

    #[test]
    fn import_clear_aes_key() {
        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let aes_key_material: ExplicitKeyMaterial =
            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        //// Decrypting
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::DECRYPT;
        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        let decrypted_msg =
            String::from_utf8(decrypted_data).expect("couldn't decode received message");
        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
    }

    #[test]
    fn import_clear_hmac_key() {
        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
        let usage = KeyUse::SIGN;
        let key_type = KeyType::HMAC_SHA256;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let aes_key_material: ExplicitKeyMaterial = ExplicitKeyMaterial::Hmac(HmacKey::Sha256([
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
            10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        ]));
        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");
        let hmac_parameters = HmacOperationParameters { key: Some(key) };
        let op_parameters = OperationParameters::Hmac(hmac_parameters);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
        let input_data = OperationData::DataBuffer(b"test data".to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        let expected_response = [
            0x1d, 0x07, 0xd7, 0x52, 0xc2, 0x1a, 0x46, 0x73, 0xd8, 0x0b, 0xc4, 0x9b, 0xc8, 0x27,
            0xbb, 0x9d, 0x9b, 0x36, 0xe8, 0xfc, 0xec, 0xc1, 0x97, 0x21, 0xb2, 0x83, 0x57, 0x4a,
            0x18, 0x95, 0x5d, 0xfc,
        ];
        expect_eq!(mac, expected_response, "Didn't get back expected mac");
    }

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
    }

    #[test]
    fn derived_clear_key() {
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

        let clear_key_policy = DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 0 });
        let mut params = DerivedKeyParameters {
            derivationKey: key,
            keyPolicy: clear_key_policy,
            context: "context".as_bytes().to_vec(),
        };
        let key = hw_device_key.deriveKey(&params);
        expect!(key.is_err(), "shouldn't be able to create a key of length 0");

        let clear_key_policy =
            DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 32 });
        params.keyPolicy = clear_key_policy;
        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
        let key1 = match derived_key {
            DerivedKey::ExplicitKey(key) => key,
            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        };

        let key_and_policy =
            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&derivation_key, &policy));
        let DiceBoundKeyResult { diceBoundKey: key, dicePolicyWasCurrent: current_policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(current_policy, "policy should have been current");
        params.derivationKey = key;
        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
        let key2 = match derived_key {
            DerivedKey::ExplicitKey(key) => key,
            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        };
        expect!(openssl::memcmp::eq(&key1, &key2), "keys should have matched");

        params.context = "cont3xt".as_bytes().to_vec();
        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
        let key3 = match derived_key {
            DerivedKey::ExplicitKey(key) => key,
            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        };
        expect!(!openssl::memcmp::eq(&key1, &key3), "keys shouldn't have matched");
    }

    #[test]
    fn hwcrypto_token_export_import_hmac_use() {
        // This test is not representative of the complete flow because here the exporter and importer
        // are the same client, which is not something we would usually do
        let hw_crypto_key: Strong<dyn IHwCryptoKey> = assert_ok!(
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT),
            "Failed to connect"
        );
        let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; 32]));
        let policy = KeyPolicy {
            usage: KeyUse::SIGN,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyManagementKey: false,
            keyType: KeyType::HMAC_SHA256,
        };
        let key = assert_ok!(
            hw_crypto_key.importClearKey(&clear_key, &policy),
            "couldn't import clear key"
        );
        let client_policy =
            assert_ok!(hw_crypto_key.getCurrentDicePolicy(), "Couldn't get dice policy back");
        let token = assert_ok!(
            key.getShareableToken(client_policy.as_slice()),
            "Couldn't get shareable token"
        );
        let imported_key = assert_ok!(
            hw_crypto_key.keyTokenImport(&token, client_policy.as_slice()),
            "Couldn't import shareable token"
        );

        let policy = imported_key.getKeyPolicy();
        assert!(policy.is_ok(), "Couldn't get token key policy");

        let hw_crypto_operations = assert_ok!(
            hw_crypto_key.getHwCryptoOperations(),
            "Couldn't get back a hwcryptokey operations binder object"
        );

        // Using operations to verify that the keys match
        let hmac_parameters = HmacOperationParameters { key: Some(key) };
        let op_parameters = OperationParameters::Hmac(hmac_parameters);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
        let input_data = OperationData::DataBuffer("text to be mac'ed".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        assert_ok!(
            hw_crypto_operations.processCommandList(&mut crypto_sets),
            "couldn't process commands"
        );
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        // creating a key with the imported key to compare
        let hmac_parameters = HmacOperationParameters { key: Some(imported_key) };
        let op_parameters = OperationParameters::Hmac(hmac_parameters);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
        let input_data = OperationData::DataBuffer("text to be mac'ed".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        assert_ok!(
            hw_crypto_operations.processCommandList(&mut crypto_sets),
            "couldn't process commands"
        );
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac2)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        assert_eq!(mac, mac2, "got a different mac");
    }

    #[test]
    fn create_key_tokens() {
        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let aes_key_material: ExplicitKeyMaterial =
            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");

        let sealing_client_policy =
            hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");

        let token = key.getShareableToken(&sealing_client_policy);
        expect!(token.is_ok(), "couldn't get shareadble token");
        let token = token.unwrap();

        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        let hw_crypto = hw_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");
        let key = hw_key.keyTokenImport(&token, &sealing_client_policy);
        expect!(key.is_ok(), "couldn't import shareable token");
        let key = key.unwrap();

        //// Decrypting
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::DECRYPT;
        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        let decrypted_msg =
            String::from_utf8(decrypted_data).expect("couldn't decode received message");
        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
    }

    #[test]
    fn key_token_import_wrong_policy() {
        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");

        let aes_key_material: ExplicitKeyMaterial =
            ExplicitKeyMaterial::Aes(AesKey::Aes128([0; 16]));
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_128_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let key = hw_key.importClearKey(&aes_key_material, &policy).expect("couldn't import key");

        let sealing_client_policy =
            hw_key.getCurrentDicePolicy().expect("couldn't get sealing policy");

        let token = key.getShareableToken(&sealing_client_policy);
        expect!(token.is_ok(), "couldn't get shareadble token");
        let token = token.unwrap();

        let bad_client_policy = assert_ok!(
            ClientPolicyWrapper::new_current(
                Uuid::new_from_string("f41a7796-975a-427a-8cc4-a73f8820430d").unwrap(),
            ),
            "couldn't create DICE policy"
        );
        let bad_client_policy = assert_ok!(bad_client_policy.encrypt(), "couldn't encrypt policy");

        let key = hw_key.keyTokenImport(&token, &bad_client_policy);
        expect!(key.is_err(), "shouldn't be able to import key using the wrong DICE policy");
    }

    #[test]
    fn get_keyslot_form_unautorized_caller() {
        let hw_key = HwCryptoKey::new_binder(
            Uuid::new_from_string("00000000-0000-0000-0000-000000000000")
                .expect("couldn't create uuid"),
        );
        let key = hw_key.getKeyslotData(KeySlot::KEYMINT_SHARED_HMAC_KEY);
        expect!(key.is_err(), "shouldn't be able to get key");
    }
}
