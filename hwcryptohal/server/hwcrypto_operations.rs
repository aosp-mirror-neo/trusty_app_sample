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

//! Implementation of the `IHwCryptoOperations` AIDL interface. It can be use to retrieve the
//! key generation interface and to process cryptographic operations.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::OperationData::OperationData, CryptoOperation::CryptoOperation,
    CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
    IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
};
use android_hardware_security_see_hwcrypto::binder;
use hwcryptohal_common::hwcrypto_err;

use crate::cmd_processing::CmdProcessorContext;
use crate::crypto_operation_context::{BinderCryptoOperationContext, CryptoOperationContext};

/// The `IHwCryptoOperations` implementation.
pub struct HwCryptoOperations;

impl binder::Interface for HwCryptoOperations {}

impl HwCryptoOperations {
    pub(crate) fn new_binder() -> binder::Strong<dyn IHwCryptoOperations> {
        let hwcrypto_operations = HwCryptoOperations;
        BnHwCryptoOperations::new_binder(hwcrypto_operations, binder::BinderFeatures::default())
    }
}

impl IHwCryptoOperations for HwCryptoOperations {
    fn processCommandList(
        &self,
        command_lists: &mut std::vec::Vec<CryptoOperationSet>,
    ) -> binder::Result<Vec<CryptoOperationResult>> {
        let mut results = Vec::<CryptoOperationResult>::new();
        for command_list in command_lists {
            results.try_reserve(1).map_err(|e| {
                hwcrypto_err!(ALLOCATION_ERROR, "couldn't grow result vector: {:?}", e)
            })?;
            results.push(CryptoOperationResult { context: None });
            match &command_list.context {
                None => {
                    let mut cmd_processor = CmdProcessorContext::new();
                    cmd_processor.process_all_steps(&mut command_list.operations)?;
                    if !cmd_processor.is_destroyed() {
                        let operation_context = CryptoOperationContext::new_binder(cmd_processor);
                        results
                            .last_mut()
                            .expect("shouldn't happen, we pushed an element before match")
                            .context = Some(operation_context);
                    }
                }
                Some(operation_context) => {
                    BinderCryptoOperationContext::from(operation_context.clone())
                        .process_all_steps(&mut command_list.operations)?;
                }
            }
            // Just keep the command list elements that contain an output that needs to be return to
            // the caller. At this point CryptoOperation::DataOutput is the only operation returning
            // data using vectors but only when it contains an OperationData::DataBuffer.
            command_list
                .operations
                .retain(|x| matches!(x, CryptoOperation::DataOutput(OperationData::DataBuffer(_))));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hwcrypto_ipc_server::RUST_SERVICE_PORT;
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
            ExplicitKeyMaterial::ExplicitKeyMaterial,
            HmacOperationParameters::HmacOperationParameters, HmacKey::HmacKey,
            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        CryptoOperation::CryptoOperation,
        IHwCryptoKey::{
            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
            DiceBoundDerivationKey::DiceBoundDerivationKey,
            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
        },
        KeyPolicy::KeyPolicy,
        OperationParameters::OperationParameters,
    };
    use binder::Strong;
    use rpcbinder::RpcSession;
    use test::{assert_ok, expect, expect_eq};

    #[test]
    fn aes_simple_test_from_binder() {
        let hw_device_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
        let DiceCurrentBoundKeyResult { diceBoundKey: key, dicePolicyForKeyVersion: policy } =
            key_and_policy;
        expect!(key.is_some(), "should have received a key");
        expect!(policy.len() > 0, "should have received a DICE policy");

        let hw_crypto = hw_device_key.getHwCryptoOperations().expect("Failed to get crypto ops.");
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::HARDWARE,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };

        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
            .expect("couldn't serialize policy");
        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);
        let params = DerivedKeyParameters {
            derivationKey: key,
            keyPolicy: key_policy,
            context: "context".as_bytes().to_vec(),
        };
        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));
        let key = match derived_key {
            DerivedKey::Opaque(key) => key.expect("key shouldn't be NULL"),
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

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
        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        let mut op_result =
            hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        let context = op_result.remove(0).context;
        // Separating the finish call on a different command set to test the returned context
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(encrypted_data);
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::Finish(None));
        let crypto_op_set = CryptoOperationSet { context, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
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
    fn hmac_simple_test_from_binder() {
        let hw_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");

        let policy = KeyPolicy {
            usage: KeyUse::SIGN,
            keyLifetime: KeyLifetime::PORTABLE,
            keyPermissions: Vec::new(),
            keyType: KeyType::HMAC_SHA256,
            keyManagementKey: false,
        };
        let hmac_key_material: ExplicitKeyMaterial =
            ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; 32]));
        let key = hw_key.importClearKey(&hmac_key_material, &policy).expect("couldn't import key");

        let hw_crypto = hw_key.getHwCryptoOperations().expect("Failed to get crypto ops.");

        let hmac_parameters = HmacOperationParameters { key: Some(key.clone()) };
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
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        //Getting a second mac to compare
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
        hw_crypto.processCommandList(&mut crypto_sets).expect("couldn't process commands");
        // Extracting the vector from the command list because of ownership
        let CryptoOperation::DataOutput(OperationData::DataBuffer(mac2)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        expect_eq!(mac, mac2, "got a different mac");
    }
}
