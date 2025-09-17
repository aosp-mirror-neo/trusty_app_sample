/*
 * Copyright (C) 2023 The Android Open Source Project
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

#[cfg(test)]
mod hwcryptokey_tests {
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters,
            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        CryptoOperation::CryptoOperation,
        CryptoOperationSet::CryptoOperationSet,
        IHwCryptoKey::{
            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
            DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult,
        },
        IHwCryptoOperations::IHwCryptoOperations,
        IOpaqueKey::IOpaqueKey,
        KeyPolicy::KeyPolicy,
        OperationParameters::OperationParameters,
    };
    use binder::{Status, Strong};
    use test::{assert_ok, expect};

    use crate::tests::get_hwcryptokey;

    pub(crate) const ENCRYPTION_PAYLOAD: &str = "string to be encrypted";

    fn do_cipher(
        hw_crypto: &dyn IHwCryptoOperations,
        key: Strong<dyn IOpaqueKey>,
        direction: SymmetricOperation,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));

        let sym_op_params = SymmetricOperationParameters { key: Some(key), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);

        let mut cmd_list = Vec::<CryptoOperation>::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        let input_data = OperationData::DataBuffer(payload);
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));

        let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
        let mut crypto_sets = Vec::new();
        crypto_sets.push(crypto_op_set);

        let result = hw_crypto.processCommandList(&mut crypto_sets);
        match result {
            Ok(..) => {}
            Err(e) => return Err(e),
        }

        let CryptoOperation::DataOutput(OperationData::DataBuffer(result)) =
            crypto_sets.remove(0).operations.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        Ok(result)
    }

    fn encrypt(
        hw_crypto: &dyn IHwCryptoOperations,
        key: Strong<dyn IOpaqueKey>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        do_cipher(hw_crypto, key, SymmetricOperation::ENCRYPT, payload)
    }

    fn decrypt(
        hw_crypto: &dyn IHwCryptoOperations,
        key: Strong<dyn IOpaqueKey>,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        do_cipher(hw_crypto, key, SymmetricOperation::DECRYPT, payload)
    }

    #[test]
    fn generate_new_policy_and_opaque_key() {
        let hw_device_key = get_hwcryptokey().expect("couldn't connect to HW Crypto service");
        let hw_crypto =
            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");

        // Get the device bound key
        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);

        // Generate the current derivation key and policy
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
        let DiceCurrentBoundKeyResult {
            diceBoundKey: derivation_key1,
            dicePolicyForKeyVersion: dice_policy,
        } = key_and_policy;

        expect!(derivation_key1.is_some(), "should have received a key");
        expect!(dice_policy.len() > 0, "should have received a DICE policy");

        // Derive an opaque key from returned current policy and derivation key
        let policy = KeyPolicy {
            usage: KeyUse::ENCRYPT_DECRYPT,
            keyLifetime: KeyLifetime::HARDWARE,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
            keyManagementKey: false,
        };

        let cbor_policy = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy)
            .expect("couldn't serialize policy");
        let key_policy = DerivedKeyPolicy::OpaqueKey(cbor_policy);

        let mut params = DerivedKeyParameters {
            derivationKey: derivation_key1,
            keyPolicy: key_policy,
            context: "context".as_bytes().to_vec(),
        };

        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));

        // Check key type
        let derived_key1 = match derived_key1 {
            DerivedKey::Opaque(k) => k,
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

        let derived_key1 = derived_key1.expect("key is missing");

        // Baseline encryption operations
        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();

        let encrypted_data =
            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
                .expect("encryption failure");
        let clear_data = decrypt(hw_crypto.as_ref(), derived_key1.clone(), encrypted_data.clone())
            .expect("decryption failure");

        assert_eq!(clear_payload, clear_data, "decrypted data mismatch");

        // Use dice policy to request same derivation key
        let key_and_policy =
            assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy));
        let DiceBoundKeyResult {
            diceBoundKey: derivation_key2,
            dicePolicyWasCurrent: dice_policy_current,
        } = key_and_policy;

        expect!(derivation_key2.is_some(), "should have received a key");
        expect!(dice_policy_current, "policy should have been current");

        // Generate derived key 2
        params.derivationKey = derivation_key2;

        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));

        // Check key type
        let derived_key2 = match derived_key2 {
            DerivedKey::Opaque(k) => k,
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

        let derived_key2 = derived_key2.expect("key is missing");

        let clear_data2 = decrypt(hw_crypto.as_ref(), derived_key2.clone(), encrypted_data.clone())
            .expect("decryption failure");
        assert_eq!(clear_payload, clear_data2, "decrypted data mismatch");

        // If we request current dice policy again, we expect the same key, but different
        // encryption of the returned policy. Note underlying policy is the same (latest),
        // but encrypted byte array returned will be different

        // Generate the current derivation key and policy again
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
        let DiceCurrentBoundKeyResult {
            diceBoundKey: derivation_key3,
            dicePolicyForKeyVersion: dice_policy3,
        } = key_and_policy;

        // We expect the dice policy to appear different due to encruption
        assert_ne!(
            dice_policy, dice_policy3,
            "expected dice policies to appear different due to encryption"
        );

        // Ensure derived key from this policy matches previously generated derived key
        params.derivationKey = derivation_key3;

        let derived_key3 = assert_ok!(hw_device_key.deriveKey(&params));

        // Check key type
        let derived_key3 = match derived_key3 {
            DerivedKey::Opaque(k) => k,
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

        let derived_key3 = derived_key3.expect("key is missing");

        // Try encrypting same clear_payload and verify encrypted result is same
        let encrypted_data3 =
            encrypt(hw_crypto.as_ref(), derived_key3.clone(), clear_payload.clone())
                .expect("encryption failure");
        assert_eq!(encrypted_data3, encrypted_data, "unexpected encrypted data mismatch");

        // try using key to decrypt earlier encryption result
        let clear_data3 = decrypt(hw_crypto.as_ref(), derived_key3.clone(), encrypted_data.clone())
            .expect("decryption failure");
        assert_eq!(clear_data3, clear_payload, "unexpected data mismatch");
    }

    #[test]
    fn opaque_keys_unique_by_context() {
        let hw_device_key = get_hwcryptokey().expect("couldn't connect to HW Crypto service");
        let hw_crypto =
            hw_device_key.getHwCryptoOperations().expect("couldn't get key crypto ops.");

        // Get the device bound key
        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);

        // Generate the current derivation key and policy
        let key_and_policy =
            assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
        let DiceCurrentBoundKeyResult {
            diceBoundKey: derivation_key,
            dicePolicyForKeyVersion: dice_policy,
        } = key_and_policy;

        expect!(derivation_key.is_some(), "should have received a key");
        expect!(dice_policy.len() > 0, "should have received a DICE policy");

        let context1 = "context1";
        let context2 = "context2";

        // Get derived key for context1
        let policy1 = KeyPolicy {
            usage: KeyUse::ENCRYPT_DECRYPT,
            keyLifetime: KeyLifetime::HARDWARE,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
            keyManagementKey: false,
        };

        let cbor_policy1 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy1)
            .expect("couldn't serialize policy");
        let key_policy1 = DerivedKeyPolicy::OpaqueKey(cbor_policy1);

        let params1 = DerivedKeyParameters {
            derivationKey: derivation_key.clone(),
            keyPolicy: key_policy1,
            context: context1.as_bytes().to_vec(),
        };

        let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params1));

        // Check key type
        let derived_key1 = match derived_key1 {
            DerivedKey::Opaque(k) => k,
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

        let derived_key1 = derived_key1.expect("key is missing");

        // Context1 encryption
        let clear_payload = ENCRYPTION_PAYLOAD.as_bytes().to_vec();
        let encrypted_data1 =
            encrypt(hw_crypto.as_ref(), derived_key1.clone(), clear_payload.clone())
                .expect("encryption failure");

        // Request key for context2 and verify key is different
        let policy2 = KeyPolicy {
            usage: KeyUse::ENCRYPT_DECRYPT,
            keyLifetime: KeyLifetime::HARDWARE,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_256_CBC_PKCS7_PADDING,
            keyManagementKey: false,
        };

        let cbor_policy2 = hwcryptohal_common::policy::cbor_serialize_key_policy(&policy2)
            .expect("couldn't serialize policy");
        let key_policy2 = DerivedKeyPolicy::OpaqueKey(cbor_policy2);

        let params2 = DerivedKeyParameters {
            derivationKey: derivation_key.clone(),
            keyPolicy: key_policy2,
            context: context2.as_bytes().to_vec(),
        };

        let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params2));

        // Check key type
        let derived_key2 = match derived_key2 {
            DerivedKey::Opaque(k) => k,
            DerivedKey::ExplicitKey(_) => panic!("wrong type of key received"),
        };

        let derived_key2 = derived_key2.expect("key is missing");

        // Context2 encryption
        let encrypted_data2 =
            encrypt(hw_crypto.as_ref(), derived_key2.clone(), clear_payload.clone())
                .expect("encryption failure");

        // Verify encryption results are different
        assert_ne!(encrypted_data2, encrypted_data1, "encrypted results should not match");
    }
}
