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
#[cfg(test)]
mod hwcryptokey_tests {
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, AesKey::AesKey,
            CipherModeParameters::CipherModeParameters,
            ExplicitKeyMaterial::ExplicitKeyMaterial,
            HmacOperationParameters::HmacOperationParameters, HmacKey::HmacKey,
            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
            OperationData::OperationData, SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        CryptoOperation::CryptoOperation,
        CryptoOperationSet::CryptoOperationSet,
        IHwCryptoKey::ClearKeyPolicy::ClearKeyPolicy,
        KeyPolicy::KeyPolicy,
        OperationParameters::OperationParameters,
        IHwCryptoKey::{
            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
            DiceBoundDerivationKey::DiceBoundDerivationKey,
            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult,
            DiceBoundKeyResult::DiceBoundKeyResult,
        },
    };
    use test::{assert_ok, expect, expect_eq};

    use crate::tests::get_hwcryptokey;

    #[test]
    fn aes_simple_test_from_binder() {
        let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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
        let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");

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

    #[test]
    fn import_clear_aes_key() {
        let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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
        let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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
    fn hwcrypto_token_export_import_hmac_use() {
        // This test is not representative of the complete flow because here the exporter and importer
        // are the same client, which is not something we would usually do
        let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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
        let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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

        let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
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
    fn derived_dice_bound_keys() {
        let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");

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
        let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");

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
}
