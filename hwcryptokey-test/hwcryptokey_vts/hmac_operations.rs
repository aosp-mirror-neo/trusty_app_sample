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

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::{
        ExplicitKeyMaterial::ExplicitKeyMaterial, HmacKey::HmacKey,
        HmacOperationParameters::HmacOperationParameters, KeyLifetime::KeyLifetime,
        KeyType::KeyType, KeyUse::KeyUse, OperationData::OperationData,
    },
    CryptoOperation::CryptoOperation,
    CryptoOperationSet::CryptoOperationSet,
    KeyPolicy::KeyPolicy,
    OperationParameters::OperationParameters,
};
use test::{assert_ok, expect_eq};

use crate::tests::get_hwcryptokey;

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
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 10, 10, 10,
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
        0x1d, 0x07, 0xd7, 0x52, 0xc2, 0x1a, 0x46, 0x73, 0xd8, 0x0b, 0xc4, 0x9b, 0xc8, 0x27, 0xbb,
        0x9d, 0x9b, 0x36, 0xe8, 0xfc, 0xec, 0xc1, 0x97, 0x21, 0xb2, 0x83, 0x57, 0x4a, 0x18, 0x95,
        0x5d, 0xfc,
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
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    let client_policy =
        assert_ok!(hw_crypto_key.getCurrentDicePolicy(), "Couldn't get dice policy back");
    let token =
        assert_ok!(key.getShareableToken(client_policy.as_slice()), "Couldn't get shareable token");
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
