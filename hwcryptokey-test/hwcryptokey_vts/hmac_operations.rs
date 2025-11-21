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
    let key = hw_key.import_clear_key(&hmac_key_material, &policy).expect("couldn't import key");

    let hw_crypto = hw_key.get_hwcrypto_operations().expect("Failed to get crypto ops.");

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
    let hw_crypto = hw_key.get_hwcrypto_operations().expect("couldn't get key crypto ops.");
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
    let key = hw_key.import_clear_key(&aes_key_material, &policy).expect("couldn't import key");
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
    let key = assert_ok!(
        hw_crypto_key.import_clear_key(&clear_key, &policy),
        "couldn't import clear key"
    );
    let client_policy =
        assert_ok!(hw_crypto_key.current_dice_policy(), "Couldn't get dice policy back");
    let token =
        assert_ok!(key.getShareableToken(client_policy.as_slice()), "Couldn't get shareable token");
    let imported_key = assert_ok!(
        hw_crypto_key.key_token_import(&token, client_policy.as_slice()),
        "Couldn't import shareable token"
    );

    let policy = imported_key.getKeyPolicy();
    assert!(policy.is_ok(), "Couldn't get token key policy");

    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.get_hwcrypto_operations(),
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

enum HmacTestKey {
    Sha256([u8; 32]),
    Sha512([u8; 64]),
}

fn rfc4868_test_case_auth(hmac_key: HmacTestKey, data: Vec<u8>, expected_result: Vec<u8>) {
    let (hmac_test_key, key_type) = match hmac_key {
        HmacTestKey::Sha256(hmac_key) => (HmacKey::Sha256(hmac_key), KeyType::HMAC_SHA256),
        HmacTestKey::Sha512(hmac_key) => (HmacKey::Sha512(hmac_key), KeyType::HMAC_SHA512),
    };
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let clear_key = ExplicitKeyMaterial::Hmac(hmac_test_key);
    let policy = KeyPolicy {
        usage: KeyUse::SIGN,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: key_type,
    };
    let key = assert_ok!(
        hw_crypto_key.import_clear_key(&clear_key, &policy),
        "couldn't import clear key"
    );

    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.get_hwcrypto_operations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );
    let hmac_parameters = HmacOperationParameters { key: Some(key) };
    let op_parameters = OperationParameters::Hmac(hmac_parameters);
    let mut cmd_list = Vec::<CryptoOperation>::new();
    let data_output = OperationData::DataBuffer(Vec::new());
    cmd_list.push(CryptoOperation::DataOutput(data_output));
    cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
    let input_data = OperationData::DataBuffer(data.to_vec());
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
    expect_eq!(mac, expected_result, "calculated mac was incorrect")
}

#[test]
fn rfc4868_test_case_auth256_1() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha256([0xb; 32]),
        b"Hi There".to_vec(),
        b"\x19\x8a\x60\x7e\xb4\x4b\xfb\xc6\x99\x03\xa0\xf1\xcf\x2b\xbd\xc5\xba\x0a\xa3\xf3\xd9\xae\x3c\x1c\x7a\x3b\x16\x96\xa0\xb6\x8c\xf7".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth256_2() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha256(*b"JefeJefeJefeJefeJefeJefeJefeJefe"),
        b"what do ya want for nothing?".to_vec(),
        b"\x16\x7f\x92\x85\x88\xc5\xcc\x2e\xef\x8e\x30\x93\xca\xa0\xe8\x7c\x9f\xf5\x66\xa1\x47\x94\xaa\x61\x64\x8d\x81\x62\x1a\x2a\x40\xc6".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth256_3() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha256([0xaa; 32]),
        vec![0xddu8; 50],
        b"\xcd\xcb\x12\x20\xd1\xec\xcc\xea\x91\xe5\x3a\xba\x30\x92\xf9\x62\xe5\x49\xfe\x6c\xe9\xed\x7f\xdc\x43\x19\x1f\xbd\xe4\x5c\x30\xb0".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth256_4() {
    let key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    rfc4868_test_case_auth(
        HmacTestKey::Sha256(key),
        vec![0xcdu8; 50],
        b"\x37\x2e\xfc\xf9\xb4\x0b\x35\xc2\x11\x5b\x13\x46\x90\x3d\x2e\xf4\x2f\xce\xd4\x6f\x08\x46\xe7\x25\x7b\xb1\x56\xd3\xd7\xb3\x0d\x3f".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth512_1() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha512([0x0b; 64]),
        b"Hi There".to_vec(),
        b"\x63\x7e\xdc\x6e\x01\xdc\xe7\xe6\x74\x2a\x99\x45\x1a\xae\x82\xdf\x23\xda\x3e\x92\x43\x9e\x59\x0e\x43\xe7\x61\xb3\x3e\x91\x0f\xb8\xac\x28\x78\xeb\xd5\x80\x3f\x6f\x0b\x61\xdb\xce\x5e\x25\x1f\xf8\x78\x9a\x47\x22\xc1\xbe\x65\xae\xa4\x5f\xd4\x64\xe8\x9f\x8f\x5b".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth512_2() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha512(*b"JefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefeJefe"),
        b"what do ya want for nothing?".to_vec(),
        b"\xcb\x37\x09\x17\xae\x8a\x7c\xe2\x8c\xfd\x1d\x8f\x47\x05\xd6\x14\x1c\x17\x3b\x2a\x93\x62\xc1\x5d\xf2\x35\xdf\xb2\x51\xb1\x54\x54\x6a\xa3\x34\xae\x9f\xb9\xaf\xc2\x18\x49\x32\xd8\x69\x5e\x39\x7b\xfa\x0f\xfb\x93\x46\x6c\xfc\xce\xaa\xe3\x8c\x83\x3b\x7d\xba\x38".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth512_3() {
    rfc4868_test_case_auth(
        HmacTestKey::Sha512([0xaa; 64]),
        vec![0xddu8; 50],
        b"\x2e\xe7\xac\xd7\x83\x62\x4c\xa9\x39\x87\x10\xf3\xee\x05\xae\x41\xb9\xf9\xb0\x51\x0c\x87\xe4\x9e\x58\x6c\xc9\xbf\x96\x17\x33\xd8\x62\x3c\x7b\x55\xce\xbe\xfc\xcf\x02\xd5\x58\x1a\xcc\x1c\x9d\x5f\xb1\xff\x68\xa1\xde\x45\x50\x9f\xbe\x4d\xa9\xa4\x33\x92\x26\x55".to_vec(),
    );
}

#[test]
fn rfc4868_test_case_auth512_4() {
    let key: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40,
    ];
    rfc4868_test_case_auth(
        HmacTestKey::Sha512(key),
        vec![0xcdu8; 50],
        b"\x5e\x66\x88\xe5\xa3\xda\xec\x82\x6c\xa3\x2e\xae\xa2\x24\xef\xf5\xe7\x00\x62\x89\x47\x47\x0e\x13\xad\x01\x30\x25\x61\xba\xb1\x08\xb8\xc4\x8c\xbc\x6b\x80\x7d\xcf\xbd\x85\x05\x21\xa6\x85\xba\xbc\x7e\xae\x4a\x2a\x2e\x66\x0d\xc0\xe8\x6b\x93\x1d\x65\x50\x3f\xd2".to_vec(),
    );
}
