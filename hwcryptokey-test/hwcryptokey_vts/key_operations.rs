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
    PatternParameters::PatternParameters,
};
use test::{assert_ok, expect, expect_eq};

use crate::tests::get_hwcryptokey;

#[test]
fn parse_cmd_list_single_item() {
    // getting hwcrypto interface
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.getHwCryptoOperations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );

    // creating command list
    let mut cmd_list = Vec::<CryptoOperation>::new();
    let data_output = OperationData::DataBuffer(Vec::new());
    cmd_list.push(CryptoOperation::DataOutput(data_output));

    // processing commands
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_ok(), "Couldn't process command");
}

#[test]
fn parse_empty_cmd_list() {
    // getting hwcrypto interface
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.getHwCryptoOperations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );

    // creating empty list
    let cmd_list = Vec::<CryptoOperation>::new();
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);

    // processing empty list
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Should have received an error");

    // trying to process it a second time
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Should have received an error");
}

#[test]
fn simple_copy_operation_on_initial_state() {
    // getting hwcrypto interface
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.getHwCryptoOperations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );

    //constructing commands list with only copy operation
    let mut cmd_list = Vec::<CryptoOperation>::new();
    let data_output = OperationData::DataBuffer(Vec::new());
    cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));

    // processing commands
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to copy before adding an output");

    // adding output
    let mut cmd_list = crypto_sets.remove(0).operations;
    cmd_list.insert(0, CryptoOperation::DataOutput(data_output));
    cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));

    // processing commands
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    crypto_sets.push(crypto_op_set);
    assert_ok!(
        hw_crypto_operations.processCommandList(&mut crypto_sets),
        "couldn't process commands"
    );

    // Extracting the vector from the command list because of ownership
    let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) =
        crypto_sets.remove(0).operations.remove(0)
    else {
        panic!("not reachable, we created this object above on the test");
    };

    expect_eq!(output, &[1, 2, 3, 4, 5, 6], "values were not copied correctly");
}

#[test]
fn invalid_operations_initial_state() {
    // getting hwcrypto interface
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_operations = assert_ok!(
        hw_crypto_key.getHwCryptoOperations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );

    //constructing invalid commands list and processing them
    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call DataInput on initial state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call AadInput on initial state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
    cmd_list.push(CryptoOperation::SetPattern(pattern_params));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on initial state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::Finish(None));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call Finish on initial state");

    // Trying to run a valid operation to check that previous errors were caused because of the
    // command lists we constructed
    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_ok(), "Should be able to call DataOutput");
}

#[test]
fn invalid_operations_destroyed_state() {
    // getting hwcrypto interface
    let hw_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let hw_crypto_operations = assert_ok!(
        hw_key.getHwCryptoOperations(),
        "Couldn't get back a hwcryptokey operations binder object"
    );

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_ok(),);

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call DataOutput on destroyed state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call DataInput on destroyed state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call AadInput on destroyed state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
    cmd_list.push(CryptoOperation::SetPattern(pattern_params));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on destroyed state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    cmd_list.push(CryptoOperation::Finish(None));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(process_result.is_err(), "Shouldn't be able to call Finish on destroyed state");

    let mut cmd_list = Vec::<CryptoOperation>::new();
    cmd_list.push(CryptoOperation::DestroyContext(None));
    let policy = KeyPolicy {
        usage: KeyUse::SIGN,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyType: KeyType::HMAC_SHA256,
        keyManagementKey: false,
    };
    let hmac_key_material: ExplicitKeyMaterial =
        ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; 32]));
    let key = assert_ok!(hw_key.importClearKey(&hmac_key_material, &policy), "couldn't import key");
    let hmac_parameters = HmacOperationParameters { key: Some(key.clone()) };
    let op_parameters = OperationParameters::Hmac(hmac_parameters);
    cmd_list.push(CryptoOperation::SetOperationParameters(op_parameters));
    let crypto_op_set = CryptoOperationSet { context: None, operations: cmd_list };
    let mut crypto_sets = Vec::new();
    crypto_sets.push(crypto_op_set);
    let process_result = hw_crypto_operations.processCommandList(&mut crypto_sets);
    expect!(
        process_result.is_err(),
        "Shouldn't be able to call SetOperationParameters on destroyed state"
    );
}
