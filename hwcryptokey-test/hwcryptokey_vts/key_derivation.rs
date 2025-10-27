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

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::{
        ExplicitKeyMaterial::ExplicitKeyMaterial, HalErrorCode, HmacKey::HmacKey,
        KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse, OperationType::OperationType,
        ProtectionId::ProtectionId,
    },
    IHwCryptoKey::{
        ClearKeyPolicy::ClearKeyPolicy, DerivedKey::DerivedKey,
        DerivedKeyParameters::DerivedKeyParameters, DerivedKeyPolicy::DerivedKeyPolicy,
        DeviceKeyId::DeviceKeyId, DiceBoundDerivationKey::DiceBoundDerivationKey,
        DiceBoundKeyResult::DiceBoundKeyResult,
        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult,
    },
    KeyPolicy::KeyPolicy,
};
use ciborium::Value;
use coset::CborSerializable;
use hwcryptohal_common::policy::cbor_serialize_key_policy;
use kmr_common::crypto::Hkdf;
use test::{assert_ok, expect, expect_eq};

use crate::tests::get_hwcryptokey;

const HMAC_SHA256_KEY_LEN: usize = 32;

fn keys_are_sufficiently_distinct(key1: Vec<u8>, key2: Vec<u8>) -> bool {
    let differing_bytes = key1.iter().zip(key2.iter()).filter(|(&x1, &x2)| x1 != x2).count();

    std::cmp::min(key1.len(), key2.len()) - differing_bytes <= 4
}

#[test]
fn generate_new_policy_and_clear_key() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't connect to HW Crypto service");

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

    // Derive a clear key from returned current policy and derivation key
    let mut params = DerivedKeyParameters {
        derivationKey: derivation_key1,
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: "context".as_bytes().to_vec(),
    };

    let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));

    // Check key type and length
    let derived_key1 = match derived_key1 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key1.len() as i32, 256, "wrong key length");

    // Use dice policy to request same key
    let key_and_policy =
        assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy));
    let DiceBoundKeyResult {
        diceBoundKey: derivation_key2,
        dicePolicyWasCurrent: dice_policy_current,
    } = key_and_policy;

    expect!(derivation_key2.is_some(), "should have received a key");
    expect!(dice_policy_current, "policy should have been current");

    // generate derived key 2 and compare to key 1
    params.derivationKey = derivation_key2;

    let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));

    // Check key type and length
    let derived_key2 = match derived_key2 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key2.len() as i32, 256, "wrong key length");

    // Make sure both derived keys match
    assert_eq!(derived_key2, derived_key1, "key mismatch");

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

    // Check key type and length
    let derived_key3 = match derived_key3 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key3.len() as i32, 256, "wrong key length");

    // Make sure both derived keys match
    assert_eq!(derived_key3, derived_key1, "key mismatch");
}

#[test]
fn dice_updates_are_unique() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't connect to HW Crypto service");

    // Get the device bound key
    let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);

    // Get current dice policy multiple times
    let key_and_policy =
        assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
    let DiceCurrentBoundKeyResult {
        diceBoundKey: derivation_key1,
        dicePolicyForKeyVersion: dice_policy1,
    } = key_and_policy;

    let key_and_policy =
        assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&device_bound_key));
    let DiceCurrentBoundKeyResult {
        diceBoundKey: derivation_key2,
        dicePolicyForKeyVersion: dice_policy2,
    } = key_and_policy;

    // policies should appear different due to encryption and not be zero length
    expect!(dice_policy1.len() > 0, "should have received a DICE policy");
    expect!(dice_policy2.len() > 0, "should have received a DICE policy");
    assert_ne!(dice_policy1, dice_policy2, "expected policies to be different");

    expect!(derivation_key1.is_some(), "should have received a key");
    expect!(derivation_key2.is_some(), "should have received a key");

    // Generate derived clear keys from returned derivation keys
    let params = DerivedKeyParameters {
        derivationKey: derivation_key1,
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: "context".as_bytes().to_vec(),
    };

    let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));

    let params = DerivedKeyParameters {
        derivationKey: derivation_key2,
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: "context".as_bytes().to_vec(),
    };

    let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));

    // Check derived keys
    let derived_key1 = match derived_key1 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    let derived_key2 = match derived_key2 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    // Check that generated keys match
    assert_eq!(derived_key1, derived_key2, "key mismatch");

    // Check that both dice policies are considered current
    let key_and_policy =
        assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy1));
    let DiceBoundKeyResult { diceBoundKey: _, dicePolicyWasCurrent: dice_policy1_current } =
        key_and_policy;

    expect!(dice_policy1_current, "policy expected to be current");

    let key_and_policy =
        assert_ok!(hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &dice_policy2));
    let DiceBoundKeyResult { diceBoundKey: _, dicePolicyWasCurrent: dice_policy2_current } =
        key_and_policy;

    expect!(dice_policy2_current, "policy expected to be current");
}

#[test]
fn explicit_keys_unique_by_context() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't connect to HW Crypto service");

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

    // Define two different contexts and get clear derived keys for each
    let context1 = "context1";
    let context2 = "context2";

    let params1 = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: context1.as_bytes().to_vec(),
    };

    let params2 = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: context2.as_bytes().to_vec(),
    };

    let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params1));
    let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params2));

    // Check key2 type and length
    let derived_key1 = match derived_key1 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    let derived_key2 = match derived_key2 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key1.len() as i32, 256, "wrong key length");
    assert_eq!(derived_key2.len() as i32, 256, "wrong key length");

    // Ensure keys are different
    assert_ne!(derived_key2, derived_key1, "returned keys are same");
    assert!(
        keys_are_sufficiently_distinct(derived_key2, derived_key1),
        "derived keys share too many bytes"
    );
}

#[test]
fn invalid_key_sizes() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't connect to HW Crypto service");

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

    // Request a zero length key
    let params = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 0 }),
        context: "context".as_bytes().to_vec(),
    };

    let derived_key = hw_device_key.deriveKey(&params);
    expect!(derived_key.is_err(), "expected error on bad key size");

    // Request a negative length key
    let params = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: -256 }),
        context: "context".as_bytes().to_vec(),
    };

    let derived_key = hw_device_key.deriveKey(&params);
    expect!(derived_key.is_err(), "expected error on bad key size");
}

#[test]
fn large_context() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't connect to HW Crypto service");

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

    // Pick a reasonable large context size
    const PAYLOAD_LEN: usize = 512;

    let mut context = vec![42; PAYLOAD_LEN];

    // Get a derived key based on large context
    let params = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: context.clone(),
    };

    let derived_key1 = assert_ok!(hw_device_key.deriveKey(&params));

    // Check key type and length
    let derived_key1 = match derived_key1 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key1.len() as i32, 256, "wrong key length");

    // Make a minor change to last byte of context and request another key
    context[PAYLOAD_LEN - 1] = 43;

    let params = DerivedKeyParameters {
        derivationKey: derivation_key.clone(),
        keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
        context: context.clone(),
    };

    let derived_key2 = assert_ok!(hw_device_key.deriveKey(&params));

    // Check key type and length
    let derived_key2 = match derived_key2 {
        DerivedKey::Opaque(_) => panic!("wrong type of key received"),
        DerivedKey::ExplicitKey(k) => k,
    };

    assert_eq!(derived_key2.len() as i32, 256, "wrong key length");

    //Ensure keys are different
    assert_ne!(derived_key1, derived_key2, "keys expected to differ");
    assert!(
        keys_are_sufficiently_distinct(derived_key1, derived_key2),
        "derived keys share too many bytes"
    );
}

#[test]
fn derived_dice_bound_keys() {
    let hw_device_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");

    let derivation_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);
    let key_and_policy = assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
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
    let key_and_policy = assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
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
    let key_and_policy = assert_ok!(hw_device_key.deriveCurrentDicePolicyBoundKey(&derivation_key));
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

    let clear_key_policy = DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 32 });
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
fn derive_keys_happy_path() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::DERIVE,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let derivation_context = b"context";
    let key_size = HMAC_SHA256_KEY_LEN;
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    // Deriving a clear key
    let derived_policy =
        DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: key_size as i32 });
    let mut params = DerivedKeyParameters {
        derivationKey: Some(key),
        keyPolicy: derived_policy,
        context: derivation_context.to_vec(),
    };
    let derived_key_result = hw_crypto_key.deriveKey(&params);
    expect!(derived_key_result.is_ok(), "should be able to derive a clear key");

    // deriving an opaque key
    let derived_key_policy =
        assert_ok!(cbor_serialize_key_policy(&policy), "couldn't crete a serialized policy");
    let derived_policy = DerivedKeyPolicy::OpaqueKey(derived_key_policy);
    params.keyPolicy = derived_policy;
    let derived_key_result = hw_crypto_key.deriveKey(&params);
    expect!(derived_key_result.is_ok(), "should be able to derive an opaque key");
}

#[test]
fn try_derive_key_wrong_key_purpose() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::SIGN,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let derivation_context = b"context";
    let key_size = HMAC_SHA256_KEY_LEN;
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    // Deriving a clear key
    let derived_policy =
        DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: key_size as i32 });
    let mut params = DerivedKeyParameters {
        derivationKey: Some(key),
        keyPolicy: derived_policy,
        context: derivation_context.to_vec(),
    };
    let derived_key_result = hw_crypto_key.deriveKey(&params);
    expect!(derived_key_result.is_err(), "should not be able to derive a key with a signing key");

    // deriving an opaque key
    let derived_key_policy =
        assert_ok!(cbor_serialize_key_policy(&policy), "couldn't crete a serialized policy");
    let derived_policy = DerivedKeyPolicy::OpaqueKey(derived_key_policy);
    params.keyPolicy = derived_policy;
    let derived_key_result = hw_crypto_key.deriveKey(&params);
    expect!(derived_key_result.is_err(), "should not be able to derive a key with a signing key");
}

#[test]
fn valid_clear_key_derivation() {
    const CLEAR_KEY_DERIVATION_CONTEXT_PREFIX: u8 = 3;
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::DERIVE,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let derivation_context = b"context";
    let key_size = 5u64;
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    let derived_policy =
        DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: key_size as i32 });
    let params = DerivedKeyParameters {
        derivationKey: Some(key),
        keyPolicy: derived_policy,
        context: derivation_context.to_vec(),
    };
    let derived_key = assert_ok!(hw_crypto_key.deriveKey(&params));
    let DerivedKey::ExplicitKey(derived_key) = derived_key else {
        panic!("shouldn't have recovered an opaque key");
    };
    // Manually deriving the same clear key
    let mut key_context = Vec::<Value>::new();
    key_context.push(Value::Integer((CLEAR_KEY_DERIVATION_CONTEXT_PREFIX).into()));
    key_context.push(Value::Integer((key_size).into()));
    key_context.push(Value::Bytes(derivation_context.to_vec()));
    let context: Vec<u8> = Value::Array(key_context).to_vec().unwrap();
    let derived_key_local = kmr_crypto_boring::hmac::BoringHmac
        .hkdf(&[], &derivation_key, context.as_slice(), key_size as usize)
        .unwrap();
    expect_eq!(derived_key, derived_key_local, "derived clear key do not match expected value");
}

#[test]
fn valid_opaque_key_derivation() {
    const OPAQUE_KEY_DERIVATION_CONTEXT_PREFIX: u8 = 4;
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let initial_derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(initial_derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::DERIVE,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let derivation_context = b"context";
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    // We will use the same key policy for the opaque derived key
    let derived_key_policy =
        assert_ok!(cbor_serialize_key_policy(&policy), "couldn't crete a serialized policy");
    let derived_policy = DerivedKeyPolicy::OpaqueKey(derived_key_policy.clone());
    let params = DerivedKeyParameters {
        derivationKey: Some(key),
        keyPolicy: derived_policy,
        context: derivation_context.to_vec(),
    };
    let derived_key = assert_ok!(hw_crypto_key.deriveKey(&params));
    let derived_opaque_key = if let DerivedKey::Opaque(derived_opaque_key) = derived_key {
        derived_opaque_key
    } else {
        panic!("shouldn't have received a clear key");
    };
    // Manually deriving the same key
    let mut key_context = Vec::<Value>::new();
    key_context.push(Value::Integer((OPAQUE_KEY_DERIVATION_CONTEXT_PREFIX).into()));
    key_context.push(Value::Bytes(derived_key_policy));
    key_context.push(Value::Bytes(derivation_context.to_vec()));
    let context: Vec<u8> = Value::Array(key_context).to_vec().unwrap();
    let derived_key_local = kmr_crypto_boring::hmac::BoringHmac
        .hkdf(&[], &initial_derivation_key, context.as_slice(), HMAC_SHA256_KEY_LEN)
        .unwrap();

    // To test that both opaque derived keys match, we will use them to derive clear keys and
    // compare them
    let key_size = 5u64;
    let clear_key_policy =
        DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: key_size as i32 });
    let mut params = DerivedKeyParameters {
        derivationKey: derived_opaque_key,
        keyPolicy: clear_key_policy,
        context: derivation_context.to_vec(),
    };
    let derived_clear_key = assert_ok!(hw_crypto_key.deriveKey(&params));
    let DerivedKey::ExplicitKey(derived_clear_key1) = derived_clear_key else {
        panic!("shouldn't have recovered an opaque key");
    };
    let derived_key_local =
        ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derived_key_local.try_into().unwrap()));
    let imported_derived_key = assert_ok!(
        hw_crypto_key.importClearKey(&derived_key_local, &policy),
        "couldn't import local key"
    );
    params.derivationKey = Some(imported_derived_key);
    let derived_clear_key = assert_ok!(hw_crypto_key.deriveKey(&params));
    let derived_clear_key2 = if let DerivedKey::ExplicitKey(derived_clear_key) = derived_clear_key {
        derived_clear_key
    } else {
        panic!("shouldn't have recovered an opaque key");
    };
    expect_eq!(derived_clear_key1, derived_clear_key2, "Derived keys should have matched");
}

#[test]
fn invalid_key_functions() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256([0; HMAC_SHA256_KEY_LEN]));
    let policy = KeyPolicy {
        usage: KeyUse::SIGN,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    let key2 =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    let export_err = assert_ok!(key
        .exportWrappedKey(&key2)
        .err()
        .ok_or("exportWrappedKey doesn't need to be implemented"));
    expect_eq!(
        export_err.service_specific_error(),
        HalErrorCode::UNSUPPORTED,
        "exportWrappedKey should return UNSUPPORTED"
    );
    let get_public_key_err =
        assert_ok!(key.getPublicKey().err().ok_or("getPublicKey doesn't need to be implemented"));
    expect_eq!(
        get_public_key_err.service_specific_error(),
        HalErrorCode::UNSUPPORTED,
        "getPublicKey should return UNSUPPORTED"
    );
}

#[test]
fn set_protection_id() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let initial_derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(initial_derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::DERIVE,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");
    let result = key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &Vec::new());
    expect!(result.is_err(), "should not be able to call protection ID without desired protection");
    let read_protection = vec![OperationType::READ];
    let result = key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &read_protection);
    expect!(result.is_err(), "should not be able to set protection id to read for widevine");
    let read_write_protection = vec![OperationType::READ, OperationType::WRITE];
    let result = key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &read_write_protection);
    expect!(result.is_err(), "should not be able to set protection id to read for widevine");
    let write_protection = vec![OperationType::WRITE];
    let result = key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &write_protection);
    expect!(result.is_ok(), "we should have been able to set protection ID");
    let result = key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &write_protection);
    expect!(result.is_err(), "should not be able to set protection id after it was set");

    // Verifying that we cannot call setProtectionId on keys we have imported
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
    let result =
        imported_key.setProtectionId(ProtectionId::WIDEVINE_OUTPUT_BUFFER, &write_protection);
    expect!(result.is_err(), "should not be able to set protection id after on an imported key");
}

#[test]
fn derive_dice_bound_from_opaque_key() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::DERIVE,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");

    let dice_derivation_key = DiceBoundDerivationKey::OpaqueKey(Some(key));

    // Generate the current derivation key and policy
    let key_and_policy =
        assert_ok!(hw_crypto_key.deriveCurrentDicePolicyBoundKey(&dice_derivation_key));
    let DiceCurrentBoundKeyResult {
        diceBoundKey: dice_bound_derivation_key,
        dicePolicyForKeyVersion: dice_policy,
    } = key_and_policy;

    expect!(dice_bound_derivation_key.is_some(), "should have received a key");
    expect!(dice_policy.len() > 0, "should have received a DICE policy");

    let dice_bound_derivation_key = dice_bound_derivation_key.unwrap();
    let key_policy =
        assert_ok!(dice_bound_derivation_key.getKeyPolicy(), "couldn't retrieve key policy");
    expect_eq!(
        key_policy.keyLifetime,
        policy.keyLifetime,
        "lifetime should match with derivation key"
    );

    // We cannot manually derive the same opaque DICE bound key here because the DICE policy we
    // receive here is encrypted, so will only check that I can derive a key with key
    let derivation_context = b"context";
    let key_size = HMAC_SHA256_KEY_LEN;

    // Deriving a clear key
    let derived_policy =
        DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: key_size as i32 });
    let params = DerivedKeyParameters {
        derivationKey: Some(dice_bound_derivation_key),
        keyPolicy: derived_policy,
        context: derivation_context.to_vec(),
    };
    let derived_key_result = hw_crypto_key.deriveKey(&params);
    expect!(derived_key_result.is_ok(), "should be able to derive a clear key");
}

#[test]
fn try_derive_dice_bound_from_opaque_key_wrong_type() {
    let hw_crypto_key = assert_ok!(get_hwcryptokey(), "couldn't retrieve hw crypto binder");
    let derivation_key = [0; HMAC_SHA256_KEY_LEN];
    let clear_key = ExplicitKeyMaterial::Hmac(HmacKey::Sha256(derivation_key));
    let policy = KeyPolicy {
        usage: KeyUse::SIGN,
        keyLifetime: KeyLifetime::PORTABLE,
        keyPermissions: Vec::new(),
        keyManagementKey: false,
        keyType: KeyType::HMAC_SHA256,
    };
    let key =
        assert_ok!(hw_crypto_key.importClearKey(&clear_key, &policy), "couldn't import clear key");

    let dice_derivation_key = DiceBoundDerivationKey::OpaqueKey(Some(key));

    // Generate the current derivation key and policy
    let result = hw_crypto_key.deriveCurrentDicePolicyBoundKey(&dice_derivation_key);

    expect!(result.is_err(), "wrong type of key provided for derivation");
}
