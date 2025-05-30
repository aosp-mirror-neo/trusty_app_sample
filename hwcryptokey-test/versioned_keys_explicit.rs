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
#[cfg(test)]
mod tests {
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
        IHwCryptoKey::{
            DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
            DerivedKeyPolicy::DerivedKeyPolicy, DeviceKeyId::DeviceKeyId,
            DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, ClearKeyPolicy::ClearKeyPolicy,
        },
    };
    use test::{expect, assert_ok};

    use crate::tests::get_hwcryptokey;

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
}
