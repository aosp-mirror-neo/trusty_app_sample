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
            DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
            ClearKeyPolicy::ClearKeyPolicy,
        },
    };
    use binder::{StatusCode, Strong};
    use rpcbinder::RpcSession;
    use test::{expect, assert_ok};
    use trusty_std::ffi::{CString, FallibleCString};

    pub(crate) const RUST_DEVICE_KEY_SERVICE_PORT: &str = "com.android.trusty.rust.hwcryptohal.V1";

    pub(crate) const VERSION_0_DICE_POLICY: [u8; 134] = [
        0x83, 0x58, 0x3a, 0xa4, 0x01, 0x03, 0x3a, 0x00, 0x01, 0x00, 0x02, 0x58, 0x20, 0x19, 0xf4,
        0x7b, 0xb6, 0xf4, 0x23, 0x8f, 0x21, 0x27, 0xe7, 0x44, 0xe2, 0xbd, 0x1d, 0xdf, 0xc7, 0x04,
        0xfa, 0x54, 0x93, 0x39, 0x4f, 0x19, 0xce, 0x90, 0x2f, 0xcb, 0xfe, 0xb1, 0x95, 0xa4, 0x79,
        0x3a, 0x00, 0x01, 0x00, 0x03, 0x44, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x01, 0x00, 0x04,
        0x01, 0xa0, 0x58, 0x46, 0xbc, 0xa7, 0x5c, 0xda, 0x9a, 0x04, 0xc7, 0xee, 0x71, 0x04, 0x7c,
        0xa4, 0x8b, 0x37, 0x24, 0x8b, 0x2d, 0x2d, 0xe5, 0xf6, 0x18, 0x81, 0xad, 0xdc, 0xe6, 0xd6,
        0x20, 0xd5, 0x43, 0x8d, 0xed, 0xc3, 0xf2, 0xdf, 0x45, 0x40, 0xd7, 0xa8, 0x54, 0xdd, 0x6f,
        0x60, 0x07, 0x06, 0x0b, 0x0b, 0xb2, 0xcb, 0x36, 0x32, 0xd7, 0x65, 0x46, 0x30, 0xa4, 0x07,
        0xfc, 0x27, 0x82, 0xb6, 0xc6, 0x20, 0x23, 0x34, 0xad, 0x12, 0x62, 0xea, 0x2f, 0x7f,
    ];

    pub(crate) const VERSION_0_CLEAR_KEY: [u8; 256] = [
        0x51, 0x8b, 0x98, 0x36, 0x13, 0x50, 0x49, 0x74, 0x55, 0xed, 0x56, 0x74, 0x38, 0x3a, 0x1b,
        0xc8, 0xd1, 0x81, 0xe4, 0xfb, 0x69, 0x49, 0x52, 0xb0, 0xb5, 0x01, 0xb3, 0x8a, 0x86, 0xa6,
        0xdc, 0x9f, 0x8d, 0xa1, 0x43, 0xac, 0x29, 0x72, 0x2f, 0x62, 0x30, 0x32, 0x60, 0x60, 0x4e,
        0xfe, 0xb0, 0x2f, 0x46, 0x20, 0x77, 0xca, 0xa3, 0x94, 0x2b, 0xbe, 0xcb, 0x39, 0x38, 0x39,
        0xe0, 0xdc, 0xc7, 0x46, 0x14, 0x1e, 0x6c, 0x08, 0x41, 0x9a, 0xed, 0xde, 0x92, 0xa8, 0xc9,
        0x77, 0x78, 0x60, 0x0a, 0xfc, 0xda, 0x98, 0x01, 0xfd, 0x5c, 0x8e, 0x9d, 0x0a, 0x76, 0x4a,
        0xb7, 0x38, 0x37, 0x61, 0xd2, 0x1f, 0xb9, 0xca, 0x9d, 0x0e, 0xb8, 0x35, 0x5a, 0x6e, 0x99,
        0x5f, 0x52, 0x2b, 0x00, 0x62, 0x85, 0xb2, 0x76, 0xe6, 0xd7, 0xf5, 0x6c, 0x66, 0x0b, 0xf1,
        0x59, 0xe2, 0xf2, 0x2f, 0xd0, 0xd5, 0xfb, 0x74, 0x99, 0xa2, 0x36, 0x51, 0x2a, 0x62, 0x5c,
        0x7b, 0xdd, 0xe8, 0x42, 0x2a, 0xa2, 0x20, 0xf3, 0xd4, 0x2d, 0x64, 0x82, 0x7c, 0xe0, 0x1f,
        0x91, 0xdd, 0x9e, 0x64, 0x63, 0x48, 0x2a, 0xf3, 0xd9, 0x20, 0xae, 0x20, 0xd6, 0xc5, 0x8b,
        0x5e, 0xac, 0x1a, 0x7f, 0x42, 0x03, 0xc5, 0x90, 0x28, 0xfa, 0xe4, 0x82, 0xd8, 0xc9, 0xb1,
        0xd7, 0xf7, 0x2c, 0x8d, 0x59, 0x37, 0x6c, 0x30, 0x19, 0x99, 0x7e, 0x1c, 0x9b, 0x9b, 0x31,
        0xd4, 0x64, 0xa6, 0xd3, 0x21, 0xad, 0xcb, 0x60, 0x67, 0x8c, 0x99, 0x6f, 0x43, 0x60, 0x96,
        0xe4, 0xaf, 0xb7, 0xc0, 0xef, 0x97, 0x6b, 0x3e, 0xec, 0x5a, 0x32, 0x58, 0x74, 0x13, 0x2e,
        0xef, 0x7d, 0x11, 0x7c, 0x06, 0xa2, 0x37, 0xc2, 0x05, 0xe4, 0xf6, 0xa4, 0x68, 0x27, 0x56,
        0x31, 0x76, 0x21, 0x0e, 0x0e, 0xd8, 0x43, 0xe0, 0x49, 0x6d, 0x01, 0xab, 0xb7, 0xde, 0x52,
        0x0b,
    ];

    fn connect() -> Result<Strong<dyn IHwCryptoKey>, StatusCode> {
        let port =
            CString::try_new(RUST_DEVICE_KEY_SERVICE_PORT).expect("Failed to allocate port name");
        RpcSession::new().setup_trusty_client(port.as_c_str())
    }

    fn keys_are_sufficiently_distinct(key1: Vec<u8>, key2: Vec<u8>) -> bool {
        let differing_bytes = key1.iter().zip(key2.iter()).filter(|(&x1, &x2)| x1 != x2).count();

        std::cmp::min(key1.len(), key2.len()) - differing_bytes <= 4
    }

    #[test]
    fn generate_new_policy_and_clear_key() {
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

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
    fn old_dice_generates_old_clear_key_and_new_policy() {
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

        // Get the device bound key
        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);

        // Generate a derived key from version 0 dice policy
        let key_and_policy = assert_ok!(
            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
        );
        let DiceBoundKeyResult {
            diceBoundKey: derivation_key,
            dicePolicyWasCurrent: dice_policy_current,
        } = key_and_policy;

        // We expect version 0 should not be current
        expect!(!dice_policy_current, "policy not expected to be current");

        // Derive clear key from derivation key
        let params = DerivedKeyParameters {
            derivationKey: derivation_key,
            keyPolicy: DerivedKeyPolicy::ClearKeyPolicy(ClearKeyPolicy { keySizeBytes: 256 }),
            context: "context".as_bytes().to_vec(),
        };

        let derived_key = assert_ok!(hw_device_key.deriveKey(&params));

        // Check key type and length
        let derived_key = match derived_key {
            DerivedKey::Opaque(_) => panic!("wrong type of key received"),
            DerivedKey::ExplicitKey(k) => k,
        };

        assert_eq!(derived_key.len() as i32, 256, "wrong key length");

        // Check we got the old key and a new policy
        assert_eq!(derived_key, VERSION_0_CLEAR_KEY.to_vec(), "Retrieved version 0 key mismatch");
    }

    #[test]
    fn dice_updates_are_unique() {
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

        // Get the device bound key
        let device_bound_key = DiceBoundDerivationKey::KeyId(DeviceKeyId::DEVICE_BOUND_KEY);

        // Generate a derived key from version 0 dice policy
        let key_and_policy = assert_ok!(
            hw_device_key.deriveDicePolicyBoundKey(&device_bound_key, &VERSION_0_DICE_POLICY)
        );
        let DiceBoundKeyResult {
            diceBoundKey: _derivation_key,
            dicePolicyWasCurrent: dice_policy_current,
        } = key_and_policy;

        // We expect version 0 should not be current
        expect!(!dice_policy_current, "policy not expected to be current");

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
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

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
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

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
        let hw_device_key = connect().expect("couldn't connect to HW Crypto service");

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
