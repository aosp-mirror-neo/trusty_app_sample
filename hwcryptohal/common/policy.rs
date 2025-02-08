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

//! KeyPolicy serialization facilities

use crate::android;
use crate::{hwcrypto_err, err::HwCryptoError};
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;

pub use crate::android::{KeyLifetimeSerializable, KeyTypeSerializable, KeyUseSerializable};

pub fn check_key_policy(key_policy: &KeyPolicy) -> Result<(), HwCryptoError> {
    android::check_key_policy_values(key_policy)
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "issue found when checking policy {:?}", e))
}

pub fn cbor_serialize_key_policy(key_policy: &KeyPolicy) -> Result<Vec<u8>, HwCryptoError> {
    android::key_policy_to_cbor(key_policy)
        .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't serialize policy"))
}

pub fn cbor_policy_to_aidl(cbor_key_policy: &[u8]) -> Result<KeyPolicy, HwCryptoError> {
    android::cbor_to_key_policy(cbor_key_policy)
        .map_err(|_| hwcrypto_err!(SERIALIZATION_ERROR, "couldn't deserialize policy"))
}
