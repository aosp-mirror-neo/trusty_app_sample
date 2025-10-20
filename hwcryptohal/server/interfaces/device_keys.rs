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

//! Module providing trait definition to access device specific keys.
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
use hwcryptohal_common::err::HwCryptoError;
use kmr_common::crypto::{OpaqueOr, hmac};

/// Definition for the Keymint shared HMAC key
pub struct KeymintHmacKey(pub OpaqueOr<hmac::Key>);

/// Abstraction of device specific keys
pub trait DeviceKeys {
    /// Returns the Keymint shared HMAC key, which is of type `HMAC_SHA256`. Returned Key is of type
    /// `OpaqueOr<hmac::Key>`, which allows the implementation to also implement this using opaque
    /// keys, with the only requirement that `HmacImpl` needs to be able to use the key.
    /// `get_keymint_shared_hmac_key` will be expected to give a valid key only after
    /// `generate_keymint_shared_hmac_key` has been executed. `policy` can be used by the
    /// implementation to verify the policy parameters that HwCrypto will use to create the
    /// Keymint shared HMAC opaque key.
    fn get_keymint_shared_hmac_key(policy: &KeyPolicy) -> Result<KeymintHmacKey, HwCryptoError>;

    /// Function receives all the parameters needed to calculate the shared secret according to the
    /// ISharedSecret protocol: <https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/sharedsecret/aidl/android/hardware/security/sharedsecret/ISharedSecret.aidl#73>
    /// Implementation shall return the 32 byte value used to verify that all `ISharedSecret`
    /// instances calculated the same shared HMAC key.
    fn generate_keymint_shared_hmac_key(
        label: &[u8],
        context: &[u8],
        key_len: usize,
        check_label: &[u8],
    ) -> Result<Vec<u8>, HwCryptoError>;

    /// Returns a unique versioned key cryptographically bound to the caller, context and security
    /// version. If the caller current version is greater or equal than the provided version,
    /// the function should succeed. Calling this function with the same caller, version and context
    /// should generate the same key, if the version check passes. Notice that `key_sec_version`
    /// could be a DICE policy and will be a byte array previously received by calling
    /// `get_caller_current_security_version`.
    fn derive_caller_unique_key(
        key_context: &[u8],
        key_sec_version: &[u8],
        key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError>;

    /// Returns the caller current security version. Notice that this version could be a DICE
    /// policy.
    fn get_caller_current_security_version() -> Result<Vec<u8>, HwCryptoError>;
}
