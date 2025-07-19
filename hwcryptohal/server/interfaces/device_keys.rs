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

use hwcryptohal_common::err::HwCryptoError;

/// Definition for the Keymint shared HMAC key
pub struct KeymintHmacKey(pub [u8; 32]);

/// Abstraction of device specific keys
pub trait DeviceKeys {
    /// Returns the Keymint shared HMAC key. The size of the key matches what Android expects. The
    /// key will be passed to the caller as a HwCrypto `IOpaqueKey`, which means all uses of it will
    /// be done through the HWCrypto HAL service. Notice that internally this key is used through an
    /// implementetion of the KeyMint `Hmac` trait. This function shall return a valid key after
    /// `generate_keymint_shared_hmac_key` has been called.
    fn get_keymint_shared_hmac_key() -> Result<KeymintHmacKey, HwCryptoError>;

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
