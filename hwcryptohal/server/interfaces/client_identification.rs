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

//! Module providing trait definition to access and check clients policies against their identities.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::KeySlot::KeySlot;
use hwcryptohal_common::err::HwCryptoError;

pub struct ClientPolicyCheck {
    pub policy_matches: bool,
    pub policy_is_current: bool,
}

/// Abstraction of client identification and authorization
pub trait ClientIdentification {
    /// checks that the provided client policy matches the client
    fn check_client_policy(
        &self,
        client_id: &[u8],
        client_policy: &[u8],
    ) -> Result<ClientPolicyCheck, HwCryptoError>;

    /// retrieves the client current client policy
    fn get_client_current_policy(&self, client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError>;

    /// checks if the caller can access the requested keyslot
    fn client_can_access_keyslot(
        &self,
        client_id: &[u8],
        key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError>;
}
