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
    /// Verifies if provided `client_policy` is valid for the current client and also if the version
    /// of all the components are the most current ones. For a policy to be valid, the
    /// implementation needs to verify that the client identity matches the policy and also that any
    /// version of the components on the policy is less or equal than the current running component.
    /// This is to prevent a rollback attack.
    fn check_client_policy(
        client_id: &[u8],
        client_policy: &[u8],
    ) -> Result<ClientPolicyCheck, HwCryptoError>;

    /// Returns a valid and current policy tied to the connected HAL client. Notice that the policy
    /// can be stored by the external client and re-used on a future session.
    fn get_client_current_policy(client_id: &[u8]) -> Result<Vec<u8>, HwCryptoError>;

    /// Checks if the connected HAL client should have access to the requested keyslot. Currently
    /// the only keyslot supported is used to get an opaque handle to use the KeyMint Shared HMAC
    /// key.
    fn client_can_access_keyslot(
        client_id: &[u8],
        key_slot: KeySlot,
    ) -> Result<bool, HwCryptoError>;
}
