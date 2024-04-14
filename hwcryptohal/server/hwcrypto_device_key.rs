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

//! Implementation of the `IHwCryptoKey` AIDL interface. It can be use to generate and
//! retrieve device specific keys.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    IHwCryptoKey::BnHwCryptoKey,
    IHwCryptoKey::{
        DerivedKey::DerivedKey, DerivedKeyParameters::DerivedKeyParameters,
        DiceBoundDerivationKey::DiceBoundDerivationKey, DiceBoundKeyResult::DiceBoundKeyResult,
        DiceCurrentBoundKeyResult::DiceCurrentBoundKeyResult, IHwCryptoKey,
    },
};
use android_hardware_security_see::binder;
use tipc::Uuid;

/// The `IHwCryptoKey` implementation.
#[derive(Debug)]
pub struct HwCryptoKey {
    #[allow(dead_code)]
    uuid: Uuid,
}

impl binder::Interface for HwCryptoKey {}

impl HwCryptoKey {
    pub(crate) fn new_binder(uuid: Uuid) -> binder::Strong<dyn IHwCryptoKey> {
        let hwcrypto_device_key = HwCryptoKey { uuid };
        BnHwCryptoKey::new_binder(hwcrypto_device_key, binder::BinderFeatures::default())
    }
}

impl IHwCryptoKey for HwCryptoKey {
    fn deriveCurrentDicePolicyBoundKey(
        &self,
        _derivation_key: &DiceBoundDerivationKey,
    ) -> binder::Result<DiceCurrentBoundKeyResult> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("operation has not been implemented yet"),
        ))
    }

    fn deriveDicePolicyBoundKey(
        &self,
        _derivation_key: &DiceBoundDerivationKey,
        _dice_policy_for_key_version: &[u8],
    ) -> binder::Result<DiceBoundKeyResult> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("operation has not been implemented yet"),
        ))
    }

    fn deriveKey(&self, _parameters: &DerivedKeyParameters) -> binder::Result<DerivedKey> {
        Err(binder::Status::new_exception_str(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some("operation has not been implemented yet"),
        ))
    }
}
