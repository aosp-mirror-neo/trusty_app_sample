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

//! Implementation of the `IHwCryptoOperations` AIDL interface. It can be use to retrieve the
//! key generation interface and to process cryptographic operations.

use alloc::ffi::CString;
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    CryptoOperationErrorAdditionalInfo::CryptoOperationErrorAdditionalInfo,
    CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
    IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
};
use android_hardware_security_see::binder;

/// The `IHwCryptoOperations` implementation.
pub struct HwCryptoOperations;

impl binder::Interface for HwCryptoOperations {}

impl HwCryptoOperations {
    pub(crate) fn new_binder() -> binder::Strong<dyn IHwCryptoOperations> {
        let hwcrypto_operations = HwCryptoOperations;
        BnHwCryptoOperations::new_binder(hwcrypto_operations, binder::BinderFeatures::default())
    }
}

impl IHwCryptoOperations for HwCryptoOperations {
    fn processCommandList(
        &self,
        _command_list: &mut std::vec::Vec<CryptoOperationSet>,
        _additional_error_info: &mut CryptoOperationErrorAdditionalInfo,
    ) -> binder::Result<Vec<CryptoOperationResult>> {
        Err(binder::Status::new_exception(
            binder::ExceptionCode::UNSUPPORTED_OPERATION,
            Some(&CString::new("operation has not been implemented yet").unwrap()),
        ))
    }
}
