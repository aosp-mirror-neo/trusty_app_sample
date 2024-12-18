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

//! Implementation of the `ICryptoOperationContext` AIDL interface. It can be used to execute more
//! commands over the same context.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    CryptoOperation::CryptoOperation, ICryptoOperationContext::BnCryptoOperationContext,
    ICryptoOperationContext::ICryptoOperationContext,
};
use binder::binder_impl::Binder;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use std::sync::Mutex;

use crate::cmd_processing::CmdProcessorContext;

/// The `ICryptoOperationContext` implementation.
pub struct CryptoOperationContext {
    cmd_processor: Mutex<CmdProcessorContext>,
}

impl binder::Interface for CryptoOperationContext {}

impl CryptoOperationContext {
    pub(crate) fn new_binder(
        cmd_processor: CmdProcessorContext,
    ) -> binder::Strong<dyn ICryptoOperationContext> {
        let hwcrypto_key = CryptoOperationContext { cmd_processor: Mutex::new(cmd_processor) };
        BnCryptoOperationContext::new_binder(hwcrypto_key, binder::BinderFeatures::default())
    }
}

impl ICryptoOperationContext for CryptoOperationContext {}

pub(crate) struct BinderCryptoOperationContext(binder::Strong<dyn ICryptoOperationContext>);

impl From<binder::Strong<dyn ICryptoOperationContext>> for BinderCryptoOperationContext {
    fn from(value: binder::Strong<dyn ICryptoOperationContext>) -> Self {
        Self(value)
    }
}

impl From<BinderCryptoOperationContext> for binder::Strong<dyn ICryptoOperationContext> {
    fn from(value: BinderCryptoOperationContext) -> Self {
        value.0
    }
}

impl BinderCryptoOperationContext {
    pub(crate) fn process_all_steps(
        &self,
        operations: &mut [CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        let binder = self.0.as_binder();
        if binder.is_remote() {
            return Err(hwcrypto_err!(GENERIC_ERROR, "binder is not local"));
        }
        let native_context: Binder<BnCryptoOperationContext> = binder.try_into().map_err(|e| {
            hwcrypto_err!(GENERIC_ERROR, "shouldn't fail because binder is local {:?}", e)
        })?;
        let mut cmd_processor = native_context
            .downcast_binder::<CryptoOperationContext>()
            .ok_or(hwcrypto_err!(GENERIC_ERROR, "couldn't cast back operation context"))?
            .cmd_processor
            .lock()
            .map_err(|e| {
                hwcrypto_err!(
                    GENERIC_ERROR,
                    "poisoned mutex, shold not happen on a single thread application: {:?}",
                    e
                )
            })?;
        cmd_processor.process_all_steps(operations)?;
        Ok(())
    }
}
