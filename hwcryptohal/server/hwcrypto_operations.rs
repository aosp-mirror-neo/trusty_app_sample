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

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::{
    types::OperationData::OperationData, CryptoOperation::CryptoOperation,
    CryptoOperationResult::CryptoOperationResult, CryptoOperationSet::CryptoOperationSet,
    IHwCryptoOperations::BnHwCryptoOperations, IHwCryptoOperations::IHwCryptoOperations,
};
use android_hardware_security_see_hwcrypto::binder;
use hwcryptohal_common::hwcrypto_err;

use crate::cmd_processing::CmdProcessorContext;
use crate::crypto_operation_context::{BinderCryptoOperationContext, CryptoOperationContext};

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
        command_lists: &mut std::vec::Vec<CryptoOperationSet>,
    ) -> binder::Result<Vec<CryptoOperationResult>> {
        let mut results = Vec::<CryptoOperationResult>::new();
        for command_list in command_lists {
            results.try_reserve(1).map_err(|e| {
                hwcrypto_err!(ALLOCATION_ERROR, "couldn't grow result vector: {:?}", e)
            })?;
            results.push(CryptoOperationResult { context: None });
            match &command_list.context {
                None => {
                    let mut cmd_processor = CmdProcessorContext::new();
                    cmd_processor.process_all_steps(&mut command_list.operations)?;
                    if !cmd_processor.is_destroyed() {
                        let operation_context = CryptoOperationContext::new_binder(cmd_processor);
                        results
                            .last_mut()
                            .expect("shouldn't happen, we pushed an element before match")
                            .context = Some(operation_context);
                    }
                }
                Some(operation_context) => {
                    BinderCryptoOperationContext::from(operation_context.clone())
                        .process_all_steps(&mut command_list.operations)?;
                }
            }
            // Just keep the command list elements that contain an output that needs to be return to
            // the caller. At this point CryptoOperation::DataOutput is the only operation returning
            // data using vectors but only when it contains an OperationData::DataBuffer.
            command_list
                .operations
                .retain(|x| matches!(x, CryptoOperation::DataOutput(OperationData::DataBuffer(_))));
        }
        Ok(results)
    }
}
