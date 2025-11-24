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

//! Implementation of the `ICommandProcessor` AIDL interface

use android_trusty_cmdprocessor::aidl::android::trusty::cmdprocessor::{
    ICommandProcessor::BnCommandProcessor, ICommandProcessor::ICommandProcessor,
    MemoryBufferReference::MemoryBufferReference,
};

/// The `ICommandProcessors` implementation.
pub struct CmdProcessor;

impl binder::Interface for CmdProcessor {}

impl CmdProcessor {
    pub fn new_binder() -> binder::Strong<dyn ICommandProcessor> {
        let cmd_processor = CmdProcessor;
        BnCommandProcessor::new_binder(cmd_processor, binder::BinderFeatures::default())
    }
}

impl ICommandProcessor for CmdProcessor {
    fn processCommand(
        &self,
        _cmd_name: &str,
        _mem_buffers_ref: &[MemoryBufferReference],
        _cmd_data_in: &[u8],
        _cmd_data_out: &mut Vec<u8>,
    ) -> binder::Result<()> {
        unimplemented!("processCommand not implemented yet")
    }
}
