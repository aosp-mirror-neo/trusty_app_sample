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

//! Implementation of the `IMemoryBufferShare` AIDL interface

use android_trusty_membuf::aidl::android::trusty::membuf::{
    IMemoryBufferShare::BnMemoryBufferShare, IMemoryBufferShare::IMemoryBufferShare,
    ShareMemoryBufferResult::ShareMemoryBufferResult,
};
use binder::ParcelFileDescriptor;

/// The `IMemoryBufferShare` implementation.
pub struct MemBuffShare;

impl binder::Interface for MemBuffShare {}

impl MemBuffShare {
    pub fn new_binder() -> binder::Strong<dyn IMemoryBufferShare> {
        let mem_buff_share = MemBuffShare;
        BnMemoryBufferShare::new_binder(mem_buff_share, binder::BinderFeatures::default())
    }
}

impl IMemoryBufferShare for MemBuffShare {
    fn shareMemoryBuffer(
        &self,
        _fd: &ParcelFileDescriptor,
        _size_bytes: i32,
    ) -> binder::Result<ShareMemoryBufferResult> {
        unimplemented!("shareMemoryBuffer not implemented yet")
    }
}
