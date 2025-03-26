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

//! Module providing trait definition to map objects to memory.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::MemoryBufferParameter::MemoryBufferParameter;
use hwcryptohal_common::err::HwCryptoError;
use vm_memory::VolatileSlice;

/// Abstraction of memory mapped objects. Notice that the trait do not contain an unmap function, so
/// any cleanup needed by the implementation must be done by implementing `Drop`.
pub trait MemoryMappedObject: Send {
    /// Maps a `MemoryBufferParameter` into a `MemoryMappedObject`
    fn mmap(memory_buffer: &MemoryBufferParameter) -> Result<Self, HwCryptoError>
    where
        Self: std::marker::Sized;

    /// Gets a memory slice that can be used to read or write on the memory mapped object
    fn get_memory_slice(&mut self) -> Result<VolatileSlice, HwCryptoError>;

    /// Returns the mapped memory buffer size
    fn buffer_size(&self) -> usize;
}
