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

//! Module providing an implementation for the `MemoryMappedObject` trait.
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::MemoryBufferParameter::{
    MemoryBuffer::MemoryBuffer, MemoryBufferParameter,
};
use binder::ParcelFileDescriptor;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::MemoryMappedObject;
use std::ffi::c_void;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use vm_memory::VolatileSlice;

const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
const INPUT_MEMORY_BUFFER_FLAGS: u32 = trusty_sys::MMAP_FLAG_PROT_READ;

fn mmap(
    buffer_size: usize,
    protection_flags: u32,
    buffer_handle: &ParcelFileDescriptor,
) -> Result<*mut c_void, HwCryptoError> {
    let buffer_size = u32::try_from(buffer_size)
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "error converting buffer size {:?}", e))?;
    // SAFETY: mmap is left to choose the address for the allocation. It will check that the
    //         protection flags, size and fd are correct and return a negative value if
    //         not.
    let buffer_ptr = unsafe {
        trusty_sys::mmap(
            std::ptr::null_mut(),
            buffer_size,
            protection_flags,
            buffer_handle.as_ref().as_raw_fd(),
        )
    };
    if trusty_sys::Error::is_ptr_err(buffer_ptr as *const c_void) {
        return Err(hwcrypto_err!(BAD_PARAMETER, "mapping buffer handle failed: {}", buffer_ptr));
    }
    Ok(buffer_ptr as *mut c_void)
}

fn get_mmap_prot_flags(memory_buffer: &MemoryBuffer) -> u32 {
    match memory_buffer {
        MemoryBuffer::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
        MemoryBuffer::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
    }
}

// Wrapper over pointer used to map memory buffer.
pub struct MappedBuffer(NonNull<u8>);

// SAFETY: `MappedBuffer` is only used to free object on drop or to create a `VolatileSlice` when
//         we need to access the underlying memory buffer; never directly. It is safe to access and
//         drop on a different thread. All accesses to the mmaped memory are done through the
//         `VolatileSlice` which already has the assumption that the underlying memory is shared
//         between different entities, so it only uses `std::ptr::{copy, read_volatile,
//         write_volatile}` to access memory.
unsafe impl Send for MappedBuffer {}

pub struct TrustyMappedObject {
    buffer_ptr: MappedBuffer,
    buffer_size: usize,
}

impl MemoryMappedObject for TrustyMappedObject {
    fn mmap(memory_buffer: &MemoryBufferParameter) -> Result<Self, HwCryptoError> {
        if memory_buffer.sizeBytes <= 0 {
            return Err(hwcrypto_err!(BAD_PARAMETER, "Buffer size was not greater than 0"));
        }
        // memory_buffer_parameters.size is positive and because it is an i32, conversion is correct
        let buffer_size = memory_buffer.sizeBytes as usize;
        let protection_flags = get_mmap_prot_flags(&memory_buffer.bufferHandle);
        let buffer_handle = match &memory_buffer.bufferHandle {
            MemoryBuffer::Input(handle) | MemoryBuffer::Output(handle) => handle,
        };
        let buffer_handle = buffer_handle
            .as_ref()
            .ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "received a null buffer handle"))?;
        let buffer_ptr = mmap(buffer_size, protection_flags, buffer_handle)?;
        let buffer_ptr = NonNull::new(buffer_ptr as *mut u8)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "buffer_ptr was NULL"))?;

        Ok(Self { buffer_ptr: MappedBuffer(buffer_ptr), buffer_size })
    }

    fn get_memory_slice(&mut self) -> Result<VolatileSlice<'_>, HwCryptoError> {
        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
        //         operation would have failed. All accesses to this memory on this service are
        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory is
        //         only unmapped on drop, so it will available for the lifetime of the
        //         `VolatileSlice`.
        let mem_buffer =
            unsafe { VolatileSlice::new(self.buffer_ptr.0.as_ptr(), self.buffer_size) };
        Ok(mem_buffer)
    }

    fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

impl Drop for TrustyMappedObject {
    fn drop(&mut self) {
        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
        //         of the object. `buffer_ptr` is still mapped at this point
        unsafe {
            trusty_sys::munmap(self.buffer_ptr.0.as_ptr().cast::<c_void>(), self.buffer_size as u32)
        };
    }
}
