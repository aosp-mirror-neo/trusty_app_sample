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

//! Module providing an implementation of a cryptographic command processor.

use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::types::{
    MemoryBufferReference::MemoryBufferReference, OperationData::OperationData,
};
use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
    CryptoOperation::CryptoOperation,
    MemoryBufferParameter::{
        MemoryBuffer::MemoryBuffer as MemoryBufferAidl, MemoryBufferParameter,
    },
};
use core::ffi::c_void;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use std::{os::fd::AsRawFd, ptr::NonNull};
use vm_memory::volatile_memory::VolatileSlice;

const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;
const INPUT_MEMORY_BUFFER_FLAGS: u32 = trusty_sys::MMAP_FLAG_PROT_READ;

/// `CmdProcessorState` is a state machine with 3 states:
///
/// * `InitialState`: State machine operation starts here. No cryptographic operations can be
///                   performed on this state (but copy operations are permitted). It is used to
///                   set up memory buffers and Cryptographic operation parameters. We can go back
///                   to this state from `RunningOperation` state after a `Finish` call.
/// * `RunningOperation`: Once a call to `SetOperationParameters` is performed, we move to this
///                       state. Any call to `DataInput` on this state will immediately perform the
//                        requested cryptographic operation.
/// * `Destroyed`: Any call to `DestroyContext` will make the state machine move to this state. Once
///                in this state, the state machine cannot be used anymore.
///
/// The following diagram shows how we move between states. It is written in the form
/// [Current State] -> [Next State]: [Operation performed on current state]:
///
/// `InitialState` -> `InitialState`: `CopyData`
///         Call requires that an output buffer has been set and will immediately try to copy the
///         data provided
/// `InitialState` -> `InitialState`: `DataOutput`
///         Sets output buffer. Any previously set up DataOutput is not used after this.
/// `InitialState` -> `InitialState`: `SetMemoryBuffer`
///         Sets an fd to be used by memory references. It can only be set once
///         because currently output buffers will directly use the active memory buffer, instead of
///         remembering which memory buffer was active at the moment the output was added. This
///         should cover the current use cases, but could be refactored if needed.
/// `InitialState` -> `RunningOperation`: `SetOperationParameters`
///         Starts executing cryptographic operation.
/// `RunningOperation` -> `RunningOperation`: `DataOutput`
///         Sets output buffer. Any previously set up DataOutput is not used after this.
/// `RunningOperation` -> `RunningOperation`: `CopyData`
///         Call requires that an output buffer has been set and will immediately try to copy the
///         data provided. It can be used to implement some cryptographic protocols which decrypt
///         only some areas and directly copy other areas
/// `RunningOperation` -> `RunningOperation`: `AadInput`
///         Processes the provided data as Authenticated Additional Data
/// `RunningOperation` -> `RunningOperation`: `DataInput`
///         Immediately processes the provided data. For operations like encryption or decryption on
///         which we need to immediately generate data, this call requires that an output buffer has
///         been already set up
/// `RunningOperation` -> `RunningOperation`: `SetPattern`
///         Sets up a pattern of encrypted/unencrypted data to process on the subsequent calls to
///         `DataInput`. Currently it is only used for AES CBC decryption (cbcs mode from IEC
///         23001-7:2016)
/// `RunningOperation` -> `InitialState`: `Finish`
///         Finish an ongoing cryptographic operation. Notice that this call can generate data as in
///         the case of signing operations or padded encryption. This call will invalidate any
///         settings done by `SetOperationParameters` or `SetPattern`
/// `RunningOperation` -> `RunningOperation`: `SetOperationParameters`
///         Resets all cryptographic parameters set up on the previous `SetOperationParameters`
///         operation and implicitly calls finish. Main use case is to reset IV for cbcs mode
///         decryption without needing to call finish.
/// `RunningOperation` -> `Destroyed`: `DestroyContext`
///         This context cannot be used anymore
/// `InitialState` -> `Destroyed`: `DestroyContext`
///         This context cannot be used anymore
enum CmdProcessorState {
    InitialState,
    RunningOperation,
    Destroyed,
}

// Structure to keep track how much space we still have on the current output buffer.
struct OutputData {
    #[allow(unused)]
    step: usize,
    remaining_size: Option<usize>,
}

fn get_mmap_prot_flags(memory_buffer: &MemoryBufferAidl) -> u32 {
    match memory_buffer {
        MemoryBufferAidl::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
        MemoryBufferAidl::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
    }
}

// Type added to be able to use AIDL `MemoryBufferReference` type more conveniently
struct MemoryBufferSlice {
    start_offset: i32,
    size_bytes: i32,
}

impl From<&MemoryBufferReference> for MemoryBufferSlice {
    fn from(value: &MemoryBufferReference) -> Self {
        MemoryBufferSlice { start_offset: value.startOffset, size_bytes: value.sizeBytes }
    }
}

// `MemoryBufferSlice`/`MemoryBufferReference` types do not contain the necessary information to
// know if it should operate on an Input or Output buffer. That information is provided by the
// Operation which contains the `MemoryBufferReference`. This wrapper preserves that information to
// be used along function call sequences.
enum MemoryBufferReferenceWithType {
    #[allow(dead_code)]
    Input(MemoryBufferSlice),
    Output(MemoryBufferSlice),
}

impl MemoryBufferReferenceWithType {
    fn len(&self) -> Result<usize, HwCryptoError> {
        match self {
            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.size_bytes,
            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.size_bytes,
        }
        .try_into()
        .map_err(|e| {
            hwcrypto_err!(BAD_PARAMETER, "buffer reference sizes cannot be negative: {:?}", e)
        })
    }

    fn start_offset(&self) -> Result<usize, HwCryptoError> {
        match self {
            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.start_offset,
            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.start_offset,
        }
        .try_into()
        .map_err(|e| {
            hwcrypto_err!(BAD_PARAMETER, "buffer reference offsets cannot be negative: {:?}", e)
        })
    }
}

// TODO: This type is still a WIP.
struct MemoryBuffer {
    #[allow(dead_code)]
    mem_buffer: VolatileSlice<'static>,
    buffer_ptr: NonNull<u8>,
    total_size: usize,
}

impl MemoryBuffer {
    fn new(memory_buffer_parameters: &MemoryBufferParameter) -> Result<Self, HwCryptoError> {
        if memory_buffer_parameters.sizeBytes <= 0 {
            return Err(hwcrypto_err!(BAD_PARAMETER, "Buffer size was not greater than 0"));
        }
        // memory_buffer_parameters.size is positive and because it is an i32, conversion is correct
        let buffer_size = memory_buffer_parameters.sizeBytes as u32;
        let protection_flags = get_mmap_prot_flags(&memory_buffer_parameters.bufferHandle);
        let buffer_handle = match &memory_buffer_parameters.bufferHandle {
            MemoryBufferAidl::Input(handle) | MemoryBufferAidl::Output(handle) => handle,
        };

        let buffer_handle = buffer_handle
            .as_ref()
            .ok_or_else(|| hwcrypto_err!(BAD_PARAMETER, "received a null buffer handle"))?;
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
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "mapping buffer handle failed: {}",
                buffer_ptr
            ));
        }
        // cast is correct because buffer_ptr is positive and a pointer
        let buffer_ptr = NonNull::new(buffer_ptr as *mut u8)
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "buffer_ptr was NULL"))?;
        // cast is correct because buffer_size is an u32
        let buffer_size = buffer_size as usize;

        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
        //         operation would have failed. All accesses to this memory on this service are
        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory
        //         is only unmapped on drop, so it will available for the lifetime of the
        //         `VolatileSlice`.
        let mem_buffer = unsafe { VolatileSlice::new(buffer_ptr.as_ptr(), buffer_size) };
        Ok(Self { mem_buffer, buffer_ptr, total_size: buffer_size })
    }
}

impl Drop for MemoryBuffer {
    fn drop(&mut self) {
        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
        //         of the object. `buffer_ptr` is still mapped at this point
        unsafe {
            trusty_sys::munmap(self.buffer_ptr.as_ptr().cast::<c_void>(), self.total_size as u32)
        };
    }
}

// `CmdProcessorContext` is the type in charge of executing a set of commands.
struct CmdProcessorContext {
    current_input_memory_buffer: Option<MemoryBuffer>,
    current_output_memory_buffer: Option<MemoryBuffer>,
    current_output_data: Option<OutputData>,
    current_state: CmdProcessorState,
}

impl CmdProcessorContext {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            current_input_memory_buffer: None,
            current_output_memory_buffer: None,
            current_output_data: None,
            current_state: CmdProcessorState::InitialState,
        }
    }

    // Helper function used to check if a given `MemoryBufferReference` is valid for the active
    // `MemoryBuffer`s of the state machine
    fn check_memory_reference_in_range(
        &self,
        buffer_reference: &MemoryBufferReferenceWithType,
    ) -> Result<(), HwCryptoError> {
        let current_memory_buffer = match buffer_reference {
            MemoryBufferReferenceWithType::Input(_) => &self.current_input_memory_buffer,
            MemoryBufferReferenceWithType::Output(_) => &self.current_output_memory_buffer,
        };
        let buffer_start = buffer_reference.start_offset()?;
        let buffer_size = buffer_reference.len()?;
        if buffer_size == 0 {
            return Err(hwcrypto_err!(BAD_PARAMETER, "cannot create buffer references of size 0"));
        }
        if let Some(current_memory_buffer) = current_memory_buffer {
            if buffer_start >= current_memory_buffer.total_size {
                return Err(hwcrypto_err!(BAD_PARAMETER, "buffer start falls outside of buffer"));
            }
            // Because both values are positive and signed, then the addition should not
            // overflow. Using a checked add in case we can change these values to unsigned
            // in the future
            if let Some(buffer_end) = buffer_size.checked_add(buffer_start) {
                if buffer_end > current_memory_buffer.total_size {
                    Err(hwcrypto_err!(BAD_PARAMETER, "buffer reference falls outside of buffer"))
                } else {
                    Ok(())
                }
            } else {
                Err(hwcrypto_err!(BAD_PARAMETER, "requested size goes past buffer end"))
            }
        } else {
            Err(hwcrypto_err!(
                BAD_PARAMETER,
                "memory buffer has not been set yet, so we cannot process references to it"
            ))
        }
    }

    fn get_data_buffer_size(
        &self,
        buffer_reference: &MemoryBufferReferenceWithType,
    ) -> Result<usize, HwCryptoError> {
        self.check_memory_reference_in_range(buffer_reference)?;
        buffer_reference.len()
    }

    fn set_memory_buffer_step(
        &mut self,
        parameters: &MemoryBufferParameter,
        _step: usize,
        _previous_operations: &[CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        let current_memory_buffer = match &parameters.bufferHandle {
            MemoryBufferAidl::Input(_) => &mut self.current_input_memory_buffer,
            MemoryBufferAidl::Output(_) => &mut self.current_output_memory_buffer,
        };
        if current_memory_buffer.is_some() {
            Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer already set"))
        } else {
            if parameters.sizeBytes < 0 {
                Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer size is negative"))
            } else {
                *current_memory_buffer = Some(MemoryBuffer::new(parameters)?);
                Ok(())
            }
        }
    }

    fn add_output_step(
        &mut self,
        output_parameters: &OperationData,
        step: usize,
        _previous_operations: &[CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        match output_parameters {
            OperationData::DataBuffer(_) => {
                // A data buffer (Vector) doesn't have a size limit because you can keep
                // pushing data into it
                self.current_output_data = Some(OutputData { step, remaining_size: None })
            }
            OperationData::MemoryBufferReference(buffer_reference) => {
                self.current_output_data = Some(OutputData {
                    step,
                    remaining_size: Some(self.get_data_buffer_size(
                        &MemoryBufferReferenceWithType::Output(buffer_reference.into()),
                    )?),
                })
            }
        };
        Ok(())
    }

    #[allow(dead_code)]
    fn set_current_output_remaining_size(
        &mut self,
        remaining_size: usize,
    ) -> Result<(), HwCryptoError> {
        match &mut self.current_output_data {
            Some(current_output) => {
                current_output.remaining_size = Some(remaining_size);
                Ok(())
            }
            None => Err(hwcrypto_err!(ALLOCATION_ERROR, "no output buffer available")),
        }
    }

    fn destroy_step(
        &mut self,
        _step: usize,
        _previous_operations: &[CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        self.current_input_memory_buffer = None;
        self.current_output_memory_buffer = None;
        self.current_output_data = None;
        self.current_state = CmdProcessorState::Destroyed;
        Ok(())
    }

    #[allow(dead_code)]
    fn process_step(
        &mut self,
        step: usize,
        operations: &mut [CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        if step >= operations.len() {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "Step to process {} exceeds command list length {}",
                step,
                operations.len()
            ));
        }
        let (previous_operations, operation) = operations.split_at_mut(step);
        let current_step = &operation[0];
        match self.current_state {
            CmdProcessorState::InitialState => match current_step {
                CryptoOperation::DataOutput(step_data) => {
                    self.add_output_step(&step_data, step, previous_operations)
                }
                CryptoOperation::CopyData(_) => unimplemented!("copy step not implemented yet"),
                CryptoOperation::DestroyContext(_) => self.destroy_step(step, previous_operations),
                CryptoOperation::SetMemoryBuffer(step_data) => {
                    self.set_memory_buffer_step(&step_data, step, previous_operations)
                }
                CryptoOperation::SetOperationParameters(_step_data) => {
                    self.current_state = CmdProcessorState::RunningOperation;
                    unimplemented!("SetOperationParameters from InitialState not implemented yet")
                }
                CryptoOperation::SetPattern(_) => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "SetPattern not permitted before calling SetOperationParameters"
                )),
                CryptoOperation::DataInput(_) => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "DataInput not permitted before calling SetOperationParameters"
                )),
                CryptoOperation::AadInput(_) => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "AadInput not permitted before calling SetOperationParameters"
                )),
                CryptoOperation::Finish(_) => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "Finish not permitted before calling SetOperationParameters"
                )),
            },
            CmdProcessorState::RunningOperation => match current_step {
                CryptoOperation::DataOutput(step_data) => {
                    self.add_output_step(&step_data, step, previous_operations)
                }
                CryptoOperation::CopyData(_) => unimplemented!("copy step not implemented yet"),
                CryptoOperation::DestroyContext(_) => self.destroy_step(step, previous_operations),
                CryptoOperation::Finish(_step_data) => {
                    self.current_state = CmdProcessorState::InitialState;
                    unimplemented!("Finish not implemented yet")
                }
                CryptoOperation::SetPattern(_) => unimplemented!("SetPattern not implemented yet"),
                CryptoOperation::DataInput(_) => unimplemented!("DataInput not implemented yet"),
                CryptoOperation::AadInput(_) => unimplemented!("AadInput not implemented yet"),
                CryptoOperation::SetOperationParameters(_step) => unimplemented!(
                    "SetOperationParameters from RunningOperation not implemented yet"
                ),
                CryptoOperation::SetMemoryBuffer(_) => Err(hwcrypto_err!(
                    BAD_PARAMETER,
                    "SetMemoryBuffer not permitted once SetOperationParameters has been called"
                )),
            },
            CmdProcessorState::Destroyed => {
                Err(hwcrypto_err!(BAD_PARAMETER, "Cannot send any command after DestroyContext"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opaque_key::OpaqueKey;
    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::{
        types::{
            AesCipherMode::AesCipherMode, CipherModeParameters::CipherModeParameters, HalErrorCode,
            KeyLifetime::KeyLifetime, KeyType::KeyType, KeyUse::KeyUse,
            SymmetricCryptoParameters::SymmetricCryptoParameters,
            SymmetricOperation::SymmetricOperation,
            SymmetricOperationParameters::SymmetricOperationParameters,
        },
        KeyPolicy::KeyPolicy,
        OperationParameters::OperationParameters,
        PatternParameters::PatternParameters,
    };
    use binder::ParcelFileDescriptor;
    use core::ffi::c_void;
    use std::alloc::{alloc_zeroed, dealloc, Layout};
    use std::os::fd::{FromRawFd, OwnedFd};
    use test::{expect, expect_eq};
    use vm_memory::Bytes;

    /// Structure only intended to use on unit tests. It will allocate a single memory page and
    /// create a memref to it.
    struct TestPageAllocator {
        allocated_buffer: *mut u8,
        layout: Layout,
        raw_trusty_fd: i64,
        parcel_file_descriptor_created: bool,
    }

    impl TestPageAllocator {
        fn new() -> Result<Self, HwCryptoError> {
            let page_size = Self::get_allocation_size();
            if page_size == 0 {
                return Err(hwcrypto_err!(ALLOCATION_ERROR, "received zero as the page size"));
            }
            let layout = Layout::from_size_align(page_size, page_size).map_err(|e| {
                hwcrypto_err!(
                    GENERIC_ERROR,
                    "layout creation error, should not have happened: {:?}",
                    e
                )
            })?;
            // SAFETY: Layout is non-zero
            let allocated_buffer = unsafe { alloc_zeroed(layout) };
            // Always mapping things as output to change the buffer values for tests
            let prot_flags = OUTPUT_MEMORY_BUFFER_FLAGS;
            // SAFETY: address and size are correct because they came from the allocation.
            let raw_trusty_fd = unsafe {
                trusty_sys::memref_create(
                    allocated_buffer as *mut c_void,
                    page_size as u32,
                    prot_flags,
                )
            };
            if raw_trusty_fd < 0 {
                return Err(hwcrypto_err!(ALLOCATION_ERROR, "memref creation failed"));
            }
            let parcel_file_descriptor_created = false;
            Ok(Self {
                allocated_buffer,
                layout,
                raw_trusty_fd: raw_trusty_fd.into(),
                parcel_file_descriptor_created,
            })
        }

        fn get_parcel_file_descriptor(&mut self) -> Result<ParcelFileDescriptor, HwCryptoError> {
            if self.parcel_file_descriptor_created {
                return Err(hwcrypto_err!(
                    GENERIC_ERROR,
                    "only a single parcel file descriptor can be created"
                ));
            }
            // fd is valid if the object has been created and we can take ownership of it.
            self.parcel_file_descriptor_created = true;
            let fd = unsafe { OwnedFd::from_raw_fd(self.raw_trusty_fd as i32) };
            Ok(ParcelFileDescriptor::new(fd))
        }

        fn get_allocation_size() -> usize {
            // SAFETY: FFI call with all safe arguments.
            let page_size = unsafe { libc::getauxval(libc::AT_PAGESZ) };
            page_size as usize
        }

        fn copy_values(&mut self, start: usize, values: &[u8]) -> Result<(), HwCryptoError> {
            if self.parcel_file_descriptor_created {
                // There is already another reference to this memory area, don't allow to change it
                // anymore through this method
                return Err(hwcrypto_err!(GENERIC_ERROR, "copy_values is meant for initialization before creating any other references to this memory area"));
            }
            if start + values.len() > Self::get_allocation_size() {
                return Err(hwcrypto_err!(BAD_PARAMETER, "input won't fit in buffer"));
            }
            // SAFETY: - value is valid for all the range that is read
            //         - allocated_buffer[start, start + values.len()] is a valid area to write
            //         - allocated_buffer and values are properly aligned because they are `u8`
            //         - both areas do not overlap because allocated_buffer is a newly allocated
            //           buffer and we do not have methods to get references to this area until
            //           after this method is no longer valid.
            unsafe {
                self.allocated_buffer
                    .wrapping_add(start)
                    .copy_from_nonoverlapping(values.as_ptr(), values.len());
            }
            Ok(())
        }
    }

    impl Drop for TestPageAllocator {
        fn drop(&mut self) {
            // SAFETY: `allocated_buffer` is valid and have been allocated by the same allocator.
            //         layout was stored at allocation time, so it matches.
            unsafe { dealloc(self.allocated_buffer, self.layout) };
        }
    }

    fn read_slice(
        memory_buffer: &MemoryBuffer,
        buf: &mut [u8],
        start: usize,
    ) -> Result<(), HwCryptoError> {
        memory_buffer.mem_buffer.read_slice(buf, start).map_err(HwCryptoError::from)
    }

    fn write_slice(
        memory_buffer: &MemoryBuffer,
        buf: &[u8],
        start: usize,
    ) -> Result<(), HwCryptoError> {
        Ok(memory_buffer.mem_buffer.write_slice(buf, start)?)
    }

    #[test]
    fn create_memory_buffer() {
        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
        output_page.copy_values(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();

        let total_buffer_size = TestPageAllocator::get_allocation_size();
        let mem_buffer_parameters = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Output(Some(
                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
            )),
            sizeBytes: total_buffer_size as i32,
        };
        let memory_buffer =
            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't create a memory buffer");

        let mut slice = vec![0; 5];

        read_slice(&memory_buffer, &mut slice[0..2], 1).expect("couldn't get slice");
        expect_eq!(&slice[0..2], &[2, 3], "wrong value retrieved through slice");

        read_slice(&memory_buffer, &mut slice[0..1], 8).expect("couldn't get slice");
        expect_eq!(&slice[0..1], &[9], "wrong value retrieved through slice");

        let result = read_slice(&memory_buffer, &mut slice[0..2], total_buffer_size - 1);
        expect!(result.is_err(), "Shouldn't be able to get slice with end out of range");

        let result = read_slice(&memory_buffer, &mut slice[0..1], total_buffer_size);
        expect!(result.is_err(), "Shouldn't be able to get slice with start out of range");

        read_slice(&memory_buffer, &mut slice[0..1], 0).expect("couldn't get slice");
        expect_eq!(&slice[0..1], &[1], "wrong value retrieved through slice");

        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
        expect_eq!(&slice[0..3], &[5, 6, 7], "wrong value retrieved through slice");

        write_slice(&memory_buffer, &[55], 5).expect("couldn't write slice");
        read_slice(&memory_buffer, &mut slice[0..3], 4).expect("couldn't get slice");
        expect_eq!(&slice[0..3], &[5, 55, 7], "wrong value retrieved through slice");

        read_slice(&memory_buffer, &mut slice[0..5], 3).expect("couldn't get slice");
        expect_eq!(&slice[0..5], &[4, 5, 55, 7, 8], "wrong value retrieved through slice");
    }

    #[test]
    fn create_output_data_references() {
        let mut output_page = TestPageAllocator::new().expect("couldn't allocate test page");
        let total_buffer_size = TestPageAllocator::get_allocation_size();
        let mem_buffer_parameters = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Output(Some(
                output_page.get_parcel_file_descriptor().expect("couldn't create fd"),
            )),
            sizeBytes: total_buffer_size as i32,
        };

        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();

        cmd_list.push(CryptoOperation::SetMemoryBuffer(mem_buffer_parameters));
        let mem_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));

        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process SetMemoryBuffer command");

        let process_result = cmd_processor.process_step(1, &mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process valid memory reference");

        let mem_reference =
            MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 1 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));

        let process_result = cmd_processor.process_step(2, &mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference outside of buffer"
        );

        let mem_reference =
            MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 0 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
        let process_result = cmd_processor.process_step(3, &mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference outside of buffer"
        );

        let mem_reference = MemoryBufferReference { startOffset: 3, sizeBytes: 0 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
        let process_result = cmd_processor.process_step(4, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to process 0 size references");

        let mem_reference =
            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 1 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
        let process_result = cmd_processor.process_step(5, &mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process valid memory reference");

        let mem_reference =
            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 2 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));
        let process_result = cmd_processor.process_step(6, &mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference that falls out of range"
        );
    }

    #[test]
    fn parse_empty_cmd_list() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();

        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        let e = process_result.unwrap_err();
        expect!(
            e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
            "should have received a BAD_PARAMETER error"
        );

        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        let e = process_result.unwrap_err();
        expect!(
            e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
            "should have received a BAD_PARAMETER error"
        );

        let process_result = cmd_processor.process_step(1, &mut cmd_list);
        let e = process_result.unwrap_err();
        expect!(
            e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
            "should have received a BAD_PARAMETER error"
        );
    }

    #[test]
    fn parse_cmd_list_single_item() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
    }

    #[test]
    fn invalid_operations_initial_state() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
        cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));
        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
        cmd_list.push(CryptoOperation::SetPattern(pattern_params));
        cmd_list.push(CryptoOperation::Finish(None));
        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));

        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on initial state");
        let process_result = cmd_processor.process_step(1, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on initial state");
        let process_result = cmd_processor.process_step(2, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on initial state");
        let process_result = cmd_processor.process_step(3, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call Finish on initial state");
        let process_result = cmd_processor.process_step(4, &mut cmd_list);
        expect!(process_result.is_ok(), "Should be able to call DataOutput");
        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on initial state");
        let process_result = cmd_processor.process_step(1, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on initial state");
    }

    #[test]
    fn invalid_operations_destroyed_state() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DestroyContext(None));
        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
        cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));
        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
        cmd_list.push(CryptoOperation::SetPattern(pattern_params));
        cmd_list.push(CryptoOperation::Finish(None));
        let policy = KeyPolicy {
            usage: KeyUse::SIGN,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: KeyType::AES_128_CBC_NO_PADDING,
            keyManagementKey: false,
        };
        let key = OpaqueKey::generate_opaque_key(&policy);
        expect!(key.is_ok(), "couldn't generate key");
        let key = key.unwrap();
        let mode = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: [0; 16],
        }));
        let op_parameters = SymmetricOperationParameters {
            key: Some(key),
            direction: SymmetricOperation::ENCRYPT,
            parameters: mode,
        };
        cmd_list.push(CryptoOperation::SetOperationParameters(
            OperationParameters::SymmetricCrypto(op_parameters),
        ));
        let process_result = cmd_processor.process_step(0, &mut cmd_list);
        expect!(process_result.is_ok(), "Should be able to call DestroyContext");
        let process_result = cmd_processor.process_step(1, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataOutput on destroyed state");
        let process_result = cmd_processor.process_step(2, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on destroyed state");
        let process_result = cmd_processor.process_step(3, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on destroyed state");
        let process_result = cmd_processor.process_step(4, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on destroyed state");
        let process_result = cmd_processor.process_step(5, &mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call Finish on destroyed state");
        let process_result = cmd_processor.process_step(6, &mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to call SetOperationParameters on destroyed state"
        );
    }
}
