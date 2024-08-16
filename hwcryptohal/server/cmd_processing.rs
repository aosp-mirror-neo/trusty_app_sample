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
    OperationParameters::OperationParameters,
};
use core::ffi::c_void;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use std::{os::fd::AsRawFd, ptr::NonNull};
use vm_memory::{volatile_memory::VolatileSlice, Bytes, VolatileMemory};

use crate::crypto_operation::{CopyOperation, CryptographicOperation, ICryptographicOperation};

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
#[derive(Debug, PartialEq)]
enum CmdProcessorState {
    InitialState,
    RunningOperation,
    Destroyed,
}

// `DataToProcess`is used to abstract away if the cryptographic operations are working on memory
// buffers or vectors.
pub(crate) enum DataToProcess<'a> {
    VolatileSlice(VolatileSlice<'a>),
    Slice(&'a mut [u8]),
}

impl<'a> DataToProcess<'a> {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::VolatileSlice(vs) => vs.len(),
            Self::Slice(s) => s.len(),
        }
    }

    pub(crate) fn copy_slice(&mut self, from: &[u8]) -> Result<(), HwCryptoError> {
        if self.len() < from.len() {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "slice size: {} is less than the slice provided {}",
                self.len(),
                from.len()
            ));
        }
        match self {
            Self::VolatileSlice(to) => to.write_slice(from, 0)?,
            Self::Slice(to) => to[..from.len()].copy_from_slice(from),
        }
        Ok(())
    }

    pub(crate) fn copy_from_slice(
        &mut self,
        slice: &DataToProcess<'a>,
    ) -> Result<(), HwCryptoError> {
        if self.len() < slice.len() {
            return Err(hwcrypto_err!(
                BAD_PARAMETER,
                "slice size: {} is less than the slice provided {}",
                self.len(),
                slice.len()
            ));
        }

        match (slice, self) {
            (Self::Slice(from), Self::VolatileSlice(to)) => to.write_slice(from, 0)?,
            (Self::VolatileSlice(from), Self::VolatileSlice(to)) => {
                from.copy_to_volatile_slice(to.get_slice(0, to.len())?)
            }
            (Self::Slice(from), Self::Slice(to)) => to[..from.len()].copy_from_slice(from),
            (Self::VolatileSlice(from), Self::Slice(to)) => from.read_slice(to, 0)?,
        }
        Ok(())
    }

    /// Grows the vector to the required size and return a `DataToProcess` to the newly allocated
    /// portion
    pub(crate) fn allocate_buffer_end_vector(
        vector: &'a mut Vec<u8>,
        buffer_size: usize,
    ) -> Result<DataToProcess<'a>, HwCryptoError> {
        let original_len = vector.len();
        vector.try_reserve(buffer_size)?;
        // Addition should be safe because try_reserve didn't fail
        let new_len = original_len + buffer_size;
        vector.resize_with(new_len, Default::default);
        Ok(Self::Slice(&mut vector[original_len..new_len]))
    }
}

// Structure that keeps track of current output buffer
enum OutputData<'a> {
    DataBuffer(&'a mut Vec<u8>),
    MemoryReference(MemoryBufferReference, usize),
}

fn get_mmap_prot_flags(memory_buffer: &MemoryBufferAidl) -> u32 {
    match memory_buffer {
        MemoryBufferAidl::Input(_) => INPUT_MEMORY_BUFFER_FLAGS,
        MemoryBufferAidl::Output(_) => OUTPUT_MEMORY_BUFFER_FLAGS,
    }
}

// `MemoryBufferReference` types do not contain the necessary information to
// know if it should operate on an Input or Output buffer. That information is provided by the
// Operation which contains the `MemoryBufferReference`. This wrapper preserves that information to
// be used along function call sequences.
#[derive(Copy, Clone)]
enum MemoryBufferReferenceWithType {
    Input(MemoryBufferReference),
    Output(MemoryBufferReference),
}

impl MemoryBufferReferenceWithType {
    fn len(&self) -> Result<usize, HwCryptoError> {
        match self {
            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.sizeBytes,
            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.sizeBytes,
        }
        .try_into()
        .map_err(|e| {
            hwcrypto_err!(BAD_PARAMETER, "buffer reference sizes cannot be negative: {:?}", e)
        })
    }

    fn start_offset(&self) -> Result<usize, HwCryptoError> {
        match self {
            MemoryBufferReferenceWithType::Input(buff_ref) => buff_ref.startOffset,
            MemoryBufferReferenceWithType::Output(buff_ref) => buff_ref.startOffset,
        }
        .try_into()
        .map_err(|e| {
            hwcrypto_err!(BAD_PARAMETER, "buffer reference offsets cannot be negative: {:?}", e)
        })
    }
}

/// Given a `MemoryBufferReference` it checks that its elements are valid (buffer_start should be
/// positive and buffer_size should be greater than 0) and then returns the memory reference
/// start/stop/size as an `usize` tuple
fn get_limits(
    buffer_reference: &MemoryBufferReferenceWithType,
) -> Result<(usize, usize, usize), HwCryptoError> {
    let buffer_size = buffer_reference.len()?;
    let buffer_start = buffer_reference.start_offset()?;
    if buffer_size == 0 {
        return Err(hwcrypto_err!(BAD_PARAMETER, "buffer reference size shouldn't be 0"));
    }
    // Because both values are positive and originally signed, then the unsigned addition should not
    // overflow. Using a checked add in case we can change these values to unsigned
    // in the future
    if let Some(buffer_end) = buffer_size.checked_add(buffer_start) {
        Ok((buffer_start, buffer_end, buffer_size))
    } else {
        Err(hwcrypto_err!(BAD_PARAMETER, "buffer end overflowed"))
    }
}

// Wrapper over pointer used to map memory buffer.
struct MappedBuffer(NonNull<u8>);

// SAFETY: `MappedBuffer` is only used to free object on drop or to create a `VolatileSlice` when
//         we need to access the underlying memory buffer; never directly. It is safe to access and
//         drop on a different thread. All accesses to the mmaped memory are done through the
//         `VolatileSlice` which already has the assumption that the underlying memory is shared
//         between different entities, so it only uses `std::ptr::{copy, read_volatile,
//         write_volatile}` to access memory.
unsafe impl Send for MappedBuffer {}

struct MemoryBuffer {
    buffer_ptr: MappedBuffer,
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
        let total_size = buffer_size as usize;

        Ok(Self { buffer_ptr: MappedBuffer(buffer_ptr), total_size })
    }

    fn get_memory_slice<'a>(&'a mut self) -> Result<VolatileSlice<'a>, HwCryptoError> {
        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
        //         operation would have failed. All accesses to this memory on this service are
        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory is
        //         only unmapped on drop, so it will available for the lifetime of the
        //         `VolatileSlice`.
        let mem_buffer = unsafe { VolatileSlice::new(self.buffer_ptr.0.as_ptr(), self.total_size) };
        Ok(mem_buffer)
    }

    fn get_subslice_as_data_to_process<'a>(
        &'a mut self,
        start: usize,
        size: usize,
    ) -> Result<DataToProcess<'a>, HwCryptoError> {
        let mem_buffer = self.get_memory_slice()?;
        Ok(DataToProcess::VolatileSlice(mem_buffer.subslice(start, size)?))
    }
}

impl Drop for MemoryBuffer {
    fn drop(&mut self) {
        // SAFETY: `buffer_ptr` and `total_size` were set up and remain unchanged for the lifetime
        //         of the object. `buffer_ptr` is still mapped at this point
        unsafe {
            trusty_sys::munmap(self.buffer_ptr.0.as_ptr().cast::<c_void>(), self.total_size as u32)
        };
    }
}

// `CmdProcessorContext` is the type in charge of executing a set of commands.
pub(crate) struct CmdProcessorContext {
    current_input_memory_buffer: Option<MemoryBuffer>,
    current_output_memory_buffer: Option<MemoryBuffer>,
    current_state: CmdProcessorState,
    current_crypto_operation: Option<Box<dyn ICryptographicOperation>>,
}

impl std::fmt::Debug for CmdProcessorContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CmdProcessorContext {{ input buffer set: {}, output buffer set: {}, state: {:?} }}",
            self.current_input_memory_buffer.is_some(),
            self.current_output_memory_buffer.is_some(),
            self.current_state
        )
    }
}

impl CmdProcessorContext {
    pub(crate) fn new() -> Self {
        Self {
            current_input_memory_buffer: None,
            current_output_memory_buffer: None,
            current_state: CmdProcessorState::InitialState,
            current_crypto_operation: None,
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
        current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        let (current_memory_buffer, buffer_is_output) = match &parameters.bufferHandle {
            MemoryBufferAidl::Input(_) => (&mut self.current_input_memory_buffer, false),
            MemoryBufferAidl::Output(_) => (&mut self.current_output_memory_buffer, true),
        };
        if current_memory_buffer.is_some() {
            Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer already set"))
        } else {
            if parameters.sizeBytes < 0 {
                Err(hwcrypto_err!(BAD_PARAMETER, "Memory buffer size is negative"))
            } else {
                // With the current behaviour, next check should not be needed, because we can only
                // set up the current_memory_buffer once and we can only set the current_output_ref
                // after setting a current output memory buffer. Leaving the check here in case the
                // behavior changes in the future
                if buffer_is_output {
                    if let Some(OutputData::MemoryReference(_, _)) = current_output_ref {
                        // If the current output is a buffer reference, we need to invalidate it
                        return Err(hwcrypto_err!(BAD_PARAMETER, "This should not be possible with current flow, we need to invalidate the current output reference now."));
                    }
                }
                *current_memory_buffer = Some(MemoryBuffer::new(parameters)?);
                Ok(())
            }
        }
    }

    fn add_output_step<'a>(
        &mut self,
        output_parameters: &'a mut OperationData,
    ) -> Result<OutputData<'a>, HwCryptoError> {
        match output_parameters {
            OperationData::DataBuffer(buf) => Ok(OutputData::DataBuffer(buf)),
            OperationData::MemoryBufferReference(buffer_reference) => {
                Ok(OutputData::MemoryReference(
                    *buffer_reference,
                    self.get_data_buffer_size(&MemoryBufferReferenceWithType::Output(
                        (*buffer_reference).into(),
                    ))?,
                ))
            }
        }
    }

    fn finish_step(
        &mut self,
        current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        self.operation_step(None, current_output_ref, true, None)?;
        self.current_crypto_operation = None;
        Ok(())
    }

    fn input_step(
        &mut self,
        input_parameters: &mut OperationData,
        current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        self.operation_step(Some(input_parameters), current_output_ref, false, None)
    }

    fn operation_step(
        &mut self,
        input_parameters: Option<&mut OperationData>,
        current_output_ref: &mut Option<OutputData>,
        is_finish: bool,
        operation_impl: Option<&mut dyn ICryptographicOperation>,
    ) -> Result<(), HwCryptoError> {
        // Doing this check here to keep the borrow checker happy because the next step borrows self
        // mutably. This is because even though it is an input, if it is a buffer reference, the
        // available method could potentially be use to modify the underlying memory buffer.
        if let Some(OutputData::MemoryReference(buff_ref, _)) = current_output_ref.as_ref() {
            self.check_memory_reference_in_range(&MemoryBufferReferenceWithType::Output(
                (*buff_ref).into(),
            ))?;
        }
        // Creating a `DataToProcess` variable to abstract away where the input is located
        let input = match input_parameters {
            Some(OperationData::MemoryBufferReference(buffer_reference)) => Some({
                let buffer_reference =
                    MemoryBufferReferenceWithType::Input((*buffer_reference).into());
                self.check_memory_reference_in_range(&buffer_reference)?;
                let (input_start, _input_stop, input_size) = get_limits(&buffer_reference)?;
                self.current_input_memory_buffer
                    .as_mut()
                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "input buffer not set yet"))?
                    .get_subslice_as_data_to_process(input_start, input_size)?
            }),
            Some(OperationData::DataBuffer(input)) => Some(DataToProcess::Slice(&mut input[..])),
            None => None,
        };
        if let Some(ref input) = input {
            if input.len() == 0 {
                return Err(hwcrypto_err!(BAD_PARAMETER, "received an input of size 0"));
            }
        }
        let crypto_operation: &mut dyn ICryptographicOperation =
            operation_impl.ok_or(()).or_else(|_| {
                let crypto_operation = self
                    .current_crypto_operation
                    .as_mut()
                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "crypto operation has not been set yet"))?;
                if !crypto_operation.is_active() {
                    return Err(hwcrypto_err!(BAD_PARAMETER, "operation is not active"));
                }
                Ok(&mut **crypto_operation)
            })?;
        let req_output_size = crypto_operation.get_operation_req_size(input.as_ref(), is_finish)?;

        // Getting a reference to the output for the copy operation
        match current_output_ref
            .as_mut()
            .ok_or(hwcrypto_err!(BAD_PARAMETER, "no output buffer available"))?
        {
            OutputData::DataBuffer(output_vec) => {
                // We are saving data into a vector, as long as we can resize the vector we can fit
                // the result
                let original_size = output_vec.len();
                let output_buff =
                    DataToProcess::allocate_buffer_end_vector(*output_vec, req_output_size)?;
                let added_bytes = crypto_operation.operation(input, output_buff, is_finish)?;
                output_vec.truncate(original_size + added_bytes);
            }
            OutputData::MemoryReference(output_buff_ref, remaining_size) => {
                if req_output_size > *remaining_size {
                    return Err(hwcrypto_err!(ALLOCATION_ERROR, "run out of space output buffer"));
                }
                let (_output_start, output_stop, _output_size) =
                    get_limits(&MemoryBufferReferenceWithType::Output((*output_buff_ref).into()))?;
                // We are automatically filling up the output buffer with the received input, so
                // the first available position will be equal to the end of the buffer minus the
                // remaining space:
                //
                //         |---------------------_output_size------------------------------|
                //         |--------used space--------|----------remaining_size------------|
                //         |xxxxxxxxxxxxxxxxxxxxxxxxxx|====================================|
                // _output_start                output_start_offset                    output_stop
                //
                let output_start_offset = output_stop - *remaining_size;
                let output_slice = self
                    .current_output_memory_buffer
                    .as_mut()
                    .ok_or(hwcrypto_err!(BAD_PARAMETER, "output buffer not set yet"))?
                    .get_subslice_as_data_to_process(output_start_offset, req_output_size)?;
                let req_output_size = crypto_operation.operation(input, output_slice, is_finish)?;
                *remaining_size = *remaining_size - req_output_size;
            }
        }
        Ok(())
    }

    fn copy_step(
        &mut self,
        copy_parameters: &mut OperationData,
        current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        self.operation_step(
            Some(copy_parameters),
            current_output_ref,
            false,
            Some(&mut CopyOperation),
        )
    }

    fn destroy_step(
        &mut self,
        current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        self.current_input_memory_buffer = None;
        self.current_output_memory_buffer = None;
        self.current_crypto_operation = None;
        *current_output_ref = None;
        self.current_state = CmdProcessorState::Destroyed;
        Ok(())
    }

    pub(crate) fn is_destroyed(&self) -> bool {
        self.current_state == CmdProcessorState::Destroyed
    }

    fn set_operation_parameters_step(
        &mut self,
        crypto_operation_parameters: &OperationParameters,
        _current_output_ref: &mut Option<OutputData>,
    ) -> Result<(), HwCryptoError> {
        let crypto_operation = CryptographicOperation::new_binder(crypto_operation_parameters)?;
        self.current_crypto_operation = Some(crypto_operation);
        Ok(())
    }

    pub(crate) fn process_all_steps(
        &mut self,
        operations: &mut [CryptoOperation],
    ) -> Result<(), HwCryptoError> {
        if operations.is_empty() {
            return Err(hwcrypto_err!(BAD_PARAMETER, "Cannot process list of length 0",));
        }
        let mut curr_output: Option<OutputData> = None;
        for current_step in operations {
            match self.current_state {
                CmdProcessorState::InitialState => match current_step {
                    CryptoOperation::DataOutput(step_data) => {
                        curr_output = Some(self.add_output_step(step_data)?);
                    }
                    CryptoOperation::CopyData(step_data) => {
                        self.copy_step(step_data, &mut curr_output)?;
                    }
                    CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
                    CryptoOperation::SetMemoryBuffer(step_data) => {
                        self.set_memory_buffer_step(&step_data, &mut curr_output)?
                    }
                    CryptoOperation::SetOperationParameters(step_data) => {
                        self.current_state = CmdProcessorState::RunningOperation;
                        self.set_operation_parameters_step(&step_data, &mut curr_output)?;
                    }
                    CryptoOperation::SetPattern(_) => {
                        return Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "SetPattern not permitted before calling SetOperationParameters"
                        ))
                    }
                    CryptoOperation::DataInput(_) => {
                        return Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "DataInput not permitted before calling SetOperationParameters"
                        ))
                    }
                    CryptoOperation::AadInput(_) => {
                        return Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "AadInput not permitted before calling SetOperationParameters"
                        ))
                    }
                    CryptoOperation::Finish(_) => {
                        return Err(hwcrypto_err!(
                            BAD_PARAMETER,
                            "Finish not permitted before calling SetOperationParameters"
                        ))
                    }
                },
                CmdProcessorState::RunningOperation => match current_step {
                    CryptoOperation::DataOutput(step_data) => {
                        curr_output = Some(self.add_output_step(step_data)?);
                    }
                    CryptoOperation::CopyData(step_data) => {
                        self.copy_step(step_data, &mut curr_output)?;
                    }
                    CryptoOperation::DestroyContext(_) => self.destroy_step(&mut curr_output)?,
                    CryptoOperation::Finish(_step_data) => {
                        self.current_state = CmdProcessorState::InitialState;
                        self.finish_step(&mut curr_output)?;
                    }
                    CryptoOperation::SetPattern(_) => {
                        unimplemented!("SetPattern not implemented yet")
                    }
                    CryptoOperation::DataInput(step_data) => {
                        self.input_step(step_data, &mut curr_output)?;
                    }
                    CryptoOperation::AadInput(_) => unimplemented!("AadInput not implemented yet"),
                    CryptoOperation::SetOperationParameters(_step) => unimplemented!(
                        "SetOperationParameters from RunningOperation not implemented yet"
                    ),
                    CryptoOperation::SetMemoryBuffer(_) => {
                        return Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "SetMemoryBuffer not permitted once SetOperationParameters has been called"
                    ))
                    }
                },
                CmdProcessorState::Destroyed => {
                    return Err(hwcrypto_err!(
                        BAD_PARAMETER,
                        "Cannot send any command after DestroyContext"
                    ));
                }
            }
        }
        Ok(())
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
            let allocated_buffer = unsafe {
                let ptr = alloc_zeroed(layout);
                ptr
            };
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
        // SAFETY: Memory at address `buffer_ptr` has length `buffer_size` because if not mmap
        //         operation would have failed. All accesses to this memory on this service are
        //         through the VolatileSlice methods, so accesses are volatile accesses. Memory
        //         is only unmapped on drop, so it will available for the lifetime of the
        //         `VolatileSlice`.
        let mem_buffer = unsafe {
            VolatileSlice::new(memory_buffer.buffer_ptr.0.as_ptr(), memory_buffer.total_size)
        };
        mem_buffer.read_slice(buf, start).map_err(HwCryptoError::from)
    }

    fn write_slice(
        memory_buffer: &mut MemoryBuffer,
        buf: &[u8],
        start: usize,
    ) -> Result<(), HwCryptoError> {
        let mem_buffer = memory_buffer.get_memory_slice()?;
        Ok(mem_buffer.write_slice(buf, start)?)
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
        let mut memory_buffer =
            MemoryBuffer::new(&mem_buffer_parameters).expect("Couldn't createa memory buffer");

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

        write_slice(&mut memory_buffer, &[55], 5).expect("couldn't write slice");
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
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process SetMemoryBuffer command");
        let mem_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
        cmd_list
            .push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_reference)));

        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process valid memory reference");

        let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 1 };
        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference outside of buffer"
        );

        let mem_ref = MemoryBufferReference { startOffset: total_buffer_size as i32, sizeBytes: 0 };
        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference outside of buffer"
        );

        let mem_ref = MemoryBufferReference { startOffset: 3, sizeBytes: 0 };
        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to process 0 size references");

        let mem_ref =
            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 1 };
        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_ok(),
            "Couldn't process a valid memory reference, len {}",
            cmd_list.len()
        );

        let mem_ref =
            MemoryBufferReference { startOffset: total_buffer_size as i32 - 1, sizeBytes: 2 };
        cmd_list[1] = CryptoOperation::DataOutput(OperationData::MemoryBufferReference(mem_ref));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to process reference that falls out of range"
        );
    }

    #[test]
    fn parse_empty_cmd_list() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();

        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        match &process_result {
            Err(e) => expect!(
                e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
                "should have received a BAD_PARAMETER error"
            ),
            Ok(_) => expect!(process_result.is_err(), "Should have received an error"),
        };

        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        match &process_result {
            Err(e) => expect!(
                e.matches_hal_error_code(HalErrorCode::BAD_PARAMETER),
                "should have received a BAD_PARAMETER error"
            ),
            Ok(_) => expect!(process_result.is_err(), "Should have received an error"),
        };
    }

    #[test]
    fn parse_cmd_list_single_item() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
    }

    #[test]
    fn invalid_operations_initial_state() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new())));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on initial state");
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new())));

        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on initial state");
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
        cmd_list.push(CryptoOperation::SetPattern(pattern_params));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on initial state");
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::Finish(None));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call Finish on initial state");
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Should be able to call DataOutput");
    }

    #[test]
    fn invalid_operations_destroyed_state() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DestroyContext(None));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Should be able to call DestroyContext");
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::DataOutput(OperationData::DataBuffer(Vec::new())));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataOutput on destroyed state");
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list[1] = CryptoOperation::DataInput(OperationData::DataBuffer(Vec::new()));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call DataInput on destroyed state");
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list[1] = CryptoOperation::AadInput(OperationData::DataBuffer(Vec::new()));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call AadInput on destroyed state");
        let pattern_params = PatternParameters { numberBlocksProcess: 1, numberBlocksCopy: 9 };
        cmd_list[1] = CryptoOperation::SetPattern(pattern_params);
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call SetPattern on destroyed state");
        cmd_list[1] = CryptoOperation::Finish(None);
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to call Finish on destroyed state");
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
        cmd_list[1] = CryptoOperation::SetOperationParameters(
            OperationParameters::SymmetricCrypto(op_parameters),
        );
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "Shouldn't be able to call SetOperationParameters on destroyed state"
        );
    }

    #[test]
    fn check_output_step_length() {
        let alloc_size = TestPageAllocator::get_allocation_size();
        let mut output_page = TestPageAllocator::new().expect("couldn't create test page");
        let output_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Output(Some(
                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
            )),
            sizeBytes: alloc_size as i32,
        };
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
        let output_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
            output_reference,
        )));
        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let mut read_slice_val = vec![55; 9];
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(
            &read_slice_val[..],
            &[1, 2, 3, 0, 0, 0, 0, 0, 0],
            "unexpected values after copy"
        );

        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(
            process_result.is_err(),
            "Command should have failed because we run out of output buffer"
        );
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(
            &read_slice_val[..],
            &[1, 2, 3, 0, 0, 0, 0, 0, 0],
            "unexpected values after failed copy"
        );
    }

    #[test]
    fn output_step_out_range() {
        let alloc_size = TestPageAllocator::get_allocation_size();
        let mut output_page = TestPageAllocator::new().expect("couldn't get test page");
        let output_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Output(Some(
                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
            )),
            sizeBytes: alloc_size as i32,
        };
        let mut input_page = TestPageAllocator::new().expect("couldn't get test page");
        let input_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Input(Some(
                input_page.get_parcel_file_descriptor().expect("couldn't get fd"),
            )),
            sizeBytes: alloc_size as i32,
        };
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
        let output_reference =
            MemoryBufferReference { startOffset: 0, sizeBytes: (alloc_size + 4) as i32 };
        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
            output_reference,
        )));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "shouldn't be able to add an output outside of range");
        let output_reference =
            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
        cmd_list[2] =
            CryptoOperation::DataOutput(OperationData::MemoryBufferReference(output_reference));
        let input_reference =
            MemoryBufferReference { startOffset: 0, sizeBytes: (alloc_size + 4) as i32 };
        cmd_list
            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "shouldn't be able to add an input ref outside of range");
        let input_reference =
            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
        cmd_list[3] =
            CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "operation should have succeeded");
    }

    #[test]
    fn memory_reference_copy_operation_on_initial_state() {
        let alloc_size = TestPageAllocator::get_allocation_size();
        let mut output_page = TestPageAllocator::new().expect("couldn't get test page");
        let output_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Output(Some(
                output_page.get_parcel_file_descriptor().expect("couldn't get fd"),
            )),
            sizeBytes: alloc_size as i32,
        };
        let mut input_page = TestPageAllocator::new().expect("couldn't get test page");
        input_page.copy_values(0, &[7, 8, 9]).unwrap();
        let input_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Input(Some(
                input_page.get_parcel_file_descriptor().expect("couldn't get fd"),
            )),
            sizeBytes: alloc_size as i32,
        };
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list.push(CryptoOperation::SetMemoryBuffer(output_memory_buffer));
        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let mut read_slice_val = vec![55; 9];
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(&read_slice_val[..], &[0, 0, 0, 0, 0, 0, 0, 0, 0], "initial values where not 0");
        let mut cmd_processor = CmdProcessorContext::new();
        let output_reference =
            MemoryBufferReference { startOffset: 0, sizeBytes: alloc_size as i32 };
        cmd_list.push(CryptoOperation::DataOutput(OperationData::MemoryBufferReference(
            output_reference,
        )));
        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(&read_slice_val[..], &[1, 2, 3, 0, 0, 0, 0, 0, 0], "initial values where not 0");
        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 0, 0, 0], "initial values where not 0");
        let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 };
        cmd_list
            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
        let mut cmd_processor = CmdProcessorContext::new();
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        cmd_list.clear();
        let mem_buffer = cmd_processor.current_output_memory_buffer.as_ref().unwrap();
        read_slice(&mem_buffer, &mut read_slice_val[..], 0).unwrap();
        expect_eq!(&read_slice_val[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9], "initial values where not 0");
    }

    #[test]
    fn simple_copy_operation_on_initial_state() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![1, 2, 3])));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_err(), "Shouldn't be able to copy before adding an output");
        cmd_list.insert(0, CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::CopyData(OperationData::DataBuffer(vec![4, 5, 6])));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process commands");
        expect!(process_result.is_ok(), "Couldn't process second copy command");
        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
            unreachable!("should not happen beucase we created the cmd list on the test");
        };
        expect_eq!(output, &[1, 2, 3, 4, 5, 6], "values were not copied correctly");
    }

    #[test]
    fn simple_copy_opeartion_on_initial_state_buffer_reference_input() {
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        let mut input_page = TestPageAllocator::new().expect("couldn't create test page");
        input_page.copy_values(0, &[2, 4, 8, 3, 6, 9]).unwrap();
        let input_memory_buffer = MemoryBufferParameter {
            bufferHandle: MemoryBufferAidl::Input(Some(
                input_page.get_parcel_file_descriptor().expect("couldn't create fd"),
            )),
            sizeBytes: TestPageAllocator::get_allocation_size() as i32,
        };
        cmd_list.push(CryptoOperation::SetMemoryBuffer(input_memory_buffer));
        let input_reference = MemoryBufferReference { startOffset: 0, sizeBytes: 3 as i32 };
        cmd_list
            .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
        let input_reference = MemoryBufferReference { startOffset: 3, sizeBytes: 3 as i32 };
        //cmd_list
        //    .push(CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference)));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
            unreachable!("should not happen beucase we created the cmd list on the test");
        };
        expect_eq!(output, &[2, 4, 8], "values were not copied correctly");
        let mut cmd_processor = CmdProcessorContext::new();
        cmd_list[2] =
            CryptoOperation::CopyData(OperationData::MemoryBufferReference(input_reference));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process second copy command");
        let CryptoOperation::DataOutput(OperationData::DataBuffer(output)) = &cmd_list[0] else {
            unreachable!("should not happen beucase we created the cmd list on the test");
        };
        expect_eq!(output, &[2, 4, 8, 3, 6, 9], "values were not copied correctly");
    }

    #[test]
    fn aes_simple_test() {
        let usage = KeyUse::ENCRYPT_DECRYPT;
        let key_type = KeyType::AES_256_CBC_PKCS7_PADDING;
        let policy = KeyPolicy {
            usage,
            keyLifetime: KeyLifetime::EPHEMERAL,
            keyPermissions: Vec::new(),
            keyType: key_type,
            keyManagementKey: false,
        };
        let key = OpaqueKey::generate_opaque_key(&policy).expect("couldn't generate key");
        let nonce = [0u8; 16];
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::ENCRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        let input_data = OperationData::DataBuffer("string to be encrypted".as_bytes().to_vec());
        cmd_list.push(CryptoOperation::DataInput(input_data));
        cmd_list.push(CryptoOperation::Finish(None));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let CryptoOperation::DataOutput(OperationData::DataBuffer(encrypted_data)) =
            cmd_list.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };

        // Decrypting
        let parameters = SymmetricCryptoParameters::Aes(AesCipherMode::Cbc(CipherModeParameters {
            nonce: nonce.into(),
        }));
        let direction = SymmetricOperation::DECRYPT;
        let sym_op_params =
            SymmetricOperationParameters { key: Some(key.clone()), direction, parameters };
        let op_params = OperationParameters::SymmetricCrypto(sym_op_params);
        let mut cmd_list = Vec::<CryptoOperation>::new();
        let mut cmd_processor = CmdProcessorContext::new();
        let data_output = OperationData::DataBuffer(Vec::new());
        cmd_list.push(CryptoOperation::DataOutput(data_output));
        cmd_list.push(CryptoOperation::SetOperationParameters(op_params));
        cmd_list.push(CryptoOperation::DataInput(OperationData::DataBuffer(encrypted_data)));
        cmd_list.push(CryptoOperation::Finish(None));
        let process_result = cmd_processor.process_all_steps(&mut cmd_list);
        expect!(process_result.is_ok(), "Couldn't process command");
        let CryptoOperation::DataOutput(OperationData::DataBuffer(decrypted_data)) =
            cmd_list.remove(0)
        else {
            panic!("not reachable, we created this object above on the test");
        };
        let decrypted_msg =
            String::from_utf8(decrypted_data).expect("couldn't decode received message");
        expect_eq!(decrypted_msg, "string to be encrypted", "couldn't retrieve original message");
    }
}
