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

//! Module providing trait definition to provided implementation of functions onyl required for
//! testing.

#[cfg(feature = "use_vm_memory_crate")]
use binder::ParcelFileDescriptor;
#[cfg(feature = "use_vm_memory_crate")]
use hwcryptohal_common::err::HwCryptoError;

/// Enum indicating which identity we are requesting from `TestHelpers::mock_client_id`
pub enum ClientIdentity {
    /// Valid client identity that can be used to derive DiceBoundKeys
    Identity1,
    /// Valid client identity, different than `Identity1`, that can be used to derive DiceBoundKeys
    Identity2,
}

/// Trait to access a single page of memory allocated for the test. Implementers should use `Drop`
/// for any cleanup required
#[cfg(feature = "use_vm_memory_crate")]
pub trait TestAllocatedPage {
    /// Returns a file descriptor that can be used to map this test page using a
    /// `MemoryMappedObject`. Calling this is unsafe because the caller have to make sure to not use
    /// the returned `ParcelFileDescriptor` once the `TestAllocatedPage` goes out of scope.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `TestAllocatedPage` is not dropped before the last use of
    /// the returned `ParcelFileDescriptor`.
    unsafe fn get_parcel_file_descriptor(&mut self) -> Result<ParcelFileDescriptor, HwCryptoError>;

    /// Returns the total allocation size. All implementations of `TestAllocatedPage` must always
    /// allocate the same amount of memory for all `TestAllocatedPage`s
    fn allocation_size(&self) -> usize;
}

/// Abstraction of device specific time functionality
pub trait TestHelpers {
    /// Returns a byte blob that can be used on `ClientIdentification` which the desired
    /// capabilities indicated by `identity`.
    fn mock_client_id(identity: ClientIdentity) -> Vec<u8>;

    /// Returns a `TestAllocatedPage` which will contains on it the data of `initial_data`.
    /// `initial_data` doesn't need to cover the whole allocated memory. Any space not initialized
    /// by `initial_data` must be set to 0. This memory can be referenced latter using a
    /// `ParcelFileDescriptor`.
    #[cfg(feature = "use_vm_memory_crate")]
    fn allocate_test_page(
        initial_data: Option<&[u8]>,
    ) -> Result<impl TestAllocatedPage, HwCryptoError>;
}
