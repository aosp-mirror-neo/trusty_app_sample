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

//! Module providing test related memory functions.
use binder::ParcelFileDescriptor;
use core::ffi::c_void;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::TestAllocatedPage;
use std::alloc::{alloc_zeroed, Layout};
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{LazyLock, Mutex};

const OUTPUT_MEMORY_BUFFER_FLAGS: u32 =
    trusty_sys::MMAP_FLAG_PROT_READ | trusty_sys::MMAP_FLAG_PROT_WRITE;

fn get_page_size() -> usize {
    // SAFETY: FFI call with all safe arguments.
    let page_size = unsafe { libc::getauxval(libc::AT_PAGESZ) };
    page_size as usize
}

struct AllocatedBufferPtr(*mut u8);

impl AllocatedBufferPtr {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0
    }
}

// Safety: Page is allocated with global allocator, so they can be accessed from different threads.
//         Moreover, because Trusty Apps are single threaded, this type will only be referenced from
//         a single thread.
unsafe impl Send for AllocatedBufferPtr {}

static PAGE_POOL: LazyLock<Mutex<Vec<AllocatedPage>>> = LazyLock::new(|| Mutex::new(Vec::new()));

struct AllocatedPage {
    allocated_buffer: AllocatedBufferPtr,
}

pub struct TrustyTestAllocatedPage {
    allocated_page: Option<AllocatedPage>,
    trusty_fd: Option<OwnedFd>,
}

impl TestAllocatedPage for TrustyTestAllocatedPage {
    unsafe fn get_parcel_file_descriptor(&mut self) -> Result<ParcelFileDescriptor, HwCryptoError> {
        let fd = self
            .trusty_fd
            .take()
            .ok_or(hwcrypto_err!(BAD_STATE, "get_parcel_file_descriptor can only be calle once"))?;
        Ok(ParcelFileDescriptor::new(fd))
    }
    fn allocation_size(&self) -> usize {
        get_page_size()
    }
}

impl Drop for TrustyTestAllocatedPage {
    fn drop(&mut self) {
        // At this point we will return it to the page pool to be reused on a future test.
        if let Some(page) = self.allocated_page.take() {
            // Mutex won't be poisoned on a single threaded application
            let mut allocated_pages = PAGE_POOL.lock().unwrap();
            allocated_pages.push(page);
        }
    }
}

fn allocate_new_test_page() -> Result<AllocatedPage, HwCryptoError> {
    let page_size = get_page_size();
    if page_size == 0 {
        return Err(hwcrypto_err!(ALLOCATION_ERROR, "received zero as the page size"));
    }
    let layout = Layout::from_size_align(page_size, page_size).map_err(|e| {
        hwcrypto_err!(GENERIC_ERROR, "layout creation error, should not have happened: {:?}", e)
    })?;
    // SAFETY: Layout is non-zero
    let allocated_buffer = AllocatedBufferPtr(unsafe { alloc_zeroed(layout) });

    Ok(AllocatedPage { allocated_buffer })
}

pub(crate) fn allocate_test_page(
    initial_data: Option<&[u8]>,
) -> Result<impl TestAllocatedPage, HwCryptoError> {
    // Mutex won't be poisoned on a single thread application
    let mut allocated_pages = PAGE_POOL.lock().unwrap();
    let page_size = get_page_size();
    let mut allocated_page = if allocated_pages.is_empty() {
        // We do not have available pages on the pool, allocate a new one
        allocate_new_test_page()?
    } else {
        // unwrap won't fail because we checked that there is at least one page
        let mut page = allocated_pages.pop().unwrap();
        // clearing page contents
        // Safety: page.allocated_buffer is properly aligned and is valid for writing
        //         page_size bytes
        unsafe { page.allocated_buffer.as_mut_ptr().write_bytes(0, page_size) };
        page
    };
    // Always mapping things as output to change the buffer values for tests
    let prot_flags = OUTPUT_MEMORY_BUFFER_FLAGS;
    // SAFETY: address and size are correct because they came from the allocation.
    let raw_trusty_fd = unsafe {
        trusty_sys::memref_create(
            allocated_page.allocated_buffer.as_mut_ptr() as *mut c_void,
            page_size as u32,
            prot_flags,
        )
    };
    if raw_trusty_fd < 0 {
        return Err(hwcrypto_err!(ALLOCATION_ERROR, "memref creation failed"));
    }
    if let Some(initial_data) = initial_data {
        if initial_data.len() > page_size {
            return Err(hwcrypto_err!(BAD_PARAMETER, "input won't fit in buffer"));
        }
        // SAFETY: - value is valid for all the range that is read
        //         - allocated_buffer[0, initial_data.len()] is a valid area to write
        //         - allocated_buffer and initial_data are properly aligned because they are u8
        //         - both areas do not overlap because allocated_buffer is a newly allocated
        //           buffer and we do not have methods to get references to this area until
        //           after this method is no longer valid.
        unsafe {
            allocated_page
                .allocated_buffer
                .0
                .copy_from_nonoverlapping(initial_data.as_ptr(), initial_data.len());
        }
    }
    // SAFETY: we have checked that raw_trusty_fd is valid and we are take ownership of it here.
    let trusty_fd = Some(unsafe { OwnedFd::from_raw_fd(raw_trusty_fd as i32) });
    Ok(TrustyTestAllocatedPage { allocated_page: Some(allocated_page), trusty_fd })
}
