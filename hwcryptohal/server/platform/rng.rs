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

//! Module providing access to platform specific functions used by the library.
use kmr_common::crypto;

use crate::ffi_bindings;

#[derive(Default)]
pub struct PlatformRng;

impl crypto::Rng for PlatformRng {
    fn add_entropy(&mut self, data: &[u8]) {
        trusty_rng_add_entropy(data);
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        openssl::rand::rand_bytes(dest)
            .expect("shouldn't happen, function never fails on BoringSSL");
    }
}

/// Add entropy to Trusty's RNG.
pub fn trusty_rng_add_entropy(data: &[u8]) {
    // Safety: `data` is a valid slice
    let rc = unsafe { ffi_bindings::sys::trusty_rng_add_entropy(data.as_ptr(), data.len()) };
    if rc != 0 {
        panic!("trusty_rng_add_entropy() failed, {}", rc)
    }
}
