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

//! Module providing time related functions.
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use log::error;

const NANOSECONDS_IN_1_MS: u64 = 1000000;

pub fn current_epoch_time_ms() -> Result<u64, HwCryptoError> {
    let mut secure_time_ns = 0;
    // Safety: external syscall gets valid raw pointer to a `u64`.
    let rc = unsafe { trusty_sys::gettime(0, 0, &mut secure_time_ns) };
    if rc < 0 {
        // Couldn't get time
        error!("Error calling trusty_gettime: {:#x}", rc);
        Err(hwcrypto_err!(GENERIC_ERROR, "error calling trusty_gettime: {:#x}", rc))
    } else {
        // secure_time_ns is positive, so casting is correct
        Ok((secure_time_ns as u64) / NANOSECONDS_IN_1_MS)
    }
}
