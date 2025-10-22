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

//! Module providing trait definition to access boot information.

use hwcryptohal_common::err::HwCryptoError;
use hwcryptohalinterfaces::{BootUniqueValue, UNIQUE_VALUE_SIZEOF};
use kmr_common::crypto::Rng;
use std::sync::OnceLock;

use crate::RngImpl;

/// Struct to wrap boot unique counter. It is used to tag objects to the current boot.
#[derive(Clone, Eq, PartialEq)]
pub struct TrustyBootUniqueValue([u8; UNIQUE_VALUE_SIZEOF]);

impl core::fmt::Debug for TrustyBootUniqueValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[BootUniqueValue size: {UNIQUE_VALUE_SIZEOF}; data redacted]")
    }
}

// Boot unique value is lazily initialized on the first call to retrieve it
static BOOT_UNIQUE_VALUE: OnceLock<TrustyBootUniqueValue> = OnceLock::new();

/// Retrieves boot unique value used to check if the key material was created on this boot. It
/// lazily initializes it.
fn get_boot_unique_value() -> Result<TrustyBootUniqueValue, HwCryptoError> {
    // The function returns a `Result` even if it is currently infallible to allow replacing its
    // current implementation with one that can fail when trying to retrieve a random number.
    // If the RNG changes to a fallible one we could use `get_or_try_init`.
    let boot_unique_value = BOOT_UNIQUE_VALUE.get_or_init(|| {
        let mut new_boot_unique_value = TrustyBootUniqueValue([0u8; UNIQUE_VALUE_SIZEOF]);
        RngImpl.fill_bytes(&mut new_boot_unique_value.0);
        new_boot_unique_value
    });
    Ok(boot_unique_value.clone())
}

impl BootUniqueValue for TrustyBootUniqueValue {
    fn new() -> Result<Self, HwCryptoError> {
        get_boot_unique_value()
    }

    fn new_from_array(unique_value: [u8; UNIQUE_VALUE_SIZEOF]) -> Result<Self, HwCryptoError> {
        Ok(TrustyBootUniqueValue(unique_value))
    }

    fn get_unique_value_array(&self) -> [u8; UNIQUE_VALUE_SIZEOF] {
        self.0
    }
}
