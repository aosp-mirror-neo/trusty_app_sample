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

/// Number of bytes used to serialize a BootUniqueValue object.
pub const UNIQUE_VALUE_SIZEOF: usize = 32;

/// Trait that will be used to determine if we are on the same boot. Any BootUniqueValue object
/// created during a single boot shall compare equal. When importing a key, this value will be
/// serialized using `UNIQUE_VALUE_SIZEOF` bytes. Any BootUniqueValue object created out of this
/// serialized value by calling `new_from_array` shall compare equal to any BootUniqueValue created
/// during the same boot
pub trait BootUniqueValue: core::fmt::Debug + PartialEq + Eq + Clone {
    /// Create a new BootUniqueValue
    fn new() -> Result<Self, HwCryptoError>;

    /// Create a new BootUniqueValue from a serialized value
    fn new_from_array(unique_value: [u8; UNIQUE_VALUE_SIZEOF]) -> Result<Self, HwCryptoError>;

    /// Serialize a BootUniqueValue
    fn get_unique_value_array(&self) -> [u8; UNIQUE_VALUE_SIZEOF];
}
