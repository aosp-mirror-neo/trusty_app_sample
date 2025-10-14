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

//! library implementing platform specific functions.

mod allowed_connections;
mod client_identification;
mod device_keys;
mod ffi_bindings;
mod memory;
mod rng;
mod test_helpers;
mod time;

pub use client_identification::TrustyClientIdentificationImpl as ClientIdentificationImpl;
pub use device_keys::TrustyDeviceKeys as DeviceKeysImpl;
pub use kmr_crypto_boring::aes::BoringAes as AesImpl;
pub use kmr_crypto_boring::hmac::BoringHmac as HmacImpl;
pub use memory::TrustyMappedObject as MemoryMappedObjectImpl;
pub use rng::PlatformRng as RngImpl;
pub use test_helpers::TrustyTestHelpers as TestHelpersImpl;
pub use time::TrustyDeviceTime as DeviceTimeImpl;
