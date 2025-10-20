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

//! Module providing trait definitions
mod client_identification;
mod device_keys;
#[cfg(feature = "use_vm_memory_crate")]
mod memory_access;
mod test;
mod time;

pub use client_identification::ClientIdentification;
pub use client_identification::ClientPolicyCheck;
pub use device_keys::{DeviceKeys, KeymintHmacKey};
#[cfg(feature = "use_vm_memory_crate")]
pub use memory_access::MemoryMappedObject;
pub use test::ClientIdentity;
#[cfg(feature = "use_vm_memory_crate")]
pub use test::TestAllocatedPage;
pub use test::TestHelpers;
pub use time::DeviceTime;
