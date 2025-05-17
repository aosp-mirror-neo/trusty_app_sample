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

//! Library implementing the different `IHwCrypto` AIDL interfaces.

#![feature(cfg_version)]
// C string literals were stabilized in Rust 1.77
#![cfg_attr(not(version("1.77")), feature(c_str_literals))]

pub mod hwcrypto_ipc_server;

mod cmd_processing;
mod crypto_operation;
mod crypto_operation_context;
mod crypto_provider;
mod ffi_bindings;
mod helpers;
mod hwcrypto_device_key;
mod hwcrypto_operations;
mod opaque_key;
mod platform_functions;
mod service_encryption_key;

use hwcryptohalinterfaces::{ClientIdentification, DeviceKeys};
use hwcryptohalplatform::{ClientIdentificationImpl, DeviceKeysImpl};
use static_assertions::assert_impl_all;

assert_impl_all!(ClientIdentificationImpl: ClientIdentification);
assert_impl_all!(DeviceKeysImpl: DeviceKeys);

#[cfg(test)]
mod tests {
    test::init!();

    pub(crate) fn connection_info() -> Vec<u8> {
        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
        "f41a7796-975a-4279-8cc4-b73f8820430d".as_bytes().to_vec()
    }

    pub(crate) fn unauthorized_connection_info() -> Vec<u8> {
        // TODO: This is a temporary mock function for testing until we move to use DICE policies.
        "00000000-0000-0000-0000-000000000000".as_bytes().to_vec()
    }
}
