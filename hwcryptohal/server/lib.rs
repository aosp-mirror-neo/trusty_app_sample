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
mod crypto_provider;
mod ffi_bindings;
mod helpers;
mod hwcrypto_device_key;
mod hwcrypto_operations;
mod opaque_key;
mod platform_functions;
mod service_encryption_key;

#[cfg(test)]
mod tests {
    test::init!();
}
