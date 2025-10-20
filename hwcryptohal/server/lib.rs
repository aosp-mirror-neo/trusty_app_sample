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
#![cfg_attr(version("1.86"), allow(clippy::doc_overindented_list_items))]

pub const HWCRYPTO_SERVICE_NAME: &str =
    "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";
/// Port where we serve HwCrypto shared secret service participant
pub const SHARED_SECRET_SERVICE_PORT: &std::ffi::CStr =
    c"android.hardware.security.hwcrypto.sharedsecret/default.bnd";

mod cmd_processing;
mod crypto_operation;
mod crypto_operation_context;
mod helpers;
mod hwcrypto_device_key;
mod hwcrypto_operations;
mod opaque_key;
mod secret;
mod service_encryption_key;

pub use hwcrypto_device_key::HwCryptoKey;
pub use secret::SharedSecret;

use hwcryptohalinterfaces::{ClientIdentification, DeviceKeys, DeviceTime, MemoryMappedObject};
use hwcryptohalplatform::{
    AesImpl, ClientIdentificationImpl, DeviceKeysImpl, DeviceTimeImpl, HmacImpl,
    MemoryMappedObjectImpl, RngImpl,
};
use kmr_common::crypto::{Aes, Hkdf, Hmac, Rng};
use static_assertions::assert_impl_all;

assert_impl_all!(ClientIdentificationImpl: ClientIdentification);
assert_impl_all!(DeviceKeysImpl: DeviceKeys);
assert_impl_all!(DeviceTimeImpl: DeviceTime);
assert_impl_all!(MemoryMappedObjectImpl: MemoryMappedObject);

assert_impl_all!(AesImpl: Aes);
assert_impl_all!(HmacImpl: Hkdf, Hmac);
assert_impl_all!(RngImpl: Rng);

#[cfg(test)]
mod tests {
    use hwcryptohalinterfaces::{ClientIdentity, TestHelpers};
    use hwcryptohalplatform::TestHelpersImpl;
    use static_assertions::assert_impl_all;

    assert_impl_all!(TestHelpersImpl: TestHelpers);

    test::init!();

    pub(crate) fn connection_info() -> Vec<u8> {
        TestHelpersImpl::mock_client_id(ClientIdentity::Identity1)
    }

    pub(crate) fn connection_info_second_identity() -> Vec<u8> {
        TestHelpersImpl::mock_client_id(ClientIdentity::Identity2)
    }
}
