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

//! Module providing test related functions.
#[cfg(feature = "use_vm_memory_crate")]
use hwcryptohal_common::err::HwCryptoError;
use hwcryptohalinterfaces::ClientIdentity;
#[cfg(feature = "use_vm_memory_crate")]
use hwcryptohalinterfaces::TestAllocatedPage;
use hwcryptohalinterfaces::TestHelpers;
use tipc::{ClientIdentifier, Uuid};

#[cfg(feature = "use_vm_memory_crate")]
use crate::test_helpers_memory::allocate_test_page;

pub struct TrustyTestHelpers;

impl TestHelpers for TrustyTestHelpers {
    fn mock_client_id(identity: ClientIdentity) -> Vec<u8> {
        match identity {
            ClientIdentity::Identity1 => {
                let client_id = ClientIdentifier::UUID(
                    Uuid::new_from_string("f41a7796-975a-4279-8cc4-b73f8820430d").unwrap(),
                );
                client_id.c_repr().as_generic().as_bytes().to_vec()
            }
            ClientIdentity::Identity2 => {
                let client_id = ClientIdentifier::UUID(
                    Uuid::new_from_string("f4240823-21a8-446b-96d4-7e48030827c8").unwrap(),
                );
                client_id.c_repr().as_generic().as_bytes().to_vec()
            }
        }
    }

    #[cfg(feature = "use_vm_memory_crate")]
    fn allocate_test_page(
        initial_data: Option<&[u8]>,
    ) -> Result<impl TestAllocatedPage, HwCryptoError> {
        allocate_test_page(initial_data)
    }
}
