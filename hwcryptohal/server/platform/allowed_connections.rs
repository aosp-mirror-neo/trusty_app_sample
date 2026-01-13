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

//! Module providing IDs of allowed VM clients.

use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::KeySlot::KeySlot;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};

// Instance IDs are created by the script gen_instance_id_for_vm_with_trusted_hal.py, which is run
// under soong build system. It takes as information the characteristics of the VM and also a
// primary uuid and an optional secondary uuid

// Security VM Instance ID parameters
//    "vm_partition": "system",
//    "is_vm_persistent": true,
//    "vm_primary_uuid": "6c07e3dc-79e1-45a3-936d-b5d73a978f41"
const SECURITY_VM_INSTANCE_ID: [u8; 64] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x6c, 0x07, 0xe3, 0xdc, 0x79, 0xe1, 0x45, 0xa3, 0x93, 0x6d, 0xb5, 0xd7, 0x3a, 0x97, 0x8f, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// KeyMint UUID: "5f902ace-5e5c-4cd8-ae54-87b88c22ddaf"
const KEYMINT_CLIENT_ID: [u8; 16] = [
    0xCE, 0x2A, 0x90, 0x5F, 0x5C, 0x5E, 0xD8, 0x4C, 0xAE, 0x54, 0x87, 0xB8, 0x8C, 0x22, 0xDD, 0xAF,
];

/// Gatekeeper UUID: "d9039cf4-a54c-405d-a316-4aedfe325231"
const GATEKEEPER_CLIENT_ID: [u8; 16] = [
    0xF4, 0x9C, 0x03, 0xD9, 0x4C, 0xA5, 0x5D, 0x40, 0xA3, 0x16, 0x4A, 0xED, 0xFE, 0x32, 0x52, 0x31,
];

// Test VM Instance ID parameters
//    "vm_partition": "system",
//    "is_vm_persistent": true,
//    "vm_primary_uuid": "07590497-b72d-4434-ab36-51442e130536",
//    "vm_secondary_uuid": "0bea1ffc-b036-4d3a-8268-a5a041ade6b8"
const TEST_VM_INSTANCE_ID: [u8; 64] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x59, 0x04, 0x97, 0xb7, 0x2d, 0x44, 0x34, 0xab, 0x36, 0x51, 0x44, 0x2e, 0x13, 0x05, 0x36,
    0x0b, 0xea, 0x1f, 0xfc, 0xb0, 0x36, 0x4d, 0x3a, 0x82, 0x68, 0xa5, 0xa0, 0x41, 0xad, 0xe6, 0xb8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

type InstanceId = [u8; 64];
type ClientId = [u8; 16];

pub(crate) struct AllowedVmClients {
    pub(crate) instance_id: InstanceId,
    pub(crate) client_ids: Option<Vec<ClientId>>,
}

fn production_allowed_connections(
    key_slot: KeySlot,
) -> Result<Vec<AllowedVmClients>, HwCryptoError> {
    match key_slot {
        KeySlot::KEYMINT_SHARED_HMAC_KEY => {
            let mut client_ids = Vec::new();
            client_ids.try_reserve(2)?;
            client_ids.push(KEYMINT_CLIENT_ID);
            client_ids.push(GATEKEEPER_CLIENT_ID);
            let mut allowed_connections = Vec::new();
            allowed_connections.try_reserve(1)?;
            allowed_connections.push(AllowedVmClients {
                instance_id: SECURITY_VM_INSTANCE_ID,
                client_ids: Some(client_ids),
            });
            Ok(allowed_connections)
        }
        _ => {
            log::error!("Invalid keyslot {key_slot:?}");
            Err(hwcrypto_err!(BAD_PARAMETER, "invalid keyslot {:?}", key_slot))
        }
    }
}

pub(crate) fn get_allowed_connections(
    key_slot: KeySlot,
) -> Result<Vec<AllowedVmClients>, HwCryptoError> {
    let mut allowed_connections = production_allowed_connections(key_slot)?;
    if cfg!(TEST_BUILD) {
        // Not doing try allocations in this case because this function is only used on test builds
        allowed_connections
            .push(AllowedVmClients { instance_id: TEST_VM_INSTANCE_ID, client_ids: None });
    }
    Ok(allowed_connections)
}
