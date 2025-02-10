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

//! Module implementing the `DeviceKeys` for trusty.
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::{DeviceKeys, KeymintHmacKey};
use hwkey::{Hwkey, KdfVersion, OsRollbackVersion, RollbackVersionSource};

#[derive(Default)]
pub struct TrustyDeviceKeys;

impl DeviceKeys for TrustyDeviceKeys {
    fn get_keymint_shared_hmac_key(&self) -> Result<KeymintHmacKey, HwCryptoError> {
        // TODO: Bug 416737037 implement shared HMAC key generation
        Err(hwcrypto_err!(UNSUPPORTED, "error communicating with HwKey service"))
    }

    fn derive_caller_unique_key(
        &self,
        key_context: &[u8],
        key_sec_version: &[u8],
        key_size: usize,
    ) -> Result<Vec<u8>, HwCryptoError> {
        let mut derived_key = Vec::<u8>::new();
        derived_key.try_reserve(key_size)?;
        derived_key.resize(key_size, 0);

        let version_bytes: [u8; 4] = key_sec_version.try_into()?;
        let version = u32::from_le_bytes(version_bytes);

        let hwkey_session = Hwkey::open()?;
        let session = hwkey_session.derive_key_req().unique_key();

        session
            .kdf(KdfVersion::Best)
            .os_rollback_version(OsRollbackVersion::Version(version))
            .rollback_version_source(RollbackVersionSource::CommittedVersion)
            .derive(key_context, &mut derived_key[..])
            .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to derive key {:?}", e))?;

        Ok(derived_key)
    }

    fn get_caller_current_security_version(&self) -> Result<Vec<u8>, HwCryptoError> {
        let hwkey_session = Hwkey::open()?;

        let version =
            match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
                Ok(OsRollbackVersion::Version(n)) => Ok(n),
                _ => Err(hwcrypto_err!(GENERIC_ERROR, "error communicating with HwKey service")),
            }?;
        Ok(version.to_le_bytes().to_vec())
    }
}

pub fn bytes_to_version(version: &[u8]) -> Result<u32, HwCryptoError> {
    Ok(u32::from_le_bytes(version.try_into()?))
}
