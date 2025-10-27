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
use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::KeyPolicy::KeyPolicy;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use hwcryptohalinterfaces::{DeviceKeys, KeymintHmacKey};
use hwkey::{Hwkey, KdfVersion, OsRollbackVersion, RollbackVersionSource};
use kmr_common::crypto::{aes, hmac, Ckdf, Hmac, OpaqueOr};
use kmr_wire::keymint::Digest;
use log::error;
use std::ffi::CStr;
use std::sync::{LazyLock, Mutex};

// We use a singleton because the key is generated once with the parameters received on
// `generate_keymint_shared_hmac_key`, so we need to keep the state to remember what
// the key is on the current boot.
static DEVICE_KEY_OBJECT: LazyLock<Mutex<TrustyDeviceKeysSingleton>> =
    LazyLock::new(|| Mutex::new(TrustyDeviceKeysSingleton { keymint_shared_hmac_key: None }));

// Name of the legacy hwkey key slot name for KeyMint's KAK.
const KM_KAK_SLOT_ID: &[u8] = b"com.android.trusty.keymint.kak\0";
// We are using an AES 256 key for KAK, so its size is 32 bytes.
const TRUSTY_KM_KAK_SIZE: usize = 32;

// Getting the same KAK used by the legacy components to facilitate implementation on devices
// using legacy HwCrypto.
fn kak() -> Result<kmr_common::crypto::OpaqueOr<aes::Key>, HwCryptoError> {
    let hwkey_session = Hwkey::open()?;
    let mut key_buffer = [0; TRUSTY_KM_KAK_SIZE];
    let keyslot = CStr::from_bytes_with_nul(KM_KAK_SLOT_ID)
        .expect("should never happen, KM_KAK_SLOT_ID follows from_bytes_with_nul rules");
    let _kak = hwkey_session
        .get_keyslot_data(keyslot, &mut key_buffer)
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "failed to get kak keslot {:?}", e))?;
    Ok(OpaqueOr::Explicit(aes::Key::Aes256(key_buffer)))
}

struct TrustyDeviceKeysSingleton {
    keymint_shared_hmac_key: Option<Vec<u8>>,
}

impl TrustyDeviceKeysSingleton {
    fn get_keymint_shared_hmac_key(&self) -> Result<KeymintHmacKey, HwCryptoError> {
        match self.keymint_shared_hmac_key.as_ref() {
            Some(hmac_key) => {
                let mut key = Vec::new();
                key.try_reserve(hmac_key.len())?;
                key.extend_from_slice(hmac_key);
                Ok(KeymintHmacKey(OpaqueOr::Explicit(hmac::Key(key))))
            }
            None => {
                error!("shared hmac key requested before generation");
                Err(hwcrypto_err!(BAD_STATE, "key not generated yet"))
            }
        }
    }

    fn generate_keymint_shared_hmac_key(
        &mut self,
        label: &[u8],
        context: &[u8],
        key_len: usize,
        check_label: &[u8],
    ) -> Result<Vec<u8>, HwCryptoError> {
        let key =
            kmr_crypto_boring::aes_cmac::BoringAesCmac.ckdf(&kak()?, label, &[context], key_len)?;
        let mut hmac_key = Vec::new();
        hmac_key.try_reserve(key.len())?;
        hmac_key.extend_from_slice(key.as_slice());
        let hmac_key = hmac::Key(hmac_key);
        let mut hmac_op =
            kmr_crypto_boring::hmac::BoringHmac.begin(hmac_key.into(), Digest::Sha256)?;
        hmac_op.update(check_label)?;
        let verification_value = hmac_op.finish()?;
        self.keymint_shared_hmac_key = Some(key);
        Ok(verification_value)
    }
}

pub struct TrustyDeviceKeys;

impl DeviceKeys for TrustyDeviceKeys {
    fn get_keymint_shared_hmac_key(_policy: &KeyPolicy) -> Result<KeymintHmacKey, HwCryptoError> {
        // unwrapping directly because mutex won't be poisoned on a single threaded application
        let device_key_singleton = DEVICE_KEY_OBJECT.lock().unwrap();
        device_key_singleton.get_keymint_shared_hmac_key()
    }

    fn generate_keymint_shared_hmac_key(
        label: &[u8],
        context: &[u8],
        key_len: usize,
        check_label: &[u8],
    ) -> Result<Vec<u8>, HwCryptoError> {
        // unwrapping directly because mutex won't be poisoned on a single threaded application
        let mut device_key_singleton = DEVICE_KEY_OBJECT.lock().unwrap();
        device_key_singleton.generate_keymint_shared_hmac_key(label, context, key_len, check_label)
    }

    fn derive_caller_unique_key(
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

    fn get_caller_current_security_version() -> Result<Vec<u8>, HwCryptoError> {
        let hwkey_session = Hwkey::open()?;

        let version =
            match hwkey_session.query_current_os_version(RollbackVersionSource::CommittedVersion) {
                Ok(OsRollbackVersion::Version(n)) => Ok(n),
                _ => Err(hwcrypto_err!(GENERIC_ERROR, "error communicating with HwKey service")),
            }?;
        Ok(version.to_le_bytes().to_vec())
    }
}

pub(crate) fn bytes_to_version(version: &[u8]) -> Result<u32, HwCryptoError> {
    Ok(u32::from_le_bytes(version.try_into()?))
}
