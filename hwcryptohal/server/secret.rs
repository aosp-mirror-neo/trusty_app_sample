// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TA functionality for shared secret negotiation.

use alloc::vec::Vec;
use hwcryptohalinterfaces::DeviceKeys;
use hwcryptohalplatform::DeviceKeysImpl;
use kmr_common::{crypto::Rng, vec_try, FallibleAllocExt};
use kmr_wire::keymint::ErrorCode;
use log::info;
use std::sync::Mutex;

use android_hardware_security_sharedsecret::aidl::android::hardware::security::sharedsecret::{
    ISharedSecret::BnSharedSecret, ISharedSecret::ISharedSecret,
    SharedSecretParameters::SharedSecretParameters,
};

// ISharedSecret protocol dictates that the nonces len is 32 bytes
const SHARED_SECRET_PARAM_LEN: usize = 32;

pub struct SharedSecret {
    shared_secret_params: Mutex<Option<SharedSecretParameters>>,
}

impl binder::Interface for SharedSecret {}

impl ISharedSecret for SharedSecret {
    fn getSharedSecretParameters(&self) -> binder::Result<SharedSecretParameters> {
        self.get_shared_secret_params()
    }

    fn computeSharedSecret(
        &self,
        shared_secret_parameters: &[SharedSecretParameters],
    ) -> binder::Result<Vec<u8>> {
        self.compute_shared_secret(shared_secret_parameters)
    }
}

impl SharedSecret {
    pub fn new_binder() -> binder::Strong<dyn ISharedSecret> {
        let shared_secret = SharedSecret { shared_secret_params: Mutex::new(None) };
        BnSharedSecret::new_binder(shared_secret, binder::BinderFeatures::default())
    }

    fn get_shared_secret_params(&self) -> binder::Result<SharedSecretParameters> {
        {
            // Mutex won't be poisoned on a single threaded application
            let mut shared_secret_params = self.shared_secret_params.lock().unwrap();
            if shared_secret_params.is_none() {
                let mut nonce = vec_try![0u8; SHARED_SECRET_PARAM_LEN].map_err(|_| {
                    binder::Status::new_service_specific_error(
                        ErrorCode::MemoryAllocationFailed as i32,
                        None,
                    )
                })?;
                hwcryptohalplatform::RngImpl.fill_bytes(&mut nonce);
                *shared_secret_params = Some(SharedSecretParameters { seed: Vec::new(), nonce });
            }
        }
        // safe to unwrap filled above and mutex won't be poisoned in a single threaded application
        Ok(self.shared_secret_params.lock().unwrap().as_ref().unwrap().clone())
    }

    fn compute_shared_secret(&self, params: &[SharedSecretParameters]) -> binder::Result<Vec<u8>> {
        info!("Setting HMAC key from {} shared secret parameters", params.len());
        let local_params_option = self.shared_secret_params.lock().unwrap();
        let local_params =
            local_params_option.as_ref().ok_or(binder::Status::new_service_specific_error(
                ErrorCode::HardwareNotYetAvailable as i32,
                Some(c"no local shared secret params"),
            ))?;

        let context = shared_secret_context(params, local_params)?;
        DeviceKeysImpl::generate_keymint_shared_hmac_key(
            kmr_wire::sharedsecret::KEY_AGREEMENT_LABEL.as_bytes(),
            &context,
            kmr_common::crypto::SHA256_DIGEST_LEN,
            kmr_wire::sharedsecret::KEY_CHECK_LABEL.as_bytes(),
        )
        .map_err(|e| {
            log::error!("Couldn't generate hmac key: {:?}", e);
            binder::Status::new_service_specific_error(
                ErrorCode::UnknownError as i32,
                Some(c"error generating shared hmac key"),
            )
        })
    }
}

/// Build the shared secret context from the given `params`, which
/// is required to include `must_include` (our own parameters).
fn shared_secret_context(
    params: &[SharedSecretParameters],
    must_include: &SharedSecretParameters,
) -> binder::Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut seen = false;
    for param in params {
        result.try_extend_from_slice(&param.seed).map_err(|_| {
            binder::Status::new_service_specific_error(
                ErrorCode::MemoryAllocationFailed as i32,
                None,
            )
        })?;
        if param.nonce.len() != SHARED_SECRET_PARAM_LEN {
            return Err(binder::Status::new_service_specific_error(
                ErrorCode::InvalidArgument as i32,
                Some(c"nonce len not 32"),
            ));
        }
        result.try_extend_from_slice(&param.nonce).map_err(|_| {
            binder::Status::new_service_specific_error(
                ErrorCode::MemoryAllocationFailed as i32,
                None,
            )
        })?;
        if param == must_include {
            seen = true;
        }
    }
    if !seen {
        Err(binder::Status::new_service_specific_error(
            ErrorCode::InvalidArgument as i32,
            Some(c"shared secret params missing local value"),
        ))
    } else {
        Ok(result)
    }
}
