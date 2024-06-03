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

//! AIDL IPC Server code.
use crate::hwcrypto_device_key;
use binder::SpIBinder;
use core::ffi::CStr;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use rpcbinder::RpcServer;
use tipc::{Manager, PortCfg, Uuid};

const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";

fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
    Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
}

pub fn main_loop() -> Result<(), HwCryptoError> {
    let hwdk_rpc_server = RpcServer::new_per_session(create_device_key_service);

    let cfg = PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
        .map_err(|e| {
            hwcrypto_err!(
                GENERIC_ERROR,
                "could not create port config for {:?}: {:?}",
                RUST_SERVICE_PORT,
                e
            )
        })?
        .allow_ta_connect()
        .allow_ns_connect();

    let manager = Manager::<_, _, 1, 4>::new_unbuffered(hwdk_rpc_server, cfg)
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not create service manager: {:?}", e))?;

    manager
        .run_event_loop()
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "service manager received error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use android_hardware_security_see::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
    use rpcbinder::RpcSession;
    use binder::{IBinder, Strong};
    use test::expect_eq;
    use super::*;

    #[test]
    fn connect_server() {
        let session: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        expect_eq!(session.as_binder().ping_binder(), Ok(()));
    }
}
