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
use crate::hwcrypto_operations;
use alloc::rc::Rc;
use binder::SpIBinder;
use core::ffi::CStr;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use rpcbinder::RpcServer;
use tipc::{self, service_dispatcher, wrap_service, Manager, PortCfg, Uuid};

wrap_service!(HwCryptoDeviceKey(RpcServer: UnbufferedService));
wrap_service!(HwCryptoOperations(RpcServer: UnbufferedService));

service_dispatcher! {
    enum HWCryptoHal {
        HwCryptoOperations,
        HwCryptoDeviceKey,
    }
}

pub(crate) const RUST_HWCRYPTO_OPS_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.ops.V1";
pub(crate) const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";

fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
    Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
}

pub fn main_loop() -> Result<(), HwCryptoError> {
    let mut dispatcher = HWCryptoHal::<2>::new().map_err(|e| {
        hwcrypto_err!(GENERIC_ERROR, "could not create multi-service dispatcher: {:?}", e)
    })?;

    let hw_key = hwcrypto_operations::HwCryptoOperations::new_binder();
    let hwk_rpc_server = RpcServer::new(hw_key.as_binder());
    let hwk_service = HwCryptoOperations(hwk_rpc_server);
    let hwdk_rpc_server = RpcServer::new_per_session(create_device_key_service);
    let hwdk_service = HwCryptoDeviceKey(hwdk_rpc_server);

    let cfg =
        PortCfg::new(RUST_HWCRYPTO_OPS_PORT.to_str().expect("should not happen, valid utf-8"))
            .map_err(|e| {
                hwcrypto_err!(
                    GENERIC_ERROR,
                    "could not create port config for {:?}: {:?}",
                    RUST_HWCRYPTO_OPS_PORT,
                    e
                )
            })?
            .allow_ta_connect()
            .allow_ns_connect();

    dispatcher
        .add_service(Rc::new(hwk_service), cfg)
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto service: {:?}", e))?;

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

    dispatcher.add_service(Rc::new(hwdk_service), cfg).map_err(|e| {
        hwcrypto_err!(GENERIC_ERROR, "could add HWCrypto device key service: {:?}", e)
    })?;

    let manager = Manager::<_, _, 2, 4>::new_with_dispatcher(dispatcher, [])
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "could not create service manager: {:?}", e))?;

    manager
        .run_event_loop()
        .map_err(|e| hwcrypto_err!(GENERIC_ERROR, "service manager received error: {:?}", e))
}

#[cfg(test)]
mod tests {
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoOperations::IHwCryptoOperations;
    use rpcbinder::RpcSession;
    use binder::{IBinder, Strong};
    use test::expect_eq;
    use super::*;

    #[test]
    fn connect_server() {
        let session: Strong<dyn IHwCryptoOperations> = RpcSession::new()
            .setup_trusty_client(RUST_HWCRYPTO_OPS_PORT)
            .expect("Failed to connect");
        expect_eq!(session.as_binder().ping_binder(), Ok(()));

        let session_device_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        expect_eq!(session_device_key.as_binder().ping_binder(), Ok(()));
    }
}
