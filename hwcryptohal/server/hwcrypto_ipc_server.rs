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
use authmgr_be_lib::{default_handover_port_config, HandoverService};
use binder::SpIBinder;
use core::ffi::CStr;
use hwcryptohal_common::{err::HwCryptoError, hwcrypto_err};
use rpcbinder::RpcServer;
use std::sync::Arc;
use tipc::raw::{EventLoop, HandleSetWrapper};
use tipc::{self, PortCfg, Uuid};

pub(crate) const RUST_SERVICE_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
pub(crate) const HANDOVER_SERVICE_PORT: &CStr = c"ahss.hwcrypto.IHwCryptoKey/default.hnd";
pub(crate) const NUM_IPC_QUEUES: u32 = 4;

fn create_device_key_service(uuid: Uuid) -> Option<SpIBinder> {
    Some(hwcrypto_device_key::HwCryptoKey::new_binder(uuid).as_binder())
}

fn hwcryptohal_port_cfg() -> Result<PortCfg, HwCryptoError> {
    Ok(PortCfg::new(RUST_SERVICE_PORT.to_str().expect("should not happen, valid utf-8"))
        .map_err(|e| {
            hwcrypto_err!(
                GENERIC_ERROR,
                "could not create port config for {:?}: {:?}",
                RUST_SERVICE_PORT,
                e
            )
        })?
        .msg_queue_len(NUM_IPC_QUEUES)
        .allow_ta_connect()
        .allow_ns_connect())
}

pub fn main_loop() -> Result<(), HwCryptoError> {
    let hwdk_rpc_server = Arc::new(RpcServer::new_per_session(create_device_key_service));
    let hwdk_cfg = hwcryptohal_port_cfg()?;

    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);
    // keeping a reference to `_port_wrapper_hw_crypto` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_hw_crypto =
        handle_set_wrapper.add_port(&hwdk_cfg, hwdk_rpc_server.clone())?;

    let handle_set_wrapper_for_cb = Arc::clone(&handle_set_wrapper);

    let handover_cb_per_session = move |uuid| {
        Some(
            HandoverService::new_handover_session(
                uuid,
                Arc::downgrade(&handle_set_wrapper_for_cb),
                Arc::clone(&hwdk_rpc_server),
                hwcryptohal_port_cfg().ok()?,
            )
            .as_binder(),
        )
    };

    let handover_rpc_service = Arc::new(RpcServer::new_per_session(handover_cb_per_session));

    let handover_service_port_cfg =
        default_handover_port_config(HANDOVER_SERVICE_PORT).map_err(|e| {
            hwcrypto_err!(
                GENERIC_ERROR,
                "could not create port config for {:?}: {:?}",
                HANDOVER_SERVICE_PORT,
                e
            )
        })?;
    // keeping a reference to `_port_wrapper_handover` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_handover =
        handle_set_wrapper.add_port(&handover_service_port_cfg, handover_rpc_service)?;

    let event_loop = EventLoop::new(handle_set_wrapper.clone());
    Ok(event_loop.run()?)
}

#[cfg(test)]
mod tests {
    use android_hardware_security_see_hwcrypto::aidl::android::hardware::security::see::hwcrypto::IHwCryptoKey::IHwCryptoKey;
    use rpcbinder::RpcSession;
    use binder::{IBinder, Strong};
    use test::expect_eq;
    use super::*;

    #[test]
    fn connect_server() {
        let session_device_key: Strong<dyn IHwCryptoKey> =
            RpcSession::new().setup_trusty_client(RUST_SERVICE_PORT).expect("Failed to connect");
        expect_eq!(session_device_key.as_binder().ping_binder(), Ok(()));
    }
}
