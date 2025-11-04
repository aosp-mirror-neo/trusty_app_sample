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

//! AIDL IPC Server code

use crate::devicestate::DeviceState;
use authmgr_be_lib::{default_handover_port_config, HandoverService};
use binder::SpIBinder;
use rpcbinder::RpcServer;
use service_manager::service_name_to_trusty_port;
use std::sync::Arc;
use tipc::raw::{EventLoop, HandleSetWrapper};
use tipc::{self, ClientIdentifier, PortCfg, TipcError};

const NUM_IPC_QUEUES: u32 = 4;

const DEVICESTATE_SERVICE_NAME: &str =
    "android.hardware.security.see.devicestate.IDeviceState/default";

fn create_device_state_service(_client_id: ClientIdentifier) -> Option<SpIBinder> {
    Some(DeviceState::new_binder().as_binder())
}

fn devicestatehal_port_cfg() -> Result<PortCfg, TipcError> {
    Ok(PortCfg::new(
        service_name_to_trusty_port(DEVICESTATE_SERVICE_NAME)
            .map_err(|_| TipcError::UnknownError)?,
    )?
    .msg_queue_len(NUM_IPC_QUEUES)
    .allow_ta_connect())
}

pub fn main_loop() -> Result<(), TipcError> {
    let device_state_rpc_server = Arc::new(RpcServer::new_per_session(create_device_state_service));
    let device_state_cfg = devicestatehal_port_cfg()?;

    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);

    // keeping a reference to `_port_wrapper_device_state` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_device_state =
        handle_set_wrapper.add_port(&device_state_cfg, device_state_rpc_server.clone())?;

    let handle_set_wrapper_for_cb = Arc::clone(&handle_set_wrapper);

    let handover_cb_per_session = move |client_id| {
        Some(
            HandoverService::new_handover_session(
                client_id,
                Arc::downgrade(&handle_set_wrapper_for_cb),
                Arc::clone(&device_state_rpc_server),
                devicestatehal_port_cfg().ok()?,
            )
            .as_binder(),
        )
    };

    let handover_rpc_service = Arc::new(RpcServer::new_per_session(handover_cb_per_session));
    let handover_rpc_service_name = format!("IHandover/{}", DEVICESTATE_SERVICE_NAME);
    let handover_service_port_cfg = default_handover_port_config(&handover_rpc_service_name)?;

    // keeping a reference to `_port_wrapper_handover` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_handover =
        handle_set_wrapper.add_port(&handover_service_port_cfg, handover_rpc_service)?;

    let event_loop = EventLoop::new(handle_set_wrapper.clone());
    Ok(event_loop.run()?)
}

#[cfg(test)]
mod tests {
    use android_hardware_security_see_devicestate::aidl::android::hardware::security::see::devicestate::IDeviceState::IDeviceState;
    use rpcbinder::RpcSession;
    use binder::{IBinder, Strong};
    use std::ffi::CString;
    use test::expect_eq;
    use super::*;

    #[test]
    fn connect_server() {
        let session_device_key: Strong<dyn IDeviceState> = RpcSession::new()
            .setup_trusty_client(
                CString::new(
                    service_name_to_trusty_port(DEVICESTATE_SERVICE_NAME)
                        .expect("Failed to get port"),
                )
                .expect("Failed to get port name as cstring")
                .as_c_str(),
            )
            .expect("Failed to connect");
        expect_eq!(session_device_key.as_binder().ping_binder(), Ok(()));
    }
}
