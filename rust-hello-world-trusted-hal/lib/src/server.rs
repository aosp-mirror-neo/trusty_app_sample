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

//! Setting up the server for the Hello World Trusted HAL service.
use crate::hand_over_service::HandoverService;
use crate::hello_world_trusted_service::HelloWorldService;
use log::error;
use rpcbinder::RpcServer;
use service_manager::service_name_to_trusty_c_port;
use std::sync::Arc;
use tipc::raw::{EventLoop, HandleSetWrapper};
use tipc::{PortCfg, TipcError};

// Port for the handover service for the HelloWorld trusted service
pub const HANDOVER_SERVICE_PORT: &str = "IHandover/android.hardware.security.IHelloWorld/default";

// Port for the HelloWorld trusted service
// Note: The TAs that host trusted services do not usually register a port handle for a trusted
// service in their event loop. They register a port handle only for the corresponding hand over
// service. We define the port name for the trusted service here because it is needed as an input
// for `on_connect` method that is invoked in the call path of connection handover.
pub const HELLO_WORLD_TRUSTED_SERVICE_PORT: &str = "android.hardware.security.IHelloWorld/default";

pub fn main_loop() -> Result<(), TipcError> {
    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);
    let handle_set_wrapper_clone = Arc::clone(&handle_set_wrapper);
    let helloworld_binder = HelloWorldService::new_binder();
    let helloworld_rpc_service = Arc::new(RpcServer::new(helloworld_binder.as_binder()));

    // Only the AuthMgr BE TA is allowed to connect
    let handover_service_port_cfg =
        PortCfg::new_raw(service_name_to_trusty_c_port(HANDOVER_SERVICE_PORT).map_err(|e| {
            error!("Failed to construct the handover service port name: {:?}", e);
            TipcError::UnknownError
        })?)
        .allow_ta_connect();

    let cb_per_session = move |uuid| {
        HandoverService::new_handover_session(
            uuid,
            Arc::downgrade(&handle_set_wrapper),
            Arc::clone(&helloworld_rpc_service),
        )
    };

    let handover_rpc_service = RpcServer::new_per_session(cb_per_session);
    let _port_wrapper = handle_set_wrapper_clone
        .add_port(&handover_service_port_cfg, Arc::new(handover_rpc_service))?;
    let event_loop = EventLoop::new(handle_set_wrapper_clone.clone());
    event_loop.run()
}
