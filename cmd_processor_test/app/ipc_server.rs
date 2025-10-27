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

//! AIDL IPC Server code.
use cmd_processor_test_lib::{CmdProcessor, MemBuffShare};
use rpcbinder::RpcServer;
use std::sync::Arc;
use thiserror::Error;
use tipc::raw::{EventLoop, HandleSetWrapper};
use tipc::{self, PortCfg, TipcError};

pub(crate) const NUM_IPC_QUEUES: u32 = 4;

const CMD_PROCESSOR_SERVICE_NAME: &str = "android.trusty.cmdprocessor.ICommandProcessor/default";
const BUFFER_SHARE_SERVICE_NAME: &str = "android.trusty.membuf.IMemoryBufferShare/default";

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("Port configuration error for port: {0}")]
    PortConfigError(String),

    #[error("Tipc Error found: {0:?}")]
    TipcError(TipcError),
}

impl From<TipcError> for IpcError {
    fn from(err: TipcError) -> Self {
        Self::TipcError(err)
    }
}

fn cmd_processor_service_port_cfg() -> Result<PortCfg, IpcError> {
    Ok(PortCfg::new(CMD_PROCESSOR_SERVICE_NAME)
        .map_err(|e| {
            log::error!(
                "could not create port config for {:?}: {:?}",
                CMD_PROCESSOR_SERVICE_NAME,
                e
            );
            IpcError::PortConfigError(CMD_PROCESSOR_SERVICE_NAME.to_string())
        })?
        .msg_queue_len(NUM_IPC_QUEUES)
        .allow_ns_connect())
}

fn buff_share_service_port_cfg() -> Result<PortCfg, IpcError> {
    Ok(PortCfg::new(BUFFER_SHARE_SERVICE_NAME)
        .map_err(|e| {
            log::error!(
                "could not create port config for {:?}: {:?}",
                CMD_PROCESSOR_SERVICE_NAME,
                e
            );
            IpcError::PortConfigError(BUFFER_SHARE_SERVICE_NAME.to_string())
        })?
        .msg_queue_len(NUM_IPC_QUEUES)
        .allow_ns_connect())
}

pub fn main_loop() -> Result<(), IpcError> {
    // Creating main handle set wrapper that wil manage connection to both services running on this
    // application
    let handle_set_wrapper = Arc::new(HandleSetWrapper::new()?);

    // Creating the Command Processor service and adding it to the handle set wrapper
    let cmd_processor_binder = CmdProcessor::new_binder();
    let cmd_processor = Arc::new(RpcServer::new(cmd_processor_binder.as_binder()));
    let cmd_processor_cfg = cmd_processor_service_port_cfg()?;
    // keeping a reference to `_port_wrapper_cmd_processor` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_cmd_processor =
        handle_set_wrapper.add_port(&cmd_processor_cfg, cmd_processor)?;

    // Creating the Memory Buffer share service and adding it to the handle set wrapper
    let membuf_binder = MemBuffShare::new_binder();
    let membuf = Arc::new(RpcServer::new(membuf_binder.as_binder()));
    let membuf_cfg = buff_share_service_port_cfg()?;
    // keeping a reference to `_port_wrapper_membuf` is necessary for the service not to be
    // removed from the set
    let _port_wrapper_membuf = handle_set_wrapper.add_port(&membuf_cfg, membuf)?;

    // Starting the main loop that handles all connections
    let event_loop = EventLoop::new(handle_set_wrapper.clone());
    Ok(event_loop.run()?)
}
